/*
 * mod_bw.c - Module entry point: hook registration, lifecycle hooks,
 *             module declaration, and the global state instance.
 */

#include "mod_bw.h"
#include "mod_bw_config.h"
#include "mod_bw_shm.h"
#include "mod_bw_tokens.h"

/* ------------------------------------------------------------------ */
/* Global module state (one per process; initialised in post_config)   */
/* ------------------------------------------------------------------ */
bw_global_t bw_g = {0};

/* ------------------------------------------------------------------ */
/* bw_pre_config - APR atomics init (runs before config parsing)       */
/* ------------------------------------------------------------------ */
int bw_pre_config(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp)
{
  apr_status_t rv = apr_atomic_init(p);
  if (rv != APR_SUCCESS)
  {
    ap_log_error(APLOG_MARK, APLOG_CRIT, rv, NULL,
                 "mod_bw: apr_atomic_init failed");
    return HTTP_INTERNAL_SERVER_ERROR;
  }
  return OK;
}

/* ------------------------------------------------------------------ */
/* bw_post_config - SHM creation and SHM population (second call)     */
/* ------------------------------------------------------------------ */
int bw_post_config(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp,
                   server_rec *s)
{
  /* Double-init guard: Apache calls post_config twice.
     * The first call (data == NULL) is for the config check phase;
     * we skip real init and return immediately. */
  void *data;
  const char *key = "mod_bw_postconfig_v2";
  apr_pool_userdata_get(&data, key, s->process->pool);
  if (!data)
  {
    apr_pool_userdata_set((const void *)1, key,
                          apr_pool_cleanup_null, s->process->pool);
    return OK;
  }

  if (bw_g.mod_disabled)
  {
    ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s,
                 "mod_bw: module disabled; skipping init");
    return OK;
  }

  /* Gather SHM config from the main server's config.
     * Vhost-level BandWidthSHMFile / BandWidthMax* directives on the
     * main server win; individual vhosts' settings are ignored here. */
  bandwidth_server_config *msc =
      (bandwidth_server_config *)ap_get_module_config(
          s->module_config, &bw_module);

  const char *shm_file = msc->shm_file ? msc->shm_file : BW_SHM_FILE_DEFAULT;
  const char *lock_file = msc->lock_file ? msc->lock_file : BW_LOCK_FILE_DEFAULT;
  apr_uint32_t max_v = msc->max_vhosts ? msc->max_vhosts : BW_MAX_VHOSTS_DEFAULT;
  apr_uint32_t max_p = msc->max_pools ? msc->max_pools : BW_MAX_POOLS_DEFAULT;
  apr_uint32_t max_r = msc->max_rules ? msc->max_rules : BW_MAX_RULES_DEFAULT;
  apr_uint32_t max_t = msc->max_tokens ? msc->max_tokens : BW_MAX_TOKENS_DEFAULT;

  bw_g.stats_dir = msc->stats_dir ? msc->stats_dir : STATS_DIR_DEFAULT;
  bw_g.token_store = bw_token_store_path(p, msc, shm_file);

  /* Ensure stats directory exists */
  apr_dir_make_recursive(bw_g.stats_dir, APR_OS_DEFAULT, ptemp);

  /* Create / attach to named SHM and create global mutex */
  apr_status_t rv = bw_shm_init(p, s, shm_file, lock_file,
                                max_v, max_p, max_r, max_t);
  if (rv != APR_SUCCESS)
    return HTTP_INTERNAL_SERVER_ERROR;

  /* Walk all server configs and populate SHM slots */
  rv = bwcfg_populate_shm(s, p);
  if (rv != APR_SUCCESS)
    return HTTP_INTERNAL_SERVER_ERROR;

  /* Seed the token store from disk only when we just created the SHM
     * region; on a graceful restart the existing tokens are still live. */
  if (bw_shm_was_created)
    bw_tokens_load(p, s);

  ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s,
               "mod_bw %s initialised: %u vhosts, %u pools, %u rules",
               MOD_BW_VERSION,
               bw_g.hdr->n_vhosts,
               bw_g.hdr->n_pools,
               bw_g.hdr->n_rules);

  return OK;
}

/* ------------------------------------------------------------------ */
/* bw_child_init - per-worker initialisation                           */
/* ------------------------------------------------------------------ */
void bw_child_init(apr_pool_t *pchild, server_rec *s)
{
  if (bw_g.mod_disabled || !bw_g.hdr)
    return;

  bandwidth_server_config *msc =
      (bandwidth_server_config *)ap_get_module_config(
          s->module_config, &bw_module);

  const char *lock_file =
      (msc && msc->lock_file) ? msc->lock_file : BW_LOCK_FILE_DEFAULT;

  /* Re-attach mutex in child process (required for some APR backends) */
  bw_mutex_child_init(pchild, s, lock_file);

  /* Allocate per-process compiled rule cache */
  bw_rule_cache_init(pchild, bw_g.hdr->max_rules);
}

/* ------------------------------------------------------------------ */
/* Module hook registration                                            */
/* ------------------------------------------------------------------ */
static void register_hooks(apr_pool_t *p)
{
  ap_hook_pre_config(bw_pre_config, NULL, NULL, APR_HOOK_REALLY_FIRST);
  ap_hook_post_config(bw_post_config, NULL, NULL, APR_HOOK_MIDDLE);
  ap_hook_child_init(bw_child_init, NULL, NULL, APR_HOOK_MIDDLE);

  /* Status page content handler (SetHandler mod-bw-status) */
  ap_hook_handler(bw_status_handler, NULL, NULL, APR_HOOK_MIDDLE);

  /* Access checker runs first to install filters and enforce maxconn */
  ap_hook_handler(handle_bw, NULL, NULL, APR_HOOK_FIRST);

  /* Output throttle filter */
  ap_register_output_filter("mod_bw_out", bw_filter,
                            NULL, AP_FTYPE_TRANSCODE);

  /* Input throttle filter */
  ap_register_input_filter("mod_bw_in",
                           (ap_in_filter_func)bw_in_filter,
                           NULL, AP_FTYPE_TRANSCODE);
}

/* ------------------------------------------------------------------ */
/* Module declaration                                                  */
/* ------------------------------------------------------------------ */
module AP_MODULE_DECLARE_DATA bw_module = {
    STANDARD20_MODULE_STUFF,
    create_bw_config,        /* create per-directory config  */
    NULL,                    /* merge per-directory config   */
    create_bw_server_config, /* create per-server config     */
    NULL,                    /* merge per-server config      */
    bw_cmds,                 /* command table                */
    register_hooks           /* register hooks               */
};
