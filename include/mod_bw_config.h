/*
 * mod_bw_config.h - Apache config structures and directive declarations
 *
 * Config-phase data lives in Apache's normal per-server / per-directory
 * config pools (apr_palloc from cmd->pool or server->process->pool).
 * In post_config these are walked to populate the SHM slot arrays.
 */

#ifndef MOD_BW_CONFIG_H
#define MOD_BW_CONFIG_H

#include "mod_bw.h"

/* ------------------------------------------------------------------ */
/* Rule types (mirror BW_RULE_T_* from mod_bw_slots.h)                */
/* ------------------------------------------------------------------ */
typedef enum
{
  T_ALL = BW_RULE_T_ALL,
  T_IP = BW_RULE_T_IP,
  T_HOST = BW_RULE_T_HOST,
  T_AGENT = BW_RULE_T_AGENT
} bw_from_type;

/* ------------------------------------------------------------------ */
/* Per-rule config (stored in pool's rules array during config phase)  */
/* ------------------------------------------------------------------ */
typedef struct
{
  bw_from_type rule_type;
  unsigned char direction;       /* BW_RULE_OUT/IN/BOTH             */
  char value[BW_RULE_VALUE_LEN]; /* raw string before compile */
  apr_int32_t rate;              /* output bytes/sec                */
  apr_int32_t in_rate;           /* input bytes/sec                 */
  apr_int32_t min_rate;          /* minimum fair-share output rate  */
  /* Compiled forms, set in post_config; only used until child_init
     * builds the per-process cache */
  apr_ipsubnet_t *ip_subnet;
  ap_regex_t *regex;
} bw_rule_cfg_t;

/* ------------------------------------------------------------------ */
/* Per-pool config (stored in server config during config phase)       */
/* ------------------------------------------------------------------ */
typedef struct
{
  apr_uint32_t id;           /* user-assigned pool ID           */
  apr_uint32_t parent_id;    /* 0 = root pool                   */
  apr_uint32_t bwlimit;      /* output bytes/sec                */
  apr_uint32_t in_bwlimit;   /* input bytes/sec                 */
  apr_uint32_t maxc;         /* max concurrent connections      */
  apr_int32_t packet;        /* -1 = inherit from dir config    */
  apr_int32_t error_code;    /* -1 = inherit                    */
  apr_array_header_t *rules; /* bw_rule_cfg_t[]                 */
  /* Back-reference to SHM slot (set during post_config) */
  apr_uint32_t shm_pool_idx;
} bw_pool_cfg_t;

/* ------------------------------------------------------------------ */
/* Per-server config                                                    */
/* ------------------------------------------------------------------ */
typedef struct
{
  int state; /* BANDWIDTH_ENABLED / DISABLED    */
  int force; /* unused; kept for compat         */

  /* Pool list for this vhost (bw_pool_cfg_t*[]) */
  apr_array_header_t *pool_cfgs;

  /* API (meaningful on any vhost; the one that serves /_bw_api) */
  int api_enabled;
  char *api_token; /* Bearer token value              */
  char *api_path;  /* URL prefix, default /_bw_api    */

  /* SHM / mutex paths - only used from the main server's config.
     * If set on a vhost they are silently ignored. */
  char *shm_file;
  char *lock_file;
  char *stats_dir;

  /* SHM capacities */
  apr_uint32_t max_vhosts;
  apr_uint32_t max_pools;
  apr_uint32_t max_rules;
  apr_uint32_t max_tokens; /* API token store capacity        */

  /* Path to the persisted token store (JSON). Only used from the main
     * server's config; default derived from the SHM file's directory. */
  char *token_store;

  /* Back-reference to SHM vhost slot (set during post_config) */
  apr_uint32_t shm_vhost_idx;
} bandwidth_server_config;

/* ------------------------------------------------------------------ */
/* Per-directory config (packet size and error code overrides only)    */
/* ------------------------------------------------------------------ */
typedef struct
{
  int packet;             /* PACKET_DEFAULT if not set       */
  int error;              /* HTTP_SERVICE_UNAVAILABLE        */
  int throttle_mode;      /* BW_MODE_* (default BW_MODE_SLEEP)*/
  int ingress_mode;       /* BW_IMODE_* (default BW_IMODE_SLEEP)*/
  apr_uint32_t mark_base; /* fwmark base for 'mark' mode (+pool id)*/
  char *directory;
} bandwidth_config;

/* ------------------------------------------------------------------ */
/* Enabled flag values (for bandwidth_server_config.state)             */
/* ------------------------------------------------------------------ */
#define BANDWIDTH_DISABLED 0
#define BANDWIDTH_ENABLED 1

/* ------------------------------------------------------------------ */
/* Directive handlers (implemented in mod_bw_config.c)                 */
/* ------------------------------------------------------------------ */
const char *bwcfg_module(cmd_parms *cmd, void *dcfg, int flag);
const char *bwcfg_pool(cmd_parms *cmd, void *dcfg, const char *args);
const char *bwcfg_packet(cmd_parms *cmd, void *dcfg, const char *val);
const char *bwcfg_error(cmd_parms *cmd, void *dcfg, const char *val);
const char *bwcfg_throttle_mode(cmd_parms *cmd, void *dcfg, const char *val);
const char *bwcfg_ingress_mode(cmd_parms *cmd, void *dcfg, const char *val);
const char *bwcfg_mark_base(cmd_parms *cmd, void *dcfg, const char *val);

/* API directives */
const char *bwcfg_api_enabled(cmd_parms *cmd, void *dcfg, int flag);
const char *bwcfg_api_token(cmd_parms *cmd, void *dcfg, const char *val);
const char *bwcfg_api_path(cmd_parms *cmd, void *dcfg, const char *val);
const char *bwcfg_token_store(cmd_parms *cmd, void *dcfg, const char *val);
const char *bwcfg_max_tokens(cmd_parms *cmd, void *dcfg, const char *val);

/* SHM / capacity directives (global) */
const char *bwcfg_shm_file(cmd_parms *cmd, void *dcfg, const char *val);
const char *bwcfg_lock_file(cmd_parms *cmd, void *dcfg, const char *val);
const char *bwcfg_stats_dir(cmd_parms *cmd, void *dcfg, const char *val);
const char *bwcfg_max_vhosts(cmd_parms *cmd, void *dcfg, const char *val);
const char *bwcfg_max_pools(cmd_parms *cmd, void *dcfg, const char *val);
const char *bwcfg_max_rules(cmd_parms *cmd, void *dcfg, const char *val);

/* Called by bw_post_config to walk all servers and fill SHM slots */
apr_status_t bwcfg_populate_shm(server_rec *main_server, apr_pool_t *p);

/* Helper: return the server config for a request */
static APR_INLINE bandwidth_server_config *
bw_sconf(const request_rec *r)
{
  return (bandwidth_server_config *)
      ap_get_module_config(r->server->module_config, &bw_module);
}

/* Helper: return the directory config for a request */
static APR_INLINE bandwidth_config *
bw_dconf(const request_rec *r)
{
  return (bandwidth_config *)
      ap_get_module_config(r->per_dir_config, &bw_module);
}

/* Command table (defined in mod_bw_config.c, used in mod_bw.c) */
extern const command_rec bw_cmds[];

#endif /* MOD_BW_CONFIG_H */
