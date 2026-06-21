/*
 * mod_bw_config.c - Apache configuration directive handlers and
 *                   post_config SHM population.
 *
 * Design: directive handlers write ONLY to Apache config pool memory
 * (bandwidth_server_config, bandwidth_config).  The SHM slot arrays
 * are populated in bwcfg_populate_shm(), which is called from
 * bw_post_config() on the second (real) invocation.
 */

#include "mod_bw_config.h"
#include "mod_bw_shm.h"
#include <apr_strings.h>
#include <apr_lib.h>
#include <http_core.h>

/* ------------------------------------------------------------------ */
/* Apache config struct creators (called by the module framework)     */
/* ------------------------------------------------------------------ */

void *create_bw_config(apr_pool_t *p, char *path)
{
  bandwidth_config *cfg = apr_pcalloc(p, sizeof(*cfg));
  cfg->packet = PACKET_DEFAULT;
  cfg->error = HTTP_SERVICE_UNAVAILABLE;
  cfg->throttle_mode = BW_MODE_SLEEP;
  cfg->ingress_mode = BW_IMODE_SLEEP;
  cfg->mark_base = 0;
  cfg->directory = apr_pstrdup(p, path ? path : "");
  return cfg;
}

void *create_bw_server_config(apr_pool_t *p, server_rec *s)
{
  bandwidth_server_config *sc = apr_pcalloc(p, sizeof(*sc));
  sc->state = BANDWIDTH_DISABLED;
  sc->force = 0;
  sc->api_enabled = 0;
  sc->api_token = NULL;
  sc->api_path = "/_bw_api";
  sc->shm_file = BW_SHM_FILE_DEFAULT;
  sc->lock_file = BW_LOCK_FILE_DEFAULT;
  sc->stats_dir = STATS_DIR_DEFAULT;
  sc->max_vhosts = BW_MAX_VHOSTS_DEFAULT;
  sc->max_pools = BW_MAX_POOLS_DEFAULT;
  sc->max_rules = BW_MAX_RULES_DEFAULT;
  sc->pool_cfgs = apr_array_make(p, 4, sizeof(bw_pool_cfg_t *));
  sc->shm_vhost_idx = BW_IDX_NONE;
  return sc;
}

/* ------------------------------------------------------------------ */
/* Internal: locate the server config for a directive                 */
/* ------------------------------------------------------------------ */
static bandwidth_server_config *sconf_for(cmd_parms *cmd)
{
  return (bandwidth_server_config *)
      ap_get_module_config(cmd->server->module_config, &bw_module);
}

/* ------------------------------------------------------------------ */
/* BandWidthModule on|off                                             */
/* ------------------------------------------------------------------ */
const char *bwcfg_module(cmd_parms *cmd, void *dcfg, int flag)
{
  bandwidth_server_config *sc = sconf_for(cmd);

  if (ap_check_cmd_context(cmd, NOT_IN_VIRTUALHOST) == NULL)
  {
    /* Appeared outside any <VirtualHost>: disable globally */
    bw_g.mod_disabled = 1;
    ap_log_error(APLOG_MARK, APLOG_WARNING, 0, NULL,
                 "mod_bw: BandWidthModule outside <VirtualHost> - "
                 "module globally disabled");
    return NULL;
  }
  sc->state = flag ? BANDWIDTH_ENABLED : BANDWIDTH_DISABLED;
  return NULL;
}

/* ------------------------------------------------------------------ */
/* BandWidthPool <id> <where> <out_bwlimit> <maxc>                    */
/*              [parent:<id>] [in:<in_bwlimit>] [min:<min_rate>]      */
/*                                                                    */
/* Creates a pool entry and one rule within it.  Multiple             */
/* BandWidthPool directives with the same pool id are allowed; they   */
/* just add additional rules to the same pool.                        */
/* ------------------------------------------------------------------ */
const char *bwcfg_pool(cmd_parms *cmd, void *dcfg, const char *args)
{
  bandwidth_server_config *sc = sconf_for(cmd);
  apr_pool_t *p = cmd->pool;

  if (ap_check_cmd_context(cmd, NOT_IN_VIRTUALHOST) == NULL)
  {
    ap_log_error(APLOG_MARK, APLOG_WARNING, 0, NULL,
                 "mod_bw: BandWidthPool outside <VirtualHost> - ignored");
    return NULL;
  }
  if (bw_g.mod_disabled)
    return NULL;

  /* Parse: <pool_id> <where> <out_bwlimit> <maxc>
     *        [parent:<n>] [in:<n>] [min:<n>]  */
  char *token;
  long pool_id = 0;
  long out_bw = 0;
  long maxc = 0;
  long parent_id = 0;
  long in_bw = 0;
  long min_bw = 0;
  char where[BW_RULE_VALUE_LEN] = {0};

  /* field 1: pool id */
  token = ap_get_token(p, &args, 0);
  if (!token || !*token)
    return "BandWidthPool: missing pool ID";
  pool_id = atol(token);
  if (pool_id <= 0)
    return "BandWidthPool: pool ID must be > 0";

  /* field 2: where */
  token = ap_get_token(p, &args, 0);
  if (!token || !*token)
    return "BandWidthPool: missing <where>";
  if (strlen(token) >= sizeof(where))
    return "BandWidthPool: <where> too long (max 255 chars)";
  apr_cpystrn(where, token, sizeof(where));

  /* field 3: out_bwlimit */
  token = ap_get_token(p, &args, 0);
  if (!token || !*token)
    return "BandWidthPool: missing output bandwidth limit";
  if (!apr_isdigit(*token))
    return "BandWidthPool: output bandwidth limit must be a number";
  out_bw = atol(token);

  /* field 4: maxc */
  if (!*args)
    return "BandWidthPool: missing max connections";
  token = ap_get_token(p, &args, 0);
  if (!token || !apr_isdigit(*token))
    return "BandWidthPool: max connections must be a number";
  maxc = atol(token);

  /* optional key:value pairs */
  while (*args)
  {
    token = ap_get_token(p, &args, 0);
    if (!token || !*token)
      break;
    if (!strncasecmp(token, "parent:", 7))
      parent_id = atol(token + 7);
    else if (!strncasecmp(token, "in:", 3))
      in_bw = atol(token + 3);
    else if (!strncasecmp(token, "min:", 4))
      min_bw = atol(token + 4);
    /* unknown options are silently ignored for forward compat */
  }

  /* Reject negative numeric fields: cast into apr_uint32_t/apr_int32_t below
     * would otherwise wrap a negative into a huge limit. */
  if (in_bw < 0 || min_bw < 0 || parent_id < 0)
    return "BandWidthPool: in:/min:/parent: values must be >= 0";

  /* Find or create the pool config entry */
  bw_pool_cfg_t *pcfg = NULL;
  bw_pool_cfg_t **slots = (bw_pool_cfg_t **)sc->pool_cfgs->elts;
  int i;
  for (i = 0; i < sc->pool_cfgs->nelts; i++)
  {
    if (slots[i]->id == (apr_uint32_t)pool_id)
    {
      pcfg = slots[i];
      break;
    }
  }
  if (!pcfg)
  {
    pcfg = apr_pcalloc(p, sizeof(*pcfg));
    pcfg->id = (apr_uint32_t)pool_id;
    pcfg->parent_id = (apr_uint32_t)parent_id;
    pcfg->bwlimit = (apr_uint32_t)out_bw;
    pcfg->in_bwlimit = (apr_uint32_t)in_bw;
    pcfg->maxc = (apr_uint32_t)maxc;
    pcfg->packet = -1;
    pcfg->error_code = -1;
    pcfg->rules = apr_array_make(p, 4, sizeof(bw_rule_cfg_t));
    pcfg->shm_pool_idx = BW_IDX_NONE;
    *(bw_pool_cfg_t **)apr_array_push(sc->pool_cfgs) = pcfg;
  }

  /* Build the rule entry */
  bw_rule_cfg_t *rule = (bw_rule_cfg_t *)apr_array_push(pcfg->rules);
  memset(rule, 0, sizeof(*rule));
  rule->rate = (apr_int32_t)out_bw;
  rule->in_rate = (apr_int32_t)in_bw;
  rule->min_rate = (apr_int32_t)min_bw;
  rule->direction = BW_RULE_BOTH;
  apr_cpystrn(rule->value, where, sizeof(rule->value));

  /* Classify the 'where' field */
  apr_status_t rv;
  char msgbuf[128];

  if (!strcasecmp(where, "all"))
  {
    rule->rule_type = T_ALL;
  }
  else if (!strncasecmp(where, "u:", 2))
  {
    rule->rule_type = T_AGENT;
    rule->regex = ap_pregcomp(p, where + 2, AP_REG_EXTENDED | AP_REG_ICASE);
    if (!rule->regex)
      return "BandWidthPool: cannot compile User-Agent regex";
  }
  else
  {
    char buf[BW_RULE_VALUE_LEN];
    char *slash;
    apr_cpystrn(buf, where, sizeof(buf));
    slash = strchr(buf, '/');
    if (slash)
      *slash++ = '\0';

    rv = apr_ipsubnet_create(&rule->ip_subnet, buf, slash, p);
    if (rv == APR_SUCCESS || !APR_STATUS_IS_EINVAL(rv))
    {
      if (rv != APR_SUCCESS)
      {
        apr_strerror(rv, msgbuf, sizeof(msgbuf));
        return apr_pstrdup(p, msgbuf);
      }
      rule->rule_type = T_IP;
    }
    else
    {
      rule->rule_type = T_HOST;
    }
  }

  return NULL;
}

/* ------------------------------------------------------------------ */
/* BandWidthPacket <bytes>                                            */
/* ------------------------------------------------------------------ */
const char *bwcfg_packet(cmd_parms *cmd, void *dcfg, const char *val)
{
  bandwidth_config *cfg = (bandwidth_config *)dcfg;
  int n;

  if (!val || !apr_isdigit(*val))
    return "BandWidthPacket: invalid argument";
  n = atoi(val);
  if (n < PACKET_MIN || n > PACKET_MAX)
    return apr_psprintf(cmd->pool,
                        "BandWidthPacket: must be between %d and %d bytes",
                        PACKET_MIN, PACKET_MAX);
  cfg->packet = n;
  return NULL;
}

/* ------------------------------------------------------------------ */
/* BandWidthError <code>                                              */
/* ------------------------------------------------------------------ */
const char *bwcfg_error(cmd_parms *cmd, void *dcfg, const char *val)
{
  bandwidth_config *cfg = (bandwidth_config *)dcfg;
  int n;

  if (!val || !apr_isdigit(*val))
    return "BandWidthError: invalid argument";
  n = atoi(val);
  if (n < 300 || n > 999)
    return "BandWidthError: code must be 300-999";
  cfg->error = n;
  return NULL;
}

/* ------------------------------------------------------------------ */
/* BandWidthThrottleMode  sleep|pacing|tc                              */
/* ------------------------------------------------------------------ */
const char *bwcfg_throttle_mode(cmd_parms *cmd, void *dcfg, const char *val)
{
  bandwidth_config *cfg = (bandwidth_config *)dcfg;
  int m;

  if (!strcasecmp(val, "sleep"))
    m = BW_MODE_SLEEP;
  else if (!strcasecmp(val, "pacing"))
    m = BW_MODE_PACING;
  else if (!strcasecmp(val, "tc"))
    m = BW_MODE_TC;
  else if (!strcasecmp(val, "mark"))
    m = BW_MODE_MARK;
  else
    return "BandWidthThrottleMode: must be one of sleep|pacing|tc|mark";

  /* Accept even if not compiled in; the filter falls back to sleep at
     * runtime.  Warn now so the operator knows the directive is inert. */
  if (!bw_mode_supported(m))
    ap_log_error(APLOG_MARK, APLOG_WARNING, 0, cmd->server,
                 "mod_bw: BandWidthThrottleMode '%s' is not compiled in "
                 "on this build/platform - will use 'sleep'",
                 val);

  cfg->throttle_mode = m;
  return NULL;
}

/* ------------------------------------------------------------------ */
/* BandWidthIngressMode  sleep|clamp                                   */
/* ------------------------------------------------------------------ */
const char *bwcfg_ingress_mode(cmd_parms *cmd, void *dcfg, const char *val)
{
  bandwidth_config *cfg = (bandwidth_config *)dcfg;
  int m;

  if (!strcasecmp(val, "sleep"))
    m = BW_IMODE_SLEEP;
  else if (!strcasecmp(val, "clamp"))
    m = BW_IMODE_CLAMP;
  else if (!strcasecmp(val, "mark"))
    m = BW_IMODE_MARK;
  else
    return "BandWidthIngressMode: must be one of sleep|clamp|mark";

  if (!bw_ingress_supported(m))
    ap_log_error(APLOG_MARK, APLOG_WARNING, 0, cmd->server,
                 "mod_bw: BandWidthIngressMode '%s' is not compiled in "
                 "on this build/platform - will use 'sleep'",
                 val);

  cfg->ingress_mode = m;
  return NULL;
}

/* ------------------------------------------------------------------ */
/* BandWidthMarkBase <n>  - fwmark base for 'mark' mode (mark = base+pool id) */
/* ------------------------------------------------------------------ */
const char *bwcfg_mark_base(cmd_parms *cmd, void *dcfg, const char *val)
{
  bandwidth_config *cfg = (bandwidth_config *)dcfg;
  if (!val || !*val)
    return "BandWidthMarkBase: missing value";
  /* strtoul with base 0 accepts decimal, 0x-hex, and 0-octal. */
  cfg->mark_base = (apr_uint32_t)strtoul(val, NULL, 0);
  return NULL;
}

/* ------------------------------------------------------------------ */
/* API directives                                                      */
/* ------------------------------------------------------------------ */
const char *bwcfg_api_enabled(cmd_parms *cmd, void *dcfg, int flag)
{
  sconf_for(cmd)->api_enabled = flag;
  if (flag)
    bw_g.hdr ? apr_atomic_set32(&bw_g.hdr->api_flags, BW_API_ENABLED) : 0;
  return NULL;
}

const char *bwcfg_api_token(cmd_parms *cmd, void *dcfg, const char *val)
{
  sconf_for(cmd)->api_token = apr_pstrdup(cmd->pool, val);
  return NULL;
}

const char *bwcfg_api_path(cmd_parms *cmd, void *dcfg, const char *val)
{
  if (!val || val[0] != '/')
    return "BandWidthAPIPath: must start with /";
  sconf_for(cmd)->api_path = apr_pstrdup(cmd->pool, val);
  return NULL;
}

/* ------------------------------------------------------------------ */
/* SHM / capacity directives                                          */
/* ------------------------------------------------------------------ */
const char *bwcfg_shm_file(cmd_parms *cmd, void *dcfg, const char *val)
{
  sconf_for(cmd)->shm_file = apr_pstrdup(cmd->pool, val);
  return NULL;
}
const char *bwcfg_lock_file(cmd_parms *cmd, void *dcfg, const char *val)
{
  sconf_for(cmd)->lock_file = apr_pstrdup(cmd->pool, val);
  return NULL;
}
const char *bwcfg_stats_dir(cmd_parms *cmd, void *dcfg, const char *val)
{
  sconf_for(cmd)->stats_dir = apr_pstrdup(cmd->pool, val);
  return NULL;
}

static const char *set_uint32(cmd_parms *cmd, void *dcfg,
                              const char *val, apr_uint32_t *dst,
                              const char *name, apr_uint32_t min)
{
  long n;
  if (!val || !apr_isdigit(*val))
    return apr_psprintf(cmd->pool, "%s: invalid number", name);
  n = atol(val);
  if (n < (long)min)
    return apr_psprintf(cmd->pool, "%s: must be >= %u", name, min);
  if ((apr_uint64_t)n > 0xFFFFFFFFu)
    return apr_psprintf(cmd->pool, "%s: must be <= %u", name, 0xFFFFFFFFu);
  *dst = (apr_uint32_t)n;
  return NULL;
}

const char *bwcfg_max_vhosts(cmd_parms *cmd, void *dcfg, const char *val)
{
  return set_uint32(cmd, dcfg, val, &sconf_for(cmd)->max_vhosts, "BandWidthMaxVHosts", 1);
}

const char *bwcfg_max_pools(cmd_parms *cmd, void *dcfg, const char *val)
{
  return set_uint32(cmd, dcfg, val, &sconf_for(cmd)->max_pools, "BandWidthMaxPools", 1);
}

const char *bwcfg_max_rules(cmd_parms *cmd, void *dcfg, const char *val)
{
  return set_uint32(cmd, dcfg, val, &sconf_for(cmd)->max_rules, "BandWidthMaxRules", 1);
}

const char *bwcfg_max_tokens(cmd_parms *cmd, void *dcfg, const char *val)
{
  return set_uint32(cmd, dcfg, val, &sconf_for(cmd)->max_tokens, "BandWidthMaxTokens", 1);
}

const char *bwcfg_token_store(cmd_parms *cmd, void *dcfg, const char *val)
{
  sconf_for(cmd)->token_store = apr_pstrdup(cmd->pool, val);
  return NULL;
}

/* ------------------------------------------------------------------ */
/* bwcfg_populate_shm - walk all servers, fill SHM from config        */
/* ------------------------------------------------------------------ */

/* Recursively allocate a pool and its children from config */
static apr_uint32_t alloc_pool_tree(bandwidth_server_config *sc,
                                    bw_pool_cfg_t *pcfg,
                                    apr_uint32_t vhost_idx,
                                    apr_uint32_t parent_shm_idx,
                                    apr_pool_t *p,
                                    server_rec *s)
{
  apr_uint32_t pool_idx = bw_pool_alloc(
      vhost_idx, pcfg->id, parent_shm_idx,
      pcfg->bwlimit, pcfg->in_bwlimit, pcfg->maxc,
      pcfg->packet, pcfg->error_code);

  if (pool_idx == BW_IDX_NONE)
  {
    ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s,
                 "mod_bw: pool slot exhausted for pool %u", pcfg->id);
    return BW_IDX_NONE;
  }
  pcfg->shm_pool_idx = pool_idx;

  /* Allocate rules */
  int i;
  bw_rule_cfg_t *rules = (bw_rule_cfg_t *)pcfg->rules->elts;
  for (i = 0; i < pcfg->rules->nelts; i++)
  {
    bw_rule_cfg_t *r = &rules[i];
    apr_uint32_t ridx = bw_rule_alloc(pool_idx,
                                      r->rule_type, r->direction,
                                      r->value,
                                      r->rate, r->in_rate,
                                      r->min_rate);
    if (ridx == BW_IDX_NONE)
      ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s,
                   "mod_bw: rule slot exhausted for pool %u rule %d",
                   pcfg->id, i);
  }

  /* Allocate child pools (those whose parent_id == this pool's id) */
  bw_pool_cfg_t **slots = (bw_pool_cfg_t **)sc->pool_cfgs->elts;
  int j;
  for (j = 0; j < sc->pool_cfgs->nelts; j++)
  {
    bw_pool_cfg_t *child = slots[j];
    if (child->parent_id == pcfg->id && child->id != pcfg->id)
      alloc_pool_tree(sc, child, vhost_idx, pool_idx, p, s);
  }

  return pool_idx;
}

apr_status_t bwcfg_populate_shm(server_rec *main_server, apr_pool_t *p)
{
  server_rec *srv;
  apr_uint32_t vhost_id = 1;

  for (srv = main_server; srv; srv = srv->next)
  {
    bandwidth_server_config *sc =
        (bandwidth_server_config *)ap_get_module_config(
            srv->module_config, &bw_module);

    if (!sc || sc->state != BANDWIDTH_ENABLED)
      continue;

    const char *hostname = srv->server_hostname;
    if (!hostname)
      hostname = "_default_";

    /* Don't add duplicates (can happen if config is re-parsed) */
    apr_uint32_t vhost_idx = bw_vhost_find(hostname);
    if (vhost_idx == BW_IDX_NONE)
    {
      vhost_idx = bw_vhost_alloc(hostname, vhost_id++);
      if (vhost_idx == BW_IDX_NONE)
      {
        ap_log_error(APLOG_MARK, APLOG_CRIT, 0, srv,
                     "mod_bw: vhost slot exhausted for %s", hostname);
        continue;
      }
    }
    sc->shm_vhost_idx = vhost_idx;

    /* Allocate root-level pools first, then children will be
         * grafted recursively */
    bw_pool_cfg_t **slots = (bw_pool_cfg_t **)sc->pool_cfgs->elts;
    int i;
    for (i = 0; i < sc->pool_cfgs->nelts; i++)
    {
      bw_pool_cfg_t *pcfg = slots[i];
      /* Only root pools at this stage */
      if (pcfg->parent_id == 0)
        alloc_pool_tree(sc, pcfg, vhost_idx, BW_IDX_NONE, p, srv);
    }

    /* Warn about pools that were never allocated: a non-zero parent: that
         * names a missing pool, or a parent cycle, leaves them unreachable. */
    for (i = 0; i < sc->pool_cfgs->nelts; i++)
    {
      if (slots[i]->shm_pool_idx == BW_IDX_NONE)
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, srv,
                     "mod_bw: pool %u not registered (parent:%u not found "
                     "or cyclic); ignored",
                     slots[i]->id, slots[i]->parent_id);
    }

    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, srv,
                 "mod_bw: registered vhost [%u] %s with %d pool(s)",
                 vhost_idx, hostname, sc->pool_cfgs->nelts);
  }

  return APR_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* Command table                                                      */
/* ------------------------------------------------------------------ */
const command_rec bw_cmds[] = {
    AP_INIT_FLAG("BandWidthModule",
                 (const char *(*)())bwcfg_module, NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "On/Off - enable or disable bandwidth control for this VirtualHost"),

    AP_INIT_RAW_ARGS("BandWidthPool",
                     (const char *(*)())bwcfg_pool, NULL,
                     RSRC_CONF | ACCESS_CONF,
                     "<pool_id> <where> <out_bwlimit> <maxc> [parent:<id>] [in:<n>] [min:<n>]"),

    AP_INIT_TAKE1("BandWidthPacket",
                  (const char *(*)())bwcfg_packet, NULL,
                  RSRC_CONF | ACCESS_CONF,
                  "Packet size in bytes (1024-131072)"),

    AP_INIT_TAKE1("BandWidthError",
                  (const char *(*)())bwcfg_error, NULL,
                  RSRC_CONF | ACCESS_CONF,
                  "HTTP error code when max connections exceeded (300-999)"),

    AP_INIT_TAKE1("BandWidthThrottleMode",
                  (const char *(*)())bwcfg_throttle_mode, NULL,
                  RSRC_CONF | ACCESS_CONF,
                  "Egress enforcement: sleep (portable) | pacing (kernel SO_MAX_PACING_RATE) "
                  "| tc (DSCP mark for an external HTB qdisc)"),

    AP_INIT_TAKE1("BandWidthIngressMode",
                  (const char *(*)())bwcfg_ingress_mode, NULL,
                  RSRC_CONF | ACCESS_CONF,
                  "Ingress enforcement: sleep (portable) | clamp (kernel TCP receive-window cap) "
                  "| mark (SO_MARK for an external ingress shaper)"),

    AP_INIT_TAKE1("BandWidthMarkBase",
                  (const char *(*)())bwcfg_mark_base, NULL,
                  RSRC_CONF | ACCESS_CONF,
                  "Base fwmark for 'mark' mode; the socket mark is base + pool id "
                  "(decimal, 0x-hex, or 0-octal)"),

    /* API */
    AP_INIT_FLAG("BandWidthAPIEnabled",
                 (const char *(*)())bwcfg_api_enabled, NULL,
                 RSRC_CONF,
                 "On/Off - enable the REST management API on this VirtualHost"),

    AP_INIT_TAKE1("BandWidthAPIToken",
                  (const char *(*)())bwcfg_api_token, NULL,
                  RSRC_CONF,
                  "Bearer token required for API authentication"),

    AP_INIT_TAKE1("BandWidthAPIPath",
                  (const char *(*)())bwcfg_api_path, NULL,
                  RSRC_CONF,
                  "URL prefix for the management API (default: /_bw_api)"),

    AP_INIT_TAKE1("BandWidthTokenStore",
                  (const char *(*)())bwcfg_token_store, NULL,
                  RSRC_CONF,
                  "Path to the persisted API token store (JSON); default: tokens.json "
                  "beside the SHM file"),

    AP_INIT_TAKE1("BandWidthMaxTokens",
                  (const char *(*)())bwcfg_max_tokens, NULL,
                  RSRC_CONF,
                  "Maximum number of API token slots in shared memory (default 64)"),

    /* SHM / mutex / stats paths */
    AP_INIT_TAKE1("BandWidthSHMFile",
                  (const char *(*)())bwcfg_shm_file, NULL,
                  RSRC_CONF,
                  "Path to the named shared memory file"),

    AP_INIT_TAKE1("BandWidthLockFile",
                  (const char *(*)())bwcfg_lock_file, NULL,
                  RSRC_CONF,
                  "Path to the global mutex lock file"),

    AP_INIT_TAKE1("BandWidthStatsDir",
                  (const char *(*)())bwcfg_stats_dir, NULL,
                  RSRC_CONF,
                  "Directory for CSV statistics files"),

    /* Capacities */
    AP_INIT_TAKE1("BandWidthMaxVHosts",
                  (const char *(*)())bwcfg_max_vhosts, NULL,
                  RSRC_CONF,
                  "Maximum number of virtual host slots in shared memory"),

    AP_INIT_TAKE1("BandWidthMaxPools",
                  (const char *(*)())bwcfg_max_pools, NULL,
                  RSRC_CONF,
                  "Maximum number of pool slots in shared memory"),

    AP_INIT_TAKE1("BandWidthMaxRules",
                  (const char *(*)())bwcfg_max_rules, NULL,
                  RSRC_CONF,
                  "Maximum number of rule slots in shared memory"),

    {NULL}};
