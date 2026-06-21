/*
 * mod_bw_filter.c - Access checker, output throttle filter, input
 *                   throttle filter, and the HTML/JSON status handler.
 *
 * Rule matching order (output, mirrors the original mod_bw logic):
 *   1. User-Agent (T_AGENT) - highest priority
 *   2. IP / CIDR (T_IP)
 *   3. Reverse-DNS hostname (T_HOST)
 *   4. Catch-all (T_ALL)
 *
 * For each request:
 *   handle_bw (access_checker):
 *     - Finds vhost slot by server hostname
 *     - Finds matching pool (via rule matching)
 *     - Enforces max-connection limit
 *     - Installs output and input filters
 *     - Stores (vhost_idx, pool_idx) in request notes
 *
 *   bw_filter (output filter, AP_FTYPE_TRANSCODE):
 *     - Retrieves (vhost_idx, pool_idx) from request notes
 *     - Throttles bucket brigade at the pool's bandwidth limit
 *     - Updates ring buffer, byte counters, connection count
 *
 *   bw_in_filter (input filter, AP_FTYPE_TRANSCODE):
 *     - Same but for incoming data (request bodies / uploads)
 */

#include "mod_bw.h"
#include "mod_bw_config.h"
#include "mod_bw_shm.h"
#include "mod_bw_api.h"
#include <apr_buckets.h>
#include <apr_portable.h> /* apr_os_sock_get */
#include <ap_mpm.h>
#include <http_core.h> /* ap_get_conn_socket */

#if defined(__linux__)
#include <sys/socket.h>
#include <netinet/in.h>  /* IP_TOS, IPPROTO_IP */
#include <netinet/tcp.h> /* TCP_INFO, TCP_WINDOW_CLAMP, struct tcp_info */
#endif

/* Compile-time capability gates (Layer 1+2): a kernel mode is real only on
 * Linux, only when its CMake option defined BW_WANT_* , and only when the
 * kernel headers actually expose the socket option. */
#if defined(BW_WANT_PACING) && defined(__linux__) && defined(SO_MAX_PACING_RATE)
#define BW_PACING_ACTIVE 1
#endif
#if defined(BW_WANT_TC) && defined(__linux__) && defined(IP_TOS)
#define BW_TC_ACTIVE 1
#endif
#if defined(BW_WANT_CLAMP) && defined(__linux__) && defined(TCP_WINDOW_CLAMP)
#define BW_CLAMP_ACTIVE 1
#endif
#if defined(BW_WANT_MARK) && defined(__linux__) && defined(SO_MARK)
#define BW_MARK_ACTIVE 1
#endif

/* Bounds for the ingress receive-window clamp (bytes). The kernel also
 * imposes its own minimum (~MSS), so on very low-RTT links the effective
 * window can exceed BW_CLAMP_MIN. */
#define BW_CLAMP_MIN 2048
#define BW_CLAMP_MAX (4 * 1024 * 1024)

/* Keys for storing vhost/pool indices in the request notes table */
#define BW_NOTE_VHOST "bw_vhost_idx"
#define BW_NOTE_POOL "bw_pool_idx"

/* ------------------------------------------------------------------ */
/* Kernel-assisted throttle helpers                                   */
/* ------------------------------------------------------------------ */

#if defined(BW_PACING_ACTIVE) || defined(BW_TC_ACTIVE) || \
    defined(BW_CLAMP_ACTIVE) || defined(BW_MARK_ACTIVE)
/* Raw client socket fd for this request, or -1 if unavailable.
 * Only needed by the kernel-assisted paths. */
static apr_os_sock_t bw_client_fd(request_rec *r)
{
  apr_socket_t *csd = ap_get_conn_socket(r->connection);
  apr_os_sock_t fd = -1;
  if (csd)
    apr_os_sock_get(&fd, csd);
  return fd;
}
#endif

int bw_mode_supported(int mode)
{
  switch (mode)
  {
#ifdef BW_PACING_ACTIVE
  case BW_MODE_PACING:
    return 1;
#endif
#ifdef BW_TC_ACTIVE
  case BW_MODE_TC:
    return 1;
#endif
#ifdef BW_MARK_ACTIVE
  case BW_MODE_MARK:
    return 1;
#endif
  case BW_MODE_SLEEP:
    return 1;
  default:
    return 0;
  }
}

int bw_ingress_supported(int mode)
{
  switch (mode)
  {
#ifdef BW_CLAMP_ACTIVE
  case BW_IMODE_CLAMP:
    return 1;
#endif
#ifdef BW_MARK_ACTIVE
  case BW_IMODE_MARK:
    return 1;
#endif
  case BW_IMODE_SLEEP:
    return 1;
  default:
    return 0;
  }
}

/* Parse the BW_MODE / BW_INGRESS_MODE env strings. Unknown falls back to the default. */
static int bw_parse_mode(const char *s, int dflt)
{
  if (!s || !*s)
    return dflt;
  if (!strcasecmp(s, "sleep"))
    return BW_MODE_SLEEP;
  if (!strcasecmp(s, "pacing"))
    return BW_MODE_PACING;
  if (!strcasecmp(s, "tc"))
    return BW_MODE_TC;
  if (!strcasecmp(s, "mark"))
    return BW_MODE_MARK;
  return dflt;
}
static int bw_parse_imode(const char *s, int dflt)
{
  if (!s || !*s)
    return dflt;
  if (!strcasecmp(s, "sleep"))
    return BW_IMODE_SLEEP;
  if (!strcasecmp(s, "clamp"))
    return BW_IMODE_CLAMP;
  if (!strcasecmp(s, "mark"))
    return BW_IMODE_MARK;
  return dflt;
}

/* Emit a message at most once per process, keyed by a small slot id (0-31). */
static void bw_note_once(request_rec *r, unsigned slot, int level,
                         const char *msg)
{
  static volatile apr_uint32_t logged = 0;
  apr_uint32_t bit = 1u << (slot & 31u);
  if (apr_atomic_read32(&logged) & bit)
    return;
  apr_atomic_set32(&logged, apr_atomic_read32(&logged) | bit);
  ap_log_rerror(APLOG_MARK, level, 0, r, "%s", msg);
}
/* Log slots (success even, fallback odd) */
#define BW_LOG_PACE 0
#define BW_LOG_TC 2
#define BW_LOG_EMARK 4 /* egress SO_MARK */
#define BW_LOG_CLAMP 6
#define BW_LOG_IMARK 8 /* ingress SO_MARK */

/* Cap egress with SO_MAX_PACING_RATE (bytes/sec). Returns 0 on success. */
static int bw_set_pacing(request_rec *r, long rate)
{
#ifdef BW_PACING_ACTIVE
  apr_os_sock_t fd = bw_client_fd(r);
  if (fd < 0)
    return -1;
  /* rate <= 0 means "unlimited": clear any previous cap. Compare against the
     * u32 ceiling as an unsigned 64-bit value so the clamp is correct even
     * where long is 32-bit. */
  unsigned int v = (rate <= 0)                          ? 0u
                   : ((apr_uint64_t)rate > 0xFFFFFFFFu) ? 0xFFFFFFFFu
                                                        : (unsigned int)rate;
  if (setsockopt(fd, SOL_SOCKET, SO_MAX_PACING_RATE, &v, sizeof(v)) != 0)
    return -1;
  return 0;
#else
  (void)r;
  (void)rate;
  return -1;
#endif
}

/* Stamp a DSCP class (low 6 bits of pool id) so an external tc/HTB qdisc
 * can classify and shape this connection. Returns 0 on success. */
static int bw_set_dscp(request_rec *r, apr_uint32_t pool_id)
{
#ifdef BW_TC_ACTIVE
  apr_os_sock_t fd = bw_client_fd(r);
  if (fd < 0)
    return -1;
  int tos = (int)((pool_id & 0x3fu) << 2); /* DSCP occupies the top 6 bits */
  if (setsockopt(fd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos)) != 0)
    return -1;
  return 0;
#else
  (void)r;
  (void)pool_id;
  return -1;
#endif
}

/* Stamp an fwmark (SO_MARK) on the socket so external nftables/tc can
 * classify it - for EITHER direction (the mark survives to conntrack, so it
 * can drive ingress shaping too, unlike DSCP). Needs CAP_NET_ADMIN; fails
 * with EPERM otherwise. Returns 0 on success. */
static int bw_set_mark(request_rec *r, apr_uint32_t mark)
{
#ifdef BW_MARK_ACTIVE
  apr_os_sock_t fd = bw_client_fd(r);
  if (fd < 0)
    return -1;
  if (setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) != 0)
    return -1;
  return 0;
#else
  (void)r;
  (void)mark;
  return -1;
#endif
}

/* Cap the TCP receive window so the kernel back-pressures the sender at
 * ~rate bytes/sec.  rate ~ window / RTT, so we size the window from the
 * socket's measured RTT (TCP_INFO).  Fills *win_out / *rtt_out for logging.
 * Returns 0 on success. */
static int bw_set_rcv_clamp(request_rec *r, long rate,
                            long *win_out, unsigned int *rtt_out)
{
#ifdef BW_CLAMP_ACTIVE
  apr_os_sock_t fd = bw_client_fd(r);
  if (fd < 0)
    return -1;

  unsigned int rtt_us = 50000; /* fallback ~50ms if unavailable */
  struct tcp_info ti;
  socklen_t tilen = sizeof(ti);
  if (getsockopt(fd, IPPROTO_TCP, TCP_INFO, &ti, &tilen) == 0 && ti.tcpi_rtt > 0)
    rtt_us = ti.tcpi_rtt;

  long w = (long)((double)rate * ((double)rtt_us / 1000000.0));
  if (w < BW_CLAMP_MIN)
    w = BW_CLAMP_MIN;
  if (w > BW_CLAMP_MAX)
    w = BW_CLAMP_MAX;
  *win_out = w;
  *rtt_out = rtt_us;

  /* SO_RCVBUF first (disables autotuning, ~2x window for overhead), then
     * TCP_WINDOW_CLAMP to bound the advertised window directly. */
  int rcvbuf = (int)(w * 2);
  setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
  int clamp = (int)w;
  if (setsockopt(fd, IPPROTO_TCP, TCP_WINDOW_CLAMP, &clamp, sizeof(clamp)) != 0)
    return -1;
  return 0;
#else
  (void)r;
  (void)rate;
  (void)win_out;
  (void)rtt_out;
  return -1;
#endif
}

/* The effective fwmark: env BW_MARK overrides; else mark_base + pool id. */
static apr_uint32_t bw_effective_mark(request_rec *r, bandwidth_config *dc,
                                      bw_pool_slot_t *pool)
{
  const char *e = apr_table_get(r->subprocess_env, BW_ENV_MARK);
  if (e && *e)
    return (apr_uint32_t)strtoul(e, NULL, 0); /* 0x.. accepted */
  return dc->mark_base + pool->id;
}

/* ------------------------------------------------------------------ */
/* Utility: read (vhost_idx, pool_idx) from request notes             */
/* ------------------------------------------------------------------ */
static int get_notes(request_rec *r,
                     apr_uint32_t *vhost_idx, apr_uint32_t *pool_idx)
{
  const char *sv = apr_table_get(r->notes, BW_NOTE_VHOST);
  const char *sp = apr_table_get(r->notes, BW_NOTE_POOL);
  if (!sv || !sp)
    return 0;
  *vhost_idx = (apr_uint32_t)atol(sv);
  *pool_idx = (apr_uint32_t)atol(sp);
  return 1;
}

/* ------------------------------------------------------------------ */
/* Rule matching: find the pool_idx that should serve this request    */
/*                                                                    */
/* We walk the rule list of every pool that belongs to this vhost.    */
/* The first pool whose rule list contains a matching rule wins.      */
/* Within a pool, rule priority is: AGENT > IP > HOST > ALL.          */
/* ------------------------------------------------------------------ */
typedef struct
{
  int priority; /* lower = higher priority */
  apr_uint32_t pool_idx;
  apr_int32_t rate;
  apr_int32_t in_rate;
  apr_int32_t min_rate;
} match_result_t;

static int domain_match(const char *domain, const char *what)
{
  int dl = (int)strlen(domain);
  int wl = (int)strlen(what);
  if (wl < dl)
    return 0;
  if (strcasecmp(domain, what + (wl - dl)) != 0)
    return 0;
  if (wl == dl)
    return 1;
  return (domain[0] == '.' || what[wl - dl - 1] == '.');
}

/* Walk one pool's rule list looking for the best match.
 * Updates *best if a higher-priority match is found. */
static void match_pool_rules(request_rec *r,
                             apr_uint32_t pool_idx,
                             match_result_t *best,
                             apr_pool_t *tmp)
{
  apr_uint32_t rule_idx = bw_g.pools[pool_idx].first_rule_idx;
  const char *ua = NULL;
  const char *rhost = NULL;
  int got_host = 0;

  while (rule_idx != BW_IDX_NONE)
  {
    bw_rule_slot_t *rule = &bw_g.rules[rule_idx];
    const bw_rule_cache_entry_t *ce = bw_rule_cache_get(rule_idx, tmp);
    int priority = 99;
    int matched = 0;

    if (apr_atomic_read32(&rule->flags) != BW_SLOT_ACTIVE)
      goto next;

    switch (rule->rule_type)
    {
    case BW_RULE_T_AGENT:
      if (!ua)
        ua = apr_table_get(r->headers_in, "User-Agent");
      if (ua && ce && ce->regex &&
          ap_regexec(ce->regex, ua, 0, NULL, 0) == 0)
      {
        matched = 1;
        priority = 0;
      }
      break;

    case BW_RULE_T_IP:
      if (ce && ce->ip_subnet &&
          apr_ipsubnet_test(ce->ip_subnet, r->useragent_addr))
      {
        matched = 1;
        priority = 1;
      }
      break;

    case BW_RULE_T_HOST:
      if (!got_host)
      {
        int is_ip;
        rhost = ap_get_useragent_host(r, REMOTE_DOUBLE_REV, &is_ip);
        got_host = (rhost && !is_ip) ? 2 : 1;
      }
      if (got_host == 2 && domain_match(rule->value, rhost))
      {
        matched = 1;
        priority = 2;
      }
      break;

    case BW_RULE_T_ALL:
      matched = 1;
      priority = 3;
      break;
    }

    if (matched && priority < best->priority)
    {
      best->priority = priority;
      best->pool_idx = pool_idx;
      best->rate = rule->rate;
      best->in_rate = rule->in_rate;
      best->min_rate = rule->min_rate;
    }
  next:
    rule_idx = bw_g.rules[rule_idx].next_rule_idx;
  }
}

/* Walk all pools of a vhost, return the best-matching pool index.
 * Returns BW_IDX_NONE if no rule matches. */
static apr_uint32_t find_matching_pool(request_rec *r,
                                       apr_uint32_t vhost_idx,
                                       match_result_t *out_match)
{
  apr_pool_t *tmp;
  apr_pool_create(&tmp, r->pool);

  match_result_t best = {.priority = 100, .pool_idx = BW_IDX_NONE};
  apr_uint32_t seq;

  BW_SEQ_READ(seq, {
    apr_uint32_t pool_idx =
        apr_atomic_read32(&bw_g.vhosts[vhost_idx].pool_root_idx);
    while (pool_idx != BW_IDX_NONE)
    {
      if (apr_atomic_read32(&bw_g.pools[pool_idx].flags) == BW_SLOT_ACTIVE)
        match_pool_rules(r, pool_idx, &best, tmp);
      /* Also check children */
      apr_uint32_t child =
          apr_atomic_read32(&bw_g.pools[pool_idx].first_child_idx);
      while (child != BW_IDX_NONE)
      {
        if (apr_atomic_read32(&bw_g.pools[child].flags) == BW_SLOT_ACTIVE)
          match_pool_rules(r, child, &best, tmp);
        child = apr_atomic_read32(&bw_g.pools[child].next_sibling_idx);
      }
      pool_idx =
          apr_atomic_read32(&bw_g.pools[pool_idx].next_sibling_idx);
    }
  });

  apr_pool_destroy(tmp);
  *out_match = best;
  return best.pool_idx;
}

/* ------------------------------------------------------------------ */
/* Per-request filter context                                         */
/* ------------------------------------------------------------------ */
typedef struct
{
  apr_bucket_brigade *bb; /* scratch brigade for outgoing data */
  apr_uint32_t vhost_idx;
  apr_uint32_t pool_idx;
  apr_int32_t rate;    /* effective output rate for this req */
  apr_int32_t in_rate; /* effective input rate               */
  apr_int32_t min_rate;
  int packet;               /* effective packet size              */
  int mode;                 /* effective BW_MODE_* for this request */
  apr_uint32_t paced_count; /* conn_count last used to set pacing */
} bw_ctx_t;

/* Connection-count holder. The count is taken once per matched request in
 * handle_bw (so it works regardless of which filter, if any, is installed)
 * and released by this request-pool cleanup, which also covers client
 * disconnects and Apache error paths. */
typedef struct
{
  apr_uint32_t vhost_idx;
  apr_uint32_t pool_idx;
  int counted;
} bw_conn_t;

static apr_status_t bw_conn_cleanup(void *data)
{
  bw_conn_t *c = (bw_conn_t *)data;
  if (!c->counted)
    return APR_SUCCESS;
  c->counted = 0;
  apr_atomic_dec32(&bw_g.pools[c->pool_idx].stats.connection_count);
  apr_atomic_dec32(&bw_g.vhosts[c->vhost_idx].stats.connection_count);
  return APR_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* handle_bw - access_checker hook                                    */
/* ------------------------------------------------------------------ */
int handle_bw(request_rec *r)
{
  /* Skip sub-requests */
  if (r->main)
    return DECLINED;

  bandwidth_server_config *sc = bw_sconf(r);
  bandwidth_config *dc = bw_dconf(r);

  /* Let the API handler intercept if this vhost has it enabled */
  if (sc->api_enabled && sc->api_path)
  {
    size_t plen = strlen(sc->api_path);
    if (strncmp(r->uri, sc->api_path, plen) == 0 &&
        (r->uri[plen] == '\0' || r->uri[plen] == '/'))
    {
      return bw_api_handler(r);
    }
  }

  if (bw_g.mod_disabled)
    return DECLINED;
  if (sc->state != BANDWIDTH_ENABLED)
    return DECLINED;
  if (!bw_g.hdr || !bw_g.vhosts)
    return DECLINED;

  /* Find the vhost slot */
  apr_uint32_t vhost_idx = sc->shm_vhost_idx;
  if (vhost_idx == BW_IDX_NONE)
  {
    /* Could be a dynamically-added vhost - look up by hostname */
    vhost_idx = bw_vhost_find(r->server->server_hostname);
    if (vhost_idx == BW_IDX_NONE)
      return DECLINED;
  }

  if (apr_atomic_read32(&bw_g.vhosts[vhost_idx].flags) != BW_SLOT_ACTIVE)
    return DECLINED;

  /* Trigger per-minute CSV rollover - cheap no-op on most requests */
  bw_check_rollover(r->pool);

  /* Find the matching pool / rule */
  match_result_t match;
  apr_uint32_t pool_idx = find_matching_pool(r, vhost_idx, &match);
  if (pool_idx == BW_IDX_NONE)
    return DECLINED;

  bw_pool_slot_t *pool = &bw_g.pools[pool_idx];

  /* Enforce max-connection limit */
  apr_uint32_t maxc = apr_atomic_read32(&pool->maxc);
  if (maxc > 0 &&
      apr_atomic_read32(&pool->stats.connection_count) >= maxc)
  {
    apr_atomic_inc32(&pool->stats.cutoff);
    apr_atomic_inc32(&bw_g.vhosts[vhost_idx].stats.cutoff);
    return dc->error;
  }

  /* Update hit counters */
  apr_atomic_inc32(&bw_g.vhosts[vhost_idx].stats.counter);
  apr_atomic_inc32(&pool->stats.counter);
  apr_time_exp_t te;
  apr_time_exp_tz(&te, apr_time_now(), 0);
  apr_atomic_inc32(&bw_g.vhosts[vhost_idx].stats.counter_avg[te.tm_hour]);
  apr_atomic_inc32(&pool->stats.counter_avg[te.tm_hour]);

  /* Count this request against the pool for its whole lifetime, released by
     * a request-pool cleanup. Done here (not in the filter) so fair-share and
     * maxc are correct even when only the input filter, or no filter, is
     * installed (e.g. ingress-only or maxc-only pools). */
  bw_conn_t *cn = apr_pcalloc(r->pool, sizeof(*cn));
  cn->vhost_idx = vhost_idx;
  cn->pool_idx = pool_idx;
  cn->counted = 1;
  apr_atomic_inc32(&pool->stats.connection_count);
  apr_atomic_inc32(&bw_g.vhosts[vhost_idx].stats.connection_count);
  apr_pool_cleanup_register(r->pool, cn, bw_conn_cleanup, apr_pool_cleanup_null);

  /* Track hourly peak connection count */
  apr_uint32_t cc_now = apr_atomic_read32(&pool->stats.connection_count);
  if (cc_now > apr_atomic_read32(&pool->stats.conn_avg[te.tm_hour]))
    apr_atomic_set32(&pool->stats.conn_avg[te.tm_hour], cc_now);

  /* Stash the indices in request notes for the filters */
  char buf[16];
  apr_snprintf(buf, sizeof(buf), "%u", vhost_idx);
  apr_table_setn(r->notes, BW_NOTE_VHOST, apr_pstrdup(r->pool, buf));
  apr_snprintf(buf, sizeof(buf), "%u", pool_idx);
  apr_table_setn(r->notes, BW_NOTE_POOL, apr_pstrdup(r->pool, buf));

  /* Propagate the matched rule's rate overrides to the filters. A non-zero
     * rule rate takes precedence over the pool limit (0 = inherit the pool).
     * Without this, a rule whose rate differs from its pool's bwlimit - as can
     * happen with API-added rules - was silently ignored. */
  if (match.rate != 0)
  {
    apr_snprintf(buf, sizeof(buf), "%d", match.rate);
    apr_table_setn(r->notes, "bw_rule_rate", apr_pstrdup(r->pool, buf));
  }
  if (match.in_rate != 0)
  {
    apr_snprintf(buf, sizeof(buf), "%d", match.in_rate);
    apr_table_setn(r->notes, "bw_rule_in_rate", apr_pstrdup(r->pool, buf));
  }
  if (match.min_rate != 0)
  {
    apr_snprintf(buf, sizeof(buf), "%d", match.min_rate);
    apr_table_setn(r->notes, "bw_rule_min_rate", apr_pstrdup(r->pool, buf));
  }

  /* Register filters.  Install when a static limit applies, when a non-sleep
     * enforcement mode is configured (mark/pacing/tc/clamp classify even with
     * no rate), or when a per-request env override is present - so SetEnvIf can
     * impose a limit on an otherwise-unlimited pool. */
  const char *env_rate = apr_table_get(r->subprocess_env, BW_ENV_RATE);
  const char *env_mode = apr_table_get(r->subprocess_env, BW_ENV_MODE);
  const char *env_irate = apr_table_get(r->subprocess_env, BW_ENV_IN_RATE);
  const char *env_imode = apr_table_get(r->subprocess_env, BW_ENV_IMODE);

  if (match.rate != 0 || pool->bwlimit != 0 ||
      dc->throttle_mode != BW_MODE_SLEEP || env_rate || env_mode)
    ap_add_output_filter("mod_bw_out", NULL, r, r->connection);

  if (match.in_rate != 0 || pool->in_bwlimit != 0 ||
      dc->ingress_mode != BW_IMODE_SLEEP || env_irate || env_imode)
    ap_add_input_filter("mod_bw_in", NULL, r, r->connection);

  return DECLINED;
}

/* ------------------------------------------------------------------ */
/* Shared throttle logic                                              */
/* ------------------------------------------------------------------ */

/* Determine the per-connection fair share rate.
 * rule_rate: rate from the matched rule (0 = use pool limit)
 * pool_limit: hard pool limit
 * conn_count: current active connections sharing the pool */
static long calc_share_rate(apr_int32_t rule_rate,
                            apr_uint32_t pool_limit,
                            apr_uint32_t conn_count,
                            apr_int32_t min_rate)
{
  long base = rule_rate ? (long)rule_rate : (long)pool_limit;
  if (base <= 0)
    return 0; /* unlimited */

  long share = (conn_count > 0) ? (base / (long)conn_count) : base;

  /* Enforce minimum fair share */
  long floor = min_rate > 0 ? (long)min_rate : MIN_BW;
  if (share < floor)
    share = floor;
  if (share > base)
    share = base;
  return share;
}

/* ------------------------------------------------------------------ */
/* bw_filter - output throttle filter                                 */
/* ------------------------------------------------------------------ */
int bw_filter(ap_filter_t *f, apr_bucket_brigade *bb)
{
  request_rec *r = f->r;

  if (r->main)
  {
    ap_remove_output_filter(f);
    return ap_pass_brigade(f->next, bb);
  }

  apr_uint32_t vhost_idx, pool_idx;
  if (!get_notes(r, &vhost_idx, &pool_idx))
  {
    ap_remove_output_filter(f);
    return ap_pass_brigade(f->next, bb);
  }

  if (vhost_idx >= bw_g.hdr->max_vhosts ||
      pool_idx >= bw_g.hdr->max_pools)
  {
    ap_remove_output_filter(f);
    return ap_pass_brigade(f->next, bb);
  }

  bw_vhost_slot_t *vhost = &bw_g.vhosts[vhost_idx];
  bw_pool_slot_t *pool = &bw_g.pools[pool_idx];

  if (apr_atomic_read32(&vhost->flags) != BW_SLOT_ACTIVE ||
      apr_atomic_read32(&pool->flags) != BW_SLOT_ACTIVE)
  {
    ap_remove_output_filter(f);
    return ap_pass_brigade(f->next, bb);
  }

  /* Initialise per-request context */
  bw_ctx_t *ctx = (bw_ctx_t *)f->ctx;
  if (!ctx)
  {
    ctx = apr_pcalloc(r->pool, sizeof(*ctx));
    ctx->bb = apr_brigade_create(r->pool,
                                 apr_bucket_alloc_create(r->pool));
    ctx->vhost_idx = vhost_idx;
    ctx->pool_idx = pool_idx;

    bandwidth_config *dc = bw_dconf(r);

    /* Effective rates: env override > rule notes > pool/config.
         * The env vars (BW_RATE / BW_IN_RATE / BW_MIN_RATE) let
         * SetEnv/SetEnvIf/rewrite vary the rate per-request without touching
         * the pool tree. */
    const char *sv = apr_table_get(r->notes, "bw_rule_rate");
    const char *si = apr_table_get(r->notes, "bw_rule_in_rate");
    const char *sm = apr_table_get(r->notes, "bw_rule_min_rate");
    const char *ev = apr_table_get(r->subprocess_env, BW_ENV_RATE);
    const char *ei = apr_table_get(r->subprocess_env, BW_ENV_IN_RATE);
    const char *em = apr_table_get(r->subprocess_env, BW_ENV_MIN_RATE);
    ctx->rate = ev ? atoi(ev) : sv ? atoi(sv)
                                   : (apr_int32_t)pool->bwlimit;
    ctx->in_rate = ei ? atoi(ei) : si ? atoi(si)
                                      : (apr_int32_t)pool->in_bwlimit;
    ctx->min_rate = em ? atoi(em) : sm ? atoi(sm)
                                       : MIN_BW;

    ctx->packet = (pool->packet > 0) ? (int)pool->packet : dc->packet;

    /* connection_count is taken/released in handle_bw; just read it here
         * for the initial pacing share. */
    apr_uint32_t cc = apr_atomic_read32(&pool->stats.connection_count);

    /* Egress enforcement mode: env BW_MODE overrides the directive.
         * Arm the kernel hook now; a failed/unsupported mode degrades to sleep. */
    ctx->mode = bw_parse_mode(apr_table_get(r->subprocess_env, BW_ENV_MODE),
                              dc->throttle_mode);
    ctx->paced_count = 0;
    if (ctx->mode == BW_MODE_PACING)
    {
      long share = calc_share_rate(ctx->rate, pool->bwlimit, cc,
                                   ctx->min_rate);
      if (bw_set_pacing(r, share) == 0)
      {
        ctx->paced_count = cc;
        bw_note_once(r, BW_LOG_PACE, APLOG_NOTICE, apr_psprintf(r->pool, "mod_bw: throttle mode 'pacing' active via kernel (rate=%ld B/s)", share));
      }
      else
      {
        bw_note_once(r, BW_LOG_PACE + 1, APLOG_WARNING,
                     "mod_bw: throttle mode 'pacing' unavailable here - using sleep");
        ctx->mode = BW_MODE_SLEEP;
      }
    }
    else if (ctx->mode == BW_MODE_TC)
    {
      if (bw_set_dscp(r, pool->id) == 0)
        bw_note_once(r, BW_LOG_TC, APLOG_NOTICE, apr_psprintf(r->pool, "mod_bw: throttle mode 'tc' active (DSCP=%u from pool %u)", pool->id & 0x3fu, pool->id));
      else
      {
        bw_note_once(r, BW_LOG_TC + 1, APLOG_WARNING,
                     "mod_bw: throttle mode 'tc' unavailable here - using sleep");
        ctx->mode = BW_MODE_SLEEP;
      }
    }
    else if (ctx->mode == BW_MODE_MARK)
    {
      apr_uint32_t mk = bw_effective_mark(r, dc, pool);
      if (bw_set_mark(r, mk) == 0)
        bw_note_once(r, BW_LOG_EMARK, APLOG_NOTICE, apr_psprintf(r->pool, "mod_bw: throttle mode 'mark' active (egress SO_MARK=0x%x)", mk));
      else
      {
        bw_note_once(r, BW_LOG_EMARK + 1, APLOG_WARNING,
                     "mod_bw: throttle mode 'mark' failed (needs CAP_NET_ADMIN) - using sleep");
        ctx->mode = BW_MODE_SLEEP;
      }
    }

    f->ctx = ctx;
  }

  apr_bucket *b = APR_BRIGADE_FIRST(bb);
  apr_uint32_t now_sec = (apr_uint32_t)(apr_time_now() / APR_USEC_PER_SEC);

  while (b != APR_BRIGADE_SENTINEL(bb))
  {
    if (APR_BUCKET_IS_EOS(b) || APR_BUCKET_IS_FLUSH(b))
    {
      APR_BUCKET_REMOVE(b);
      APR_BRIGADE_INSERT_TAIL(ctx->bb, b);
      ap_pass_brigade(f->next, ctx->bb);
      return APR_SUCCESS;
    }

    const char *buf;
    apr_size_t bytes;
    apr_status_t rv = apr_bucket_read(b, &buf, &bytes,
                                      APR_NONBLOCK_READ);
    if (rv != APR_SUCCESS)
    {
      APR_BUCKET_REMOVE(b);
      APR_BRIGADE_INSERT_TAIL(ctx->bb, b);
      b = APR_BRIGADE_FIRST(bb);
      ap_pass_brigade(f->next, ctx->bb);
      continue;
    }

    while (bytes > 0)
    {
      long rate;
      if (ctx->mode == BW_MODE_SLEEP)
      {
        rate = calc_share_rate(ctx->rate, pool->bwlimit,
                               apr_atomic_read32(&pool->stats.connection_count),
                               ctx->min_rate);
      }
      else
      {
        /* Kernel-managed egress (pacing/tc): never sleep in the
                 * worker.  For pacing, re-set the rate when the pool's
                 * connection count changes so the per-flow share keeps the
                 * pool aggregate roughly correct. */
        if (ctx->mode == BW_MODE_PACING)
        {
          apr_uint32_t cc =
              apr_atomic_read32(&pool->stats.connection_count);
          if (cc != ctx->paced_count)
          {
            long share = calc_share_rate(ctx->rate, pool->bwlimit,
                                         cc, ctx->min_rate);
            bw_set_pacing(r, share);
            ctx->paced_count = cc;
          }
        }
        rate = 0; /* fall through to the no-sleep passthrough path */
      }

      if (rate <= 0)
      {
        /* Unlimited: pass the rest of this bucket directly */
        apr_size_t chunk = bytes;
        apr_bucket_split(b, chunk);
        APR_BUCKET_REMOVE(b);
        APR_BRIGADE_INSERT_TAIL(ctx->bb, b);
        ap_pass_brigade(f->next, ctx->bb);
        b = APR_BRIGADE_FIRST(bb);
        /* Update counters without sleeping */
        bw_bytes64_add(&vhost->stats.bytes_out, (apr_uint32_t)chunk);
        bw_bytes64_add(&pool->stats.bytes_out, (apr_uint32_t)chunk);
        bw_ring_add(&vhost->stats.ring_out, (apr_uint32_t)chunk, now_sec);
        bw_ring_add(&pool->stats.ring_out, (apr_uint32_t)chunk, now_sec);
        bytes -= chunk;
        continue;
      }

      /* Adapt packet size: if rate < packet, shrink packet so we
             * never go silent for more than 1 second at a time */
      apr_size_t pkt = (apr_size_t)ctx->packet;
      if ((long)pkt > rate)
        pkt = (apr_size_t)rate;
      if (pkt > bytes)
        pkt = bytes;
      if (pkt == 0)
        pkt = 1;

      /* Time to sleep between packets (microseconds) */
      long sleep_us = (long)(1000000.0 / ((double)rate / (double)pkt));

      /* Split, send, sleep */
      apr_bucket_split(b, pkt);
      APR_BUCKET_REMOVE(b);
      APR_BRIGADE_INSERT_TAIL(ctx->bb, b);
      ap_pass_brigade(f->next, ctx->bb);
      b = APR_BRIGADE_FIRST(bb);

      bytes -= pkt;

      /* Update counters */
      bw_bytes64_add(&vhost->stats.bytes_out, (apr_uint32_t)pkt);
      bw_bytes64_add(&pool->stats.bytes_out, (apr_uint32_t)pkt);
      bw_ring_add(&vhost->stats.ring_out, (apr_uint32_t)pkt, now_sec);
      bw_ring_add(&pool->stats.ring_out, (apr_uint32_t)pkt, now_sec);
      apr_atomic_inc32(&vhost->stats.throttled);

      /* Check for aborted connection */
      if (r->connection->aborted)
      {
        return APR_SUCCESS;
      }

      apr_sleep((apr_interval_time_t)sleep_us);
    }

    /* Move leftover bucket tail to scratch brigade */
    APR_BUCKET_REMOVE(b);
    APR_BRIGADE_INSERT_TAIL(ctx->bb, b);
    ap_pass_brigade(f->next, ctx->bb);
    b = APR_BRIGADE_FIRST(bb);
  }

  return APR_SUCCESS;
}

/* Per-filter ingress context: enforcement mode + clamp arming state. */
typedef struct
{
  int imode;                  /* effective BW_IMODE_* for this request */
  int armed;                  /* 1 once the receive-window clamp is set */
  apr_uint32_t clamped_count; /* conn_count last used to size the window */
  apr_int32_t min_rate;       /* effective minimum fair-share input rate */
} bw_in_ctx_t;

/* ------------------------------------------------------------------ */
/* bw_in_filter - input throttle filter (upload limiting)             */
/* ------------------------------------------------------------------ */
int bw_in_filter(ap_filter_t *f, apr_bucket_brigade *bb,
                 ap_input_mode_t mode, apr_read_type_e block,
                 apr_off_t readbytes)
{
  request_rec *r = f->r;

  if (r->main)
  {
    ap_remove_input_filter(f);
    return ap_get_brigade(f->next, bb, mode, block, readbytes);
  }

  apr_uint32_t vhost_idx, pool_idx;
  if (!get_notes(r, &vhost_idx, &pool_idx))
  {
    ap_remove_input_filter(f);
    return ap_get_brigade(f->next, bb, mode, block, readbytes);
  }

  bw_vhost_slot_t *vhost = &bw_g.vhosts[vhost_idx];
  bw_pool_slot_t *pool = &bw_g.pools[pool_idx];

  /* Per-filter ingress context. env BW_INGRESS_MODE overrides the directive. */
  bw_in_ctx_t *ictx = (bw_in_ctx_t *)f->ctx;
  if (!ictx)
  {
    ictx = apr_pcalloc(r->pool, sizeof(*ictx));
    ictx->imode = bw_parse_imode(
        apr_table_get(r->subprocess_env, BW_ENV_IMODE),
        bw_dconf(r)->ingress_mode);
    /* Effective minimum fair-share: env BW_MIN_RATE > matched rule > MIN_BW */
    const char *em = apr_table_get(r->subprocess_env, BW_ENV_MIN_RATE);
    const char *sm = apr_table_get(r->notes, "bw_rule_min_rate");
    ictx->min_rate = em ? atoi(em) : sm ? atoi(sm)
                                        : MIN_BW;
    f->ctx = ictx;
  }

  /* Fetch a brigade from upstream */
  apr_status_t rv = ap_get_brigade(f->next, bb, mode, block, readbytes);
  if (rv != APR_SUCCESS)
    return rv;

  /* Kernel ingress modes - arm once (re-size on membership change), no sleep:
     *   clamp = cap the receive window so the kernel back-pressures the sender.
     *   mark  = stamp SO_MARK for an external ingress shaper (tc/IFB/HTB). */
  if (ictx->imode == BW_IMODE_CLAMP || ictx->imode == BW_IMODE_MARK)
  {
    apr_uint32_t cc = apr_atomic_read32(&pool->stats.connection_count);
    if (!ictx->armed || cc != ictx->clamped_count)
    {
      if (ictx->imode == BW_IMODE_CLAMP)
      {
        /* env BW_IN_RATE overrides the pool input limit */
        const char *ei = apr_table_get(r->subprocess_env, BW_ENV_IN_RATE);
        long want = ei ? atol(ei)
                       : (long)apr_atomic_read32(&pool->in_bwlimit);
        if (want > 0)
        {
          long share = calc_share_rate((apr_int32_t)want,
                                       (apr_uint32_t)want, cc,
                                       ictx->min_rate);
          long win = 0;
          unsigned int rtt = 0;
          if (bw_set_rcv_clamp(r, share, &win, &rtt) == 0)
          {
            bw_note_once(r, BW_LOG_CLAMP, APLOG_NOTICE,
                         apr_psprintf(r->pool, "mod_bw: ingress mode 'clamp' "
                                               "active (rate=%ld B/s rtt=%uus window=%ld B)",
                                      share, rtt, win));
            ictx->armed = 1;
            ictx->clamped_count = cc;
          }
          else
          {
            bw_note_once(r, BW_LOG_CLAMP + 1, APLOG_WARNING,
                         "mod_bw: ingress mode 'clamp' unavailable here - using sleep");
            ictx->imode = BW_IMODE_SLEEP;
          }
        }
      }
      else
      { /* BW_IMODE_MARK */
        apr_uint32_t mk = bw_effective_mark(r, bw_dconf(r), pool);
        if (bw_set_mark(r, mk) == 0)
        {
          bw_note_once(r, BW_LOG_IMARK, APLOG_NOTICE,
                       apr_psprintf(r->pool,
                                    "mod_bw: ingress mode 'mark' active (SO_MARK=0x%x)", mk));
          ictx->armed = 1;
          ictx->clamped_count = cc;
        }
        else
        {
          bw_note_once(r, BW_LOG_IMARK + 1, APLOG_WARNING,
                       "mod_bw: ingress mode 'mark' failed (needs CAP_NET_ADMIN) - using sleep");
          ictx->imode = BW_IMODE_SLEEP;
        }
      }
    }
  }

  apr_uint32_t now_sec = (apr_uint32_t)(apr_time_now() / APR_USEC_PER_SEC);

  /* Walk the returned brigade and throttle */
  apr_bucket *b;
  for (b = APR_BRIGADE_FIRST(bb);
       b != APR_BRIGADE_SENTINEL(bb);
       b = APR_BUCKET_NEXT(b))
  {
    if (APR_BUCKET_IS_EOS(b) || APR_BUCKET_IS_METADATA(b))
      continue;

    const char *buf;
    apr_size_t bytes;
    rv = apr_bucket_read(b, &buf, &bytes, APR_BLOCK_READ);
    if (rv != APR_SUCCESS)
      continue;

    if (bytes == 0)
      continue;

    /* Update input counters */
    bw_bytes64_add(&vhost->stats.bytes_in, (apr_uint32_t)bytes);
    bw_bytes64_add(&pool->stats.bytes_in, (apr_uint32_t)bytes);
    bw_ring_add(&vhost->stats.ring_in, (apr_uint32_t)bytes, now_sec);
    bw_ring_add(&pool->stats.ring_in, (apr_uint32_t)bytes, now_sec);

    /* Sleep-mode throttle (clamp/mark modes let the kernel/qdisc do it).
         * env BW_IN_RATE overrides the pool input limit. */
    const char *ei = apr_table_get(r->subprocess_env, BW_ENV_IN_RATE);
    apr_uint32_t in_limit = ei ? (apr_uint32_t)atol(ei)
                               : apr_atomic_read32(&pool->in_bwlimit);
    if (ictx->imode == BW_IMODE_SLEEP && in_limit > 0 && bytes > 0)
    {
      bandwidth_config *dc = bw_dconf(r);
      apr_size_t pkt = (apr_size_t)((pool->packet > 0)
                                        ? (int)pool->packet
                                        : dc->packet);
      if (pkt > bytes)
        pkt = bytes;
      if (pkt == 0)
        pkt = 1;

      long rate = calc_share_rate((apr_int32_t)in_limit, in_limit,
                                  apr_atomic_read32(&pool->stats.connection_count),
                                  ictx->min_rate);
      if (rate > 0)
      {
        long sleep_us = (long)(1000000.0 / ((double)rate / (double)pkt));
        if (sleep_us > 0)
          apr_sleep((apr_interval_time_t)sleep_us);
      }
    }
  }

  return APR_SUCCESS;
}
