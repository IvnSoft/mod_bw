/*
 * mod_bw.h - Main header for mod_bw v2
 *
 * Declares the global module state (bw_g), the module record itself,
 * and the hook/filter entry points that the other translation units
 * need to reference.
 */

#ifndef MOD_BW_H
#define MOD_BW_H

#include <httpd.h>
#include <http_config.h>
#include <http_protocol.h>
#include <http_request.h>
#include <http_log.h>
#include <ap_config.h>
#include <ap_regex.h>
#include <apr_shm.h>
#include <apr_global_mutex.h>
#include <apr_atomic.h>
#include <apr_strings.h>
#include <apr_time.h>
#include <apr_network_io.h> /* apr_ipsubnet_t, apr_ipsubnet_create/test */
#include <util_filter.h>
#include <http_core.h> /* ap_get_useragent_host, REMOTE_DOUBLE_REV */
#include <unixd.h>     /* ap_unixd_set_global_mutex_perms */
#include <sys/time.h>

#include "mod_bw_slots.h"

/* ------------------------------------------------------------------ */
/* Version                                                             */
/* ------------------------------------------------------------------ */
#define MOD_BW_VERSION "2.0"

/* ------------------------------------------------------------------ */
/* Bandwidth / throttle constants                                      */
/* ------------------------------------------------------------------ */
#define MIN_BW 256          /* absolute floor: 256 bytes/s  */
#define PACKET_DEFAULT 8192 /* default chunk size           */
#define PACKET_MIN 1024
#define PACKET_MAX 131072
#define MAX_BUFFER 8192
#define STATS_DIR_DEFAULT "/var/log/apache2/bandwidth"

/* ------------------------------------------------------------------ */
/* Default SHM / mutex paths and slot capacities                       */
/* ------------------------------------------------------------------ */
#define BW_SHM_FILE_DEFAULT "/var/run/apache2/mod_bw.shm"
#define BW_LOCK_FILE_DEFAULT "/var/run/apache2/mod_bw.lock"
#define BW_MAX_VHOSTS_DEFAULT 512u
#define BW_MAX_POOLS_DEFAULT 4096u
#define BW_MAX_RULES_DEFAULT 8192u

/* ------------------------------------------------------------------ */
/* Throttle enforcement modes (BandWidthThrottleMode directive)        */
/*                                                                     */
/*   sleep  - portable: split the brigade and apr_sleep() between      */
/*            packets inside the worker (the classic mod_bw method).   */
/*            Ties up one worker per throttled connection.             */
/*   pacing - Linux: set SO_MAX_PACING_RATE on the client socket and   */
/*            let the kernel pace egress.  The worker writes and        */
/*            returns - no per-connection blocking.                    */
/*   tc     - Linux: stamp a DSCP class (derived from the pool id) on   */
/*            the socket so an external tc/HTB qdisc shapes egress.     */
/*            Also non-blocking; requires operator-side qdisc setup.    */
/*                                                                     */
/* pacing/tc affect EGRESS only; ingress always uses the sleep method. */
/* They are compiled in only on Linux and only when the matching CMake  */
/* option is enabled.  At runtime an unsupported/failed mode falls back */
/* to sleep (logged once).  See bw_mode_supported().                   */
/* ------------------------------------------------------------------ */
#define BW_MODE_SLEEP 0
#define BW_MODE_PACING 1
#define BW_MODE_TC 2
#define BW_MODE_MARK 3 /* SO_MARK fwmark for external nftables/tc        */

/* ------------------------------------------------------------------ */
/* Per-request env-var overrides (read from r->subprocess_env, settable */
/* with SetEnv / SetEnvIf / mod_rewrite [E=]). Each overrides the        */
/* matched pool's value for THIS request; absence = configured value.    */
/*   BW_RATE / BW_IN_RATE / BW_MIN_RATE  - effective rates (bytes/sec)    */
/*   BW_MODE        - egress mode  (sleep|pacing|tc|mark)                 */
/*   BW_INGRESS_MODE- ingress mode (sleep|clamp|mark)                     */
/*   BW_MARK        - fwmark value for 'mark' mode (decimal or 0x-hex)    */
/* ------------------------------------------------------------------ */
#define BW_ENV_RATE "BW_RATE"
#define BW_ENV_IN_RATE "BW_IN_RATE"
#define BW_ENV_MIN_RATE "BW_MIN_RATE"
#define BW_ENV_MODE "BW_MODE"
#define BW_ENV_IMODE "BW_INGRESS_MODE"
#define BW_ENV_MARK "BW_MARK"

/* ------------------------------------------------------------------ */
/* Ingress (upload) enforcement modes (BandWidthIngressMode directive)  */
/*                                                                     */
/*   sleep  - portable: read a chunk in the input filter then           */
/*            apr_sleep() to hold the average rate (blocks the worker). */
/*   clamp  - Linux: cap the TCP receive window (SO_RCVBUF +            */
/*            TCP_WINDOW_CLAMP) so the kernel back-pressures the sender. */
/*            Non-blocking, but the achieved rate is window / RTT, so it */
/*            is coarse and RTT-dependent (loose on low-latency links). */
/*                                                                     */
/* clamp is compiled in only on Linux + when BW_ENABLE_RCV_CLAMP is set; */
/* at runtime an unsupported mode falls back to sleep (logged once).     */
/* ------------------------------------------------------------------ */
#define BW_IMODE_SLEEP 0
#define BW_IMODE_CLAMP 1
#define BW_IMODE_MARK 2 /* SO_MARK fwmark for external ingress shaper     */

/* ------------------------------------------------------------------ */
/* Apache compat: regex API before 2.1 used posix directly            */
/* ------------------------------------------------------------------ */
#if !AP_MODULE_MAGIC_AT_LEAST(20050127, 0)
typedef regex_t ap_regex_t;
#define AP_REG_EXTENDED REG_EXTENDED
#define AP_REG_ICASE REG_ICASE
#endif

/* ------------------------------------------------------------------ */
/* APR compat: APR < 1 used different atomic names                    */
/* ------------------------------------------------------------------ */
#if defined(APR_MAJOR_VERSION) && (APR_MAJOR_VERSION < 1)
#define apr_atomic_inc32 apr_atomic_inc
#define apr_atomic_dec32 apr_atomic_dec
#define apr_atomic_add32 apr_atomic_add
#define apr_atomic_cas32 apr_atomic_cas
#define apr_atomic_set32 apr_atomic_set
#endif

/* ------------------------------------------------------------------ */
/* Global module state - one instance, lives in the master process     */
/* and is inherited by (or re-created in) each worker.                */
/* ------------------------------------------------------------------ */
typedef struct
{
  /* SHM handles */
  apr_shm_t *shm;
  bw_shm_header_t *hdr;    /* points to SHM base             */
  bw_vhost_slot_t *vhosts; /* start of vhost array in SHM    */
  bw_pool_slot_t *pools;   /* start of pool array in SHM     */
  bw_rule_slot_t *rules;   /* start of rule array in SHM     */
  bw_token_slot_t *tokens; /* start of token array in SHM    */

  /* Global write mutex (structural changes: add/remove vhost/pool/rule) */
  apr_global_mutex_t *mutex;

  /* Per-process compiled rule cache (allocated from child pool) */
  bw_rule_cache_entry_t *rule_cache;
  apr_uint32_t rule_cache_sz;
  apr_pool_t *cache_pool; /* parent for per-entry sub-pools */

  /* Module-level disable flag (set when BandWidthModule appears outside
     * a <VirtualHost> context, which is a config error we gracefully handle
     * by disabling the whole module rather than crashing) */
  int mod_disabled;

  /* Stats directory for CSV export */
  const char *stats_dir;

  /* Resolved path of the persisted API token store (JSON Lines).
     * Set once in post_config; read by the API on every token mutation. */
  const char *token_store;
} bw_global_t;

/* The single module state instance; defined in mod_bw.c */
extern bw_global_t bw_g;

/* ------------------------------------------------------------------ */
/* Module record (extern for use by other translation units)           */
/* ------------------------------------------------------------------ */
extern module AP_MODULE_DECLARE_DATA bw_module;

/* ------------------------------------------------------------------ */
/* Hook / filter entry points (implementations in their .c files)      */
/* ------------------------------------------------------------------ */
int bw_pre_config(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp);
int bw_post_config(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp,
                   server_rec *s);
void bw_child_init(apr_pool_t *pchild, server_rec *s);

int handle_bw(request_rec *r);
int bw_filter(ap_filter_t *f, apr_bucket_brigade *bb);
int bw_in_filter(ap_filter_t *f, apr_bucket_brigade *bb,
                 ap_input_mode_t mode, apr_read_type_e block,
                 apr_off_t readbytes);

/* Returns 1 if the given BW_MODE_* is compiled in and usable on this
 * platform/build, else 0.  (sleep is always supported.) */
int bw_mode_supported(int mode);

/* Same, for the BW_IMODE_* ingress modes. */
int bw_ingress_supported(int mode);

void *create_bw_config(apr_pool_t *p, char *path);
void *create_bw_server_config(apr_pool_t *p, server_rec *s);

/* Utility / metrics (mod_bw_util.c) */
int bw_status_handler(request_rec *r);
void bw_check_rollover(apr_pool_t *p);

/* ------------------------------------------------------------------ */
/* Seqlock helpers - structural reads (vhost/pool/rule traversal)      */
/*                                                                     */
/* Usage:                                                              */
/*   apr_uint32_t _seq;                                                */
/*   BW_SEQ_READ_BEGIN(_seq)                                           */
/*     ... read fields from hdr/vhosts/pools/rules ...                */
/*   BW_SEQ_READ_END(_seq)    <- retries if a write landed mid-read   */
/*                                                                     */
/* Per-counter atomics (bytes_out, connection_count, etc.) do NOT need */
/* the seqlock; they are individually atomic. The seqlock protects     */
/* multi-field structural reads (e.g. traversing next_sibling_idx      */
/* while another worker is inserting a sibling).                       */
/* ------------------------------------------------------------------ */
#define BW_SEQ_READ_BEGIN(seq)                 \
  do                                           \
  {                                            \
    (seq) = apr_atomic_read32(&bw_g.hdr->seq); \
    if ((seq) & 1u)                            \
    {                                          \
      apr_sleep(0);                            \
      continue;                                \
    }                                          \
  } while (0)

#define BW_SEQ_READ_RETRY(seq) \
  (apr_atomic_read32(&bw_g.hdr->seq) != (seq))

/* Wrap a structural read in a seqlock retry loop.
 * _body must not contain break/return/goto out of the loop. */
#define BW_SEQ_READ(_seq, _body)                \
  do                                            \
  {                                             \
    (_seq) = apr_atomic_read32(&bw_g.hdr->seq); \
    if ((_seq) & 1u)                            \
    {                                           \
      apr_sleep(0);                             \
      continue;                                 \
    }                                           \
    _body;                                      \
  } while (apr_atomic_read32(&bw_g.hdr->seq) != (_seq))

/* Writers: caller must hold bw_g.mutex */
#define BW_SEQ_WRITE_BEGIN() \
  apr_atomic_inc32(&bw_g.hdr->seq) /* make odd */

#define BW_SEQ_WRITE_END() \
  apr_atomic_inc32(&bw_g.hdr->seq) /* make even */

#endif /* MOD_BW_H */
