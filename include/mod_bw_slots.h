/*
 * mod_bw_slots.h - Shared memory slot structures for mod_bw v2
 *
 * All structures live inside a single named SHM region. Links between
 * structures use 32-bit slot indices rather than raw pointers, so the
 * region can be mapped at different virtual addresses in different
 * processes (which happens with prefork/worker/event MPMs) and can be
 * re-attached after a graceful restart without rebuilding the data.
 *
 * Layout inside the SHM region:
 *   [0]                    bw_shm_header_t  (one header, 1 KB)
 *   [hdr->vhost_offset]    bw_vhost_slot_t  [hdr->max_vhosts]
 *   [hdr->pool_offset]     bw_pool_slot_t   [hdr->max_pools]
 *   [hdr->rule_offset]     bw_rule_slot_t   [hdr->max_rules]
 *
 * The header stores max_vhosts/pools/rules and the byte offsets of each
 * array so any attaching process can locate them without knowing the
 * compile-time defaults.
 */

#ifndef MOD_BW_SLOTS_H
#define MOD_BW_SLOTS_H

#include <apr.h> /* unsigned char, apr_uint32_t, etc. */
#include <apr_atomic.h>
#include <apr_time.h>

/* ------------------------------------------------------------------ */
/* Constants                                                           */
/* ------------------------------------------------------------------ */

#define BW_SHM_MAGIC UINT32_C(0xBEEF0204)
#define BW_SHM_VERSION UINT32_C(3) /* v3 adds the token region */

/* Slot index sentinel meaning "no link" (analogous to NULL for pointers) */
#define BW_IDX_NONE UINT32_MAX

/* Slot flags */
#define BW_SLOT_FREE UINT32_C(0)
#define BW_SLOT_ACTIVE UINT32_C(1)
#define BW_SLOT_DISABLED UINT32_C(2)
#define BW_SLOT_DELETING UINT32_C(3) /* drain in progress */

/* Vhost flags (in hdr->api_flags) */
#define BW_API_ENABLED UINT32_C(1)

/* Rule directions */
#define BW_RULE_OUT (unsigned char)(1)
#define BW_RULE_IN (unsigned char)(2)
#define BW_RULE_BOTH (unsigned char)(3)

/* Rule types (must match enum from_type in mod_bw_config.h) */
#define BW_RULE_T_ALL (unsigned char)(0)
#define BW_RULE_T_IP (unsigned char)(1)
#define BW_RULE_T_HOST (unsigned char)(2)
#define BW_RULE_T_AGENT (unsigned char)(3)

/* Size of the per-second ring buffer (seconds of history) */
#define BW_RING_SIZE 60

/* Maximum lengths for strings stored in SHM */
#define BW_VHOST_NAME_LEN 256
#define BW_RULE_VALUE_LEN 256

/* ------------------------------------------------------------------ */
/* API token store                                                     */
/* ------------------------------------------------------------------ */
#define BW_MAX_TOKENS_DEFAULT 64u
#define BW_TOKEN_LABEL_LEN 48
#define BW_TOKEN_HASH_LEN 65  /* 64 hex chars of SHA-256 + nul */
#define BW_TOKEN_MAX_VHOSTS 8 /* per-token vhost allow-list cap */
#define BW_TOKEN_MAX_POOLS 16 /* per-token pool-id allow-list cap */

/* Token scope (privilege tier) */
#define BW_TOKEN_SCOPE_RO UINT32_C(1)    /* read-only: GET endpoints only   */
#define BW_TOKEN_SCOPE_ADMIN UINT32_C(2) /* full CRUD within resource scope */

/* ------------------------------------------------------------------ */
/* Ring-buffer helpers                                                 */
/* ------------------------------------------------------------------ */

/* 60-slot ring indexed by (unix_second % BW_RING_SIZE).
 * Each slot counts bytes transferred in that second. The companion
 * ring_sec[] array records which calendar second each slot belongs to
 * so stale slots can be zeroed on write. */
typedef struct
{
  volatile apr_uint32_t bytes[BW_RING_SIZE];
  volatile apr_uint32_t sec[BW_RING_SIZE]; /* unix second for slot */
} bw_ring_t;

/* ------------------------------------------------------------------ */
/* 64-bit byte counter (two 32-bit halves, lo then hi)                */
/*                                                                     */
/* APR 1.x has no apr_atomic_add64; we split into lo+hi and handle    */
/* the carry explicitly. Reads may see a transient inconsistency at    */
/* the carry boundary, but that is acceptable for statistics.          */
/* ------------------------------------------------------------------ */
typedef struct
{
  volatile apr_uint32_t lo;
  volatile apr_uint32_t hi;
} bw_bytes64_t;

/* Inline adder: add 'n' bytes; rolls hi when lo wraps */
static APR_INLINE void bw_bytes64_add(bw_bytes64_t *c, apr_uint32_t n)
{
  apr_uint32_t prev = apr_atomic_add32(&c->lo, n);
  if ((apr_uint32_t)(prev + n) < prev)
    apr_atomic_inc32(&c->hi);
}

/* Return the combined 64-bit value (snapshot, may be briefly inconsistent) */
static APR_INLINE apr_uint64_t bw_bytes64_read(const bw_bytes64_t *c)
{
  return ((apr_uint64_t)c->hi << 32) | c->lo;
}

/* ------------------------------------------------------------------ */
/* Shared statistics block (embedded in both vhost and pool slots)    */
/* ------------------------------------------------------------------ */
typedef struct
{
  volatile apr_uint32_t connection_count; /* active simultaneous connections */
  volatile apr_uint32_t bandwidth_out;    /* estimated output bytes/sec       */
  volatile apr_uint32_t bandwidth_in;     /* estimated input bytes/sec        */
  volatile apr_uint32_t counter;          /* total requests served            */
  volatile apr_uint32_t throttled;        /* requests that were rate-limited  */
  volatile apr_uint32_t cutoff;           /* requests rejected (maxconn)      */
  bw_bytes64_t bytes_out;                 /* cumulative output bytes          */
  bw_bytes64_t bytes_in;                  /* cumulative input bytes           */
  volatile apr_uint32_t conn_avg[24];     /* peak conns per hour (0-23)       */
  volatile apr_uint32_t bytes_avg[24];    /* peak bytes/s per hour            */
  volatile apr_uint32_t counter_avg[24];  /* requests per hour                */
  bw_ring_t ring_out;                     /* per-second output ring buffer    */
  bw_ring_t ring_in;                      /* per-second input ring buffer     */
  volatile apr_uint32_t lock;             /* spinlock for bandwidth recalc    */
  apr_time_t bw_time;                     /* last bandwidth recalc timestamp  */
} bw_stats_t;

/* ------------------------------------------------------------------ */
/* SHM Header                                                          */
/* ------------------------------------------------------------------ */
typedef struct
{
  volatile apr_uint32_t magic;   /* BW_SHM_MAGIC                        */
  volatile apr_uint32_t version; /* BW_SHM_VERSION                      */

  /* Seqlock: even = stable, odd = write in progress.
     * Readers spin if odd; retry if value changes between begin/end read. */
  volatile apr_uint32_t seq;

  apr_uint32_t max_vhosts; /* capacity of vhost slot array        */
  apr_uint32_t max_pools;  /* capacity of pool slot array         */
  apr_uint32_t max_rules;  /* capacity of rule slot array         */

  volatile apr_uint32_t n_vhosts; /* currently allocated vhost slots     */
  volatile apr_uint32_t n_pools;  /* currently allocated pool slots      */
  volatile apr_uint32_t n_rules;  /* currently allocated rule slots      */

  apr_uint32_t vhost_offset; /* byte offset of vhost array in SHM  */
  apr_uint32_t pool_offset;  /* byte offset of pool array           */
  apr_uint32_t rule_offset;  /* byte offset of rule array           */
  apr_uint32_t shm_size;     /* total SHM region size in bytes      */

  /* Token region (v3) */
  apr_uint32_t max_tokens;             /* capacity of token slot array      */
  volatile apr_uint32_t n_tokens;      /* currently allocated token slots   */
  apr_uint32_t token_offset;           /* byte offset of token array in SHM */
  volatile apr_uint32_t next_token_id; /* monotonic source of token ids     */

  volatile apr_uint32_t api_flags; /* BW_API_ENABLED etc.                 */

  /* Time tracking for stats rollover */
  volatile apr_uint32_t last_year;
  volatile apr_uint32_t last_yday; /* 0-365 */
  volatile apr_uint32_t last_hour; /* 0-23  */
  volatile apr_uint32_t last_min;  /* 0-59  */

  char shm_file[256];  /* path used to create this SHM        */
  char lock_file[256]; /* path for the APR global mutex       */

  unsigned char _pad[240]; /* reserved; zeroed on creation        */
} bw_shm_header_t;

/* ------------------------------------------------------------------ */
/* Per-Vhost Slot                                                      */
/* ------------------------------------------------------------------ */
typedef struct
{
  volatile apr_uint32_t flags;  /* BW_SLOT_*                       */
  apr_uint32_t id;              /* monotonically assigned vhost ID */
  char name[BW_VHOST_NAME_LEN]; /* ServerName / hostname   */

  /* Tree linkage: vhost owns a list of top-level pools */
  volatile apr_uint32_t pool_root_idx; /* first pool slot index           */

  /* Whether this vhost was added dynamically via the API (not from config) */
  apr_uint32_t dynamic; /* 0 = from config, 1 = API-added  */

  bw_stats_t stats;
  unsigned char _pad[128];
} bw_vhost_slot_t;

/* ------------------------------------------------------------------ */
/* Per-Pool Slot                                                       */
/* ------------------------------------------------------------------ */
typedef struct
{
  volatile apr_uint32_t flags;
  apr_uint32_t id;        /* user-assigned pool ID           */
  apr_uint32_t vhost_idx; /* owning vhost slot index         */

  /* Tree linkage */
  apr_uint32_t parent_idx;                /* BW_IDX_NONE = root pool         */
  volatile apr_uint32_t first_child_idx;  /* BW_IDX_NONE = leaf              */
  volatile apr_uint32_t next_sibling_idx; /* BW_IDX_NONE = last sibling      */

  /* Rule linked list (within this pool) */
  volatile apr_uint32_t first_rule_idx; /* BW_IDX_NONE = no rules          */

  /* Limits */
  volatile apr_uint32_t bwlimit;    /* max output bytes/sec (0=unlimited)*/
  volatile apr_uint32_t in_bwlimit; /* max input bytes/sec  (0=unlimited)*/
  volatile apr_uint32_t maxc;       /* max concurrent connections (0=unlimited) */
  volatile apr_int32_t packet;      /* packet size override (-1=inherit)*/
  volatile apr_int32_t error;       /* HTTP error code override (-1=inh)*/

  /* Generation counter: incremented when bwlimit/in_bwlimit/maxc changes.
     * Per-process rule cache checks this to know when to recompile. */
  volatile apr_uint32_t generation;

  bw_stats_t stats;
  unsigned char _pad[64];
} bw_pool_slot_t;

/* ------------------------------------------------------------------ */
/* Per-Rule Slot                                                       */
/* ------------------------------------------------------------------ */
typedef struct
{
  volatile apr_uint32_t flags;
  apr_uint32_t pool_idx;   /* owning pool slot index         */
  unsigned char rule_type; /* BW_RULE_T_*                    */
  unsigned char direction; /* BW_RULE_OUT/IN/BOTH            */
  unsigned char _pad0[2];
  char value[BW_RULE_VALUE_LEN]; /* IP CIDR / hostname / regex */

  volatile apr_int32_t rate;     /* output bytes/sec (0=unlimited) */
  volatile apr_int32_t in_rate;  /* input bytes/sec  (0=unlimited) */
  volatile apr_int32_t min_rate; /* minimum fair-share output rate */

  /* Linked list within a pool */
  volatile apr_uint32_t next_rule_idx;

  /* Incremented when value/rate/in_rate/min_rate changes so the per-process
     * compiled cache (ip_subnet, regex) knows to recompile */
  volatile apr_uint32_t generation;

  unsigned char _pad1[32];
} bw_rule_slot_t;

/* ------------------------------------------------------------------ */
/* API Token Slot                                                      */
/*                                                                     */
/* One per API-managed bearer token. The secret itself is never        */
/* stored; only its SHA-256 hex hash. Resource scope is keyed by        */
/* STABLE identity (vhost hostname + user-assigned pool id) rather than */
/* slot index, so it survives reload from disk where indices change.    */
/* An empty vhost list means "all vhosts"; an empty pool list means     */
/* "all pools within the allowed vhosts".                               */
/* ------------------------------------------------------------------ */
typedef struct
{
  volatile apr_uint32_t flags;    /* BW_SLOT_FREE / BW_SLOT_ACTIVE   */
  apr_uint32_t id;                /* stable, monotonically assigned  */
  apr_uint32_t scope;             /* BW_TOKEN_SCOPE_RO / _ADMIN      */
  char label[BW_TOKEN_LABEL_LEN]; /* human-readable name*/
  char hash[BW_TOKEN_HASH_LEN];   /* hex SHA-256 secret */

  apr_uint32_t n_vhosts; /* 0 = all vhosts                  */
  char vhosts[BW_TOKEN_MAX_VHOSTS][BW_VHOST_NAME_LEN];
  apr_uint32_t n_pools;                   /* 0 = all pools in scope          */
  apr_uint32_t pools[BW_TOKEN_MAX_POOLS]; /* allowed pool ids   */

  apr_time_t created;
  volatile apr_int64_t last_used; /* apr_time_t of last successful use*/
  unsigned char _pad[64];
} bw_token_slot_t;

/* ------------------------------------------------------------------ */
/* Per-process compiled rule cache (NOT in SHM; lives in child pool)  */
/* ------------------------------------------------------------------ */
typedef struct
{
  apr_uint32_t generation;   /* matches rule_slot->generation when valid */
  apr_ipsubnet_t *ip_subnet; /* compiled from value if rule_type == IP   */
  ap_regex_t *regex;         /* compiled from value if rule_type == AGENT*/
  apr_pool_t *pool;          /* per-entry pool; outlives each request    */
} bw_rule_cache_entry_t;

#endif /* MOD_BW_SLOTS_H */
