/*
 * mod_bw_shm.h - SHM lifecycle and slot allocation API
 */

#ifndef MOD_BW_SHM_H
#define MOD_BW_SHM_H

#include "mod_bw.h"

/* ------------------------------------------------------------------ */
/* SHM lifecycle                                                       */
/* ------------------------------------------------------------------ */

/* Called in post_config (second pass) to create or re-attach to the
 * named SHM.  shm_file and lock_file come from the server config;
 * max_* values are the configured capacities. */
apr_status_t bw_shm_init(apr_pool_t *p, server_rec *s,
                         const char *shm_file,
                         const char *lock_file,
                         apr_uint32_t max_vhosts,
                         apr_uint32_t max_pools,
                         apr_uint32_t max_rules,
                         apr_uint32_t max_tokens);

/* Non-zero only after the post_config call that actually (re)created the SHM
 * region; zero when an existing region was re-attached (graceful restart).
 * Lets the token loader decide whether to seed the store from disk. */
extern int bw_shm_was_created;

/* Called in child_init to attach the global mutex in each worker. */
apr_status_t bw_mutex_child_init(apr_pool_t *pchild, server_rec *s,
                                 const char *lock_file);

/* ------------------------------------------------------------------ */
/* Slot allocation - all CAS-based, safe for concurrent callers        */
/* ------------------------------------------------------------------ */

/* Find an existing vhost slot by hostname. Returns BW_IDX_NONE if not
 * found.  Does NOT take the mutex; uses a seqlock snapshot for safety. */
apr_uint32_t bw_vhost_find(const char *name);

/* Allocate a new vhost slot.  Caller must hold bw_g.mutex and have
 * already bracketed with BW_SEQ_WRITE_BEGIN/END. */
apr_uint32_t bw_vhost_alloc(const char *name, apr_uint32_t id);

/* Allocate a new pool slot under vhost_idx.  Caller must hold mutex. */
apr_uint32_t bw_pool_alloc(apr_uint32_t vhost_idx, apr_uint32_t id,
                           apr_uint32_t parent_idx,
                           apr_uint32_t bwlimit, apr_uint32_t in_bwlimit,
                           apr_uint32_t maxc,
                           apr_int32_t packet, apr_int32_t error_code);

/* Allocate a new rule slot under pool_idx.  Caller must hold mutex. */
apr_uint32_t bw_rule_alloc(apr_uint32_t pool_idx,
                           unsigned char rule_type, unsigned char direction,
                           const char *value,
                           apr_int32_t rate, apr_int32_t in_rate,
                           apr_int32_t min_rate);

/* Free a vhost slot and all its pools/rules.  Structural only: the caller
 * must hold bw_g.mutex, bracket the call with BW_SEQ_WRITE_BEGIN/END, and
 * have already drained active connections (connection_count == 0).  Never
 * sleeps, so it never stalls the seqlock read path.  `tmp` is unused. */
apr_status_t bw_vhost_free(apr_uint32_t vhost_idx, apr_pool_t *tmp);

/* Unlink a pool from its parent's child list (or the vhost's root list)
 * without freeing it. Call before bw_pool_free when deleting a single pool so
 * no dangling sibling/root pointer survives. Caller must hold mutex. */
void bw_pool_unlink(apr_uint32_t pool_idx);

/* Free a single pool slot and its rules.  Caller must hold mutex. */
apr_status_t bw_pool_free(apr_uint32_t pool_idx);

/* Free a single rule slot.  Caller must hold mutex. */
void bw_rule_free(apr_uint32_t rule_idx);

/* ------------------------------------------------------------------ */
/* API token slots                                                     */
/* ------------------------------------------------------------------ */

/* Allocate a token slot with the given label/scope/hash. Assigns a stable
 * id and stamps created. Resource scope (vhosts/pools) is left empty for the
 * caller to fill while still holding the mutex. Returns BW_IDX_NONE if the
 * store is full. Caller must hold bw_g.mutex + bracket BW_SEQ_WRITE_BEGIN/END.
 * If id_in != 0 the slot keeps that id (used when loading from disk); when 0
 * a fresh id is drawn from hdr->next_token_id. */
apr_uint32_t bw_token_alloc(const char *label, apr_uint32_t scope,
                            const char *hash, apr_uint32_t id_in);

/* Free a token slot by index. Caller must hold mutex + seqlock write. */
void bw_token_free(apr_uint32_t tok_idx);

/* Find an active token slot whose stored hash matches `hash` (constant-time).
 * Lock-free seqlock snapshot. Returns BW_IDX_NONE if none. */
apr_uint32_t bw_token_find_by_hash(const char *hash);

/* Find an active token slot by its stable id. Returns BW_IDX_NONE if none. */
apr_uint32_t bw_token_find_by_id(apr_uint32_t id);

/* ------------------------------------------------------------------ */
/* Per-process compiled rule cache                                     */
/* ------------------------------------------------------------------ */

/* Allocate the per-process cache array (called from child_init). */
apr_status_t bw_rule_cache_init(apr_pool_t *pchild, apr_uint32_t max_rules);

/* Return (or recompile) the cache entry for rule_idx.
 * Called from the filter hot path; does NOT take any lock - it checks
 * cache->generation against rule->generation and recompiles on mismatch.
 * pool is used only when recompilation is needed. */
const bw_rule_cache_entry_t *bw_rule_cache_get(apr_uint32_t rule_idx,
                                               apr_pool_t *pool);

/* ------------------------------------------------------------------ */
/* Ring buffer update helper (inlined for filter hot path)             */
/* ------------------------------------------------------------------ */
static APR_INLINE void bw_ring_add(bw_ring_t *ring,
                                   apr_uint32_t bytes,
                                   apr_uint32_t now_sec)
{
  apr_uint32_t slot = now_sec % BW_RING_SIZE;
  apr_uint32_t old_sec = apr_atomic_read32(&ring->sec[slot]);

  /* If the slot belongs to a different second, claim it and zero it.
     * The CAS ensures only one worker zeroes a given slot. */
  if (old_sec != now_sec)
  {
    if (apr_atomic_cas32(&ring->sec[slot], now_sec, old_sec) == old_sec)
      apr_atomic_set32(&ring->bytes[slot], 0);
  }
  apr_atomic_add32(&ring->bytes[slot], bytes);
}

/* Sum the last 'seconds' slots of the ring to estimate bytes/sec */
static APR_INLINE apr_uint32_t bw_ring_sum(const bw_ring_t *ring,
                                           apr_uint32_t now_sec,
                                           apr_uint32_t seconds)
{
  apr_uint32_t sum = 0;
  apr_uint32_t i;
  if (seconds > BW_RING_SIZE)
    seconds = BW_RING_SIZE;
  for (i = 0; i < seconds; i++)
  {
    apr_uint32_t slot = (now_sec - i) % BW_RING_SIZE;
    if (ring->sec[slot] + i == now_sec || i == 0) /* slot is recent */
      sum += ring->bytes[slot];                   /* volatile field; direct read is safe */
  }
  return sum / (seconds ? seconds : 1);
}

#endif /* MOD_BW_SHM_H */
