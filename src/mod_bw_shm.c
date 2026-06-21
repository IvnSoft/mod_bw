/*
 * mod_bw_shm.c - Named SHM lifecycle, slot allocator, global mutex,
 *                per-process rule compilation cache.
 */

#include "mod_bw_shm.h"
#include "mod_bw_config.h"
#include <apr_file_io.h>
#include <apr_lib.h>

/* ------------------------------------------------------------------ */
/* Internal helpers                                                    */
/* ------------------------------------------------------------------ */

/* Non-zero after a post_config call that (re)created the SHM region. */
int bw_shm_was_created = 0;

/* Compute the total SHM size needed for the given capacities */
static apr_size_t shm_needed(apr_uint32_t max_v,
                             apr_uint32_t max_p,
                             apr_uint32_t max_r,
                             apr_uint32_t max_t)
{
  return sizeof(bw_shm_header_t) + (apr_size_t)max_v * sizeof(bw_vhost_slot_t) + (apr_size_t)max_p * sizeof(bw_pool_slot_t) + (apr_size_t)max_r * sizeof(bw_rule_slot_t) + (apr_size_t)max_t * sizeof(bw_token_slot_t);
}

/* Point the array pointers in bw_g at the right offsets */
static void shm_set_pointers(void)
{
  char *base = (char *)bw_g.hdr;
  bw_g.vhosts = (bw_vhost_slot_t *)(base + bw_g.hdr->vhost_offset);
  bw_g.pools = (bw_pool_slot_t *)(base + bw_g.hdr->pool_offset);
  bw_g.rules = (bw_rule_slot_t *)(base + bw_g.hdr->rule_offset);
  bw_g.tokens = (bw_token_slot_t *)(base + bw_g.hdr->token_offset);
}

/* Zero-init the stats block */
static void stats_init(bw_stats_t *s)
{
  memset(s, 0, sizeof(*s));
}

/* ------------------------------------------------------------------ */
/* bw_shm_init                                                         */
/* ------------------------------------------------------------------ */
apr_status_t bw_shm_init(apr_pool_t *p, server_rec *s,
                         const char *shm_file,
                         const char *lock_file,
                         apr_uint32_t max_vhosts,
                         apr_uint32_t max_pools,
                         apr_uint32_t max_rules,
                         apr_uint32_t max_tokens)
{
  apr_status_t rv;
  apr_size_t need = shm_needed(max_vhosts, max_pools, max_rules, max_tokens);
  int reuse = 0;

  /* Offsets and shm_size in the header are 32-bit; refuse a region that
     * would not fit so they can never silently truncate/overflow. */
  if (need > 0xFFFFFFFFu)
  {
    ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s,
                 "mod_bw: requested SHM size %" APR_SIZE_T_FMT
                 " exceeds 4GB; lower BandWidthMax* capacities",
                 need);
    return APR_EINVAL;
  }

  bw_shm_was_created = 0;

  /* Try to attach to an existing named SHM first */
  rv = apr_shm_attach(&bw_g.shm, shm_file, p);
  if (rv == APR_SUCCESS)
  {
    bw_shm_header_t *h = apr_shm_baseaddr_get(bw_g.shm);
    if (h->magic == BW_SHM_MAGIC &&
        h->version == BW_SHM_VERSION &&
        h->shm_size == (apr_uint32_t)need)
    {
      reuse = 1;
      ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s,
                   "mod_bw: re-attached existing SHM %s (%u bytes)",
                   shm_file, h->shm_size);
    }
    else
    {
      /* Stale or incompatible - destroy and re-create */
      apr_shm_detach(bw_g.shm);
      apr_shm_remove(shm_file, p);
      bw_g.shm = NULL;
    }
  }
  else
  {
    /* Remove any leftover file so create works clean */
    apr_shm_remove(shm_file, p);
    bw_g.shm = NULL;
  }

  if (!reuse)
  {
    rv = apr_shm_create(&bw_g.shm, need, shm_file, p);
    if (rv != APR_SUCCESS)
    {
      ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s,
                   "mod_bw: cannot create SHM at %s", shm_file);
      return rv;
    }

    bw_g.hdr = (bw_shm_header_t *)apr_shm_baseaddr_get(bw_g.shm);
    memset(bw_g.hdr, 0, need);

    bw_g.hdr->magic = BW_SHM_MAGIC;
    bw_g.hdr->version = BW_SHM_VERSION;
    bw_g.hdr->seq = 0;
    bw_g.hdr->max_vhosts = max_vhosts;
    bw_g.hdr->max_pools = max_pools;
    bw_g.hdr->max_rules = max_rules;
    bw_g.hdr->max_tokens = max_tokens;
    bw_g.hdr->n_vhosts = 0;
    bw_g.hdr->n_pools = 0;
    bw_g.hdr->n_rules = 0;
    bw_g.hdr->n_tokens = 0;
    bw_g.hdr->next_token_id = 1;
    bw_g.hdr->shm_size = (apr_uint32_t)need;
    bw_g.hdr->api_flags = 0;

    bw_g.hdr->vhost_offset = (apr_uint32_t)sizeof(bw_shm_header_t);
    bw_g.hdr->pool_offset = bw_g.hdr->vhost_offset + max_vhosts * (apr_uint32_t)sizeof(bw_vhost_slot_t);
    bw_g.hdr->rule_offset = bw_g.hdr->pool_offset + max_pools * (apr_uint32_t)sizeof(bw_pool_slot_t);
    bw_g.hdr->token_offset = bw_g.hdr->rule_offset + max_rules * (apr_uint32_t)sizeof(bw_rule_slot_t);

    bw_shm_was_created = 1;

    strncpy(bw_g.hdr->shm_file, shm_file, sizeof(bw_g.hdr->shm_file) - 1);
    strncpy(bw_g.hdr->lock_file, lock_file, sizeof(bw_g.hdr->lock_file) - 1);

    /* Seed time info */
    apr_time_exp_t now_exp;
    apr_time_exp_tz(&now_exp, apr_time_now(), 0);
    bw_g.hdr->last_year = (apr_uint32_t)now_exp.tm_year;
    bw_g.hdr->last_yday = (apr_uint32_t)now_exp.tm_yday;
    bw_g.hdr->last_hour = (apr_uint32_t)now_exp.tm_hour;
    bw_g.hdr->last_min = (apr_uint32_t)now_exp.tm_min;

    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s,
                 "mod_bw: created SHM %s (%lu bytes, %u vhosts, %u pools, %u rules)",
                 shm_file, (unsigned long)need,
                 max_vhosts, max_pools, max_rules);
  }
  else
  {
    bw_g.hdr = (bw_shm_header_t *)apr_shm_baseaddr_get(bw_g.shm);
  }

  shm_set_pointers();

  /* Create (or re-create) the global mutex */
  rv = apr_global_mutex_create(&bw_g.mutex, lock_file,
                               APR_LOCK_DEFAULT, p);
  if (rv != APR_SUCCESS)
  {
    ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s,
                 "mod_bw: cannot create global mutex at %s", lock_file);
    return rv;
  }

  /* Let child processes inherit the mutex file descriptor */
  rv = ap_unixd_set_global_mutex_perms(bw_g.mutex);
  if (rv != APR_SUCCESS)
  {
    ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s,
                 "mod_bw: cannot set mutex permissions");
    return rv;
  }

  return APR_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* bw_mutex_child_init                                                 */
/* ------------------------------------------------------------------ */
apr_status_t bw_mutex_child_init(apr_pool_t *pchild, server_rec *s,
                                 const char *lock_file)
{
  apr_status_t rv;

  if (!bw_g.mutex)
    return APR_SUCCESS; /* module disabled */

  rv = apr_global_mutex_child_init(&bw_g.mutex, lock_file, pchild);
  if (rv != APR_SUCCESS)
  {
    ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s,
                 "mod_bw: child cannot init mutex at %s", lock_file);
  }
  return rv;
}

/* ------------------------------------------------------------------ */
/* Slot allocators                                                     */
/* ------------------------------------------------------------------ */

apr_uint32_t bw_vhost_find(const char *name)
{
  apr_uint32_t i, seq;
  apr_uint32_t found = BW_IDX_NONE;

  /* The BW_SEQ_READ body must not break/return out of the seqlock loop,
     * or a value read mid-write could be returned without the retry check.
     * Capture the hit in `found` and break only the inner for-loop; the
     * seqlock loop re-runs the whole scan if a writer landed in between. */
  BW_SEQ_READ(seq, {
    found = BW_IDX_NONE;
    for (i = 0; i < bw_g.hdr->max_vhosts; i++)
    {
      if (apr_atomic_read32(&bw_g.vhosts[i].flags) == BW_SLOT_ACTIVE &&
          strncasecmp(bw_g.vhosts[i].name, name,
                      BW_VHOST_NAME_LEN) == 0)
      {
        found = i;
        break;
      }
    }
  });

  return found;
}

apr_uint32_t bw_vhost_alloc(const char *name, apr_uint32_t id)
{
  apr_uint32_t i;

  for (i = 0; i < bw_g.hdr->max_vhosts; i++)
  {
    if (apr_atomic_cas32(&bw_g.vhosts[i].flags,
                         BW_SLOT_ACTIVE, BW_SLOT_FREE) == BW_SLOT_FREE)
    {
      bw_vhost_slot_t *v = &bw_g.vhosts[i];
      strncpy(v->name, name, BW_VHOST_NAME_LEN - 1);
      v->name[BW_VHOST_NAME_LEN - 1] = '\0';
      v->id = id;
      v->pool_root_idx = BW_IDX_NONE;
      v->dynamic = 0;
      stats_init(&v->stats);
      apr_atomic_inc32(&bw_g.hdr->n_vhosts);
      return i;
    }
  }
  return BW_IDX_NONE; /* exhausted */
}

apr_uint32_t bw_pool_alloc(apr_uint32_t vhost_idx, apr_uint32_t id,
                           apr_uint32_t parent_idx,
                           apr_uint32_t bwlimit, apr_uint32_t in_bwlimit,
                           apr_uint32_t maxc,
                           apr_int32_t packet, apr_int32_t error_code)
{
  apr_uint32_t i;

  for (i = 0; i < bw_g.hdr->max_pools; i++)
  {
    if (apr_atomic_cas32(&bw_g.pools[i].flags,
                         BW_SLOT_ACTIVE, BW_SLOT_FREE) == BW_SLOT_FREE)
    {
      bw_pool_slot_t *pool = &bw_g.pools[i];
      pool->id = id;
      pool->vhost_idx = vhost_idx;
      pool->parent_idx = parent_idx;
      pool->first_child_idx = BW_IDX_NONE;
      pool->next_sibling_idx = BW_IDX_NONE;
      pool->first_rule_idx = BW_IDX_NONE;
      pool->bwlimit = bwlimit;
      pool->in_bwlimit = in_bwlimit;
      pool->maxc = maxc;
      pool->packet = packet;
      pool->error = error_code;
      pool->generation = 0;
      stats_init(&pool->stats);

      /* Graft into the tree */
      if (parent_idx == BW_IDX_NONE)
      {
        /* Root-level pool: append to vhost's pool list */
        volatile apr_uint32_t *head = &bw_g.vhosts[vhost_idx].pool_root_idx;
        if (*head == BW_IDX_NONE)
        {
          *head = i;
        }
        else
        {
          apr_uint32_t cur = *head, guard = 0;
          while (bw_g.pools[cur].next_sibling_idx != BW_IDX_NONE &&
                 guard++ < bw_g.hdr->max_pools)
            cur = bw_g.pools[cur].next_sibling_idx;
          bw_g.pools[cur].next_sibling_idx = i;
        }
      }
      else
      {
        /* Child pool: append to parent's child list */
        volatile apr_uint32_t *head = &bw_g.pools[parent_idx].first_child_idx;
        if (*head == BW_IDX_NONE)
        {
          *head = i;
        }
        else
        {
          apr_uint32_t cur = *head, guard = 0;
          while (bw_g.pools[cur].next_sibling_idx != BW_IDX_NONE &&
                 guard++ < bw_g.hdr->max_pools)
            cur = bw_g.pools[cur].next_sibling_idx;
          bw_g.pools[cur].next_sibling_idx = i;
        }
      }

      apr_atomic_inc32(&bw_g.hdr->n_pools);
      return i;
    }
  }
  return BW_IDX_NONE;
}

apr_uint32_t bw_rule_alloc(apr_uint32_t pool_idx,
                           unsigned char rule_type, unsigned char direction,
                           const char *value,
                           apr_int32_t rate, apr_int32_t in_rate,
                           apr_int32_t min_rate)
{
  apr_uint32_t i;

  for (i = 0; i < bw_g.hdr->max_rules; i++)
  {
    if (apr_atomic_cas32(&bw_g.rules[i].flags,
                         BW_SLOT_ACTIVE, BW_SLOT_FREE) == BW_SLOT_FREE)
    {
      bw_rule_slot_t *rule = &bw_g.rules[i];
      rule->pool_idx = pool_idx;
      rule->rule_type = rule_type;
      rule->direction = direction;
      strncpy(rule->value, value, BW_RULE_VALUE_LEN - 1);
      rule->value[BW_RULE_VALUE_LEN - 1] = '\0';
      rule->rate = rate;
      rule->in_rate = in_rate;
      rule->min_rate = min_rate;
      rule->next_rule_idx = BW_IDX_NONE;
      rule->generation = 1; /* non-zero so the cache recompiles */

      /* Append to pool's rule list. The walk is capped at max_rules so a
             * corrupted/cyclic link can never spin under the global mutex. */
      volatile apr_uint32_t *head = &bw_g.pools[pool_idx].first_rule_idx;
      if (*head == BW_IDX_NONE)
      {
        *head = i;
      }
      else
      {
        apr_uint32_t cur = *head;
        apr_uint32_t guard = 0;
        while (bw_g.rules[cur].next_rule_idx != BW_IDX_NONE &&
               guard++ < bw_g.hdr->max_rules)
          cur = bw_g.rules[cur].next_rule_idx;
        bw_g.rules[cur].next_rule_idx = i;
      }

      apr_atomic_inc32(&bw_g.hdr->n_rules);
      return i;
    }
  }
  return BW_IDX_NONE;
}

/* ------------------------------------------------------------------ */
/* Slot freeing                                                        */
/* ------------------------------------------------------------------ */

void bw_rule_free(apr_uint32_t rule_idx)
{
  if (rule_idx >= bw_g.hdr->max_rules)
    return;
  /* Clear the link before freeing so a reused slot can never re-introduce a
     * stale edge into a live list. */
  bw_g.rules[rule_idx].next_rule_idx = BW_IDX_NONE;
  apr_atomic_dec32(&bw_g.hdr->n_rules);
  apr_atomic_set32(&bw_g.rules[rule_idx].flags, BW_SLOT_FREE);
}

/* ------------------------------------------------------------------ */
/* API token slots                                                     */
/* ------------------------------------------------------------------ */

/* Constant-time compare of two equal-purpose hex hashes. Always walks the
 * full BW_TOKEN_HASH_LEN so timing does not leak which slot matched. */
static int token_hash_eq(const char *a, const char *b)
{
  int diff = 0;
  apr_size_t i;
  for (i = 0; i < BW_TOKEN_HASH_LEN; i++)
  {
    diff |= (int)(unsigned char)a[i] ^ (int)(unsigned char)b[i];
    if (a[i] == '\0' || b[i] == '\0')
      break;
  }
  /* Length sentinel: differing terminators already flagged via diff above */
  return diff == 0;
}

apr_uint32_t bw_token_alloc(const char *label, apr_uint32_t scope,
                            const char *hash, apr_uint32_t id_in)
{
  apr_uint32_t i;

  if (!bw_g.tokens || bw_g.hdr->max_tokens == 0)
    return BW_IDX_NONE;

  for (i = 0; i < bw_g.hdr->max_tokens; i++)
  {
    if (apr_atomic_cas32(&bw_g.tokens[i].flags,
                         BW_SLOT_ACTIVE, BW_SLOT_FREE) == BW_SLOT_FREE)
    {
      bw_token_slot_t *t = &bw_g.tokens[i];
      apr_uint32_t id = id_in ? id_in
                              : apr_atomic_inc32(&bw_g.hdr->next_token_id);
      /* apr_atomic_inc32 returns the PRE-increment value; +1 gives the
             * id we reserved. Keep next_token_id ahead of any loaded id. */
      if (!id_in)
        id += 1;
      if (id_in && id_in >= apr_atomic_read32(&bw_g.hdr->next_token_id))
        apr_atomic_set32(&bw_g.hdr->next_token_id, id_in + 1);

      t->id = id;
      t->scope = (scope == BW_TOKEN_SCOPE_RO) ? BW_TOKEN_SCOPE_RO
                                              : BW_TOKEN_SCOPE_ADMIN;
      strncpy(t->label, label ? label : "", BW_TOKEN_LABEL_LEN - 1);
      t->label[BW_TOKEN_LABEL_LEN - 1] = '\0';
      strncpy(t->hash, hash ? hash : "", BW_TOKEN_HASH_LEN - 1);
      t->hash[BW_TOKEN_HASH_LEN - 1] = '\0';
      t->n_vhosts = 0;
      t->n_pools = 0;
      memset(t->vhosts, 0, sizeof(t->vhosts));
      memset(t->pools, 0, sizeof(t->pools));
      t->created = apr_time_now();
      t->last_used = 0;
      apr_atomic_inc32(&bw_g.hdr->n_tokens);
      return i;
    }
  }
  return BW_IDX_NONE; /* store full */
}

void bw_token_free(apr_uint32_t tok_idx)
{
  if (!bw_g.tokens || tok_idx >= bw_g.hdr->max_tokens)
    return;
  apr_atomic_dec32(&bw_g.hdr->n_tokens);
  apr_atomic_set32(&bw_g.tokens[tok_idx].flags, BW_SLOT_FREE);
}

apr_uint32_t bw_token_find_by_hash(const char *hash)
{
  apr_uint32_t i, seq;
  apr_uint32_t found = BW_IDX_NONE;

  if (!bw_g.tokens || !hash || !*hash)
    return BW_IDX_NONE;

  BW_SEQ_READ(seq, {
    found = BW_IDX_NONE;
    for (i = 0; i < bw_g.hdr->max_tokens; i++)
    {
      if (apr_atomic_read32(&bw_g.tokens[i].flags) == BW_SLOT_ACTIVE &&
          token_hash_eq(bw_g.tokens[i].hash, hash))
      {
        found = i;
        break;
      }
    }
  });
  return found;
}

apr_uint32_t bw_token_find_by_id(apr_uint32_t id)
{
  apr_uint32_t i, seq;
  apr_uint32_t found = BW_IDX_NONE;

  if (!bw_g.tokens)
    return BW_IDX_NONE;

  BW_SEQ_READ(seq, {
    found = BW_IDX_NONE;
    for (i = 0; i < bw_g.hdr->max_tokens; i++)
    {
      if (apr_atomic_read32(&bw_g.tokens[i].flags) == BW_SLOT_ACTIVE &&
          bw_g.tokens[i].id == id)
      {
        found = i;
        break;
      }
    }
  });
  return found;
}

/* Remove pool_idx from its parent's child list (or the vhost's root list).
 * Singly-linked walk; safe to call once before freeing a single pool. Does
 * NOT touch pool_idx's own children - the caller frees the subtree. Iteration
 * is capped at max_pools so a corrupt list can never spin. */
void bw_pool_unlink(apr_uint32_t pool_idx)
{
  if (pool_idx >= bw_g.hdr->max_pools)
    return;

  bw_pool_slot_t *pool = &bw_g.pools[pool_idx];
  volatile apr_uint32_t *head;
  if (pool->parent_idx == BW_IDX_NONE)
  {
    if (pool->vhost_idx >= bw_g.hdr->max_vhosts)
      return;
    head = &bw_g.vhosts[pool->vhost_idx].pool_root_idx;
  }
  else
  {
    if (pool->parent_idx >= bw_g.hdr->max_pools)
      return;
    head = &bw_g.pools[pool->parent_idx].first_child_idx;
  }

  if (*head == pool_idx)
  { /* unlink at head */
    *head = pool->next_sibling_idx;
    pool->next_sibling_idx = BW_IDX_NONE;
    return;
  }
  apr_uint32_t cur = *head, guard = 0;
  while (cur != BW_IDX_NONE && guard++ < bw_g.hdr->max_pools)
  {
    if (bw_g.pools[cur].next_sibling_idx == pool_idx)
    {
      bw_g.pools[cur].next_sibling_idx = pool->next_sibling_idx;
      pool->next_sibling_idx = BW_IDX_NONE;
      return;
    }
    cur = bw_g.pools[cur].next_sibling_idx;
  }
}

apr_status_t bw_pool_free(apr_uint32_t pool_idx)
{
  apr_uint32_t rule_idx, next, guard;

  if (pool_idx >= bw_g.hdr->max_pools)
    return APR_EINVAL;

  /* Free all rules (guard against a corrupt/cyclic rule list) */
  rule_idx = bw_g.pools[pool_idx].first_rule_idx;
  guard = 0;
  while (rule_idx != BW_IDX_NONE && guard++ < bw_g.hdr->max_rules)
  {
    next = bw_g.rules[rule_idx].next_rule_idx;
    bw_rule_free(rule_idx);
    rule_idx = next;
  }

  /* Free child pools (recursive; guard against a corrupt/cyclic list) */
  apr_uint32_t child = bw_g.pools[pool_idx].first_child_idx;
  guard = 0;
  while (child != BW_IDX_NONE && guard++ < bw_g.hdr->max_pools)
  {
    apr_uint32_t sib = bw_g.pools[child].next_sibling_idx;
    bw_pool_free(child);
    child = sib;
  }

  apr_atomic_dec32(&bw_g.hdr->n_pools);
  apr_atomic_set32(&bw_g.pools[pool_idx].flags, BW_SLOT_FREE);
  return APR_SUCCESS;
}

/* Structural free only.  The CALLER must hold bw_g.mutex, bracket the call
 * with BW_SEQ_WRITE_BEGIN/END, and have already drained active connections
 * (connection_count == 0).  This function never sleeps, so the seqlock is
 * held only for the few microseconds the tree-walk takes - it must NOT block
 * the request-matching read path.  Draining is done lock-free by the caller
 * (see api_delete_vhost) after marking the slot BW_SLOT_DELETING. */
apr_status_t bw_vhost_free(apr_uint32_t vhost_idx, apr_pool_t *tmp)
{
  apr_uint32_t pool_idx, sib;
  (void)tmp;

  if (vhost_idx >= bw_g.hdr->max_vhosts)
    return APR_EINVAL;

  /* Free all top-level pools (and their subtrees). Guard against a corrupt
     * or cyclic sibling list so a bad link can never spin under the mutex. */
  apr_uint32_t guard = 0;
  pool_idx = bw_g.vhosts[vhost_idx].pool_root_idx;
  while (pool_idx != BW_IDX_NONE && guard++ < bw_g.hdr->max_pools)
  {
    sib = bw_g.pools[pool_idx].next_sibling_idx;
    bw_pool_free(pool_idx);
    pool_idx = sib;
  }
  bw_g.vhosts[vhost_idx].pool_root_idx = BW_IDX_NONE;

  apr_atomic_dec32(&bw_g.hdr->n_vhosts);
  apr_atomic_set32(&bw_g.vhosts[vhost_idx].flags, BW_SLOT_FREE);
  return APR_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* Per-process rule cache                                              */
/* ------------------------------------------------------------------ */

apr_status_t bw_rule_cache_init(apr_pool_t *pchild, apr_uint32_t max_rules)
{
  bw_g.rule_cache = apr_pcalloc(pchild,
                                max_rules * sizeof(bw_rule_cache_entry_t));
  if (!bw_g.rule_cache)
    return APR_ENOMEM;
  bw_g.rule_cache_sz = max_rules;
  bw_g.cache_pool = pchild;
  return APR_SUCCESS;
}

const bw_rule_cache_entry_t *bw_rule_cache_get(apr_uint32_t rule_idx,
                                               apr_pool_t *pool)
{
  (void)pool; /* kept for API compatibility; allocations use the entry pool */

  if (!bw_g.rule_cache || rule_idx >= bw_g.rule_cache_sz ||
      rule_idx >= bw_g.hdr->max_rules)
    return NULL;

  bw_rule_cache_entry_t *ce = &bw_g.rule_cache[rule_idx];
  const bw_rule_slot_t *rule = &bw_g.rules[rule_idx];
  apr_uint32_t gen = rule->generation;

  if (ce->generation == gen)
    return ce; /* cache hit - regex/ip_subnet still valid */

  /* Invalidate: destroy old per-entry pool (frees old regex/ip_subnet) */
  if (ce->pool)
  {
    apr_pool_destroy(ce->pool);
    ce->pool = NULL;
  }
  ce->ip_subnet = NULL;
  ce->regex = NULL;

  /* Allocate a fresh per-entry pool parented to the long-lived child pool */
  apr_pool_create(&ce->pool, bw_g.cache_pool);

  if (rule->rule_type == BW_RULE_T_IP)
  {
    char buf[BW_RULE_VALUE_LEN];
    char *slash;
    strncpy(buf, rule->value, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    slash = strchr(buf, '/');
    if (slash)
      *slash++ = '\0';
    apr_ipsubnet_create(&ce->ip_subnet, buf, slash, ce->pool);
  }
  else if (rule->rule_type == BW_RULE_T_AGENT)
  {
    const char *pat = rule->value;
    if (pat[0] == 'u' && pat[1] == ':')
      pat += 2;
    ce->regex = ap_pregcomp(ce->pool, pat, AP_REG_EXTENDED | AP_REG_ICASE);
  }

  ce->generation = gen;
  return ce;
}
