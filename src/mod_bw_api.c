/*
 * mod_bw_api.c - REST management API for mod_bw
 *
 * Endpoints (all require "Authorization: Bearer <token>"):
 *
 *   GET  /_bw_api/status
 *   GET  /_bw_api/vhosts
 *   POST /_bw_api/vhosts               body: {"name":"host","enabled":true}
 *   PUT  /_bw_api/vhosts/:idx          body: {"enabled":false}
 *   DELETE /_bw_api/vhosts/:idx
 *
 *   GET  /_bw_api/vhosts/:idx/pools
 *   POST /_bw_api/vhosts/:idx/pools    body: {"id":1,"bwlimit":100000,"in_bwlimit":0,"maxc":50,"parent_idx":4294967295}
 *   PUT  /_bw_api/vhosts/:idx/pools/:pidx  body: {"bwlimit":200000,"in_bwlimit":0,"maxc":100}
 *   DELETE /_bw_api/vhosts/:idx/pools/:pidx
 *
 *   GET  /_bw_api/vhosts/:idx/pools/:pidx/rules
 *   POST /_bw_api/vhosts/:idx/pools/:pidx/rules  body: {"type":"ip","value":"...","rate":0,"in_rate":0,"min_rate":0}
 *   DELETE /_bw_api/vhosts/:idx/pools/:pidx/rules/:ridx
 *
 *   GET  /_bw_api/metrics
 *   GET  /_bw_api/metrics/:idx
 *
 * JSON parsing: minimal hand-written parser; no external dependencies.
 * All responses are UTF-8 JSON.
 */

#include "mod_bw_api.h"
#include "mod_bw_config.h"
#include "mod_bw_shm.h"
#include "mod_bw_tokens.h"
#include <http_request.h>
#include <apr_strings.h>
#include <apr_lib.h>
#include <http_protocol.h>

/* ------------------------------------------------------------------ */
/* Constant-time string comparison (guard against timing attacks)     */
/* ------------------------------------------------------------------ */
static int ct_strcmp(const char *a, const char *b)
{
  int diff = 0;
  size_t la = strlen(a), lb = strlen(b);
  size_t len = la > lb ? la : lb;
  size_t i;
  for (i = 0; i < len; i++)
  {
    diff |= (int)(unsigned char)(i < la ? a[i] : 0) ^ (int)(unsigned char)(i < lb ? b[i] : 0);
  }
  return diff; /* 0 = equal */
}

/* -------------------------------------------------------------------- */
/* Authentication & authorization                                       */
/*                                                                      */
/* Two credential sources, resolved into one bw_auth_t per request:     */
/*   1. the immutable config BandWidthAPIToken - the "root" bootstrap   */
/*      token: full admin, every vhost/pool, survives any restart, and  */
/*      it alone may administer the token store.                        */
/*   2. an API-managed token in SHM, matched by SHA-256 hash, carrying  */
/*      a scope (ro/admin) and an optional vhost/pool allow-list.       */
/* -------------------------------------------------------------------- */
typedef struct
{
  int authed;           /* a valid credential was presented             */
  int is_root;          /* matched the config BandWidthAPIToken         */
  apr_uint32_t scope;   /* BW_TOKEN_SCOPE_RO / _ADMIN (root = ADMIN)    */
  apr_uint32_t tok_idx; /* SHM slot of a stored token; BW_IDX_NONE root */
  apr_uint32_t tok_id;  /* stable token id; 0 for root                  */
} bw_auth_t;

static void bw_resolve_auth(request_rec *r, const char *cfg_token, bw_auth_t *a)
{
  memset(a, 0, sizeof(*a));
  a->tok_idx = BW_IDX_NONE;
  a->scope = BW_TOKEN_SCOPE_ADMIN;

  const char *auth = apr_table_get(r->headers_in, "Authorization");
  if (!auth || strncasecmp(auth, "Bearer ", 7) != 0)
    return;
  const char *tok = auth + 7;
  while (*tok == ' ')
    tok++;
  if (!*tok)
    return;

  /* 1. Root config token */
  if (cfg_token && *cfg_token && ct_strcmp(tok, cfg_token) == 0)
  {
    a->authed = 1;
    a->is_root = 1;
    a->scope = BW_TOKEN_SCOPE_ADMIN;
    return;
  }

  /* 2. Stored token: hash and look up */
  if (bw_g.tokens)
  {
    char hash[BW_TOKEN_HASH_LEN];
    bw_token_hash(tok, hash);
    apr_uint32_t idx = bw_token_find_by_hash(hash);
    if (idx != BW_IDX_NONE)
    {
      a->authed = 1;
      a->tok_idx = idx;
      a->tok_id = bw_g.tokens[idx].id;
      a->scope = bw_g.tokens[idx].scope;
      bw_g.tokens[idx].last_used = apr_time_now();
    }
  }
}

/* Write access = authed AND admin scope (root is always admin). */
static int auth_can_write(const bw_auth_t *a)
{
  return a->authed && a->scope == BW_TOKEN_SCOPE_ADMIN;
}

/* Is `name` within this credential's vhost allow-list? Empty list = all. */
static int auth_allows_vhost_name(const bw_auth_t *a, const char *name)
{
  if (a->is_root)
    return 1;
  if (a->tok_idx == BW_IDX_NONE)
    return 0;
  const bw_token_slot_t *t = &bw_g.tokens[a->tok_idx];
  if (t->n_vhosts == 0)
    return 1;
  apr_uint32_t k;
  for (k = 0; k < t->n_vhosts && k < BW_TOKEN_MAX_VHOSTS; k++)
    if (strncasecmp(t->vhosts[k], name, BW_VHOST_NAME_LEN) == 0)
      return 1;
  return 0;
}

static int auth_allows_vhost_idx(const bw_auth_t *a, apr_uint32_t vidx)
{
  if (a->is_root)
    return 1;
  if (vidx >= bw_g.hdr->max_vhosts)
    return 0;
  if (apr_atomic_read32(&bw_g.vhosts[vidx].flags) == BW_SLOT_FREE)
    return 0;
  return auth_allows_vhost_name(a, bw_g.vhosts[vidx].name);
}

/* Pool-id allow-list (within already-permitted vhosts). Empty list = all. */
static int auth_allows_pool_id(const bw_auth_t *a, apr_uint32_t pool_id)
{
  if (a->is_root)
    return 1;
  if (a->tok_idx == BW_IDX_NONE)
    return 0;
  const bw_token_slot_t *t = &bw_g.tokens[a->tok_idx];
  if (t->n_pools == 0)
    return 1;
  apr_uint32_t k;
  for (k = 0; k < t->n_pools && k < BW_TOKEN_MAX_POOLS; k++)
    if (t->pools[k] == pool_id)
      return 1;
  return 0;
}

/* Combined check for a pool slot index: its vhost and its id must pass. */
static int auth_allows_pool_idx(const bw_auth_t *a, apr_uint32_t pidx)
{
  if (a->is_root)
    return 1;
  if (pidx >= bw_g.hdr->max_pools)
    return 0;
  if (apr_atomic_read32(&bw_g.pools[pidx].flags) == BW_SLOT_FREE)
    return 0;
  return auth_allows_vhost_idx(a, bw_g.pools[pidx].vhost_idx) &&
         auth_allows_pool_id(a, bw_g.pools[pidx].id);
}

/* Back-compat shim retained for any external caller: plain root-token check. */
int bw_api_auth(request_rec *r, const char *expected_token)
{
  bw_auth_t a;
  bw_resolve_auth(r, expected_token, &a);
  return a.authed;
}

/* ------------------------------------------------------------------- */
/* Minimal JSON helpers                                                */
/* ------------------------------------------------------------------- */

/* Append a JSON-escaped string to buf (remaining capacity in *left) */
static void json_str_append(char **buf, apr_size_t *left, const char *s)
{
  if (!s)
    s = "";
  while (*s && *left > 2)
  {
    char c = *s++;
    if (c == '"' || c == '\\' || c == '/')
    {
      if (*left < 3)
        break;
      **buf = '\\';
      (*buf)++;
      (*left)--;
    }
    else if (c < 0x20)
    {
      /* control character - skip */
      continue;
    }
    **buf = c;
    (*buf)++;
    (*left)--;
  }
}

/* Write a NUL-terminated string into buf (checked) */
#define JCAT(buf, left, ...)                                    \
  do                                                            \
  {                                                             \
    apr_size_t _n = apr_snprintf(*(buf), *(left), __VA_ARGS__); \
    *(buf) += _n < *(left) ? _n : *(left);                      \
    *(left) = *(left) > _n ? *(left) - _n : 0;                  \
  } while (0)

/* ------------------------------------------------------------------ */
/* Minimal JSON value extractor                                       */
/*                                                                    */
/* Finds the value of "key" in the flat JSON object body.             */
/* Supports string, integer, and boolean values only.                 */
/* Writes the raw value string into out (NUL-terminated, out_sz       */
/* includes the NUL byte).                                            */
/* Returns 1 on success, 0 if key not found.                          */
/* ------------------------------------------------------------------ */
static int json_get(const char *body, const char *key,
                    char *out, apr_size_t out_sz)
{
  if (!body || !key)
    return 0;

  /* Build search pattern: "key" */
  char pat[BW_RULE_VALUE_LEN + 4];
  apr_snprintf(pat, sizeof(pat), "\"%s\"", key);
  apr_size_t patlen = strlen(pat);

  /* Find an occurrence that is actually a key, not a substring inside some
     * string value: the previous non-space character must be '{' or ',' (or
     * the match is at the very start).  This is not a full JSON parser, but it
     * closes the obvious ambiguity where e.g. a "name" value contains the text
     * "maxc": and confuses a later json_get(body,"maxc",...). */
  const char *p = body;
  const char *hit = NULL;
  while ((p = strstr(p, pat)) != NULL)
  {
    const char *q = p;
    while (q > body)
    {
      char c = *(q - 1);
      if (c == ' ' || c == '\t' || c == '\n' || c == '\r')
      {
        q--;
        continue;
      }
      break;
    }
    if (q == body || *(q - 1) == '{' || *(q - 1) == ',')
    {
      hit = p;
      break;
    }
    p += patlen;
  }
  if (!hit)
    return 0;

  p = hit + patlen;
  while (*p == ' ' || *p == '\t')
    p++;
  if (*p != ':')
    return 0;
  p++;
  while (*p == ' ' || *p == '\t')
    p++;

  apr_size_t i = 0;
  if (*p == '"')
  {
    /* String value */
    p++;
    while (*p && *p != '"' && i < out_sz - 1)
    {
      if (*p == '\\' && *(p + 1))
      {
        p++;
      } /* skip escape */
      out[i++] = *p++;
    }
  }
  else
  {
    /* Number, boolean, null */
    while (*p && *p != ',' && *p != '}' && *p != '\n' && i < out_sz - 1)
      out[i++] = *p++;
    /* Trim trailing whitespace */
    while (i > 0 && (out[i - 1] == ' ' || out[i - 1] == '\t'))
      i--;
  }
  out[i] = '\0';
  return i > 0 || *p == '"'; /* empty string is valid */
}

/* ------------------------------------------------------------------ */
/* Read request body into pool-allocated buffer                       */
/* ------------------------------------------------------------------ */
static char *read_body(request_rec *r, apr_size_t max_sz)
{
  apr_size_t total = 0;
  char *body = apr_pcalloc(r->pool, max_sz + 1);
  apr_bucket_brigade *bb = apr_brigade_create(r->pool,
                                              r->connection->bucket_alloc);

  ap_setup_client_block(r, REQUEST_CHUNKED_DECHUNK);

  if (!ap_should_client_block(r))
    return body;

  while (total < max_sz)
  {
    apr_size_t chunk = max_sz - total;
    long rd = ap_get_client_block(r, body + total, chunk);
    if (rd <= 0)
      break;
    total += (apr_size_t)rd;
  }
  body[total] = '\0';
  apr_brigade_destroy(bb);
  return body;
}

/* ------------------------------------------------------------------ */
/* Response helpers                                                    */
/* ------------------------------------------------------------------ */
static void json_reply(request_rec *r, int status, const char *json)
{
  r->status = status;
  ap_set_content_type(r, "application/json");
  ap_rprintf(r, "%s\n", json);
}

static void json_error(request_rec *r, int status, const char *msg)
{
  char buf[256];
  apr_snprintf(buf, sizeof(buf), "{\"error\":\"%s\"}", msg);
  json_reply(r, status, buf);
}

/* ------------------------------------------------------------------ */
/* Array extraction from a request body (for token scope lists)        */
/* Scans for "key":[ ... ]. Lenient; inputs are admin-supplied.        */
/* ------------------------------------------------------------------ */
static const char *json_arr_start(const char *body, const char *key)
{
  char pat[64];
  apr_snprintf(pat, sizeof(pat), "\"%s\"", key);
  const char *p = strstr(body, pat);
  if (!p)
    return NULL;
  p += strlen(pat);
  while (*p == ' ' || *p == '\t' || *p == ':')
    p++;
  return (*p == '[') ? p + 1 : NULL;
}

/* Parse ["a","b"] into arr[][BW_VHOST_NAME_LEN]; returns count. */
static apr_uint32_t json_get_str_array(const char *body, const char *key,
                                       char arr[][BW_VHOST_NAME_LEN],
                                       apr_uint32_t maxn)
{
  const char *p = json_arr_start(body, key);
  apr_uint32_t n = 0;
  if (!p)
    return 0;
  while (*p && *p != ']' && n < maxn)
  {
    while (*p == ' ' || *p == ',' || *p == '\n' || *p == '\t')
      p++;
    if (*p != '"')
      break;
    p++;
    apr_size_t j = 0;
    while (*p && *p != '"' && j + 1 < BW_VHOST_NAME_LEN)
      arr[n][j++] = *p++;
    arr[n][j] = '\0';
    if (*p == '"')
      p++;
    n++;
  }
  return n;
}

/* Parse [1,2,3] into arr[]; returns count. */
static apr_uint32_t json_get_uint_array(const char *body, const char *key,
                                        apr_uint32_t *arr, apr_uint32_t maxn)
{
  const char *p = json_arr_start(body, key);
  apr_uint32_t n = 0;
  if (!p)
    return 0;
  while (*p && *p != ']' && n < maxn)
  {
    while (*p == ' ' || *p == ',' || *p == '\n' || *p == '\t')
      p++;
    if (!apr_isdigit(*p))
      break;
    arr[n++] = (apr_uint32_t)apr_atoi64(p);
    while (apr_isdigit(*p))
      p++;
  }
  return n;
}

/* ------------------------------------------------------------------ */
/* URL path parser: splits api_path + suffix into parts               */
/* path_suffix = r->uri + strlen(api_path)                            */
/* Returns number of parts (0-4).                                     */
/* parts[] are NUL-terminated strings in r->pool.                    */
/* ------------------------------------------------------------------ */
static int parse_path(request_rec *r, const char *suffix,
                      char **parts, int max_parts)
{
  int n = 0;
  const char *p = suffix;
  while (*p == '/')
    p++;

  while (*p && n < max_parts)
  {
    const char *end = strchr(p, '/');
    apr_size_t len = end ? (apr_size_t)(end - p) : strlen(p);
    if (len == 0)
      break;
    parts[n++] = apr_pstrndup(r->pool, p, len);
    p += len;
    if (*p == '/')
      p++;
  }
  return n;
}

/* ------------------------------------------------------------------ */
/* Metrics serialisation                                               */
/* ------------------------------------------------------------------ */
static void vhost_metrics_json(bw_vhost_slot_t *v, char **buf,
                               apr_size_t *left, apr_uint32_t idx,
                               apr_uint32_t now_sec)
{
  apr_uint64_t bout = bw_bytes64_read(&v->stats.bytes_out);
  apr_uint64_t bin = bw_bytes64_read(&v->stats.bytes_in);
  apr_uint32_t bwout = bw_ring_sum(&v->stats.ring_out, now_sec, 5);
  apr_uint32_t bwin = bw_ring_sum(&v->stats.ring_in, now_sec, 5);

  JCAT(buf, left,
       "{\"idx\":%u,\"id\":%u,\"name\":\"", idx, v->id);
  json_str_append(buf, left, v->name);
  JCAT(buf, left,
       "\",\"flags\":%u,\"dynamic\":%u,"
       "\"connection_count\":%u,"
       "\"bandwidth_out\":%u,\"bandwidth_in\":%u,"
       "\"bytes_out\":%" APR_UINT64_T_FMT ","
       "\"bytes_in\":%" APR_UINT64_T_FMT ","
       "\"requests\":%u,\"throttled\":%u,\"cutoff\":%u",
       apr_atomic_read32(&v->flags), v->dynamic,
       v->stats.connection_count,
       bwout, bwin, bout, bin,
       v->stats.counter, v->stats.throttled, v->stats.cutoff);
}

static void pool_metrics_json(bw_pool_slot_t *pool, char **buf,
                              apr_size_t *left, apr_uint32_t idx,
                              apr_uint32_t now_sec)
{
  apr_uint64_t bout = bw_bytes64_read(&pool->stats.bytes_out);
  apr_uint64_t bin = bw_bytes64_read(&pool->stats.bytes_in);
  apr_uint32_t bwout = bw_ring_sum(&pool->stats.ring_out, now_sec, 5);
  apr_uint32_t bwin = bw_ring_sum(&pool->stats.ring_in, now_sec, 5);

  JCAT(buf, left,
       "{\"idx\":%u,\"id\":%u,\"vhost_idx\":%u,"
       "\"parent_idx\":%u,\"flags\":%u,"
       "\"bwlimit\":%u,\"in_bwlimit\":%u,\"maxc\":%u,"
       "\"connection_count\":%u,"
       "\"bandwidth_out\":%u,\"bandwidth_in\":%u,"
       "\"bytes_out\":%" APR_UINT64_T_FMT ","
       "\"bytes_in\":%" APR_UINT64_T_FMT ","
       "\"requests\":%u,\"throttled\":%u,\"cutoff\":%u}",
       idx, pool->id, pool->vhost_idx,
       pool->parent_idx, apr_atomic_read32(&pool->flags),
       pool->bwlimit, pool->in_bwlimit, pool->maxc,
       pool->stats.connection_count,
       bwout, bwin, bout, bin,
       pool->stats.counter, pool->stats.throttled, pool->stats.cutoff);
}

/* ------------------------------------------------------------------ */
/* Individual endpoint handlers                                        */
/* ------------------------------------------------------------------ */

/* GET /status */
static int api_status(request_rec *r)
{
  char buf[1024];
  char *p = buf;
  apr_size_t left = sizeof(buf);
  JCAT(&p, &left,
       "{\"version\":\"%s\","
       "\"shm_file\":\"%s\","
       "\"shm_size\":%u,"
       "\"max_vhosts\":%u,\"used_vhosts\":%u,"
       "\"max_pools\":%u,\"used_pools\":%u,"
       "\"max_rules\":%u,\"used_rules\":%u,"
       "\"api_flags\":%u}",
       MOD_BW_VERSION,
       bw_g.hdr->shm_file,
       bw_g.hdr->shm_size,
       bw_g.hdr->max_vhosts, bw_g.hdr->n_vhosts,
       bw_g.hdr->max_pools, bw_g.hdr->n_pools,
       bw_g.hdr->max_rules, bw_g.hdr->n_rules,
       bw_g.hdr->api_flags);
  json_reply(r, HTTP_OK, buf);
  return OK;
}

/* GET /vhosts - filtered to the credential's allowed vhosts */
static int api_list_vhosts(request_rec *r, const bw_auth_t *a)
{
  apr_uint32_t now_sec =
      (apr_uint32_t)(apr_time_now() / APR_USEC_PER_SEC);
  apr_size_t bufsz = 64 * 1024;
  char *buf = apr_pcalloc(r->pool, bufsz);
  char *p = buf;
  apr_size_t left = bufsz;
  int first = 1;

  JCAT(&p, &left, "[");
  apr_uint32_t i;
  for (i = 0; i < bw_g.hdr->max_vhosts; i++)
  {
    if (apr_atomic_read32(&bw_g.vhosts[i].flags) == BW_SLOT_FREE)
      continue;
    if (!auth_allows_vhost_idx(a, i))
      continue;
    if (!first)
      JCAT(&p, &left, ",");
    first = 0;
    vhost_metrics_json(&bw_g.vhosts[i], &p, &left, i, now_sec);
    JCAT(&p, &left, "}");
  }
  JCAT(&p, &left, "]");
  json_reply(r, HTTP_OK, buf);
  return OK;
}

/* POST /vhosts  body: {"name":"host.example.com","enabled":true} */
static int api_add_vhost(request_rec *r)
{
  char *body = read_body(r, 4096);
  char name[BW_VHOST_NAME_LEN] = {0};
  char enabled_s[8] = {0};

  if (!json_get(body, "name", name, sizeof(name)) || !name[0])
    return json_error(r, HTTP_BAD_REQUEST, "missing name"), OK;

  json_get(body, "enabled", enabled_s, sizeof(enabled_s));
  int enabled = (strcasecmp(enabled_s, "false") != 0 &&
                 strcmp(enabled_s, "0") != 0);

  /* Check for duplicate */
  if (bw_vhost_find(name) != BW_IDX_NONE)
    return json_error(r, HTTP_CONFLICT, "vhost already exists"), OK;

  apr_global_mutex_lock(bw_g.mutex);
  BW_SEQ_WRITE_BEGIN();

  apr_uint32_t new_id = apr_atomic_inc32(&bw_g.hdr->n_vhosts) + 1000u;
  apr_uint32_t idx = bw_vhost_alloc(name, new_id);
  apr_atomic_dec32(&bw_g.hdr->n_vhosts); /* bw_vhost_alloc already increments */

  if (idx == BW_IDX_NONE)
  {
    BW_SEQ_WRITE_END();
    apr_global_mutex_unlock(bw_g.mutex);
    return json_error(r, HTTP_INTERNAL_SERVER_ERROR,
                      "vhost slot exhausted"),
           OK;
  }

  bw_g.vhosts[idx].dynamic = 1;
  if (!enabled)
    apr_atomic_set32(&bw_g.vhosts[idx].flags, BW_SLOT_DISABLED);

  BW_SEQ_WRITE_END();
  apr_global_mutex_unlock(bw_g.mutex);

  char out[64];
  apr_snprintf(out, sizeof(out), "{\"idx\":%u}", idx);
  json_reply(r, HTTP_CREATED, out);
  return OK;
}

/* PUT /vhosts/:idx  body: {"enabled":true|false} */
static int api_update_vhost(request_rec *r, apr_uint32_t idx)
{
  if (idx >= bw_g.hdr->max_vhosts ||
      apr_atomic_read32(&bw_g.vhosts[idx].flags) == BW_SLOT_FREE)
    return json_error(r, HTTP_NOT_FOUND, "vhost not found"), OK;

  char *body = read_body(r, 4096);
  char enabled_s[8] = {0};
  json_get(body, "enabled", enabled_s, sizeof(enabled_s));

  apr_global_mutex_lock(bw_g.mutex);
  BW_SEQ_WRITE_BEGIN();

  int enabled = (strcasecmp(enabled_s, "false") != 0 &&
                 strcmp(enabled_s, "0") != 0);
  apr_atomic_set32(&bw_g.vhosts[idx].flags,
                   enabled ? BW_SLOT_ACTIVE : BW_SLOT_DISABLED);

  BW_SEQ_WRITE_END();
  apr_global_mutex_unlock(bw_g.mutex);

  json_reply(r, HTTP_OK, "{\"ok\":true}");
  return OK;
}

/* DELETE /vhosts/:idx
 *
 * Deleting a vhost that still has active downloads requires waiting for
 * them to drain.  That wait MUST NOT happen while holding the global mutex
 * or the seqlock : doing so would stall the request-matching read path
 * (every worker spins on an odd seqlock) for the whole drain window.
 *
 * So this is done in three short critical sections with a lock-free drain
 * in between:
 *   1. Mark the slot BW_SLOT_DELETING (stops new requests selecting it).
 *   2. Poll connection_count to zero, holding no lock (up to 30 s).
 *   3. Either free the slot structurally, or roll back to ACTIVE if it is
 *      still busy.  The DELETING guard makes concurrent deletes idempotent
 *      and prevents a double free / counter underflow.
 */
static int api_delete_vhost(request_rec *r, apr_uint32_t idx)
{
  if (idx >= bw_g.hdr->max_vhosts ||
      apr_atomic_read32(&bw_g.vhosts[idx].flags) == BW_SLOT_FREE)
    return json_error(r, HTTP_NOT_FOUND, "vhost not found"), OK;

  /* Phase 1 - mark DELETING.  No structural pointers change, so this is a
     * brief critical section; we do not even need to bump the seqlock. */
  apr_global_mutex_lock(bw_g.mutex);
  if (apr_atomic_read32(&bw_g.vhosts[idx].flags) == BW_SLOT_FREE)
  {
    apr_global_mutex_unlock(bw_g.mutex);
    return json_error(r, HTTP_NOT_FOUND, "vhost not found"), OK;
  }
  apr_atomic_set32(&bw_g.vhosts[idx].flags, BW_SLOT_DELETING);
  apr_global_mutex_unlock(bw_g.mutex);

  /* Phase 2 - drain WITHOUT holding any lock.  Readers run freely; in-flight
     * filters stop throttling once they observe the non-ACTIVE flag and
     * decrement connection_count via their pool cleanup. */
  int waited = 0;
  while (apr_atomic_read32(&bw_g.vhosts[idx].stats.connection_count) > 0 &&
         waited < 30)
  {
    apr_sleep(APR_USEC_PER_SEC);
    waited++;
  }

  if (apr_atomic_read32(&bw_g.vhosts[idx].stats.connection_count) > 0)
  {
    /* Still busy - roll back to ACTIVE (only if we still own the slot). */
    apr_global_mutex_lock(bw_g.mutex);
    if (apr_atomic_read32(&bw_g.vhosts[idx].flags) == BW_SLOT_DELETING)
      apr_atomic_set32(&bw_g.vhosts[idx].flags, BW_SLOT_ACTIVE);
    apr_global_mutex_unlock(bw_g.mutex);
    return json_error(r, HTTP_CONFLICT,
                      "active connections still open; retry later"),
           OK;
  }

  /* Phase 3 - structural free.  Brief seqlock-protected section; the guard
     * ensures only the delete that still owns the DELETING slot frees it. */
  apr_global_mutex_lock(bw_g.mutex);
  if (apr_atomic_read32(&bw_g.vhosts[idx].flags) == BW_SLOT_DELETING)
  {
    BW_SEQ_WRITE_BEGIN();
    bw_vhost_free(idx, r->pool);
    BW_SEQ_WRITE_END();
  }
  apr_global_mutex_unlock(bw_g.mutex);

  json_reply(r, HTTP_OK, "{\"ok\":true}");
  return OK;
}

/* GET /vhosts/:idx/pools */
static int api_list_pools(request_rec *r, apr_uint32_t vhost_idx)
{
  if (vhost_idx >= bw_g.hdr->max_vhosts ||
      apr_atomic_read32(&bw_g.vhosts[vhost_idx].flags) == BW_SLOT_FREE)
    return json_error(r, HTTP_NOT_FOUND, "vhost not found"), OK;

  apr_uint32_t now_sec =
      (apr_uint32_t)(apr_time_now() / APR_USEC_PER_SEC);
  apr_size_t bufsz = 64 * 1024;
  char *buf = apr_pcalloc(r->pool, bufsz);
  char *p = buf;
  apr_size_t left = bufsz;
  int first = 1;

  JCAT(&p, &left, "[");
  apr_uint32_t i;
  for (i = 0; i < bw_g.hdr->max_pools; i++)
  {
    if (bw_g.pools[i].vhost_idx != vhost_idx)
      continue;
    if (apr_atomic_read32(&bw_g.pools[i].flags) == BW_SLOT_FREE)
      continue;
    if (!first)
      JCAT(&p, &left, ",");
    first = 0;
    pool_metrics_json(&bw_g.pools[i], &p, &left, i, now_sec);
  }
  JCAT(&p, &left, "]");
  json_reply(r, HTTP_OK, buf);
  return OK;
}

/* POST /vhosts/:idx/pools
   body: {"id":1,"bwlimit":100000,"in_bwlimit":0,"maxc":50,"parent_idx":4294967295} */
static int api_add_pool(request_rec *r, apr_uint32_t vhost_idx,
                        const bw_auth_t *a)
{
  if (vhost_idx >= bw_g.hdr->max_vhosts ||
      apr_atomic_read32(&bw_g.vhosts[vhost_idx].flags) == BW_SLOT_FREE)
    return json_error(r, HTTP_NOT_FOUND, "vhost not found"), OK;

  char *body = read_body(r, 4096);
  char tmp[64];
  apr_uint32_t pid = 0;
  apr_uint32_t bwlimit = 0;
  apr_uint32_t in_bwlimit = 0;
  apr_uint32_t maxc = 0;
  apr_uint32_t parent_idx = BW_IDX_NONE;

  if (json_get(body, "id", tmp, sizeof(tmp)))
    pid = (apr_uint32_t)atol(tmp);
  if (json_get(body, "bwlimit", tmp, sizeof(tmp)))
    bwlimit = (apr_uint32_t)atol(tmp);
  if (json_get(body, "in_bwlimit", tmp, sizeof(tmp)))
    in_bwlimit = (apr_uint32_t)atol(tmp);
  if (json_get(body, "maxc", tmp, sizeof(tmp)))
    maxc = (apr_uint32_t)atol(tmp);
  if (json_get(body, "parent_idx", tmp, sizeof(tmp)))
    parent_idx = (apr_uint32_t)atol(tmp);

  if (pid == 0)
    return json_error(r, HTTP_BAD_REQUEST, "missing pool id"), OK;

  /* A scoped token may only create pools within its pool-id allow-list;
     * otherwise pool creation would let it escape that scope. */
  if (!auth_allows_pool_id(a, pid))
    return json_error(r, HTTP_FORBIDDEN, "pool id out of token scope"), OK;

  apr_global_mutex_lock(bw_g.mutex);
  BW_SEQ_WRITE_BEGIN();

  apr_uint32_t pidx = bw_pool_alloc(vhost_idx, pid, parent_idx,
                                    bwlimit, in_bwlimit, maxc, -1, -1);
  BW_SEQ_WRITE_END();
  apr_global_mutex_unlock(bw_g.mutex);

  if (pidx == BW_IDX_NONE)
    return json_error(r, HTTP_INTERNAL_SERVER_ERROR,
                      "pool slot exhausted"),
           OK;

  char out[64];
  apr_snprintf(out, sizeof(out), "{\"idx\":%u}", pidx);
  json_reply(r, HTTP_CREATED, out);
  return OK;
}

/* PUT /vhosts/:vidx/pools/:pidx
   body: {"bwlimit":200000,"in_bwlimit":50000,"maxc":100} */
static int api_update_pool(request_rec *r, apr_uint32_t pidx)
{
  if (pidx >= bw_g.hdr->max_pools ||
      apr_atomic_read32(&bw_g.pools[pidx].flags) == BW_SLOT_FREE)
    return json_error(r, HTTP_NOT_FOUND, "pool not found"), OK;

  char *body = read_body(r, 4096);
  char tmp[64];

  apr_global_mutex_lock(bw_g.mutex);
  BW_SEQ_WRITE_BEGIN();

  if (json_get(body, "bwlimit", tmp, sizeof(tmp)))
    apr_atomic_set32(&bw_g.pools[pidx].bwlimit, (apr_uint32_t)atol(tmp));
  if (json_get(body, "in_bwlimit", tmp, sizeof(tmp)))
    apr_atomic_set32(&bw_g.pools[pidx].in_bwlimit, (apr_uint32_t)atol(tmp));
  if (json_get(body, "maxc", tmp, sizeof(tmp)))
    apr_atomic_set32(&bw_g.pools[pidx].maxc, (apr_uint32_t)atol(tmp));

  /* Bump generation so per-process rule caches know to re-check */
  apr_atomic_inc32(&bw_g.pools[pidx].generation);

  BW_SEQ_WRITE_END();
  apr_global_mutex_unlock(bw_g.mutex);

  json_reply(r, HTTP_OK, "{\"ok\":true}");
  return OK;
}

/* DELETE /vhosts/:vidx/pools/:pidx */
static int api_delete_pool(request_rec *r, apr_uint32_t pidx)
{
  if (pidx >= bw_g.hdr->max_pools ||
      apr_atomic_read32(&bw_g.pools[pidx].flags) == BW_SLOT_FREE)
    return json_error(r, HTTP_NOT_FOUND, "pool not found"), OK;

  if (bw_g.pools[pidx].stats.connection_count > 0)
    return json_error(r, HTTP_CONFLICT,
                      "active connections in pool; retry later"),
           OK;

  apr_global_mutex_lock(bw_g.mutex);
  BW_SEQ_WRITE_BEGIN();

  /* Unlink from the vhost/parent sibling chain BEFORE freeing, so no
     * dangling root/sibling pointer remains to form a cycle on slot reuse. */
  bw_pool_unlink(pidx);
  bw_pool_free(pidx);

  BW_SEQ_WRITE_END();
  apr_global_mutex_unlock(bw_g.mutex);

  json_reply(r, HTTP_OK, "{\"ok\":true}");
  return OK;
}

/* GET /vhosts/:vidx/pools/:pidx/rules */
static int api_list_rules(request_rec *r, apr_uint32_t pidx)
{
  if (pidx >= bw_g.hdr->max_pools ||
      apr_atomic_read32(&bw_g.pools[pidx].flags) == BW_SLOT_FREE)
    return json_error(r, HTTP_NOT_FOUND, "pool not found"), OK;

  apr_size_t bufsz = 32 * 1024;
  char *buf = apr_pcalloc(r->pool, bufsz);
  char *p = buf;
  apr_size_t left = bufsz;
  int first = 1;

  JCAT(&p, &left, "[");
  apr_uint32_t ridx = bw_g.pools[pidx].first_rule_idx;
  while (ridx != BW_IDX_NONE)
  {
    bw_rule_slot_t *rule = &bw_g.rules[ridx];
    if (apr_atomic_read32(&rule->flags) == BW_SLOT_ACTIVE)
    {
      if (!first)
        JCAT(&p, &left, ",");
      first = 0;
      JCAT(&p, &left, "{\"idx\":%u,\"pool_idx\":%u,"
                      "\"type\":%u,\"direction\":%u,\"value\":\"",
           ridx, rule->pool_idx, rule->rule_type, rule->direction);
      json_str_append(&p, &left, rule->value);
      JCAT(&p, &left, "\",\"rate\":%d,\"in_rate\":%d,\"min_rate\":%d}",
           rule->rate, rule->in_rate, rule->min_rate);
    }
    ridx = bw_g.rules[ridx].next_rule_idx;
  }
  JCAT(&p, &left, "]");
  json_reply(r, HTTP_OK, buf);
  return OK;
}

/* POST /vhosts/:vidx/pools/:pidx/rules
   body: {"type":"all|ip|host|agent","value":"...","rate":0,"in_rate":0,"min_rate":0} */
static int api_add_rule(request_rec *r, apr_uint32_t pidx)
{
  if (pidx >= bw_g.hdr->max_pools ||
      apr_atomic_read32(&bw_g.pools[pidx].flags) == BW_SLOT_FREE)
    return json_error(r, HTTP_NOT_FOUND, "pool not found"), OK;

  char *body = read_body(r, 4096);
  char type_s[16] = {0};
  char value[BW_RULE_VALUE_LEN] = {0};
  char tmp[64] = {0};
  apr_int32_t rate = 0, in_rate = 0, min_rate = 0;

  json_get(body, "type", type_s, sizeof(type_s));
  json_get(body, "value", value, sizeof(value));
  if (json_get(body, "rate", tmp, sizeof(tmp)))
    rate = (apr_int32_t)atol(tmp);
  if (json_get(body, "in_rate", tmp, sizeof(tmp)))
    in_rate = (apr_int32_t)atol(tmp);
  if (json_get(body, "min_rate", tmp, sizeof(tmp)))
    min_rate = (apr_int32_t)atol(tmp);

  unsigned char rtype;
  if (!strcasecmp(type_s, "all"))
    rtype = BW_RULE_T_ALL;
  else if (!strcasecmp(type_s, "ip"))
    rtype = BW_RULE_T_IP;
  else if (!strcasecmp(type_s, "host"))
    rtype = BW_RULE_T_HOST;
  else if (!strcasecmp(type_s, "agent"))
    rtype = BW_RULE_T_AGENT;
  else
    return json_error(r, HTTP_BAD_REQUEST,
                      "type must be all|ip|host|agent"),
           OK;

  apr_global_mutex_lock(bw_g.mutex);
  BW_SEQ_WRITE_BEGIN();

  apr_uint32_t ridx = bw_rule_alloc(pidx, rtype, BW_RULE_BOTH,
                                    value, rate, in_rate, min_rate);
  BW_SEQ_WRITE_END();
  apr_global_mutex_unlock(bw_g.mutex);

  if (ridx == BW_IDX_NONE)
    return json_error(r, HTTP_INTERNAL_SERVER_ERROR,
                      "rule slot exhausted"),
           OK;

  char out[64];
  apr_snprintf(out, sizeof(out), "{\"idx\":%u}", ridx);
  json_reply(r, HTTP_CREATED, out);
  return OK;
}

/* DELETE /vhosts/:vidx/pools/:pidx/rules/:ridx */
static int api_delete_rule(request_rec *r, apr_uint32_t pidx, apr_uint32_t ridx)
{
  if (ridx >= bw_g.hdr->max_rules ||
      apr_atomic_read32(&bw_g.rules[ridx].flags) == BW_SLOT_FREE)
    return json_error(r, HTTP_NOT_FOUND, "rule not found"), OK;

  /* The rule must belong to the pool named in the path; the dispatcher only
     * authorized that pool, so a rule in another pool is out of scope. */
  if (bw_g.rules[ridx].pool_idx != pidx)
    return json_error(r, HTTP_NOT_FOUND, "rule not found in pool"), OK;

  apr_global_mutex_lock(bw_g.mutex);
  BW_SEQ_WRITE_BEGIN();

  /* Unlink from the pool's rule list (capped so a corrupt link can't spin) */
  volatile apr_uint32_t *cur = &bw_g.pools[pidx].first_rule_idx;
  apr_uint32_t guard = 0;
  while (*cur != BW_IDX_NONE && guard++ < bw_g.hdr->max_rules)
  {
    if (*cur == ridx)
    {
      *cur = bw_g.rules[ridx].next_rule_idx;
      break;
    }
    cur = &bw_g.rules[*cur].next_rule_idx;
  }
  bw_rule_free(ridx);

  BW_SEQ_WRITE_END();
  apr_global_mutex_unlock(bw_g.mutex);

  json_reply(r, HTTP_OK, "{\"ok\":true}");
  return OK;
}

/* GET /metrics  or  /metrics/:vhost_idx - filtered to allowed vhosts */
static int api_metrics(request_rec *r, int have_vidx, apr_uint32_t vidx,
                       const bw_auth_t *a)
{
  apr_uint32_t now_sec =
      (apr_uint32_t)(apr_time_now() / APR_USEC_PER_SEC);
  apr_size_t bufsz = 128 * 1024;
  char *buf = apr_pcalloc(r->pool, bufsz);
  char *p = buf;
  apr_size_t left = bufsz;
  int first = 1;

  if (have_vidx)
  {
    if (vidx >= bw_g.hdr->max_vhosts ||
        apr_atomic_read32(&bw_g.vhosts[vidx].flags) == BW_SLOT_FREE)
      return json_error(r, HTTP_NOT_FOUND, "vhost not found"), OK;
    if (!auth_allows_vhost_idx(a, vidx))
      return json_error(r, HTTP_FORBIDDEN, "vhost out of token scope"), OK;

    vhost_metrics_json(&bw_g.vhosts[vidx], &p, &left, vidx, now_sec);
    /* Append pool array */
    JCAT(&p, &left, ",\"pools\":[");
    apr_uint32_t pidx = bw_g.vhosts[vidx].pool_root_idx;
    while (pidx != BW_IDX_NONE)
    {
      if (!first)
        JCAT(&p, &left, ",");
      first = 0;
      pool_metrics_json(&bw_g.pools[pidx], &p, &left, pidx, now_sec);
      pidx = bw_g.pools[pidx].next_sibling_idx;
    }
    JCAT(&p, &left, "]}");
  }
  else
  {
    JCAT(&p, &left, "[");
    apr_uint32_t i;
    for (i = 0; i < bw_g.hdr->max_vhosts; i++)
    {
      if (apr_atomic_read32(&bw_g.vhosts[i].flags) == BW_SLOT_FREE)
        continue;
      if (!auth_allows_vhost_idx(a, i))
        continue;
      if (!first)
        JCAT(&p, &left, ",");
      first = 0;
      vhost_metrics_json(&bw_g.vhosts[i], &p, &left, i, now_sec);
      JCAT(&p, &left, "}");
    }
    JCAT(&p, &left, "]");
  }
  json_reply(r, HTTP_OK, buf);
  return OK;
}

/* ------------------------------------------------------------------ */
/* Token administration (root credential only)                        */
/* ------------------------------------------------------------------ */

/* Emit one token object (no secret, no full hash). buf/left are advanced. */
static void token_json(const bw_token_slot_t *t, char **p, apr_size_t *left)
{
  JCAT(p, left,
       "{\"id\":%u,\"label\":\"%s\",\"scope\":\"%s\",\"hash_prefix\":\"%.8s\","
       "\"created\":%" APR_INT64_T_FMT ",\"last_used\":%" APR_INT64_T_FMT
       ",\"vhosts\":[",
       t->id, t->label,
       t->scope == BW_TOKEN_SCOPE_RO ? "ro" : "admin",
       t->hash,
       apr_time_sec(t->created),
       apr_time_sec((apr_time_t)t->last_used));
  apr_uint32_t k;
  for (k = 0; k < t->n_vhosts && k < BW_TOKEN_MAX_VHOSTS; k++)
    JCAT(p, left, "%s\"%s\"", k ? "," : "", t->vhosts[k]);
  JCAT(p, left, "],\"pools\":[");
  for (k = 0; k < t->n_pools && k < BW_TOKEN_MAX_POOLS; k++)
    JCAT(p, left, "%s%u", k ? "," : "", t->pools[k]);
  JCAT(p, left, "]}");
}

/* GET /tokens */
static int api_list_tokens(request_rec *r)
{
  apr_size_t bufsz = 64 * 1024;
  char *buf = apr_pcalloc(r->pool, bufsz);
  char *p = buf;
  apr_size_t left = bufsz;
  int first = 1;

  JCAT(&p, &left, "[");
  apr_uint32_t i;
  for (i = 0; i < bw_g.hdr->max_tokens; i++)
  {
    if (apr_atomic_read32(&bw_g.tokens[i].flags) != BW_SLOT_ACTIVE)
      continue;
    if (!first)
      JCAT(&p, &left, ",");
    first = 0;
    token_json(&bw_g.tokens[i], &p, &left);
  }
  JCAT(&p, &left, "]");
  json_reply(r, HTTP_OK, buf);
  return OK;
}

/* Validate a label: printable ASCII, no quote/backslash/control. Keeps the
 * JSON-Lines store unambiguous without escaping. */
static int label_ok(const char *s)
{
  if (!s || !*s)
    return 0;
  for (; *s; s++)
  {
    unsigned char c = (unsigned char)*s;
    if (c < 0x20 || c == 0x7f || c == '"' || c == '\\')
      return 0;
  }
  return 1;
}

/* POST /tokens  body:
 *   {"label":"ci","scope":"ro","vhosts":["a.com"],"pools":[1,2]}
 * Returns the freshly generated secret ONCE. */
static int api_add_token(request_rec *r)
{
  char *body = read_body(r, 8192);
  char label[BW_TOKEN_LABEL_LEN] = {0};
  char scope_s[16] = {0};

  if (!json_get(body, "label", label, sizeof(label)) || !label_ok(label))
    return json_error(r, HTTP_BAD_REQUEST,
                      "label required (printable, no quotes/backslash)"),
           OK;

  json_get(body, "scope", scope_s, sizeof(scope_s));
  apr_uint32_t scope = (!strcasecmp(scope_s, "admin") ||
                        !strcasecmp(scope_s, "rw"))
                           ? BW_TOKEN_SCOPE_ADMIN
                           : BW_TOKEN_SCOPE_RO;

  char vhosts[BW_TOKEN_MAX_VHOSTS][BW_VHOST_NAME_LEN];
  apr_uint32_t pools[BW_TOKEN_MAX_POOLS];
  apr_uint32_t nv = json_get_str_array(body, "vhosts", vhosts, BW_TOKEN_MAX_VHOSTS);
  apr_uint32_t np = json_get_uint_array(body, "pools", pools, BW_TOKEN_MAX_POOLS);

  char secret[64];
  bw_token_gen_secret(secret, sizeof(secret));
  if (!secret[0])
    return json_error(r, HTTP_INTERNAL_SERVER_ERROR,
                      "secret generation failed"),
           OK;
  char hash[BW_TOKEN_HASH_LEN];
  bw_token_hash(secret, hash);

  apr_global_mutex_lock(bw_g.mutex);
  BW_SEQ_WRITE_BEGIN();

  apr_uint32_t idx = bw_token_alloc(label, scope, hash, 0);
  if (idx != BW_IDX_NONE)
  {
    bw_token_slot_t *t = &bw_g.tokens[idx];
    apr_uint32_t k;
    t->n_vhosts = (nv < BW_TOKEN_MAX_VHOSTS) ? nv : BW_TOKEN_MAX_VHOSTS;
    for (k = 0; k < t->n_vhosts; k++)
      apr_cpystrn(t->vhosts[k], vhosts[k], BW_VHOST_NAME_LEN);
    t->n_pools = (np < BW_TOKEN_MAX_POOLS) ? np : BW_TOKEN_MAX_POOLS;
    for (k = 0; k < t->n_pools; k++)
      t->pools[k] = pools[k];
  }

  BW_SEQ_WRITE_END();

  apr_uint32_t new_id = (idx != BW_IDX_NONE) ? bw_g.tokens[idx].id : 0;
  apr_status_t srv = (idx != BW_IDX_NONE) ? bw_tokens_save(r->pool) : APR_SUCCESS;
  apr_global_mutex_unlock(bw_g.mutex);

  if (idx == BW_IDX_NONE)
    return json_error(r, HTTP_INSUFFICIENT_STORAGE,
                      "token store full"),
           OK;
  if (srv != APR_SUCCESS)
    ap_log_rerror(APLOG_MARK, APLOG_WARNING, srv, r,
                  "mod_bw: token created but store save failed");

  char out[256];
  apr_snprintf(out, sizeof(out),
               "{\"id\":%u,\"label\":\"%s\",\"scope\":\"%s\",\"secret\":\"%s\"}",
               new_id, label,
               scope == BW_TOKEN_SCOPE_RO ? "ro" : "admin", secret);
  json_reply(r, HTTP_CREATED, out);
  return OK;
}

/* DELETE /tokens/:id */
static int api_delete_token(request_rec *r, apr_uint32_t id)
{
  apr_uint32_t idx = bw_token_find_by_id(id);
  if (idx == BW_IDX_NONE)
    return json_error(r, HTTP_NOT_FOUND, "token not found"), OK;

  apr_global_mutex_lock(bw_g.mutex);
  BW_SEQ_WRITE_BEGIN();
  bw_token_free(idx);
  BW_SEQ_WRITE_END();
  apr_status_t srv = bw_tokens_save(r->pool);
  apr_global_mutex_unlock(bw_g.mutex);

  if (srv != APR_SUCCESS)
    ap_log_rerror(APLOG_MARK, APLOG_WARNING, srv, r,
                  "mod_bw: token deleted but store save failed");

  json_reply(r, HTTP_OK, "{\"ok\":true}");
  return OK;
}

/* GET /whoami - any authenticated credential learns its own scope. */
static int api_whoami(request_rec *r, const bw_auth_t *a)
{
  char buf[2048];
  char *p = buf;
  apr_size_t left = sizeof(buf);

  JCAT(&p, &left,
       "{\"root\":%s,\"scope\":\"%s\",\"can_write\":%s,\"token_id\":%u,\"vhosts\":[",
       a->is_root ? "true" : "false",
       a->scope == BW_TOKEN_SCOPE_RO ? "ro" : "admin",
       auth_can_write(a) ? "true" : "false",
       a->tok_id);

  if (!a->is_root && a->tok_idx != BW_IDX_NONE)
  {
    const bw_token_slot_t *t = &bw_g.tokens[a->tok_idx];
    apr_uint32_t k;
    for (k = 0; k < t->n_vhosts && k < BW_TOKEN_MAX_VHOSTS; k++)
      JCAT(&p, &left, "%s\"%s\"", k ? "," : "", t->vhosts[k]);
    JCAT(&p, &left, "],\"pools\":[");
    for (k = 0; k < t->n_pools && k < BW_TOKEN_MAX_POOLS; k++)
      JCAT(&p, &left, "%s%u", k ? "," : "", t->pools[k]);
  }
  else
  {
    JCAT(&p, &left, "],\"pools\":[");
  }
  JCAT(&p, &left, "]}");
  json_reply(r, HTTP_OK, buf);
  return OK;
}

/* ------------------------------------------------------------------ */
/* Main API dispatcher                                                */
/* ------------------------------------------------------------------ */
int bw_api_handler(request_rec *r)
{
  if (!bw_g.hdr)
    return HTTP_SERVICE_UNAVAILABLE;

  bandwidth_server_config *sc = bw_sconf(r);

  /* Authentication: resolve the credential once. */
  bw_auth_t auth;
  bw_resolve_auth(r, sc->api_token, &auth);
  if (!auth.authed)
  {
    apr_table_setn(r->err_headers_out, "WWW-Authenticate",
                   "Bearer realm=\"mod_bw\"");
    return HTTP_UNAUTHORIZED;
  }

  /* Path relative to the configured api_path */
  const char *api_path = sc->api_path ? sc->api_path : "/_bw_api";
  size_t plen = strlen(api_path);
  const char *suffix = r->uri + plen;
  if (*suffix == '/')
    suffix++;

  char *parts[6] = {NULL, NULL, NULL, NULL, NULL, NULL};
  int nparts = parse_path(r, suffix, parts, 6);

  const char *method = r->method;

  /* Central authorization gate ----------------------------------- */
  /* (a) any non-GET verb requires write (admin) scope.             */
  int mutating = strcmp(method, "GET") != 0;
  if (mutating && !auth_can_write(&auth))
    return json_error(r, HTTP_FORBIDDEN,
                      "read-only token: write not permitted"),
           OK;

  /* (b) resource scope: a vhost- or pool-targeted route must fall   */
  /*     inside the credential's allow-list. List/aggregate routes   */
  /*     (no explicit index) are filtered inside their handlers.     */
  if (nparts >= 2 && !strcmp(parts[0], "vhosts"))
  {
    apr_uint32_t vidx = (apr_uint32_t)atol(parts[1]);
    if (!auth_allows_vhost_idx(&auth, vidx))
      return json_error(r, HTTP_FORBIDDEN, "vhost out of token scope"), OK;
    /* pool-targeted (.../pools/:pidx[/...]) also checks the pool */
    if (nparts >= 4 && !strcmp(parts[2], "pools"))
    {
      apr_uint32_t pidx = (apr_uint32_t)atol(parts[3]);
      if (!auth_allows_pool_idx(&auth, pidx))
        return json_error(r, HTTP_FORBIDDEN,
                          "pool out of token scope"),
               OK;
    }
  }

  /* Routing table */

  /* GET /status */
  if (nparts == 1 && !strcmp(parts[0], "status") &&
      !strcmp(method, "GET"))
    return api_status(r);

  /* GET /whoami - every authenticated credential may introspect itself */
  if (nparts == 1 && !strcmp(parts[0], "whoami") && !strcmp(method, "GET"))
    return api_whoami(r, &auth);

  /* /tokens - token administration is restricted to the root token */
  if (nparts >= 1 && !strcmp(parts[0], "tokens"))
  {
    if (!auth.is_root)
      return json_error(r, HTTP_FORBIDDEN,
                        "token administration requires the root token"),
             OK;
    if (nparts == 1)
    {
      if (!strcmp(method, "GET"))
        return api_list_tokens(r);
      if (!strcmp(method, "POST"))
        return api_add_token(r);
    }
    if (nparts == 2)
    {
      apr_uint32_t id = (apr_uint32_t)atol(parts[1]);
      if (!strcmp(method, "DELETE"))
        return api_delete_token(r, id);
    }
    return HTTP_NOT_FOUND;
  }

  /* GET /metrics */
  if (nparts >= 1 && !strcmp(parts[0], "metrics"))
  {
    if (nparts == 1)
      return api_metrics(r, 0, 0, &auth);
    if (nparts == 2)
      return api_metrics(r, 1, (apr_uint32_t)atol(parts[1]), &auth);
  }

  /* /vhosts ... */
  if (nparts >= 1 && !strcmp(parts[0], "vhosts"))
  {

    if (nparts == 1)
    {
      if (!strcmp(method, "GET"))
        return api_list_vhosts(r, &auth);
      if (!strcmp(method, "POST"))
        return api_add_vhost(r);
    }

    if (nparts == 2)
    {
      apr_uint32_t vidx = (apr_uint32_t)atol(parts[1]);
      if (!strcmp(method, "PUT"))
        return api_update_vhost(r, vidx);
      if (!strcmp(method, "DELETE"))
        return api_delete_vhost(r, vidx);
    }

    /* /vhosts/:vidx/pools ... */
    if (nparts >= 3 && !strcmp(parts[2], "pools"))
    {
      apr_uint32_t vidx = (apr_uint32_t)atol(parts[1]);

      if (nparts == 3)
      {
        if (!strcmp(method, "GET"))
          return api_list_pools(r, vidx);
        if (!strcmp(method, "POST"))
          return api_add_pool(r, vidx, &auth);
      }

      if (nparts == 4)
      {
        apr_uint32_t pidx = (apr_uint32_t)atol(parts[3]);
        if (!strcmp(method, "PUT"))
          return api_update_pool(r, pidx);
        if (!strcmp(method, "DELETE"))
          return api_delete_pool(r, pidx);
      }

      /* /vhosts/:vidx/pools/:pidx/rules[/:ridx] */
      if (nparts >= 5 && parts[4] && !strcmp(parts[4], "rules"))
      {
        apr_uint32_t pidx = (apr_uint32_t)atol(parts[3]);
        if (nparts == 5)
        {
          if (!strcmp(method, "GET"))
            return api_list_rules(r, pidx);
          if (!strcmp(method, "POST"))
            return api_add_rule(r, pidx);
        }
        if (nparts == 6 && parts[5])
        {
          apr_uint32_t ridx = (apr_uint32_t)atol(parts[5]);
          if (!strcmp(method, "DELETE"))
            return api_delete_rule(r, pidx, ridx);
        }
      }
    }
  }

  return HTTP_NOT_FOUND;
}
