/*
 * mod_bw_tokens.c - API token secrets, hashing, and JSON-Lines persistence.
 *
 * The store file holds one JSON object per line, one per active token:
 *
 *   {"id":2,"label":"ci","scope":"ro","hash":"<64hex>","vhosts":["a.com"],
 *    "pools":[1,2],"created":1700000000}
 *
 * One-object-per-line keeps loading simple (parse each line independently)
 * and makes the file easy to inspect. Labels are constrained at the API to a
 * quote/backslash/control-free charset, so neither writing nor the lenient
 * key scanner below needs JSON escaping.
 */
#include "mod_bw_tokens.h"
#include "mod_bw_shm.h"
#include "bw_sha256.h"
#include <apr_general.h> /* apr_generate_random_bytes */
#include <apr_strings.h>
#include <apr_file_io.h>
#include <apr_lib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* Secret generation + hashing                                         */
/* ------------------------------------------------------------------ */
void bw_token_gen_secret(char *out, apr_size_t out_sz)
{
  static const char b32[] = "abcdefghijklmnopqrstuvwxyz234567";
  unsigned char raw[30];
  char body[48];
  int i;

  if (out_sz < 53)
  {
    if (out_sz)
      out[0] = '\0';
    return;
  }

  if (apr_generate_random_bytes(raw, sizeof(raw)) != APR_SUCCESS)
  {
    /* Extremely unlikely; degrade rather than emit a predictable token */
    out[0] = '\0';
    return;
  }
  /* 30 bytes = 240 bits = 48 base32 chars (5 bits each), no padding */
  for (i = 0; i < 48; i++)
  {
    int bit = i * 5;
    int byte = bit / 8, off = bit % 8;
    int v = (raw[byte] << 8) | (byte + 1 < (int)sizeof(raw) ? raw[byte + 1] : 0);
    v = (v >> (11 - off)) & 0x1f;
    body[i] = b32[v];
  }
  memcpy(out, "bwk_", 4);
  memcpy(out + 4, body, 48);
  out[52] = '\0';
}

void bw_token_hash(const char *secret, char hash[BW_TOKEN_HASH_LEN])
{
  bw_sha256_hex(secret, secret ? strlen(secret) : 0, hash);
}

/* ------------------------------------------------------------------ */
/* Store path resolution                                               */
/* ------------------------------------------------------------------ */
const char *bw_token_store_path(apr_pool_t *p,
                                bandwidth_server_config *msc,
                                const char *shm_file)
{
  if (msc && msc->token_store && *msc->token_store)
    return apr_pstrdup(p, msc->token_store);

  /* Derive "<dir of shm_file>/mod_bw_tokens.json" */
  const char *slash = shm_file ? strrchr(shm_file, '/') : NULL;
  if (slash)
  {
    apr_size_t dlen = (apr_size_t)(slash - shm_file);
    char *dir = apr_pstrmemdup(p, shm_file, dlen);
    return apr_pstrcat(p, dir, "/mod_bw_tokens.json", NULL);
  }
  return apr_pstrdup(p, "mod_bw_tokens.json");
}

/* ------------------------------------------------------------------ */
/* Save                                                                */
/* ------------------------------------------------------------------ */
static void emit_token_line(apr_file_t *f, const bw_token_slot_t *t)
{
  apr_uint32_t k;
  apr_file_printf(f, "{\"id\":%u,\"label\":\"%s\",\"scope\":\"%s\",\"hash\":\"%s\"",
                  t->id, t->label,
                  t->scope == BW_TOKEN_SCOPE_RO ? "ro" : "admin",
                  t->hash);

  apr_file_puts(",\"vhosts\":[", f);
  for (k = 0; k < t->n_vhosts && k < BW_TOKEN_MAX_VHOSTS; k++)
    apr_file_printf(f, "%s\"%s\"", k ? "," : "", t->vhosts[k]);
  apr_file_puts("]", f);

  apr_file_puts(",\"pools\":[", f);
  for (k = 0; k < t->n_pools && k < BW_TOKEN_MAX_POOLS; k++)
    apr_file_printf(f, "%s%u", k ? "," : "", t->pools[k]);
  apr_file_puts("]", f);

  apr_file_printf(f, ",\"created\":%" APR_INT64_T_FMT "}\n",
                  apr_time_sec(t->created));
}

apr_status_t bw_tokens_save(apr_pool_t *p)
{
  const char *path = bw_g.token_store;
  if (!path)
    return APR_SUCCESS;
  if (!bw_g.tokens)
    return APR_SUCCESS;

  char *tmp = apr_pstrcat(p, path, ".tmp", NULL);
  apr_file_t *f = NULL;
  apr_status_t rv = apr_file_open(&f, tmp,
                                  APR_FOPEN_WRITE | APR_FOPEN_CREATE | APR_FOPEN_TRUNCATE,
                                  APR_FPROT_UREAD | APR_FPROT_UWRITE, p);
  if (rv != APR_SUCCESS)
    return rv;

  apr_uint32_t i;
  for (i = 0; i < bw_g.hdr->max_tokens; i++)
  {
    if (apr_atomic_read32(&bw_g.tokens[i].flags) != BW_SLOT_ACTIVE)
      continue;
    emit_token_line(f, &bw_g.tokens[i]);
  }
  apr_file_flush(f);
  apr_file_close(f);

  /* Atomic replace */
  rv = apr_file_rename(tmp, path, p);
  if (rv != APR_SUCCESS)
  {
    apr_file_remove(tmp, p);
    return rv;
  }
  /* Best-effort: ensure final file is 0600 too */
  apr_file_perms_set(path, APR_FPROT_UREAD | APR_FPROT_UWRITE);
  return APR_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* Minimal per-line JSON value extraction (controlled format)          */
/* ------------------------------------------------------------------ */
static const char *find_val(const char *line, const char *key)
{
  char pat[40];
  apr_snprintf(pat, sizeof(pat), "\"%s\":", key);
  const char *p = strstr(line, pat);
  if (!p)
    return NULL;
  p += strlen(pat);
  while (*p == ' ')
    p++;
  return p;
}

static int get_str(const char *line, const char *key, char *out, apr_size_t sz)
{
  const char *p = find_val(line, key);
  apr_size_t n = 0;
  if (!p || *p != '"')
    return 0;
  p++;
  while (*p && *p != '"' && n + 1 < sz)
    out[n++] = *p++;
  out[n] = '\0';
  return 1;
}

static int get_uint(const char *line, const char *key, apr_uint32_t *out)
{
  const char *p = find_val(line, key);
  if (!p || !apr_isdigit(*p))
    return 0;
  *out = (apr_uint32_t)apr_atoi64(p);
  return 1;
}

/* Parse ["a","b",...] of strings into a fixed 2D buffer. */
static apr_uint32_t get_str_array(const char *line, const char *key,
                                  char arr[][BW_VHOST_NAME_LEN],
                                  apr_uint32_t maxn)
{
  const char *p = find_val(line, key);
  apr_uint32_t n = 0;
  if (!p || *p != '[')
    return 0;
  p++;
  while (*p && *p != ']' && n < maxn)
  {
    while (*p == ' ' || *p == ',')
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

/* Parse [1,2,3] of unsigned ints. */
static apr_uint32_t get_uint_array(const char *line, const char *key,
                                   apr_uint32_t *arr, apr_uint32_t maxn)
{
  const char *p = find_val(line, key);
  apr_uint32_t n = 0;
  if (!p || *p != '[')
    return 0;
  p++;
  while (*p && *p != ']' && n < maxn)
  {
    while (*p == ' ' || *p == ',')
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
/* Load                                                                */
/* ------------------------------------------------------------------ */
apr_status_t bw_tokens_load(apr_pool_t *p, server_rec *s)
{
  const char *path = bw_g.token_store;
  if (!path || !bw_g.tokens)
    return APR_SUCCESS;

  apr_file_t *f = NULL;
  apr_status_t rv = apr_file_open(&f, path, APR_FOPEN_READ, 0, p);
  if (rv != APR_SUCCESS)
    return APR_SUCCESS; /* no store yet - fine */

  char line[4096];
  apr_uint32_t loaded = 0;

  BW_SEQ_WRITE_BEGIN();
  while (apr_file_gets(line, sizeof(line), f) == APR_SUCCESS)
  {
    char hash[BW_TOKEN_HASH_LEN];
    char label[BW_TOKEN_LABEL_LEN];
    char scope[16];
    apr_uint32_t id = 0;

    if (!get_str(line, "hash", hash, sizeof(hash)))
      continue; /* not a token */
    if (!*hash)
      continue;
    if (!get_str(line, "label", label, sizeof(label)))
      label[0] = '\0';
    if (!get_str(line, "scope", scope, sizeof(scope)))
      scope[0] = '\0';
    get_uint(line, "id", &id);

    /* Fail closed: only an explicit "admin" grants admin; anything missing
         * or unrecognized (e.g. a truncated store line) defaults to read-only. */
    apr_uint32_t sc = !strcmp(scope, "admin") ? BW_TOKEN_SCOPE_ADMIN
                                              : BW_TOKEN_SCOPE_RO;
    apr_uint32_t idx = bw_token_alloc(label, sc, hash, id);
    if (idx == BW_IDX_NONE)
      break; /* store full */

    bw_token_slot_t *t = &bw_g.tokens[idx];
    t->n_vhosts = get_str_array(line, "vhosts", t->vhosts, BW_TOKEN_MAX_VHOSTS);
    t->n_pools = get_uint_array(line, "pools", t->pools, BW_TOKEN_MAX_POOLS);
    /* Preserve the original creation time rather than re-stamping now. */
    apr_uint32_t created_sec = 0;
    if (get_uint(line, "created", &created_sec) && created_sec)
      t->created = apr_time_from_sec(created_sec);
    loaded++;
  }
  BW_SEQ_WRITE_END();
  apr_file_close(f);

  if (loaded)
    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s,
                 "mod_bw: loaded %u API token(s) from %s", loaded, path);
  return APR_SUCCESS;
}
