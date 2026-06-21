/*
 * mod_bw_tokens.h - API token secret generation, hashing, and on-disk
 *                   persistence (JSON Lines) for the token store.
 */
#ifndef MOD_BW_TOKENS_H
#define MOD_BW_TOKENS_H

#include "mod_bw.h"
#include "mod_bw_config.h"

/* Generate a fresh random bearer-token secret ("bwk_" + 48 base32 chars).
 * Writes a nul-terminated string into out; out_sz must be >= 53. */
void bw_token_gen_secret(char *out, apr_size_t out_sz);

/* Hash a secret to lowercase hex SHA-256 in hash[BW_TOKEN_HASH_LEN]. */
void bw_token_hash(const char *secret, char hash[BW_TOKEN_HASH_LEN]);

/* Resolve the token store path: msc->token_store if set, else
 * "<dir of shm_file>/mod_bw_tokens.json". Returns a pool-allocated string. */
const char *bw_token_store_path(apr_pool_t *p,
                                bandwidth_server_config *msc,
                                const char *shm_file);

/* Persist all active token slots to bw_g.token_store atomically (0600).
 * No-op (APR_SUCCESS) if the path is NULL. Caller need not hold the mutex
 * but typically does (called right after a mutation). */
apr_status_t bw_tokens_save(apr_pool_t *p);

/* Load tokens from disk into SHM. Intended for post_config when the SHM was
 * freshly created. A missing file is not an error. */
apr_status_t bw_tokens_load(apr_pool_t *p, server_rec *s);

#endif /* MOD_BW_TOKENS_H */
