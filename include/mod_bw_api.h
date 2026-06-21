/*
 * mod_bw_api.h - REST API handler declarations
 */

#ifndef MOD_BW_API_H
#define MOD_BW_API_H

#include "mod_bw.h"

/* Called from handle_bw when r->handler matches "mod-bw-api" or the
 * request URI starts with the configured api_path. */
int bw_api_handler(request_rec *r);

/* Verify the Authorization: Bearer <token> header.
 * Returns 1 if valid, 0 if missing/wrong (caller should return HTTP_UNAUTHORIZED). */
int bw_api_auth(request_rec *r, const char *expected_token);

#endif /* MOD_BW_API_H */
