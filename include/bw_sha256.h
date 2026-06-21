/*
 * bw_sha256.h - tiny self-contained SHA-256 (public domain).
 *
 * Bundled so the module keeps zero crypto link dependencies (no OpenSSL).
 * Used only to hash high-entropy bearer-token secrets before they are
 * stored in SHM / on disk, so a leaked token store does not reveal usable
 * tokens. A single SHA-256 pass is sufficient here because the input is a
 * 256-bit random secret, not a low-entropy password.
 */
#ifndef BW_SHA256_H
#define BW_SHA256_H

#include <stddef.h>

/* Write the lowercase hex SHA-256 of (data,len) into out[65] (64 hex + nul). */
void bw_sha256_hex(const void *data, size_t len, char out[65]);

#endif /* BW_SHA256_H */
