#ifndef COMMON_DIGEST_SHIM_H
#define COMMON_DIGEST_SHIM_H
#include <stdint.h>
#include <openssl/sha.h>
#define CC_LONG unsigned int
#define CC_SHA1_DIGEST_LENGTH SHA_DIGEST_LENGTH
#define CC_SHA256_DIGEST_LENGTH SHA256_DIGEST_LENGTH
#define CC_SHA384_DIGEST_LENGTH SHA384_DIGEST_LENGTH
static inline unsigned char *CC_SHA1(const void *d, CC_LONG n, unsigned char *md) { return SHA1(d, n, md); }
static inline unsigned char *CC_SHA256(const void *d, CC_LONG n, unsigned char *md) { return SHA256(d, n, md); }
static inline unsigned char *CC_SHA384(const void *d, CC_LONG n, unsigned char *md) { return SHA384(d, n, md); }
#endif
