#ifndef COMPRESSION_SHIM_H
#define COMPRESSION_SHIM_H
#include <stddef.h>
#include <stdint.h>
#include <lzfse.h>
#define COMPRESSION_LZFSE 0x801
static inline size_t compression_decode_buffer(uint8_t *dst, size_t dst_size,
                                               const uint8_t *src, size_t src_size,
                                               void *scratch_buffer, int algorithm) {
    (void)scratch_buffer; (void)algorithm;
    return lzfse_decode_buffer(dst, dst_size, src, src_size, NULL);
}
#endif
