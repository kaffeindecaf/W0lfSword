#ifndef OSBYTEORDER_SHIM_H
#define OSBYTEORDER_SHIM_H
#include <stdint.h>
#include <byteswap.h>
#define OSSwapInt16(x) __bswap_16(x)
#define OSSwapInt32(x) __bswap_32(x)
#define OSSwapInt64(x) __bswap_64(x)
#define OSSwapLittleToHostInt16(x) (x)
#define OSSwapLittleToHostInt32(x) (x)
#define OSSwapHostToLittleInt32(x) (x)
#define OSSwapLittleToHostInt64(x) (x)
#define OSSwapHostToLittleInt64(x) (x)
#define OSSwapBigToHostInt32(x) __bswap_32(x)
#define OSSwapHostToBigInt32(x) __bswap_32(x)
#define OSSwapBigToHostInt64(x) __bswap_64(x)
#define OSSwapHostToBigInt64(x) __bswap_64(x)
#endif
#define OSSwapHostToLittleInt16(x) (x)
#define OSSwapLittleToHostInt16(x) (x)
#define OSSwapBigToHostInt16(x) __bswap_16(x)
#define OSSwapHostToBigInt16(x) __bswap_16(x)
