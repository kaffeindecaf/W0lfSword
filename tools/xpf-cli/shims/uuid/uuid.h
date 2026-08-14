#ifndef UUID_SHIM_H
#define UUID_SHIM_H
#include <stdint.h>
#define UUID_STR_LEN 37
typedef uint8_t uuid_t[16];
static const uuid_t UUID_NULL = {0};
#endif
