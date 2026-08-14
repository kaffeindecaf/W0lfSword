#ifndef MACH_O_NLIST_SHIM_H
#define MACH_O_NLIST_SHIM_H
#include <stdint.h>
struct nlist { union { uint32_t n_strx; } n_un; uint8_t n_type; uint8_t n_sect; int16_t n_desc; uint32_t n_value; };
#define N_STAB 0xe0
#define N_TYPE 0x1e
#define N_SECT 0x0e
#define N_EXT  0x01
#endif
