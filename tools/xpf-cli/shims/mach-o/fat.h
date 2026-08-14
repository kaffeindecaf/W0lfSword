#ifndef MACH_O_FAT_SHIM_H
#define MACH_O_FAT_SHIM_H
#include <stdint.h>
#define FAT_MAGIC    0xcafebabe
#define FAT_CIGAM    0xbebafeca
#define FAT_MAGIC_64 0xcafebabf
#define FAT_CIGAM_64 0xbfbafeca
struct fat_header { uint32_t magic; uint32_t nfat_arch; };
struct fat_arch { int32_t cputype; int32_t cpusubtype; uint32_t offset; uint32_t size; uint32_t align; };
struct fat_arch_64 { int32_t cputype; int32_t cpusubtype; uint64_t offset; uint64_t size; uint32_t align; uint32_t reserved; };
#endif
