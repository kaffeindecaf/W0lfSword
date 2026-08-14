#ifndef SYS_SYSLIMITS_SHIM_H
#define SYS_SYSLIMITS_SHIM_H
#include <limits.h>
#define PATH_MAX 4096
#define NAME_MAX 255
#endif
#define PAGE_SHIFT 14
#define PAGE_SIZE (1<<PAGE_SHIFT)
#define PAGE_MASK (PAGE_SIZE-1)
