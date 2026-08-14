#ifndef SYS_SYSCTL_SHIM_H
#define SYS_SYSCTL_SHIM_H
#include <stddef.h>
#include <stdint.h>
static inline int sysctlbyname(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    (void)name; (void)oldp; (void)oldlenp; (void)newp; (void)newlen;
    return -1;
}
#endif
