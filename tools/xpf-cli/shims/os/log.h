#ifndef OS_LOG_SHIM_H
#define OS_LOG_SHIM_H
#include <stdio.h>
typedef struct { void *dummy; } os_log_t;
static inline os_log_t os_log_create(const char *a, const char *b) { (void)a; (void)b; os_log_t l = {0}; return l; }
#define os_log(l, ...) ((void)0)
#define os_log_error(l, ...) ((void)0)
#define os_log_debug(l, ...) ((void)0)
#define os_log_info(l, ...) ((void)0)
#define OS_LOG_DEFAULT ((os_log_t){0})
#define OS_LOG_TYPE_ERROR 0
#define os_trace(...) ((void)0)
#endif
