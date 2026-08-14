#ifndef XPC_SHIM_H
#define XPC_SHIM_H
#include <stdint.h>
typedef void *xpc_object_t;
xpc_object_t xpc_dictionary_create_empty(void);
void xpc_dictionary_set_uint64(xpc_object_t d, const char *k, uint64_t v);
void xpc_release(xpc_object_t o);
#endif
