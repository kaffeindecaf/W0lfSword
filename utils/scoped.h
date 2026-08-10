//
//  scoped.h — W0lfSword scoped resource cleanup helpers
//
//  Provides __attribute__((cleanup)) helpers for automatic resource cleanup:
//    scoped_fd     — auto-close file descriptors
//    scoped_port   — auto-deallocate mach ports
//    scoped_free   — auto-free heap allocations
//
//  Usage:
//    scoped_fd int fd = open("/path", O_RDONLY);
//    // fd is automatically close()'d when it goes out of scope
//
//    scoped_port mach_port_t port = MACH_PORT_NULL;
//    // port is automatically mach_port_deallocate()'d on scope exit

#ifndef W0LFSWORD_SCOPED_H
#define W0LFSWORD_SCOPED_H

#include <unistd.h>
#include <mach/mach.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

// ── scoped_fd ────────────────────────────────────────────────
static inline void _scoped_fd_cleanup(int *fd) {
    if (fd && *fd >= 0) { close(*fd); *fd = -1; }
}
#define scoped_fd __attribute__((cleanup(_scoped_fd_cleanup))) int

// ── scoped_port ──────────────────────────────────────────────
static inline void _scoped_port_cleanup(mach_port_t *port) {
    if (port && *port != MACH_PORT_NULL) {
        mach_port_deallocate(mach_task_self(), *port);
        *port = MACH_PORT_NULL;
    }
}
#define scoped_port __attribute__((cleanup(_scoped_port_cleanup))) mach_port_t

// ── scoped_free ──────────────────────────────────────────────
static inline void _scoped_free_cleanup(void **ptr) {
    if (ptr && *ptr) { free(*ptr); *ptr = NULL; }
}
#define scoped_free __attribute__((cleanup(_scoped_free_cleanup))) void *

#ifdef __cplusplus
}
#endif

#endif /* W0LFSWORD_SCOPED_H */
