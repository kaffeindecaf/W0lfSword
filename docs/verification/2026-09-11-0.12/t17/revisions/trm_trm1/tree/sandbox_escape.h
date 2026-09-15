#ifndef sandbox_escape_h
#define sandbox_escape_h

#include <stdint.h>
#include <stdbool.h>

// Escape sandbox by rewriting sandbox extension data in kernel memory.
// Walk: proc_ro -> ucred -> cr_label -> sandbox -> ext_set -> ext_table -> ext -> data
// Uses dynamic offset resolution — works on iOS 17.0 through 26.x.
// Returns 0 on success, -1 on failure.
int sandbox_escape(uint64_t self_proc);

// L5.1 (hub app): read back the current proc's kernel-side posix creds
// (uid/gid/groups[0]) after an escape — the same verification
// set_root_credentials performs internally. Returns 0 on success.
int sandbox_escape_read_posix_creds(uint64_t self_proc,
                                    uint32_t *uid, uint32_t *gid, uint32_t *groups0);

#endif
