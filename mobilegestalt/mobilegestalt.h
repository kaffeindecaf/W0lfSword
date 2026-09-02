//
//  mobilegestalt.h
//  W0lfSword - MobileGestalt editing module (Chain F kernel-route impl)
//
//  On-device MobileGestalt cache editor for the non-jailbroken Filza Arctic
//  path (and any path where this process holds root creds after the kernel
//  escape). Replaces com.apple.MobileGestalt.plist CacheExtra entries
//  atomically (temp file + rename in the same directory, ownership + mode
//  preserved) and can respring via backboardd.
//
//  Host drives it by dropping a command JSON into the app's Documents dir:
//    mg-cmd-<token>.json   -> processed by mg_poll_commands() (called from
//                             the tweak's 0.5s HUD timer tick)
//    mg-result-<token>.json -> written when the command ran (same token)
//  Command files are only consumed once the process can actually write the
//  gestalt cache (kernel escape active); before that they are left in place
//  so the host can keep polling.
//
//  Reference ground truth (2026-09): bl_sbx / SparseBoxPlus prove the cache
//  plist at systemgroup.com.apple.mobilegestaltcache/Library/Caches/ is
//  mobile-writable through iOS 26.2b1 and edits stick after a respring — so
//  the same file is trivially writable with root creds on 26.0.1.
//

#ifndef MOBILEGESTALT_H
#define MOBILEGESTALT_H

#include <stddef.h>

// Poll Documents/mg-cmd-*.json once. Returns 1 if a command file was
// consumed (result written), 0 if nothing to do, -1 if a command file
// exists but this process cannot write the gestalt cache yet (left for a
// later tick). Safe to call every timer tick.
int mg_poll_commands(void);

// Direct API (used by tests / future in-app UI). All return 0 on success.
// value JSON shapes: bool/int/string; Data is passed base64 in {"$b64": "..."}.
int mg_apply_command_json(const char *json_cmd, char *result_buf, size_t result_len);

#endif /* MOBILEGESTALT_H */
