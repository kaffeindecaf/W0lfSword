//
//  sbtweak.h
//  W0lfSword - SpringBoard live tweaks via the in-tree TaskRop RemoteCall
//
//  Drives the repo's dormant kexploit/RemoteCall.m (ported from
//  darksword-kexploit-fun, same lineage as the rest of kexploit/) to make
//  remote Objective-C calls into the running SpringBoard, then applies live
//  tweaks such as the 5-icon dock / dock column count.
//
//  Why this exists (2026-09-02): lara (referenceforAI/Projects/lara, AGPL -
//  NOT copied) demonstrated the feature set this unlocks on iOS 17-18.7.1 +
//  26.0-26.0.1, incl. the 5-icon dock previously rated not possible on
//  26.0.1 from our side (gestalt plist edits do not control the dock; the
//  dock's column count is a live SpringBoard object property). The remote
//  call machinery was already in our tree but nothing drove it. This module
//  is a fresh implementation over Apple's public runtime API surface
//  (selector names) + our own RemoteCall API - no lara code is copied.
//
//  Host protocol (mirrors mobilegestalt's): Documents/sb-cmd-<token>.json
//  -> Documents/sb-result-<token>.json. Commands are only consumed once the
//  kernel escape is live (RemoteCall needs krw).
//

#ifndef SBTWEAK_H
#define SBTWEAK_H

#include <stddef.h>

// Poll Documents/sb-cmd-*.json once. Returns 1 if a command was consumed,
// 0 if nothing to do, -1 if commands exist but the escape is not live yet.
// Heavy work (RemoteCall init + calls) runs on a private background queue.
int sbt_poll_commands(void);

// Direct API for tests: json ops are "status", "dock" (columns), "reset".
int sbt_run_command_json(const char *json_cmd, char *result_buf, size_t result_len);

#endif /* SBTWEAK_H */
