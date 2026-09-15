//
//  tweak_log_policy.h
//  W0lfSword
//
//  BUG.6 (2026-09-11 device day) - the disk-write budget.
//
//  The file sink fsyncs the app log because a kernel panic leaves the page cache
//  no chance to flush: the 2026-09-11 SE panic left the on-disk log with the boot
//  banner and none of the exploit lines. The first fix fsynced EVERY line, and
//  the SE then dirtied ~1.07 GB of file-backed memory in 18 minutes - over the
//  1 GB/day disk-write limit iOS reports for the app (W0lfTerm.diskwrites_
//  resource-*.ips) - while buying nothing: what a panic needs is that the tail is
//  at most one window old, not that every line is durable before the next one is
//  appended.
//
//  So the decision is "at most one fsync per window, first line always flushes",
//  and it lives HERE - in a plain C file compiled into the engine archive - for
//  the same reason kexploit/probe_restore_policy.c does: the decision used to sit
//  inside the ObjC-only block of utils/tweak_log.h, where no host test could
//  reach it. tests/tweak_log_throttle_host_test.c now drives THIS file with a
//  simulated clock and counts how many fsyncs a burst of N lines causes; the sink
//  and the test compile the same source, so the counted bound cannot drift from
//  the shipped one.
//
//  What this policy does NOT decide: whether the fsync happens at all (the sink
//  only pays it when a host app is mirroring the log - see tweak_log_hook_
//  installed()) and how many bytes one fsync flushes (that is the file's own
//  dirty pages; this file bounds the CALLS, which is what the pre-fix behaviour
//  made unbounded).
//
#ifndef tweak_log_policy_h
#define tweak_log_policy_h

// One fsync per 200 ms. 200 ms is the forensic window: a panic loses at most the
// last fifth of a second of lines, and the longest thing this app runs (a 600 s
// scan) can issue at most 3001 fsyncs however many lines it logs.
#define TWEAK_LOG_FSYNC_MIN_INTERVAL_MS 200

// One gate per process. utils/tweak_log.m owns the single instance: TweakLog() is
// a static function in a header, so a gate per translation unit would multiply
// the rate limit by the number of files that log - which is how a "rate limited"
// sink still dirties a gigabyte.
typedef struct {
    long long lastNs;              // CLOCK_MONOTONIC ns of the last granted fsync
    unsigned long long granted;    // fsyncs this gate allowed
    unsigned long long suppressed; // lines that landed inside the window
} tweak_log_fsync_gate;

// 1 = the caller should fflush + fsync now (the gate records the grant);
// 0 = the line is inside the window: write it, do NOT fsync.
// A gate in its all-zero state grants, so the FIRST line always reaches the disk
// (that is the line a post-panic read wants most).
// A clock that steps backwards cannot grant: the delta is negative, which is
// inside every window.
int tweak_log_fsync_due(tweak_log_fsync_gate *gate, long long nowNs);

#endif /* tweak_log_policy_h */
