//
//  tweak_log_policy.c
//  W0lfSword
//
//  BUG.6: the disk-write rate gate (see tweak_log_policy.h for why it exists and
//  what it does not decide). Compiled into the engine archive (scripts/build_
//  libengine.sh) and into the tweak (Makefile), exactly like the header the sink
//  calls it from - and compiled by tests/tweak_log_throttle_host_test.c, which
//  counts the grants for simulated bursts.
//
#include "tweak_log_policy.h"

int tweak_log_fsync_due(tweak_log_fsync_gate *gate, long long nowNs)
{
    // No gate to consult: do not silently drop a flush. Nothing in the tree
    // passes NULL; this is the fail-open default so a future caller cannot turn a
    // missing gate into "the log stops being durable".
    if (!gate) {
        return 1;
    }

    // First call (granted == 0 is the "never granted" state, so a gate is usable
    // with no init step): the first line always reaches the disk.
    if (gate->granted == 0) {
        gate->lastNs = nowNs;
        gate->granted = 1;
        return 1;
    }

    long long deltaNs = nowNs - gate->lastNs;
    if (deltaNs < (long long)TWEAK_LOG_FSYNC_MIN_INTERVAL_MS * 1000000LL) {
        // Inside the window - including a negative delta, i.e. a clock that
        // stepped backwards, which must not buy a flush.
        gate->suppressed++;
        return 0;
    }

    gate->lastNs = nowNs;
    gate->granted++;
    return 1;
}
