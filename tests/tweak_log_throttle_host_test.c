//
//  tweak_log_throttle_host_test.c
//  W0lfSword - host test for BUG.6 (the disk-write budget).
//
//  Compiles the REAL utils/tweak_log_policy.c - the file the engine archive and
//  the tweak build ship - and drives it with a simulated clock, so the number of
//  fsyncs a burst of log lines causes is COUNTED here instead of asserted in a
//  comment.
//
//  What is being verified:
//
//    * the first line always reaches the disk (a panic-forensics read wants the
//      banner most), and then at most one fsync per 200 ms window whatever the
//      line rate - the advertised bound is the WINDOW, not the rate;
//    * the counter arithmetic adds up: granted + suppressed == lines offered;
//    * exactly at the window edge a line flushes, one millisecond inside it does
//      not (the boundary is inclusive, so the bound is not "1 + one more");
//    * a clock that steps backwards buys nothing (a negative delta is inside the
//      window), and the gate recovers once it passes the window again;
//    * two gates are independent - which is WHY the sink holds exactly one for
//      the process (utils/tweak_log.m): a gate per translation unit would
//      multiply this rate limit by the number of files that log, and the 1 GB/day
//      disk-write budget is per app;
//    * a NULL gate fails open (a missing gate must not silently stop durability);
//    * the pre-fix behaviour - one fsync per line - violates the bound this test
//      asserts, so the check is not vacuous.
//
//  Run: bash scripts/run_tweak_log_throttle_host_test.sh
//
#include <stdio.h>
#include <stdbool.h>

#include "utils/tweak_log_policy.h"

static int g_checks = 0;
static int g_failures = 0;

static void check(bool ok, const char *what)
{
    g_checks++;
    if (ok) {
        printf("  ok   %s\n", what);
    } else {
        g_failures++;
        printf("  FAIL %s\n", what);
    }
}

#define MS 1000000LL   // ns per millisecond

// ---------------------------------------------------------------------------
// a burst of `lines` lines arriving every `stepNs` nanoseconds
// ---------------------------------------------------------------------------
typedef struct {
    unsigned long long granted;
    unsigned long long suppressed;
    unsigned long long lines;
} burst_result;

static burst_result run_burst(tweak_log_fsync_gate *gate, long long startNs,
                              long long stepNs, unsigned long long lines)
{
    burst_result r = { 0, 0, 0 };
    for (unsigned long long i = 0; i < lines; i++) {
        long long nowNs = startNs + (long long)i * stepNs;
        if (tweak_log_fsync_due(gate, nowNs)) {
            r.granted++;
        } else {
            r.suppressed++;
        }
        r.lines++;
    }
    return r;
}

// The one-fsync-per-line policy this bug was about (what the sink did before
// the rate gate): every line flushes. Counted the same way, for the comparison.
static unsigned long long run_burst_unthrottled(unsigned long long lines)
{
    unsigned long long granted = 0;
    for (unsigned long long i = 0; i < lines; i++) {
        granted++;   // no gate: the sink fsyncs this line
    }
    return granted;
}

// ---------------------------------------------------------------------------
// 1. the first line, and the shape of the gate
// ---------------------------------------------------------------------------
static void case_first_line_and_state(void)
{
    tweak_log_fsync_gate gate = { 0, 0, 0 };

    check(tweak_log_fsync_due(&gate, 0) == 1, "first line: granted (the banner reaches the disk even at t=0)");
    check(gate.granted == 1, "first line: the gate recorded the grant");
    check(gate.suppressed == 0, "first line: nothing suppressed yet");

    check(tweak_log_fsync_due(&gate, 0) == 0, "same timestamp again: suppressed (no free second flush)");
    check(gate.suppressed == 1, "same timestamp again: counted as suppressed");
}

// ---------------------------------------------------------------------------
// 2. the window edge: inclusive at 200 ms, not one ms earlier
// ---------------------------------------------------------------------------
static void case_window_edge(void)
{
    tweak_log_fsync_gate gate = { 0, 0, 0 };

    tweak_log_fsync_due(&gate, 0);

    check(tweak_log_fsync_due(&gate, 199 * MS) == 0, "199 ms after the last grant: suppressed");
    check(tweak_log_fsync_due(&gate, 200 * MS) == 1, "exactly 200 ms after the last grant: granted (the edge is inclusive)");
    check(tweak_log_fsync_due(&gate, 399 * MS) == 0, "199 ms after THAT grant: suppressed again (the window restarts at each grant)");
    check(tweak_log_fsync_due(&gate, 400 * MS) == 1, "one full window after the last grant: granted");
    check(gate.granted == 3, "edge case: exactly 3 grants over 400 ms");
}

// ---------------------------------------------------------------------------
// 3. the advertised bound: grants depend on the WINDOW, not on the line rate
// ---------------------------------------------------------------------------
static void case_burst_bound(void)
{
    // 10,000 lines 1 ms apart = 9.999 s of logging.
    tweak_log_fsync_gate gate = { 0, 0, 0 };
    burst_result r = run_burst(&gate, 0, 1 * MS, 10000);

    const unsigned long long expected = 9999 / TWEAK_LOG_FSYNC_MIN_INTERVAL_MS + 1;   // 50
    check(r.granted == expected, "10k lines 1 ms apart: grants == duration/window + 1 (the bound is the window)");
    check(r.suppressed == 10000 - expected, "10k lines 1 ms apart: every other line was suppressed, none dropped");
    check(r.granted + r.suppressed == r.lines, "10k lines 1 ms apart: granted + suppressed == lines offered");
    check(r.granted <= 10000ULL / TWEAK_LOG_FSYNC_MIN_INTERVAL_MS + 1,
          "10k lines 1 ms apart: the grant count honours the bound");

    // The same duration at several line rates: 510 ms is 510 ms.
    const unsigned long long rates[] = { 1, 10, 100, 450, 5000 };   // lines/s
    unsigned long long lastGranted = 0;
    bool band_ok = true;
    bool any_band_checked = false;
    printf("       counter report - a 510 ms window at increasing line rates:\n");
    for (unsigned i = 0; i < sizeof(rates) / sizeof(rates[0]); i++) {
        unsigned long long lines = rates[i] * 510 / 1000;      // lines in 510 ms
        if (lines == 0) lines = 1;
        long long stepNs = 1000000000LL / (long long)rates[i];  // ns between lines
        tweak_log_fsync_gate g = { 0, 0, 0 };
        burst_result b = run_burst(&g, 0, stepNs, lines);
        printf("         %5llu line/s  %7llu line(s)  %6llu fsync(s)  (%llu suppressed)\n",
               rates[i], b.lines, b.granted, b.suppressed);
        if (i == 2) lastGranted = b.granted;
        if (b.lines > 1) {
            any_band_checked = true;
            // 510/200 + 1 == 3; allow 2..4 for the sampling offset of each rate.
            if (b.granted < 2 || b.granted > 4) band_ok = false;
        }
    }
    check(any_band_checked && band_ok, "the line rate does not change the grant band (2..4 over 510 ms)");
    check(lastGranted == 3, "100 line/s over 510 ms: 3 grants - the counter report above");

    // The longest run this tree can make: the 600 s scan budget.
    tweak_log_fsync_gate g = { 0, 0, 0 };
    burst_result b = run_burst(&g, 0, 1 * MS, 600000);   // 600 s of lines
    check(b.granted == (600000ULL - 1) / TWEAK_LOG_FSYNC_MIN_INTERVAL_MS + 1,
          "600 s run: exactly 3000 grants (one per 200 ms window, first line inclusive)");
    check(b.granted <= 600000ULL / TWEAK_LOG_FSYNC_MIN_INTERVAL_MS + 1,
          "600 s run: within the advertised bound of 3001 fsyncs, however many lines the scan logs");
    check(b.granted + b.suppressed == b.lines, "600 s run: no line is unaccounted for");
}

// ---------------------------------------------------------------------------
// 4. a clock that steps backwards
// ---------------------------------------------------------------------------
static void case_clock_step_back(void)
{
    tweak_log_fsync_gate gate = { 0, 0, 0 };

    tweak_log_fsync_due(&gate, 1000 * MS);          // granted
    check(tweak_log_fsync_due(&gate, 500 * MS) == 0, "clock stepped back 500 ms: suppressed (a backwards step buys no flush)");
    check(tweak_log_fsync_due(&gate, 1199 * MS) == 0, "199 ms after the grant, still suppressed");
    check(tweak_log_fsync_due(&gate, 1200 * MS) == 1, "the window after the grant: granted again (the gate did not wedge)");
    check(gate.granted == 2, "clock step: exactly 2 grants");
}

// ---------------------------------------------------------------------------
// 5. why the sink holds ONE gate: two gates do not share a window
// ---------------------------------------------------------------------------
static void case_two_gates_are_independent(void)
{
    tweak_log_fsync_gate a = { 0, 0, 0 };
    tweak_log_fsync_gate b = { 0, 0, 0 };

    int ga = tweak_log_fsync_due(&a, 0);
    int gb = tweak_log_fsync_due(&b, 0);

    check(ga == 1 && gb == 1, "two gates at the same instant: BOTH grant");
    check(a.granted + b.granted == 2,
          "two gates at the same instant: 2 fsyncs - which is why tweak_log.m owns the single process-wide gate");
}

// ---------------------------------------------------------------------------
// 6. a missing gate fails open
// ---------------------------------------------------------------------------
static void case_null_gate(void)
{
    check(tweak_log_fsync_due(NULL, 0) == 1, "no gate: granted (a missing gate must not silently stop flushing)");
}

// ---------------------------------------------------------------------------
// 7. the check is not vacuous: one fsync per line violates the bound
// ---------------------------------------------------------------------------
static void case_prefix_policy_violates_the_bound(void)
{
    const unsigned long long lines = 10000;
    unsigned long long ungated = run_burst_unthrottled(lines);

    tweak_log_fsync_gate gate = { 0, 0, 0 };
    burst_result gated = run_burst(&gate, 0, 1 * MS, lines);

    check(ungated == lines, "pre-fix policy: one fsync per line (10000 of 10000)");
    check(ungated > gated.granted,
          "pre-fix policy violates the bound the gate asserts (the check is not vacuous)");
    printf("       counter report - 10k lines 1 ms apart: gated %llu fsync(s) vs one-per-line %llu (%llux fewer)\n",
           gated.granted, ungated, ungated / (gated.granted ? gated.granted : 1));
}

// ---------------------------------------------------------------------------
// 8. the constant the sink and this test share
// ---------------------------------------------------------------------------
static void case_interval_constant(void)
{
    check(TWEAK_LOG_FSYNC_MIN_INTERVAL_MS == 200,
          "the shared interval is 200 ms (the forensic window the sink's comment states)");
    check(TWEAK_LOG_FSYNC_MIN_INTERVAL_MS > 0, "the interval is not zero (which would grant every line)");
}

int main(void)
{
    printf("tweak_log_throttle host test (BUG.6: the disk-write budget, counted)\n\n");

    printf("the gate's first line and its counters:\n");
    case_first_line_and_state();

    printf("\nthe 200 ms window edge:\n");
    case_window_edge();

    printf("\nbursts of log lines:\n");
    case_burst_bound();

    printf("\na clock that steps backwards:\n");
    case_clock_step_back();

    printf("\nwhy one gate, not one per translation unit:\n");
    case_two_gates_are_independent();

    printf("\na missing gate:\n");
    case_null_gate();

    printf("\nis this check vacuous?\n");
    case_prefix_policy_violates_the_bound();

    printf("\nthe shared constant:\n");
    case_interval_constant();

    printf("\nchecks=%d failures=%d\n", g_checks, g_failures);
    if (g_failures == 0) {
        printf("TWEAK_LOG_THROTTLE_HOST_TEST PASS\n");
        return 0;
    }
    printf("TWEAK_LOG_THROTTLE_HOST_TEST FAIL\n");
    return 1;
}
