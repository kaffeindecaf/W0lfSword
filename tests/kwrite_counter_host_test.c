//
//  kwrite_counter_host_test.c
//  W0lfSword - host test for BUG.5 (the "zero writes" claim).
//
//  Compiles the REAL kexploit/kwrite_counter.c - the file the engine links - and
//  drives it the way the write primitives do. What is being verified:
//
//    * an accepted 32-byte write counts once, for the route that asked for it,
//      for exactly its length (the engine's only writer is 32 bytes wide, but
//      the byte counter is a real sum, not writes*32);
//    * a REFUSED write (setsockopt != 0) is counted as a refusal and never as a
//      write - the claim under audit is about writes that landed;
//    * the attribution stack is per-thread, so the scan thread and the pe_init
//      free thread cannot be counted as each other (the counters themselves are
//      atomics and must survive two threads emitting at once);
//    * reset zeroes everything, so "this attempt" means this attempt.
//
//  Run: bash scripts/run_kwrite_counter_host_test.sh
//
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <pthread.h>

#include "kexploit/kwrite_counter.h"

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

// ---------------------------------------------------------------------------
// 1. fresh state
// ---------------------------------------------------------------------------
static void case_fresh_state(void)
{
    kwrite_count_reset();

    check(kwrite_count_total() == 0, "reset: accepted write total is 0");
    check(kwrite_count_bytes() == 0, "reset: byte total is 0");
    check(kwrite_count_failed_total() == 0, "reset: refusal total is 0");
    check(kwrite_count_failed_bytes() == 0, "reset: refused-byte total is 0");
    for (int i = 0; i < KWRITE_SRC_COUNT; i++) {
        check(kwrite_count_for((kwrite_src_t)i) == 0, "reset: per-route write count is 0");
        check(kwrite_count_failed_for((kwrite_src_t)i) == 0, "reset: per-route refusal count is 0");
    }
}

// ---------------------------------------------------------------------------
// 2. what one accepted write does - the engine's 32-byte emit
// ---------------------------------------------------------------------------
static void case_emit_counts_and_attributes(void)
{
    kwrite_count_reset();

    kwrite_count_emit(KWRITE_SRC_KRW64, 32);

    check(kwrite_count_total() == 1, "one emit: total is 1");
    check(kwrite_count_bytes() == 32, "one emit: bytes is 32");
    check(kwrite_count_for(KWRITE_SRC_KRW64) == 1, "one emit: attributed to early_kwrite64");
    check(kwrite_count_for(KWRITE_SRC_KRW32) == 0, "one emit: the other routes stay 0");
    check(kwrite_count_for(KWRITE_SRC_ZONE) == 0, "one emit: the clamped writer stays 0");

    kwrite_count_emit(KWRITE_SRC_KRW32, 32);
    kwrite_count_emit(KWRITE_SRC_ZONE, 32);

    check(kwrite_count_total() == 3, "three emits: total is 3");
    check(kwrite_count_bytes() == 96, "three emits: bytes is 96");
    check(kwrite_count_for(KWRITE_SRC_KRW32) == 1, "per-route: the direct 32-byte write is counted");
    check(kwrite_count_for(KWRITE_SRC_ZONE) == 1, "per-route: the clamped block writer is counted");
    check(kwrite_count_for(KWRITE_SRC_KRW64) == 1, "per-route: early_kwrite64 is counted once");
}

// ---------------------------------------------------------------------------
// 3. the byte total is a sum, not writes * 32
// ---------------------------------------------------------------------------
static void case_bytes_are_a_sum(void)
{
    kwrite_count_reset();

    kwrite_count_emit(KWRITE_SRC_KRW32, 32);
    kwrite_count_emit(KWRITE_SRC_KRW32, 8);
    kwrite_count_emit(KWRITE_SRC_KRW32, 0);

    check(kwrite_count_total() == 3, "sum: three accepted writes");
    check(kwrite_count_bytes() == 40, "sum: 32 + 8 + 0 bytes");
}

// ---------------------------------------------------------------------------
// 4. a refused write is a refusal, not a write
// ---------------------------------------------------------------------------
static void case_refusal_is_not_a_write(void)
{
    kwrite_count_reset();

    kwrite_count_emit(KWRITE_SRC_ZONE, 32);
    kwrite_count_failed(KWRITE_SRC_ZONE, 32);
    kwrite_count_failed(KWRITE_SRC_KRW64, 32);

    check(kwrite_count_total() == 1, "refusal: total still counts only the accepted write");
    check(kwrite_count_bytes() == 32, "refusal: byte total excludes the refused bytes");
    check(kwrite_count_failed_total() == 2, "refusal: both refusals counted");
    check(kwrite_count_failed_bytes() == 64, "refusal: refused bytes counted separately");
    check(kwrite_count_failed_for(KWRITE_SRC_ZONE) == 1, "refusal: attributed to the clamped writer");
    check(kwrite_count_for(KWRITE_SRC_ZONE) == 1, "refusal: does not inflate the accepted count");
}

// ---------------------------------------------------------------------------
// 5. the attribution stack
// ---------------------------------------------------------------------------
static void case_source_stack(void)
{
    kwrite_count_reset();

    check(kwrite_src_current() == KWRITE_SRC_KRW32, "stack: default route is the direct 32-byte write");

    kwrite_src_t prev = kwrite_src_push(KWRITE_SRC_KRW64);
    check(prev == KWRITE_SRC_KRW32, "stack: push returns the previous route");
    check(kwrite_src_current() == KWRITE_SRC_KRW64, "stack: current is early_kwrite64");

    kwrite_src_t prev2 = kwrite_src_push(KWRITE_SRC_ZONE);
    check(prev2 == KWRITE_SRC_KRW64, "stack: nested push returns the inner route");
    check(kwrite_src_current() == KWRITE_SRC_ZONE, "stack: current is the clamped writer");

    kwrite_src_pop(prev2);
    check(kwrite_src_current() == KWRITE_SRC_KRW64, "stack: pop restores the outer route");

    kwrite_src_pop(prev);
    check(kwrite_src_current() == KWRITE_SRC_KRW32, "stack: pop restores the default");

    // The engine counts with kwrite_src_current(): an emit inside a pushed
    // region must land in THAT route's bucket.
    kwrite_count_reset();
    kwrite_src_t p = kwrite_src_push(KWRITE_SRC_KRW64);
    kwrite_count_emit(kwrite_src_current(), 32);
    kwrite_src_pop(p);

    check(kwrite_count_for(KWRITE_SRC_KRW64) == 1, "stack: emit inside push is attributed to that route");
    check(kwrite_count_for(KWRITE_SRC_KRW32) == 0, "stack: the default route keeps its own count");

    // A bad value must not corrupt the stack or the buckets.
    kwrite_count_reset();
    kwrite_src_t bogusPrev = kwrite_src_push((kwrite_src_t)99);
    check(kwrite_src_current() == KWRITE_SRC_KRW32, "stack: an out-of-range push is ignored");
    kwrite_count_emit((kwrite_src_t)99, 32);
    check(kwrite_count_for(KWRITE_SRC_KRW32) == 1, "stack: an out-of-range write is still counted");
    check(kwrite_count_for((kwrite_src_t)99) == 0, "stack: out-of-range lookup reads nothing");
    kwrite_src_pop(bogusPrev);
    check(kwrite_src_current() == KWRITE_SRC_KRW32, "stack: pop of the ignored push leaves the default");
}

// ---------------------------------------------------------------------------
// 6. names are what the summary line prints
// ---------------------------------------------------------------------------
static void case_source_names(void)
{
    const char *n32 = kwrite_src_name(KWRITE_SRC_KRW32);
    const char *n64 = kwrite_src_name(KWRITE_SRC_KRW64);
    const char *nz  = kwrite_src_name(KWRITE_SRC_ZONE);
    const char *bad = kwrite_src_name((kwrite_src_t)99);

    check(n32 && strcmp(n32, "early_kwrite32bytes") == 0, "name: KWRITE_SRC_KRW32");
    check(n64 && strcmp(n64, "early_kwrite64") == 0, "name: KWRITE_SRC_KRW64");
    check(nz && strcmp(nz, "krw_zone_write_block") == 0, "name: KWRITE_SRC_ZONE");
    check(bad != NULL && strcmp(bad, "unknown") == 0, "name: an out-of-range route is safe to print");
}

// ---------------------------------------------------------------------------
// 7. two threads writing at once (scan thread + pe_init free thread)
// ---------------------------------------------------------------------------
#define THREAD_EMITS 10000

static int g_threadSawOwnRoute[2];   // written by thread 0 / thread 1

static void *thread_emitter(void *arg)
{
    // Route 0 = scan-style 32-byte writes, route 1 = qword RMWs.
    int idx = (arg == NULL) ? 0 : 1;
    kwrite_src_t src = (idx == 0) ? KWRITE_SRC_KRW32 : KWRITE_SRC_KRW64;
    kwrite_src_t prev = kwrite_src_push(src);
    g_threadSawOwnRoute[idx] = (kwrite_src_current() == src);
    for (int i = 0; i < THREAD_EMITS; i++) {
        kwrite_count_emit(kwrite_src_current(), 32);
        if ((i % 2) == 0) kwrite_count_failed(kwrite_src_current(), 32);
    }
    kwrite_src_pop(prev);
    return NULL;
}

static void case_threads(void)
{
    kwrite_count_reset();
    g_threadSawOwnRoute[0] = g_threadSawOwnRoute[1] = -1;

    pthread_t a, b;
    pthread_create(&a, NULL, thread_emitter, NULL);            // KRW32
    pthread_create(&b, NULL, thread_emitter, (void *)1);       // KRW64

    pthread_join(a, NULL);
    pthread_join(b, NULL);

    check(g_threadSawOwnRoute[0] == 1 && g_threadSawOwnRoute[1] == 1,
          "threads: each thread saw the route it pushed (thread-local stack)");

    check(kwrite_count_total() == 2 * THREAD_EMITS, "threads: no increment lost under two writers");
    check(kwrite_count_bytes() == 2 * THREAD_EMITS * 32, "threads: byte total matches both threads");
    check(kwrite_count_failed_total() == 2 * (THREAD_EMITS / 2), "threads: refusals counted from both threads");
    check(kwrite_count_for(KWRITE_SRC_KRW32) == THREAD_EMITS, "threads: route 0 kept its own count");
    check(kwrite_count_for(KWRITE_SRC_KRW64) == THREAD_EMITS, "threads: route 1 kept its own count");
    check(kwrite_count_for(KWRITE_SRC_KRW32) + kwrite_count_for(KWRITE_SRC_KRW64) +
          kwrite_count_for(KWRITE_SRC_ZONE) == kwrite_count_total(),
          "threads: per-route counts add up to the total");

    // The attribution stack is thread_local: this thread never pushed anything,
    // so it must still be on the default route after both threads popped theirs.
    check(kwrite_src_current() == KWRITE_SRC_KRW32, "threads: the pushing threads did not leak a route here");
}

int main(void)
{
    printf("kwrite_counter host test (BUG.5: measured kernel writes, not a claim)\n\n");

    printf("fresh state:\n");
    case_fresh_state();

    printf("\ncounting one accepted write:\n");
    case_emit_counts_and_attributes();

    printf("\nthe byte total:\n");
    case_bytes_are_a_sum();

    printf("\nwhat the kernel refused:\n");
    case_refusal_is_not_a_write();

    printf("\nattribution stack:\n");
    case_source_stack();

    printf("\nroute names:\n");
    case_source_names();

    printf("\ntwo writers at once:\n");
    case_threads();

    printf("\nchecks=%d failures=%d\n", g_checks, g_failures);
    if (g_failures == 0) {
        printf("KWRITE_COUNTER_HOST_TEST PASS\n");
        return 0;
    }
    printf("KWRITE_COUNTER_HOST_TEST FAIL\n");
    return 1;
}
