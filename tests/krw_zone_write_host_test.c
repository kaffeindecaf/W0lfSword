//
//  krw_zone_write_host_test.c
//  W0lfSword - host test for BUG.1 step 3.
//
//  Compiles the REAL kexploit/krw_zone_write.c (the 32-byte block writer behind
//  kwrite_zone_element) and drives it against a fake kernel window. Every block
//  the writer emits is recorded; a block that leaves the object is reported as
//  the panic it would be on device:
//
//      zone bound checks: buffer ... of length 32 overflows object ... of
//      size 96 in zone [data.kalloc.96] @zalloc.c:1322   (SE, 2026-09-11)
//
//  Run: bash scripts/run_krw_zone_write_host_test.sh
//
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "kexploit/krw_zone_write.h"

// ---------------------------------------------------------------------------
// harness
// ---------------------------------------------------------------------------
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

// fake kernel window: 0x400 bytes of "kernel memory" at FAKE_BASE
#define FAKE_BASE 0xffffffe000000000ULL
#define KMEM_SIZE 0x400
#define OBJECT_OFF 0x80u

static uint8_t g_kmem[KMEM_SIZE];

static uint64_t g_obj_base;   // object the writer may write into, as the test declares it
static uint64_t g_obj_size;

static uint64_t g_blocks[64]; // every block address the writer emitted
static int g_block_count;
static int g_oob_reads;       // 32-byte reads that left the object
static int g_oob_writes;      // 32-byte writes that left the object (= would panic)

#define FILL 0xA5

static void reset(uint64_t obj_off, uint64_t obj_size)
{
    memset(g_kmem, FILL, sizeof(g_kmem));
    g_obj_base = FAKE_BASE + obj_off;
    g_obj_size = obj_size;
    g_block_count = 0;
    g_oob_reads = 0;
    g_oob_writes = 0;
}

static uint64_t off_of(uint64_t addr) { return addr - FAKE_BASE; }

static bool in_window(uint64_t addr, uint64_t len)
{
    if (addr < FAKE_BASE) return false;
    if (addr - FAKE_BASE + len > KMEM_SIZE) return false;
    return true;
}

static bool in_object(uint64_t addr, uint64_t len)
{
    return addr >= g_obj_base && addr + len <= g_obj_base + g_obj_size;
}

// the two engine primitives, over the fake window
void krw_zone_read_block(uint64_t where, uint8_t *buf)
{
    if (!in_window(where, KRW_ZONE_BLOCK_LEN) || !in_object(where, KRW_ZONE_BLOCK_LEN)) {
        g_oob_reads++;
        memset(buf, 0, KRW_ZONE_BLOCK_LEN);
        return;
    }
    memcpy(buf, g_kmem + off_of(where), KRW_ZONE_BLOCK_LEN);
}

void krw_zone_write_block(uint64_t where, const uint8_t *buf)
{
    if (g_block_count < (int)(sizeof(g_blocks) / sizeof(g_blocks[0]))) {
        g_blocks[g_block_count] = where;
    }
    g_block_count++;
    if (!in_window(where, KRW_ZONE_BLOCK_LEN) || !in_object(where, KRW_ZONE_BLOCK_LEN)) {
        g_oob_writes++;   // on device: zalloc.c:1322 and a reboot
        return;
    }
    memcpy(g_kmem + off_of(where), buf, KRW_ZONE_BLOCK_LEN);
}

// capture the writer's own log output (the refusal lines are part of the fix)
static char g_capture[8192];
static int g_cap_fd = -1;
static int g_saved_stdout = -1;

static void capture_begin(void)
{
    fflush(stdout);
    g_saved_stdout = dup(1);
    char path[] = "/tmp/krw_zone_write_cap.XXXXXX";
    g_cap_fd = mkstemp(path);
    unlink(path);
    dup2(g_cap_fd, 1);
    g_capture[0] = '\0';
}

static void capture_end(void)
{
    fflush(stdout);
    dup2(g_saved_stdout, 1);
    lseek(g_cap_fd, 0, SEEK_SET);
    ssize_t n = read(g_cap_fd, g_capture, sizeof(g_capture) - 1);
    if (n < 0) n = 0;
    g_capture[n] = '\0';
    close(g_cap_fd);
    close(g_saved_stdout);
    g_cap_fd = -1;
    g_saved_stdout = -1;
}

static bool cap_has(const char *needle) { return strstr(g_capture, needle) != NULL; }

// ---------------------------------------------------------------------------
// cases
// ---------------------------------------------------------------------------

// a length below one block is still refused (unchanged behaviour)
static void case_len_too_small(void)
{
    uint8_t src[0x40];
    memset(src, 0x11, sizeof(src));
    reset(OBJECT_OFF, 0x60);

    capture_begin();
    krw_zone_verdict v = krw_zone_write(g_obj_base, src, 0x10, 0, 0);
    capture_end();

    check(v == KRW_ZONE_REFUSE_LEN, "len < 0x20 is refused");
    check(g_block_count == 0, "len < 0x20 emits no block");
    check(cap_has("not supported"), "len < 0x20 logs why");
}

// exact multiples of the block width need no declaration (no shift involved)
static void case_exact_multiple_no_declaration(void)
{
    uint8_t src[0x40];
    for (size_t i = 0; i < sizeof(src); i++) src[i] = (uint8_t)(0x10 + i);
    reset(OBJECT_OFF, 0x60);
    uint64_t dst = g_obj_base;

    krw_zone_verdict v = krw_zone_write(dst, src, 0x40, 0, 0);

    check(v == KRW_ZONE_OK, "len 0x40 (multiple of 0x20) needs no declaration");
    check(g_block_count == 2, "len 0x40 emits 2 blocks");
    check(g_blocks[0] == dst && g_blocks[1] == dst + 0x20, "blocks are dst, dst+0x20 (no shift)");
    check(g_oob_writes == 0, "both blocks inside the object");
    check(memcmp(g_kmem + off_of(dst), src, 0x40) == 0, "the requested bytes landed");
}

// the step 3 refusal: a shifted tail with no object declared is not written
static void case_shift_without_object_is_refused(void)
{
    uint8_t src[0x40];
    memset(src, 0x22, sizeof(src));
    reset(OBJECT_OFF, 0x60);
    uint8_t before[KMEM_SIZE];
    memcpy(before, g_kmem, sizeof(before));
    uint64_t dst = g_obj_base;

    capture_begin();
    krw_zone_verdict v = krw_zone_write(dst, src, 0x38, 0, 0);
    capture_end();

    check(v == KRW_ZONE_REFUSE_NO_OBJECT_SHIFT, "shifted tail without a declared object is refused");
    check(g_block_count == 0, "refused write emits no block (no half-applied write)");
    check(memcmp(before, g_kmem, sizeof(before)) == 0, "refused write changed no kernel byte");
    check(cap_has("[krw] refusing 32-byte block: shifted start") &&
          cap_has("is before the object base"),
          "refusal logs 'refusing 32-byte block: shifted start ... is before the object base ...'");
}

// with the object declared the shifted tail goes out, inside the object, RMW intact
static void case_declared_object_allows_shift(void)
{
    uint8_t src[0x38];
    for (size_t i = 0; i < sizeof(src); i++) src[i] = (uint8_t)(0x60 + i);
    reset(OBJECT_OFF, 0x60);
    uint64_t dst = g_obj_base;
    uint64_t declared_base = g_obj_base;
    uint64_t declared_size = 0x60;

    capture_begin();
    krw_zone_verdict v = krw_zone_write(dst, src, 0x38, declared_base, declared_size);
    capture_end();

    check(v == KRW_ZONE_OK, "shifted tail with the object declared is written");
    check(g_capture[0] == '\0', "no refusal logged when the write is allowed");
    check(g_block_count == 2, "len 0x38 emits 1 full block + the shifted tail");
    check(g_blocks[0] == dst && g_blocks[1] == dst + 0x18,
          "last block is the backward-shifted dst+0x18");
    check(g_blocks[1] + KRW_ZONE_BLOCK_LEN == dst + 0x38,
          "shifted block ends exactly at dst+len (never past the request)");
    check(g_oob_reads == 0 && g_oob_writes == 0, "every block (and the RMW read) inside the object");
    check(memcmp(g_kmem + off_of(dst), src, 0x38) == 0, "the requested bytes landed");
    check(g_kmem[off_of(dst) + 0x38] == FILL && g_kmem[off_of(dst) + 0x40] == FILL &&
          g_kmem[off_of(dst) + 0x5F] == FILL,
          "RMW put the object bytes outside the request back unchanged");
    check(g_kmem[off_of(dst) - 1] == FILL, "nothing before the object was touched");
}

// the SE panic itself: 32-byte block at +0x50 of a 0x60 kalloc.96 object
static void case_se_panic_write_is_refused(void)
{
    uint8_t src[0x20];
    memset(src, 0x33, sizeof(src));
    reset(OBJECT_OFF, 0x60);

    uint64_t dst = g_obj_base + 0x50;   // panic: buffer 0xffffffe0d1f26550
    uint64_t declared_base = g_obj_base; //        object 0xffffffe0d1f26500
    uint64_t declared_size = 0x60;       //        size 96

    capture_begin();
    krw_zone_verdict v = krw_zone_write(dst, src, 0x20, declared_base, declared_size);
    capture_end();

    check(v == KRW_ZONE_REFUSE_PAST_END, "SE write (0x50 into a 0x60 object) is refused");
    check(g_block_count == 0, "SE write emits no block");
    check(g_oob_writes == 0, "no 32-byte write left the object");
    check(cap_has("[krw] refusing 32-byte block: block") && cap_has("is outside object"),
          "SE refusal logs the block and the object bounds");
}

// the same overrun arriving as a shifted tail (SG.9's reading) is refused too
static void case_se_panic_via_shift_is_refused(void)
{
    uint8_t src[0x40];
    memset(src, 0x44, sizeof(src));
    reset(OBJECT_OFF, 0x60);

    uint64_t dst = g_obj_base + 0x48;    // dst+len = base+0x70 -> shifted block at +0x50
    capture_begin();
    krw_zone_verdict v = krw_zone_write(dst, src, 0x28, g_obj_base, 0x60);
    capture_end();

    check(v == KRW_ZONE_REFUSE_PAST_END, "shifted variant of the SE write is refused");
    check(g_block_count == 0 && g_oob_writes == 0, "no block emitted, nothing outside the object");
}

// a declaration for some other object must not authorise this one
static void case_foreign_declaration_does_not_authorise(void)
{
    uint8_t src[0x40];
    memset(src, 0x55, sizeof(src));
    reset(OBJECT_OFF, 0x60);

    capture_begin();
    krw_zone_verdict v = krw_zone_write(g_obj_base, src, 0x38, g_obj_base + 0x100, 0x60);
    capture_end();

    check(v == KRW_ZONE_REFUSE_NO_OBJECT_SHIFT,
          "a declaration that does not contain dst is treated as no declaration");
    check(g_block_count == 0, "foreign declaration emitted no block");
}

// the window rule itself
static void case_window_rule(void)
{
    uint64_t base = 0x1000, size = 0x60;
    check(krw_zone_window_contains(base, base, size) == true, "window contains its base");
    check(krw_zone_window_contains(base + 0x5F, base, size) == true, "window contains its last byte");
    check(krw_zone_window_contains(base + size, base, size) == false, "window excludes base+size");
    check(krw_zone_window_contains(base - 1, base, size) == false, "window excludes base-1");
    check(krw_zone_window_contains(base, 0, size) == false, "base 0 = nothing declared");
    check(krw_zone_window_contains(base, base, 0) == false, "size 0 = nothing declared");
}

// the shift-before-base branch (declared window that starts above the block)
static void case_shift_before_base_branch(void)
{
    uint64_t blockStart = 0;
    krw_zone_verdict v = krw_zone_check_bounds(0x1000, 0x30, 0x2000, 0x100, true, &blockStart);
    check(v == KRW_ZONE_REFUSE_SHIFT_BEFORE_BASE, "shifted start below objBase is refused");
    check(blockStart == 0x1000 + 0x30 - 0x20, "reported shifted start is dst+len-0x20");

    // Through the writer the same call cannot reach that branch, because a
    // window that does not contain dst is not a declaration at all. Documented
    // so nobody "fixes" the check away.
    krw_zone_verdict v2 = krw_zone_check_bounds(0x1000, 0x30, 0x2000, 0x100, false, NULL);
    check(v2 == KRW_ZONE_REFUSE_NO_OBJECT_SHIFT,
          "writer path reports the same call as 'no object declared'");
}

// sweep: for every dst/len with dst inside the declared object, the verdict is
// OK exactly when the range fits, and no emitted block ever leaves the object
static void case_sweep(void)
{
    uint8_t src[0x100];
    memset(src, 0x77, sizeof(src));

    int swept = 0, oob = 0, wrongVerdict = 0, hmm = 0;
    // discard the writer's own refusal log for the sweep - 4753 lines of it
    capture_begin();
    for (uint64_t len = 0x20; len <= 0x80; len++) {
        for (uint64_t d = 0; d <= 0x30; d++) {
            reset(OBJECT_OFF, 0x60);
            uint64_t dst = g_obj_base + d;
            krw_zone_verdict v = krw_zone_write(dst, src, len, g_obj_base, 0x60);
            swept++;
            if (g_oob_writes != 0) oob++;
            // with a declared object and dst inside it, the only refusals are
            // "range past the end" (and the shifted case never precedes base)
            bool fits = (dst + len <= g_obj_base + 0x60);
            if (fits && v != KRW_ZONE_OK) wrongVerdict++;
            if (!fits && v != KRW_ZONE_REFUSE_PAST_END) wrongVerdict++;
            // every allowed block must be inside the object and cover the range
            if (v == KRW_ZONE_OK) {
                uint64_t last = dst + len - KRW_ZONE_BLOCK_LEN;
                if (!in_object(last, KRW_ZONE_BLOCK_LEN)) hmm++;
                if (memcmp(g_kmem + off_of(dst), src, len) != 0) hmm++;
                if (g_kmem[off_of(g_obj_base) + 0x60] != FILL) hmm++;
            }
        }
    }
    capture_end();
    printf("  ..   swept %d dst/len combinations (len 0x20..0x80, dst base..base+0x30)\n", swept);
    check(oob == 0, "sweep: not one emitted block left the object");
    check(wrongVerdict == 0, "sweep: verdict is OK exactly when dst+len fits the object");
    check(hmm == 0, "sweep: allowed writes landed correctly and stayed inside the object");
}

int main(void)
{
    printf("krw_zone_write_host_test (BUG.1 step 3 - clamp the 32-byte writer)\n");

    case_len_too_small();
    case_exact_multiple_no_declaration();
    case_shift_without_object_is_refused();
    case_declared_object_allows_shift();
    case_se_panic_write_is_refused();
    case_se_panic_via_shift_is_refused();
    case_foreign_declaration_does_not_authorise();
    case_window_rule();
    case_shift_before_base_branch();
    case_sweep();

    printf("\nchecks=%d failures=%d\n", g_checks, g_failures);
    if (g_failures == 0) {
        printf("KRW_ZONE_WRITE_HOST_TEST PASS\n");
        return 0;
    }
    printf("KRW_ZONE_WRITE_HOST_TEST FAIL\n");
    return 1;
}
