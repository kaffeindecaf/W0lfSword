//
//  krw_zone_write_host_test.c
//  W0lfSword - host test for BUG.1 steps 3 and 3b.
//
//  Compiles the REAL kexploit/krw_zone_write.c (the 32-byte block writer behind
//  kwrite_zone_element) and drives it against a fake kernel window. Every block
//  the writer emits is recorded; a block that leaves the object is reported as
//  the panic it would be on device:
//
//      zone bound checks: buffer ... of length 32 overflows object ... of
//      size 96 in zone [data.kalloc.96] @zalloc.c:1322   (SE, 2026-09-11)
//
//  Step 3b is the part step 3 left open: a write with NO object declared was
//  still emitted (and the SE write was one - an exact multiple of 0x20, which
//  the shifted-tail rule never saw). Nothing is written without a declaration
//  now, and the qword write the staged probe uses is clamped too.
//
//  Run: bash scripts/run_krw_zone_write_host_test.sh
//
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <unistd.h>

#include "kexploit/krw_zone_write.h"
#include "kexploit/probe_restore_policy.h"

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

// exact multiples of the block width tile their range - with the object declared
// (which is the only way a write happens at all since step 3b)
static void case_exact_multiple_with_declaration(void)
{
    uint8_t src[0x40];
    for (size_t i = 0; i < sizeof(src); i++) src[i] = (uint8_t)(0x10 + i);
    reset(OBJECT_OFF, 0x60);
    uint64_t dst = g_obj_base;

    krw_zone_verdict v = krw_zone_write(dst, src, 0x40, g_obj_base, 0x60);

    check(v == KRW_ZONE_OK, "len 0x40 (multiple of 0x20) inside a declared object is written");
    check(g_block_count == 2, "len 0x40 emits 2 blocks");
    check(g_blocks[0] == dst && g_blocks[1] == dst + 0x20, "blocks are dst, dst+0x20 (no shift)");
    check(g_oob_writes == 0, "both blocks inside the object");
    check(memcmp(g_kmem + off_of(dst), src, 0x40) == 0, "the requested bytes landed");
    check(g_kmem[off_of(dst) + 0x40] == FILL && g_kmem[off_of(dst) + 0x5F] == FILL,
          "the rest of the object was not touched");
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
          cap_has("has no enclosing object declared"),
          "refusal logs 'refusing 32-byte block: shifted start ... has no enclosing object declared'");
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

// the boundary the SE write crossed: a block that ends EXACTLY at the object end
// is legal, one byte more is not
static void case_block_ending_exactly_at_object_end(void)
{
    uint8_t src[0x48];
    for (size_t i = 0; i < sizeof(src); i++) src[i] = (uint8_t)(0x90 + i);
    reset(OBJECT_OFF, 0x60);

    // dst+len == base+0x60: the last block is base+0x40..base+0x60, inside
    krw_zone_verdict v = krw_zone_write(g_obj_base + 0x20, src, 0x40, g_obj_base, 0x60);
    check(v == KRW_ZONE_OK, "a write ending exactly at the object end is allowed");
    check(g_block_count == 2 && g_blocks[1] == g_obj_base + 0x40,
          "its last block starts at base+0x40");
    check(g_blocks[1] + KRW_ZONE_BLOCK_LEN == g_obj_base + 0x60,
          "its last block ends exactly at base+0x60 (inside kalloc.96)");
    check(g_oob_writes == 0 && g_oob_reads == 0, "nothing left the object");

    // one byte more must be refused with no block emitted at all
    reset(OBJECT_OFF, 0x60);
    uint8_t before[KMEM_SIZE];
    memcpy(before, g_kmem, sizeof(before));
    capture_begin();
    krw_zone_verdict v2 = krw_zone_write(g_obj_base + 0x20, src, 0x41, g_obj_base, 0x60);
    capture_end();
    check(v2 == KRW_ZONE_REFUSE_PAST_END, "one byte past the object end is refused");
    check(g_block_count == 0 && g_oob_writes == 0, "the refusal emits no block");
    check(memcmp(before, g_kmem, sizeof(before)) == 0, "the refusal changed no kernel byte");
    check(cap_has("is outside object"), "the refusal names the object bounds");
}

// BUG.1 step 3b: NOTHING is written without a declared object. Step 3 left this
// open ("an exact multiple of 0x20 with no object declared is still emitted
// unproven") - and the 2026-09-11 SE write WAS an exact multiple: one full block
// at +0x50 of a 0x60 object, which the shifted-tail rule never saw. Every shape
// below is now refused with zero blocks emitted.
static void case_undeclared_writes_are_refused(void)
{
    uint8_t src[0x80];
    memset(src, 0x66, sizeof(src));

    struct shape { uint64_t dstOff; uint64_t len; krw_zone_verdict want; const char *what; };
    static const struct shape shapes[] = {
        { 0x50, 0x20, KRW_ZONE_REFUSE_UNDECLARED,       "the SE write itself: one block at +0x50 of a 0x60 object" },
        { 0x00, 0x20, KRW_ZONE_REFUSE_UNDECLARED,       "a block at the object base (inside the object, but unprovable)" },
        { 0x20, 0x40, KRW_ZONE_REFUSE_UNDECLARED,       "two blocks in the middle" },
        { 0x00, 0x38, KRW_ZONE_REFUSE_NO_OBJECT_SHIFT,  "a write with a shifted tail" },
        { 0x10, 0x21, KRW_ZONE_REFUSE_NO_OBJECT_SHIFT,  "a write one byte over a block boundary" },
    };

    for (size_t i = 0; i < sizeof(shapes) / sizeof(shapes[0]); i++) {
        reset(OBJECT_OFF, 0x60);
        uint64_t dst = g_obj_base + shapes[i].dstOff;
        uint8_t before[KMEM_SIZE];
        memcpy(before, g_kmem, sizeof(before));

        capture_begin();
        krw_zone_verdict v = krw_zone_write(dst, src, shapes[i].len, 0, 0);
        capture_end();

        check(v == shapes[i].want, shapes[i].what);
        check(g_block_count == 0 && g_oob_writes == 0 && g_oob_reads == 0,
              "  ... emitted no block and no RMW read");
        check(memcmp(before, g_kmem, sizeof(before)) == 0, "  ... changed no kernel byte");
        check(cap_has("no enclosing object declared"),
              "  ... and the log says which declaration is missing");
    }

    // A declaration that is present but does not contain the target is not a
    // declaration either - it must not authorise anything.
    reset(OBJECT_OFF, 0x60);
    capture_begin();
    krw_zone_verdict foreign = krw_zone_write(g_obj_base + 0x50, src, 0x20, g_obj_base + 0x100, 0x60);
    capture_end();
    check(foreign == KRW_ZONE_REFUSE_UNDECLARED, "a window that does not contain dst is no window");
    check(g_block_count == 0, "the foreign window emitted no block");

    // A zero-size window is the same as none.
    reset(OBJECT_OFF, 0x60);
    krw_zone_verdict zeroSize = krw_zone_write(g_obj_base, src, 0x20, g_obj_base, 0);
    check(zeroSize == KRW_ZONE_REFUSE_UNDECLARED, "size 0 is nothing declared");
}

// ---------------------------------------------------------------------------
// BUG.1 step 3b: the qword write the probe uses (kwrite_zone_element_qword)
// ---------------------------------------------------------------------------

// The probe's writes are qwords, and they used to go through early_kwrite64 -
// an unclamped 32-byte read-modify-write. The clamped qword writer patches the
// 0x20-ALIGNED block containing the qword, so the very address that panicked
// the SE (+0x50 of a 0x60 object) becomes a legal, in-object write - and every
// shape that would leave the declared object is refused with zero blocks.
static void case_qword_clamp(void)
{
    // (1) the SE address, declared: the aligned block base+0x40..base+0x60 fits
    reset(OBJECT_OFF, 0x60);
    krw_zone_verdict ok = krw_zone_write_qword(g_obj_base + 0x50, 0x1122334455667788ULL,
                                               g_obj_base, 0x60);
    check(ok == KRW_ZONE_OK, "qword at +0x50 of a 0x60 object with the object declared is written");
    check(g_block_count == 1 && g_blocks[0] == g_obj_base + 0x40,
          "it emits the 0x20-aligned block containing the qword (base+0x40, not base+0x50)");
    check(g_blocks[0] + KRW_ZONE_BLOCK_LEN == g_obj_base + 0x60,
          "that block ends exactly at the object end - inside kalloc.96");
    check(*(uint64_t *)(g_kmem + off_of(g_obj_base + 0x50)) == 0x1122334455667788ULL,
          "the qword landed at the requested address");
    check(g_oob_writes == 0 && g_oob_reads == 0, "the RMW read and the block stayed inside the object");
    check(g_kmem[off_of(g_obj_base) + 0x40] == FILL && g_kmem[off_of(g_obj_base) + 0x5F] == FILL,
          "the RMW put the surrounding bytes back unchanged (only the qword changed)");

    // (2) a window whose end cuts the qword's aligned block: refused
    reset(OBJECT_OFF, 0x60);
    capture_begin();
    krw_zone_verdict past = krw_zone_write_qword(g_obj_base + 0x40, 1, g_obj_base, 0x50);
    capture_end();
    check(past == KRW_ZONE_REFUSE_PAST_END,
          "a window ending mid-block is refused (the aligned block would leave it)");
    check(g_block_count == 0 && g_oob_writes == 0 && g_oob_reads == 0, "the refusal emitted nothing");
    check(cap_has("is outside object"), "the refusal names the object bounds");

    // (3) undeclared: refused, never written unproven
    reset(OBJECT_OFF, 0x60);
    capture_begin();
    krw_zone_verdict undeclared = krw_zone_write_qword(g_obj_base + 0x50, 1, 0, 0);
    capture_end();
    check(undeclared == KRW_ZONE_REFUSE_UNDECLARED, "an undeclared qword write is refused");
    check(g_block_count == 0, "the undeclared qword write emitted no block");

    // (4) a declaration for some other object authorises nothing
    reset(OBJECT_OFF, 0x60);
    krw_zone_verdict foreign = krw_zone_write_qword(g_obj_base + 0x50, 1, g_obj_base + 0x100, 0x60);
    check(foreign == KRW_ZONE_REFUSE_UNDECLARED, "a qword write under a window that excludes it is refused");

    // (5) an unaligned declaration whose block starts below it
    reset(OBJECT_OFF, 0x60);
    capture_begin();
    krw_zone_verdict below = krw_zone_write_qword(0x1000 + 0x15, 1, 0x1000 + 0x10, 0x40);
    capture_end();
    check(below == KRW_ZONE_REFUSE_SHIFT_BEFORE_BASE,
          "a qword whose aligned block would start below the declared base is refused");
    check(cap_has("is before the object base"), "that refusal names the base it would precede");

    // (6) alignment helper
    check(krw_zone_block_align_down(0x148) == 0x140 && krw_zone_block_align_down(0x150) == 0x140 &&
          krw_zone_block_align_down(0x160) == 0x160,
          "the aligned block of the inpcb's filt/chksum qwords is 0x140 (0x160 is already aligned)");
}

// The window the probe declares for the inpcb, derived from the field table.
// The values are the pairs offsets.m ships (18.x/26.x: filt 0x148, chksum
// 0x150; 17.0-17.7.x: filt 0x150, chksum 0x158): both put-back writes are qwords
// 8 bytes apart, they share one aligned block, and the window that holds that
// block is what the probe hands the writer.
static void case_field_window_arithmetic(void)
{
    check(krw_zone_window_for_field_end(0) == 0, "no field end = no window (nothing declared)");
    check(krw_zone_window_for_field_end(8) == 0x20, "a field ending inside the first block needs one block");
    check(krw_zone_window_for_field_end(0x20) == 0x20, "a field ending on a block boundary stays there");
    check(krw_zone_window_for_field_end(0x21) == 0x40, "one byte over a boundary rounds up");

    static const uint64_t pairs[][2] = { { 0x148, 0x150 }, { 0x150, 0x158 } };  // filt, chksum
    static const char *const labels[] = { "18.x/26.x (filt 0x148, chksum 0x150)",
                                          "17.0-17.7.x (filt 0x150, chksum 0x158)" };
    for (size_t i = 0; i < sizeof(pairs) / sizeof(pairs[0]); i++) {
        uint64_t filtOff = pairs[i][0], chksumOff = pairs[i][1];
        uint64_t window = krw_zone_window_for_field_end(filtOff + 2 * sizeof(uint64_t));
        check(window == 0x160, labels[i]);
        check(krw_zone_block_align_down(filtOff) == krw_zone_block_align_down(chksumOff),
              "  ... both put-back qwords sit in the same aligned block");

        // the window must authorise exactly the two writes the restore makes
        reset(OBJECT_OFF, window);
        krw_zone_verdict vFilt = krw_zone_write_qword(g_obj_base + filtOff, 0xAA, g_obj_base, window);
        krw_zone_verdict vChk  = krw_zone_write_qword(g_obj_base + chksumOff, 0xBB, g_obj_base, window);
        check(vFilt == KRW_ZONE_OK && vChk == KRW_ZONE_OK,
              "  ... the restore's two qword writes are inside the declared window");
        check(g_oob_writes == 0 && g_oob_reads == 0, "  ... and neither left the inpcb window");
        check(*(uint64_t *)(g_kmem + off_of(g_obj_base + filtOff)) == 0xAA &&
              *(uint64_t *)(g_kmem + off_of(g_obj_base + chksumOff)) == 0xBB,
              "  ... both saved values landed where the restore writes them");
    }
}

// default deny, swept: with nothing declared, no shape writes anything
static void case_sweep_undeclared_emits_nothing(void)
{
    uint8_t src[0x100];
    memset(src, 0x88, sizeof(src));

    int swept = 0, wrote = 0;
    capture_begin();
    for (uint64_t len = 1; len <= 0x100; len++) {
        for (uint64_t d = 0; d <= 0x40; d += 0x20) {
            reset(OBJECT_OFF, 0x60);
            krw_zone_write(g_obj_base + d, src, len, 0, 0);
            swept++;
            if (g_block_count != 0 || g_oob_writes != 0 || g_oob_reads != 0) wrote++;
        }
    }
    capture_end();
    printf("  ..   swept %d undeclared shapes (len 1..0x100, dst base..base+0x40)\n", swept);
    check(wrote == 0, "sweep: not one undeclared shape emitted a block (default deny)");
}

// ---------------------------------------------------------------------------
// BUG.1 step 1: the unconditional-restore path (kexploit/probe_restore_policy.c)
// ---------------------------------------------------------------------------

// Every exit of the write probe restores, except the one promotion the caller
// takes over. The direction that matters: a code the policy has never seen must
// restore too - the original code enumerated exits and lost one.
static void case_restore_action_for_every_exit(void)
{
    check(PROBE_EXIT_PROMOTED == 0, "the promotion code is KERN_SUCCESS (0)");
    check(probe_exit_action_for(PROBE_EXIT_PROMOTED) == PROBE_ACTION_HAND_OFF,
          "the promotion is the ONE exit handed to the caller (there the socket IS the primitive)");

    // every exit the probe returns today
    static const int known[] = { -1, -7 };
    for (size_t i = 0; i < sizeof(known) / sizeof(known[0]); i++) {
        char what[128];
        snprintf(what, sizeof(what), "probe exit %d restores before the caller sees it", known[i]);
        check(probe_exit_action_for(known[i]) == PROBE_ACTION_RESTORE, what);
    }

    // ...and every code it does not have yet: the default is fail-safe
    static const int future[] = { -2, -3, -4, -5, -6, -8, -42, -99, 1, 42, INT_MIN, INT_MAX };
    int notRestoring = 0;
    for (size_t i = 0; i < sizeof(future) / sizeof(future[0]); i++) {
        if (probe_exit_action_for(future[i]) != PROBE_ACTION_RESTORE) notRestoring++;
    }
    check(notRestoring == 0,
          "an exit code the policy has never seen still restores (fail-safe default, not hand-off)");
}

// Which fds the restore may write through. The regression this pins: after
// pe_v1's release funnel has emptied the spray tracking array, the restore must
// still reach the pair - the old code reported "krw socket not live" and left
// the corruption in the kernel.
static void case_restore_fd_source(void)
{
    check(probe_restore_fd_source(true, false) == PROBE_FD_SOURCE_FILEPORTS,
          "before the release funnel: the restore re-opens from the spray tracking array");
    check(probe_restore_fd_source(true, true) == PROBE_FD_SOURCE_FILEPORTS,
          "the tracking array wins while it still holds the pair");
    check(probe_restore_fd_source(false, true) == PROBE_FD_SOURCE_PROMOTION_FDS,
          "array emptied, promotion fds live: the restore still reaches the pair");
    check(probe_restore_fd_source(false, false) == PROBE_FD_SOURCE_UNREACHABLE,
          "neither source: UNREACHABLE (the engine logs a failure, never a silent success)");
}

// The staged -5 exit (kernel-base scan exhausted) as the state machine it is:
// promotion -> pe_v1's release funnel empties the array -> the caller's restore.
static void case_staged_minus5_restore_is_reachable(void)
{
    // 1. the probe saved the fields and opened the pair: the fds are live for
    //    THIS save generation (the engine's g_probe_fds_gen == g_probe_save_gen)
    bool trackingArrayHoldsPair = true;
    bool fdsLiveForThisSave = true;
    check(probe_restore_fd_source(trackingArrayHoldsPair, fdsLiveForThisSave) ==
              PROBE_FD_SOURCE_FILEPORTS,
          "staged -5 step 1: at promotion time the array holds the pair");

    // 2. pe_v1's release funnel: sockets_release() + tracker_arrays_release()
    trackingArrayHoldsPair = false;

    // 3. the caller's restore on the -5 exit
    probe_fd_source afterRelease = probe_restore_fd_source(trackingArrayHoldsPair, fdsLiveForThisSave);
    check(afterRelease != PROBE_FD_SOURCE_UNREACHABLE,
          "staged -5 step 3: the restore is NOT unreachable after the spray array was released");
    check(afterRelease == PROBE_FD_SOURCE_PROMOTION_FDS,
          "staged -5 step 3: it writes the saved values back through the promotion's fds");

    // 4. the generation check is what keeps that fallback honest: fds left over
    //    from an EARLIER save are not usable for this corruption
    bool stalePairLive = false;   // g_probe_fds_gen != g_probe_save_gen
    check(probe_restore_fd_source(false, stalePairLive) == PROBE_FD_SOURCE_UNREACHABLE,
          "a pair opened for an earlier save is refused (no write through a foreign socket)");
}

// sweep: for every dst/len with dst inside the declared object, the verdict is
// OK exactly when the range fits, and no emitted block ever leaves the object
static void case_sweep(void)
{
    uint8_t src[0x100];
    memset(src, 0x77, sizeof(src));

    int swept = 0, oob = 0, wrongVerdict = 0, hmm = 0;
    uint64_t firstOobD = 0, firstOobLen = 0;
    bool haveFirstOob = false;
    // discard the writer's own refusal log for the sweep - 4753 lines of it
    capture_begin();
    for (uint64_t len = 0x20; len <= 0x80; len++) {
        for (uint64_t d = 0; d <= 0x30; d++) {
            reset(OBJECT_OFF, 0x60);
            uint64_t dst = g_obj_base + d;
            krw_zone_verdict v = krw_zone_write(dst, src, len, g_obj_base, 0x60);
            swept++;
            if (g_oob_writes != 0) {
                oob++;
                if (!haveFirstOob) { haveFirstOob = true; firstOobD = d; firstOobLen = len; }
            }
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
    if (haveFirstOob) {
        printf("  ..   first out-of-object block: dst=base+%#llx len=%#llx\n",
               (unsigned long long)firstOobD, (unsigned long long)firstOobLen);
    }
    check(oob == 0, "sweep: not one emitted block left the object");
    check(wrongVerdict == 0, "sweep: verdict is OK exactly when dst+len fits the object");
    check(hmm == 0, "sweep: allowed writes landed correctly and stayed inside the object");
}

int main(void)
{
    printf("krw_zone_write_host_test (BUG.1: clamp the 32-byte writer + the unconditional-restore path)\n");

    printf("\nthe block writer's object clamp (step 3 + step 3b):\n");
    case_len_too_small();
    case_exact_multiple_with_declaration();
    case_shift_without_object_is_refused();
    case_declared_object_allows_shift();
    case_se_panic_write_is_refused();
    case_se_panic_via_shift_is_refused();
    case_foreign_declaration_does_not_authorise();
    case_window_rule();
    case_shift_before_base_branch();
    case_block_ending_exactly_at_object_end();
    case_undeclared_writes_are_refused();
    case_sweep();
    case_sweep_undeclared_emits_nothing();

    printf("\nthe clamped qword write the probe uses (step 3b):\n");
    case_qword_clamp();
    case_field_window_arithmetic();

    printf("\nthe staged write probe's restore contract (step 1, probe_restore_policy.c):\n");
    case_restore_action_for_every_exit();
    case_restore_fd_source();
    case_staged_minus5_restore_is_reachable();

    printf("\nchecks=%d failures=%d\n", g_checks, g_failures);
    if (g_failures == 0) {
        printf("KRW_ZONE_WRITE_HOST_TEST PASS\n");
        return 0;
    }
    printf("KRW_ZONE_WRITE_HOST_TEST FAIL\n");
    return 1;
}
