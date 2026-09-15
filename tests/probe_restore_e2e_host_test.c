//
//  probe_restore_e2e_host_test.c
//  W0lfSword - BUG.1 end-to-end host test (clamp + restore path), task 13.
//
//  The sibling harness (tests/krw_zone_write_host_test.c) tests the clamp and
//  the restore POLICY in isolation. This one runs the two together, the way the
//  engine runs them: save the fields of a live inpcb -> corrupt them -> take a
//  probe exit -> put the saved values back through the clamped writer -> read
//  the object back. It is the sequence the SE (2026-09-11, zalloc.c:1322,
//  "Panicked task: W0lfTerm") died in.
//
//  REAL code, compiled as the engine compiles it (same two sources, no stubs):
//    kexploit/krw_zone_write.c        -> the 32-byte block clamp (steps 3 / 3b)
//    kexploit/probe_restore_policy.c  -> which exits restore + which fds (step 1)
//  MODELED by this test, and nothing else:
//    - the fake kernel window (a byte array + the two engine primitives over it)
//    - probe_restore_model(): the engine's restore loop
//      (kexploit/kexploit_opa334.m:1820-1927, its write-then-verify loop at
//      1873-1917) reduced to its decisions and its
//      write order. Every decision in it comes from the two real files above;
//      a refusal or an unreachable fd pair is returned as a FAILED restore,
//      never as a silent success (that is the whole point of the item).
//
//  Run: bash scripts/run_probe_restore_e2e_host_test.sh
//
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

#include "kexploit/krw_zone_write.h"
#include "kexploit/probe_restore_policy.h"

// ---------------------------------------------------------------------------
// harness: a fake kernel window, and the two primitives over it
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

#define FAKE_BASE 0xffffffe000000000ULL
#define KMEM_SIZE 0x400
#define OBJECT_OFF 0x80u
#define FILL 0xA5

static uint8_t g_kmem[KMEM_SIZE];

static uint64_t g_obj_base;    // the object the test declares to the writer
static uint64_t g_obj_size;

static uint64_t g_blocks[64];  // every block the writer emitted
static int g_block_count;
static int g_oob_reads;
static int g_oob_writes;       // a 32-byte write that left the object = the SE panic

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

static uint64_t kmem_read64(uint64_t addr)
{
    uint64_t v = 0;
    memcpy(&v, g_kmem + off_of(addr), sizeof v);
    return v;
}

static void kmem_write64_raw(uint64_t addr, uint64_t v)
{
    // Only used to model the OOB page write that corrupts the icmp6 filter
    // pointer: the kernel path the SE took, not the clamped writer's.
    memcpy(g_kmem + off_of(addr), &v, sizeof v);
}

// capture the writer's own log output (the refusal lines are part of the fix)
static char g_capture[8192];
static int g_cap_fd = -1;
static int g_saved_stdout = -1;

static void capture_begin(void)
{
    fflush(stdout);
    g_saved_stdout = dup(1);
    char path[] = "/tmp/probe_restore_e2e_cap.XXXXXX";
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
// the probe's restore loop, as the engine runs it
// ---------------------------------------------------------------------------
typedef struct {
    probe_exit_action action;
    probe_fd_source fdSource;
    bool attemptedWrite;   // did the model issue the put-back at all?
    bool restored;         // ...and did the saved values verify back afterwards?
    int blocksBefore;
    int blocksAfter;
} restore_report;

// kexploit/kexploit_opa334.m:1820-1927 (write-then-verify loop 1873-1917),
// reduced to its decisions:
//   1. probe_exit_action_for(rc)      -> restore at all? (step 1, real file)
//   2. probe_restore_fd_source(...)   -> which fds may the put-back use? (real file)
//   3. kwrite_zone_element_qword()    -> write +8 FIRST, the filt pointer LAST,
//      so both writes still go through the corrupted socket while its filter
//      field is still ours; each write must be proven by the clamp (steps 3/3b)
//   4. read the fields back: a put-back that did not land is not a restore
static void probe_restore_model(int probeRc, bool trackingArrayHoldsPair, bool promotionPairLive,
                                uint64_t pcb, uint64_t filtOff, uint64_t windowSize,
                                uint64_t savedFilt, uint64_t savedFilt8,
                                restore_report *rep)
{
    memset(rep, 0, sizeof *rep);
    rep->action = probe_exit_action_for(probeRc);
    rep->blocksBefore = g_block_count;

    if (rep->action != PROBE_ACTION_RESTORE) {
        // The promotion: the corrupted socket IS the krw primitive from here,
        // and the caller (run_write_test / the staged stage-2 failure path)
        // restores it. Not this path's job.
        rep->blocksAfter = g_block_count;
        return;
    }

    rep->fdSource = probe_restore_fd_source(trackingArrayHoldsPair, promotionPairLive);
    if (rep->fdSource == PROBE_FD_SOURCE_UNREACHABLE) {
        // No fd to write through (the staged -5 shape before step 1): the
        // engine logs "probe restore FAILED" and reports false. Nothing is
        // written and nothing is claimed.
        rep->blocksAfter = g_block_count;
        return;
    }

    rep->attemptedWrite = true;
    bool wrote8 = krw_zone_write_qword(pcb + filtOff + 8, savedFilt8, pcb, windowSize) == KRW_ZONE_OK;
    bool wrote0 = krw_zone_write_qword(pcb + filtOff, savedFilt, pcb, windowSize) == KRW_ZONE_OK;
    rep->blocksAfter = g_block_count;

    if (!wrote8 || !wrote0) {
        // The clamp refused a put-back block: the engine logs which field it
        // refused and reports false (BUG.1 step 3b: refused, not written
        // unproven - the failure is reported instead of assumed away).
        return;
    }
    rep->restored = (kmem_read64(pcb + filtOff) == savedFilt &&
                     kmem_read64(pcb + filtOff + 8) == savedFilt8);
}

// ---------------------------------------------------------------------------
// the inpcb shapes this tree knows (offsets.m): filt, chksum = filt + 8
// ---------------------------------------------------------------------------
typedef struct {
    const char *label;
    uint64_t filtOff;
    uint64_t chksumOff;
} inpcb_layout;

static const inpcb_layout g_layouts[] = {
    { "18.x/26.x (filt 0x148, chksum 0x150)", 0x148, 0x150 },
    { "17.0-17.7.x (filt 0x150, chksum 0x158)", 0x150, 0x158 },
};

// The kernel objects involved. kalloc.96 is the bucket the SE panic named; the
// inpcb is bigger, so the clamp is given the field-derived window the engine
// derives (probe_inpcb_window_size()), not an invented bucket size.
#define KALLOC96_SIZE 0x60u
static uint64_t inpcb_window_for(const inpcb_layout *l)
{
    return krw_zone_window_for_field_end(l->filtOff + 2 * sizeof(uint64_t));
}

// ---------------------------------------------------------------------------
// 1. the 32-byte overrun, injected
// ---------------------------------------------------------------------------
// The SE write: early_kwrite32bytes handed a block at +0x50 of a 0x60 object.
// The clamp has to refuse it, and the harness has to be able to SEE an overrun
// (the control below writes one straight through the primitive and requires the
// detector to fire) - otherwise "refused" would be unverifiable.
static void case_overrun_injection(void)
{
    uint8_t src[0x40];
    memset(src, 0x33, sizeof(src));

    // control: the detector is live - a raw out-of-object block IS counted
    reset(OBJECT_OFF, KALLOC96_SIZE);
    krw_zone_write_block(g_obj_base + 0x50, src);
    check(g_oob_writes == 1,
          "control: the harness counts a raw 32-byte write at +0x50 of a 0x60 object (the SE overrun)");

    // the injected overrun, through the writer, object declared
    reset(OBJECT_OFF, KALLOC96_SIZE);
    capture_begin();
    krw_zone_verdict v = krw_zone_write(g_obj_base + 0x50, src, 0x20, g_obj_base, KALLOC96_SIZE);
    capture_end();
    check(v == KRW_ZONE_REFUSE_PAST_END, "injected overrun (0x20 at +0x50 of 0x60) is REFUSED");
    check(g_block_count == 0 && g_oob_writes == 0 && g_oob_reads == 0,
          "the refusal emitted no block and no RMW read");
    check(g_kmem[off_of(g_obj_base) + 0x50] == FILL && g_kmem[off_of(g_obj_base) + 0x5F] == FILL,
          "the refused overrun changed no kernel byte");
    check(cap_has("is outside object") && cap_has("[krw] refusing 32-byte block"),
          "the refusal is logged with the block and the object bounds");

    // the qword shape the probe uses at the same address: 0x20-ALIGNED, so it
    // stays inside the object - which is exactly why the rest of the probe can
    // still write there after the fix
    reset(OBJECT_OFF, KALLOC96_SIZE);
    krw_zone_verdict q = krw_zone_write_qword(g_obj_base + 0x50, 0x1122334455667788ULL,
                                              g_obj_base, KALLOC96_SIZE);
    check(q == KRW_ZONE_OK, "the qword shape at the same address is allowed (block +0x40..+0x60)");
    check(g_block_count == 1 && g_blocks[0] == g_obj_base + 0x40 && g_oob_writes == 0,
          "it emits the aligned block +0x40..+0x60, wholly inside the 0x60 object");

    // ...and one qword later it is refused again: the boundary is the object end
    // (a target outside the declared object is not a declaration at all - the
    // verdict says so, and no block is emitted either way)
    reset(OBJECT_OFF, KALLOC96_SIZE);
    capture_begin();
    krw_zone_verdict q2 = krw_zone_write_qword(g_obj_base + 0x60, 1, g_obj_base, KALLOC96_SIZE);
    capture_end();
    check(q2 == KRW_ZONE_REFUSE_UNDECLARED, "the first qword past the object end is refused");
    check(g_block_count == 0 && g_oob_writes == 0, "and it emits no block either");
    check(cap_has("no enclosing object declared"),
          "and the refusal says the object does not contain the target");
}

// ---------------------------------------------------------------------------
// 2. restore on ERROR (probe exit -1, write-verify exhaustion)
// ---------------------------------------------------------------------------
static void case_restore_on_error(void)
{
    for (size_t i = 0; i < sizeof(g_layouts) / sizeof(g_layouts[0]); i++) {
        const inpcb_layout *l = &g_layouts[i];
        uint64_t window = inpcb_window_for(l);
        char what[192];

        reset(OBJECT_OFF, window);
        uint64_t pcb = g_obj_base;
        uint64_t savedFilt = 0xffffffe0d1f26000ULL;   // a canonical pointer value
        uint64_t savedFilt8 = 0x0000ffffffffffffULL;  // in6p_cksum -1 / in6p_hops 0xffff

        // the probe's save, then the corruption:
        //   filt   - the OOB page write (modelled raw: it is not this writer's
        //            path; the clamp is what protects the put-back, not this)
        //   chksum - the engine's marker round trip through the CLAMPED writer
        kmem_write64_raw(pcb + l->filtOff, 0x4141414141414141ULL);
        kmem_write64_raw(pcb + l->chksumOff, savedFilt8);
        bool marker = krw_zone_write_qword(pcb + l->chksumOff, 0xDEADBEEFULL, pcb, window) == KRW_ZONE_OK;
        snprintf(what, sizeof(what), "  %s: the probe's marker write is inside the declared window",
                 l->label);
        check(marker, what);
        check(kmem_read64(pcb + l->chksumOff) == 0xDEADBEEFULL,
              "  ... and the marker is in the object (the corruption is live)");

        int blocksBeforeCorruption = g_block_count;
        restore_report rep;
        probe_restore_model(-1, true, true, pcb, l->filtOff, window, savedFilt, savedFilt8, &rep);

        check(rep.action == PROBE_ACTION_RESTORE, "  exit -1 (write-verify exhaustion) restores");
        check(rep.fdSource == PROBE_FD_SOURCE_FILEPORTS,
              "  ... through the spray tracking array (it still holds the pair)");
        check(rep.attemptedWrite && rep.restored,
              "  ... and the saved values are back in the object (read back, not assumed)");
        check(kmem_read64(pcb + l->filtOff) == savedFilt &&
              kmem_read64(pcb + l->chksumOff) == savedFilt8,
              "  ... both fields byte-identical to the saved values (marker gone)");
        check(rep.blocksAfter == blocksBeforeCorruption + 2,
              "  ... the put-back emitted exactly the two blocks (one per qword)");
        check(g_oob_writes == 0 && g_oob_reads == 0,
              "  ... and not one of them left the declared inpcb window");
        check(kmem_read64(pcb + l->filtOff - 8) == 0xa5a5a5a5a5a5a5a5ULL,
              "  ... the qword before the first put-back field was not touched");
    }
}

// ---------------------------------------------------------------------------
// 3. restore on CANCEL (probe exit -7: cancel / scan budget)
// ---------------------------------------------------------------------------
static void case_restore_on_cancel(void)
{
    const inpcb_layout *l = &g_layouts[0];
    uint64_t window = inpcb_window_for(l);
    uint64_t savedFilt = 0xffffffe0d1f26000ULL;
    uint64_t savedFilt8 = 0x0000ffffffffffffULL;

    // (a) cancel before the release funnel: the spray array still holds the pair
    reset(OBJECT_OFF, window);
    uint64_t pcb = g_obj_base;
    kmem_write64_raw(pcb + l->filtOff, 0x4141414141414141ULL);
    kmem_write64_raw(pcb + l->chksumOff, 0x4242424242424242ULL);
    restore_report rep;
    probe_restore_model(-7, true, false, pcb, l->filtOff, window, savedFilt, savedFilt8, &rep);
    check(rep.action == PROBE_ACTION_RESTORE, "cancel (-7) restores (it is not the promotion)");
    check(rep.fdSource == PROBE_FD_SOURCE_FILEPORTS && rep.restored,
          "cancel in the write-verify loop: the pair is re-opened from the array and the values go back");
    check(kmem_read64(pcb + l->filtOff) == savedFilt &&
          kmem_read64(pcb + l->chksumOff) == savedFilt8,
          "cancel: both fields are byte-identical to the saved values again");

    // (b) cancel after pe_v1's release funnel emptied the array (the staged -5
    //     shape): only the promotion's still-open fds for THIS corruption remain
    reset(OBJECT_OFF, window);
    kmem_write64_raw(pcb + l->filtOff, 0x4141414141414141ULL);
    kmem_write64_raw(pcb + l->chksumOff, 0x4242424242424242ULL);
    probe_restore_model(-7, false, true, pcb, l->filtOff, window, savedFilt, savedFilt8, &rep);
    check(rep.fdSource == PROBE_FD_SOURCE_PROMOTION_FDS,
          "cancel after the array was released: the promotion's fds are used (not UNREACHABLE)");
    check(rep.restored,
          "cancel after the release funnel: the saved values still go back (BUG.1's 'one exit later')");

    // (c) a pair opened for an EARLIER save must not be used
    reset(OBJECT_OFF, window);
    kmem_write64_raw(pcb + l->filtOff, 0x4141414141414141ULL);
    kmem_write64_raw(pcb + l->chksumOff, 0x4242424242424242ULL);
    int blocksBefore = g_block_count;
    capture_begin();
    probe_restore_model(-7, false, false, pcb, l->filtOff, window, savedFilt, savedFilt8, &rep);
    capture_end();
    check(rep.fdSource == PROBE_FD_SOURCE_UNREACHABLE && !rep.attemptedWrite,
          "cancel with no usable fd pair: the restore writes NOTHING (no write through a foreign socket)");
    check(g_block_count == blocksBefore && !rep.restored,
          "  ... and it reports a FAILED restore, never a silent success");
    check(kmem_read64(pcb + l->filtOff) == 0x4141414141414141ULL,
          "  ... the field is still corrupted, which is what the failure report says");
}

// ---------------------------------------------------------------------------
// 4. the promotion is handed over, not restored
// ---------------------------------------------------------------------------
static void case_promotion_hands_off(void)
{
    const inpcb_layout *l = &g_layouts[0];
    uint64_t window = inpcb_window_for(l);
    reset(OBJECT_OFF, window);
    uint64_t pcb = g_obj_base;
    kmem_write64_raw(pcb + l->filtOff, 0x4141414141414141ULL);

    restore_report rep;
    probe_restore_model(PROBE_EXIT_PROMOTED, true, true, pcb, l->filtOff, window,
                        0xffffffe0d1f26000ULL, 0x0000ffffffffffffULL, &rep);
    check(rep.action == PROBE_ACTION_HAND_OFF, "the promotion (0) is handed to the caller");
    check(!rep.attemptedWrite && rep.blocksAfter == rep.blocksBefore,
          "  ... and this path issues no put-back at all (the corrupted socket IS the primitive)");
}

// ---------------------------------------------------------------------------
// 5. the clamp covers the RESTORE's own put-back (BUG.1 step 3b)
// ---------------------------------------------------------------------------
// Before step 3b the put-back went through early_kwrite64: an unclamped 32-byte
// RMW at whatever pcb the walk produced. Now every put-back block has to be
// proven against the declared window first, so the two shapes that used to be
// written unproven are refused - and a refused put-back is reported as the
// failure it is, with no byte written.
static void case_restore_putback_overrun_is_refused(void)
{
    const inpcb_layout *l = &g_layouts[0];

    // (a) the caller declares the object it really knows - the kalloc.96 bucket
    //     - while the field table puts the restored qwords at 0x148: the
    //     declaration does not contain them, so nothing may be written.
    reset(OBJECT_OFF, KALLOC96_SIZE);
    uint64_t pcb = g_obj_base;
    uint8_t before[KMEM_SIZE];
    memcpy(before, g_kmem, sizeof before);

    restore_report rep;
    capture_begin();
    probe_restore_model(-1, true, true, pcb, l->filtOff, KALLOC96_SIZE, 0xAA, 0xBB, &rep);
    capture_end();

    check(rep.fdSource == PROBE_FD_SOURCE_FILEPORTS && rep.attemptedWrite,
          "the restore is attempted (its fd pair is live) with the kalloc.96 bucket declared");
    check(!rep.restored, "  ... and it is reported as a FAILED restore, never as a written one");
    check(g_block_count == 0 && g_oob_writes == 0,
          "  ... not one block was emitted for the put-back (refused, not written unproven)");
    check(memcmp(before, g_kmem, sizeof before) == 0,
          "  ... no kernel byte changed anywhere in the window");
    check(cap_has("[krw] refusing 32-byte block") && cap_has("no enclosing object declared"),
          "  ... and the refusal names the missing declaration");

    // (b) a declared window that CUTS the qword's 0x20-aligned block: the qword
    //     itself is inside the window, the block the writer would emit is not.
    //     (A window of 0x50 with the field at +0x40: the block +0x40..+0x60
    //     leaves it. The clamp proves blocks, not bare addresses.)
    reset(OBJECT_OFF, 0x50);
    pcb = g_obj_base;
    memcpy(before, g_kmem, sizeof before);
    capture_begin();
    probe_restore_model(-1, true, true, pcb, 0x40, 0x50, 0xAA, 0xBB, &rep);
    capture_end();
    check(!rep.restored && rep.attemptedWrite && g_block_count == 0 && g_oob_writes == 0,
          "a window that cuts the put-back's aligned block: refused, no block, no restore claimed");
    check(cap_has("is outside object"),
          "  ... the refusal names the block and the object it would leave");
    check(memcmp(before, g_kmem, sizeof before) == 0, "  ... and no kernel byte changed");

    // (c) the same put-back with the field-derived window the engine declares:
    //     the block is inside it and the values DO go back. This is the pair of
    //     checks that makes (a) and (b) meaningful rather than vacuous.
    uint64_t window = inpcb_window_for(l);
    reset(OBJECT_OFF, window);
    pcb = g_obj_base;
    kmem_write64_raw(pcb + l->filtOff, 0x4141414141414141ULL);
    kmem_write64_raw(pcb + l->chksumOff, 0x4242424242424242ULL);
    probe_restore_model(-1, true, false, pcb, l->filtOff, window, 0xAA, 0xBB, &rep);
    check(rep.fdSource == PROBE_FD_SOURCE_FILEPORTS && rep.restored,
          "the same put-back under the engine's field-derived window does go back");
    check(g_oob_writes == 0 && g_oob_reads == 0,
          "  ... with every block and RMW read inside the declared window");
}

// ---------------------------------------------------------------------------
// 6. window arithmetic: what the probe declares is derived, not guessed
// ---------------------------------------------------------------------------
static void case_declared_window_is_derived(void)
{
    for (size_t i = 0; i < sizeof(g_layouts) / sizeof(g_layouts[0]); i++) {
        const inpcb_layout *l = &g_layouts[i];
        char what[192];
        uint64_t window = inpcb_window_for(l);
        snprintf(what, sizeof(what), "%s: the declared window is 0x160 (field end rounded up)",
                 l->label);
        check(window == 0x160, what);

        snprintf(what, sizeof(what), "%s: both put-back qwords share one 0x20-aligned block",
                 l->label);
        check(krw_zone_block_align_down(l->filtOff) == krw_zone_block_align_down(l->chksumOff), what);

        reset(OBJECT_OFF, window);
        uint64_t pcb = g_obj_base;
        snprintf(what, sizeof(what), "%s: the declared window contains both put-back qwords",
                 l->label);
        check(krw_zone_window_contains(pcb + l->filtOff, pcb, window) &&
              krw_zone_window_contains(pcb + l->chksumOff, pcb, window), what);

        snprintf(what, sizeof(what),
                 "%s: the 32-byte block holding them ends inside the window (no refusal)",
                 l->label);
        check(krw_zone_block_align_down(pcb + l->filtOff) + KRW_ZONE_BLOCK_LEN <= pcb + window, what);
    }
}

int main(void)
{
    printf("probe_restore_e2e_host_test (BUG.1: the 32-byte overrun clamp + the restore path, end to end)\n");

    printf("\n1. the 32-byte overrun (the SE panic) is injected and refused:\n");
    case_overrun_injection();

    printf("\n2. the probe's save -> corrupt -> exit -> put-back sequence, on ERROR:\n");
    case_restore_on_error();

    printf("\n3. the same sequence on CANCEL (-7), including after the spray array was released:\n");
    case_restore_on_cancel();

    printf("\n4. the promotion is handed over, not restored:\n");
    case_promotion_hands_off();

    printf("\n5. the clamp covers the restore's own put-back (step 3b):\n");
    case_restore_putback_overrun_is_refused();

    printf("\n6. the declared window is derived from the field offsets:\n");
    case_declared_window_is_derived();

    printf("\nchecks=%d failures=%d\n", g_checks, g_failures);
    if (g_failures == 0) {
        printf("PROBE_RESTORE_E2E_HOST_TEST PASS\n");
        return 0;
    }
    printf("PROBE_RESTORE_E2E_HOST_TEST FAIL\n");
    return 1;
}
