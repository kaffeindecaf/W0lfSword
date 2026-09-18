//
//  krw_zone_size_host_test.c
//  W0lfSword - host test for BUG.7 (ROADMAP 0.13): the kalloc BUCKET size read
//  from the zone, and the window decision built on it.
//
//  BUG.1 step 3b made every 32-byte write prove itself against SOME object; the
//  object it could name was the struct's own field span (0x160), because the
//  tree had no way to ask the kernel how big the allocation really was. The
//  scale of that guess is the SE's panic: a 32-byte block at +0x50 of a 96-byte
//  kalloc.96 object (zalloc.c:1322).
//
//  This test compiles the REAL kexploit/krw_zone_size.c - the file the engine
//  archive and the tweak build both compile - against a fake kernel window, and
//  drives:
//
//    1. the qword extraction (z_elem_size is a uint16_t inside an aligned qword,
//       so a wrong offset must yield a value the plausibility check rejects, not
//       a plausible lie);
//    2. the kalloc size-class check (16 .. 16384 - the only element sizes a
//       kalloc zone can have);
//    3. the whole chain pcb -> inpcbinfo.ipi_zone -> z_elem_size, including
//       every hop that must be refused: a non-canonical pointer at any level,
//       an offsets table without the field, a zone whose element size is not a
//       size class;
//    4. the window decision, including the case this bug is about - a bucket
//       that CONTRADICTS the field table (96 < 0x160) must refuse every write
//       rather than hand the caller a self-consistent window.
//
//  No kernel is touched and no device command is run.
//
//  Run: bash scripts/run_krw_zone_size_host_test.sh
//
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "kexploit/krw_zone_size.h"
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

// ---------------------------------------------------------------------------
// fake kernel window: a byte array the reader serves qwords out of, plus a
// transcript of every read so the test can prove WHICH address was read (the
// aligned qword, not the field's own address).
// ---------------------------------------------------------------------------
#define FAKE_BASE 0xffffffe000000000ULL
#define KMEM_SIZE 0x400

static uint8_t g_kmem[KMEM_SIZE];
static uint64_t g_reads[16];
static int g_read_count;
static bool g_read_oob;

static void kmem_reset(void)
{
    memset(g_kmem, 0, sizeof(g_kmem));
    g_read_count = 0;
    g_read_oob = false;
}

static void kmem_store64(uint64_t addr, uint64_t value)
{
    uint64_t off = addr - FAKE_BASE;
    if (off + 8 > KMEM_SIZE) return;
    memcpy(&g_kmem[off], &value, sizeof(value));
}

static uint64_t fake_read64(uint64_t where)
{
    if (g_read_count < (int)(sizeof(g_reads) / sizeof(g_reads[0]))) {
        g_reads[g_read_count] = where;
    }
    g_read_count++;
    if (where < FAKE_BASE || where - FAKE_BASE + 8 > KMEM_SIZE) {
        g_read_oob = true;
        return 0;
    }
    uint64_t value;
    memcpy(&value, &g_kmem[where - FAKE_BASE], sizeof(value));
    return value;
}

// ---------------------------------------------------------------------------
// krw_zone_write.c's two block primitives (krw.m provides them on device).
// This test drives only that file's pure decisions, but the linker pulls the
// whole object in, so they have to exist - and they are implemented over the
// same fake window rather than stubbed out, so a block that left the window
// would be recorded if any check ever reached one.
// ---------------------------------------------------------------------------
static int g_blocks_read;
static int g_blocks_written;
static int g_block_oob;

void krw_zone_read_block(uint64_t where, uint8_t *buf)
{
    if (where < FAKE_BASE || where - FAKE_BASE + KRW_ZONE_BLOCK_LEN > KMEM_SIZE) {
        g_block_oob++;
        memset(buf, 0, KRW_ZONE_BLOCK_LEN);
        return;
    }
    g_blocks_read++;
    memcpy(buf, &g_kmem[where - FAKE_BASE], KRW_ZONE_BLOCK_LEN);
}

void krw_zone_write_block(uint64_t where, const uint8_t *buf)
{
    if (where < FAKE_BASE || where - FAKE_BASE + KRW_ZONE_BLOCK_LEN > KMEM_SIZE) {
        g_block_oob++;
        return;
    }
    g_blocks_written++;
    memcpy(&g_kmem[where - FAKE_BASE], buf, KRW_ZONE_BLOCK_LEN);
}

// The layout the engine ships (offsets.m): the inpcb's inpcbinfo pointer, the
// inpcbinfo's zone pointer, and struct zone's z_elem_size inside the qword at
// +0x30 (field offset 4 in that qword).
#define OFF_PCBINFO 0x28u
#define OFF_IPI_ZONE 0x68u
#define OFF_ELEM_SIZE 0x34u

#define PCB_ADDR (FAKE_BASE + 0x100)
#define PCBINFO_ADDR (FAKE_BASE + 0x180)
#define ZONE_ADDR (FAKE_BASE + 0x200)

// A window that a working chain produces: pcb -> pcbinfo -> zone, with the zone
// carrying `elem` as its element size.
static void kmem_wire_chain(uint64_t elem)
{
    kmem_reset();
    uint64_t qword_at_0x30 = 0;
    unsigned shift = (OFF_ELEM_SIZE & 7u) * 8u;
    qword_at_0x30 |= (elem & 0xffffULL) << shift;
    // Neighbours that must not leak into the field: z_align_magic above the
    // u16s and z_elem_offs below them.
    qword_at_0x30 |= 0xdeadULL << 48;
    qword_at_0x30 |= 0xbeefULL << 16;
    kmem_store64(PCB_ADDR + OFF_PCBINFO, PCBINFO_ADDR);
    kmem_store64(PCBINFO_ADDR + OFF_IPI_ZONE, ZONE_ADDR);
    kmem_store64(ZONE_ADDR + (OFF_ELEM_SIZE & ~7u), qword_at_0x30);
}

// ---------------------------------------------------------------------------
// 1. z_elem_size out of the qword that holds it
// ---------------------------------------------------------------------------
static void test_qword_extraction(void)
{
    printf("z_elem_size out of one aligned qword:\n");

    // 0x0000_0096_0000_0000: field at byte 4 of the qword = the shipped layout.
    check(krw_zone_elem_size_from_qword(0x0000009600000000ULL, 4) == 0x96,
          "byte 4 in the qword (the shipped +0x34 layout) reads 0x96");
    check(krw_zone_elem_size_from_qword(0x0000000000000096ULL, 0) == 0x96,
          "byte 0 in the qword reads the field");
    check(krw_zone_elem_size_from_qword(0x0096000000000000ULL, 6) == 0x96,
          "byte 6 in the qword (the last offset a u16 fits) reads the field");

    // The mask is what keeps a wrong offset from becoming a plausible lie.
    check(krw_zone_elem_size_from_qword(0x0000009600000060ULL, 0) == 0x60,
          "masking takes only the field's two bytes (0x60, not a merged 0x960060)");
    check(krw_zone_elem_size_from_qword(0x0000009600000000ULL, 3) == 0x9600 &&
          !krw_bucket_size_plausible(0x9600),
          "a shifted read of the same qword yields 0x9600, which the size-class check rejects");

    // Nothing to extract: a field that does not fit the qword is not a read the
    // caller may make.
    check(krw_zone_elem_size_from_qword(0xffffffffffffffffULL, 7) == 0,
          "field offset 7 (a u16 would not fit) returns 0 instead of a truncated value");
    check(krw_zone_elem_size_from_qword(0xffffffffffffffffULL, 8) == 0,
          "field offset 8 returns 0");

    // The field is a u16: a qword full of ones yields 0xffff, which the
    // plausibility check then rejects (not a size any kalloc zone has).
    check(krw_zone_elem_size_from_qword(0xffffffffffffffffULL, 4) == 0xffff,
          "a u16 field is masked to 16 bits (0xffff), not widened");
    check(!krw_bucket_size_plausible(0xffff), "0xffff is not a kalloc size class");
}

// ---------------------------------------------------------------------------
// 2. the kalloc size classes
// ---------------------------------------------------------------------------
static void test_size_classes(void)
{
    printf("kalloc size classes:\n");

    check(krw_bucket_size_plausible(16) && krw_bucket_size_plausible(32) &&
          krw_bucket_size_plausible(96) && krw_bucket_size_plausible(1024) &&
          krw_bucket_size_plausible(16384),
          "the class edges are plausible (16/32/96/1024/16384)");
    check(krw_bucket_size_plausible(96) && krw_bucket_size_plausible(112) &&
          krw_bucket_size_plausible(160) && krw_bucket_size_plausible(192),
          "the dense low classes are plausible (96/112/160/192)");

    check(!krw_bucket_size_plausible(0), "0 is not a size class (nothing was read)");
    check(!krw_bucket_size_plausible(8), "8 is not a size class");
    check(!krw_bucket_size_plausible(24), "24 is not a size class (holes between classes matter)");
    check(!krw_bucket_size_plausible(100), "100 is not a size class");
    check(!krw_bucket_size_plausible(0x10000), "0x10000 is not a size class (the top is 16384)");
    check(!krw_bucket_size_plausible(0x1234), "0x1234 (the shape a wrong offset yields) is not a size class");

    char buf[64];
    krw_bucket_size_name(96, buf, sizeof(buf));
    check(strcmp(buf, "96") == 0, "a bucket logs as its own number");
    krw_bucket_size_name(0x1234, buf, sizeof(buf));
    check(strstr(buf, "not a kalloc class") != NULL,
          "a non-class value logs as 'not a kalloc class' instead of a number");
    krw_bucket_size_name(96, buf, 3);
    check(buf[2] == '\0', "the name never writes past the buffer it is given");
}

// ---------------------------------------------------------------------------
// 3. the chain: pcb -> inpcbinfo.ipi_zone -> z_elem_size
// ---------------------------------------------------------------------------
static void test_chain(void)
{
    printf("pcb -> inpcbinfo.ipi_zone -> z_elem_size:\n");

    kmem_wire_chain(0x60);
    uint64_t bucket = krw_zone_bucket_for_pcb(PCB_ADDR, OFF_PCBINFO, OFF_IPI_ZONE,
                                              OFF_ELEM_SIZE, fake_read64);
    check(bucket == 0x60, "a wired chain returns the zone's element size (0x60)");
    check(g_read_count == 3, "the chain reads exactly three qwords (one per hop)");
    check(g_reads[0] == PCB_ADDR + OFF_PCBINFO, "hop 1 reads pcb + off_inpcb_inp_pcbinfo");
    check(g_reads[1] == PCBINFO_ADDR + OFF_IPI_ZONE, "hop 2 reads inpcbinfo + off_inpcbinfo_ipi_zone");
    check(g_reads[2] == ZONE_ADDR + (OFF_ELEM_SIZE & ~7u),
          "hop 3 reads the ALIGNED qword holding z_elem_size (0x30, not 0x34)");
    check(!g_read_oob, "no read left the window");

    // The neighbours in the qword must not leak into the bucket.
    check(bucket == 0x60,
          "the qword's other bytes (z_align_magic / z_elem_offs) do not leak into the bucket");

    // A non-canonical pointer at any hop is an unknown bucket, not a read of a
    // bogus address - this is the hop that keeps the chain from following a
    // garbage pcb on a device whose offsets are wrong.
    kmem_wire_chain(0x60);
    check(krw_zone_bucket_for_pcb(0x0000000100000000ULL, OFF_PCBINFO, OFF_IPI_ZONE,
                                  OFF_ELEM_SIZE, fake_read64) == 0,
          "a non-canonical pcb is refused");
    check(g_read_count == 0, "no kernel read is issued for a non-canonical pcb");

    kmem_wire_chain(0x60);
    kmem_store64(PCB_ADDR + OFF_PCBINFO, 0x0000000100000000ULL);
    check(krw_zone_bucket_for_pcb(PCB_ADDR, OFF_PCBINFO, OFF_IPI_ZONE,
                                  OFF_ELEM_SIZE, fake_read64) == 0,
          "a non-canonical inpcbinfo pointer is refused");
    check(g_read_count == 1, "the chain stops at the hop it cannot trust");

    kmem_wire_chain(0x60);
    kmem_store64(PCBINFO_ADDR + OFF_IPI_ZONE, 0x0000dead00000000ULL);
    check(krw_zone_bucket_for_pcb(PCB_ADDR, OFF_PCBINFO, OFF_IPI_ZONE,
                                  OFF_ELEM_SIZE, fake_read64) == 0,
          "a non-canonical zone pointer is refused");
    check(g_read_count == 2, "the chain does not read the element size through it");

    // A zone that IS reachable but whose element size is not a class: a wrong
    // zone, a wrong offset, or a zone this tree knows nothing about. All three
    // mean "unknown bucket" (the caller keeps its own field span).
    kmem_wire_chain(0x1234);
    check(krw_zone_bucket_for_pcb(PCB_ADDR, OFF_PCBINFO, OFF_IPI_ZONE,
                                  OFF_ELEM_SIZE, fake_read64) == 0,
          "an element size that is not a kalloc class is reported as unknown");
    kmem_wire_chain(0);
    check(krw_zone_bucket_for_pcb(PCB_ADDR, OFF_PCBINFO, OFF_IPI_ZONE,
                                  OFF_ELEM_SIZE, fake_read64) == 0,
          "a zero element size is reported as unknown");

    // No reader / no offsets entry: the chain cannot run and must not guess.
    kmem_wire_chain(0x60);
    check(krw_zone_bucket_for_pcb(PCB_ADDR, OFF_PCBINFO, OFF_IPI_ZONE, OFF_ELEM_SIZE, NULL) == 0,
          "no reader means no bucket");
    check(krw_zone_bucket_for_pcb(PCB_ADDR, OFF_PCBINFO, OFF_IPI_ZONE, 0, fake_read64) == 0,
          "an offsets table without z_elem_size means no bucket");
    check(krw_zone_bucket_for_pcb(0, OFF_PCBINFO, OFF_IPI_ZONE, OFF_ELEM_SIZE, fake_read64) == 0,
          "no pcb means no bucket");
    check(g_read_count == 0, "none of those three issued a kernel read");
}

// ---------------------------------------------------------------------------
// 4. the window decision (what the clamp is actually given)
// ---------------------------------------------------------------------------
#define FIELD_SPAN 0x160u   // filt offset + 8, rounded up: both inpcb layouts

static void test_window_decision(void)
{
    printf("the window a caller may declare:\n");

    uint64_t window = 0xdead;

    // The case the SE panic was: the zone says 96 bytes, the field table needs
    // 0x160. Both numbers came from the kernel; they disagree, so the object the
    // caller thinks it has is not the object it has. Refuse.
    krw_zone_window_verdict verdict =
        krw_zone_window_from_bucket(PCB_ADDR, PCB_ADDR + FIELD_SPAN, 96, &window);
    check(verdict == KRW_WINDOW_REFUSE_BUCKET_SMALLER,
          "a plausible bucket SMALLER than the field span is refused (the SE's shape)");
    check(window == 0, "the refusal hands the caller an empty window");
    check(!krw_zone_window_contains(PCB_ADDR + 0x50, PCB_ADDR, window),
          "through the writer, an empty window refuses every block");

    // The widening: a bucket at or above the field span becomes the declaration,
    // and it is the kernel's statement about the allocation.
    window = 0;
    verdict = krw_zone_window_from_bucket(PCB_ADDR, PCB_ADDR + FIELD_SPAN, 0x200, &window);
    check(verdict == KRW_WINDOW_BUCKET && window == 0x200,
          "a bucket above the field span is declared as the window (0x200)");
    // A bucket exactly equal to the field span is accepted - the boundary the
    // refusal below must not overshoot. 0x180 (384) is both a span and a size
    // class, which is what lets the equality be tested at all.
    window = 0;
    verdict = krw_zone_window_from_bucket(PCB_ADDR, PCB_ADDR + 0x180, 0x180, &window);
    check(verdict == KRW_WINDOW_BUCKET && window == 0x180,
          "a bucket equal to the field span is accepted (the boundary)");
    window = 0;
    verdict = krw_zone_window_from_bucket(PCB_ADDR, PCB_ADDR + 0x200, 0x1c0, &window);
    check(verdict == KRW_WINDOW_REFUSE_BUCKET_SMALLER && window == 0,
          "one size class below that span (448 vs 512) is refused (the check is not vacuous)");

    // Unknown bucket: the pre-BUG.7 behaviour, so a failed read can never turn a
    // working put-back into a refusal.
    window = 0;
    verdict = krw_zone_window_from_bucket(PCB_ADDR, PCB_ADDR + FIELD_SPAN, 0, &window);
    check(verdict == KRW_WINDOW_FIELD_SPAN && window == FIELD_SPAN,
          "an unknown bucket keeps the caller's own field span");
    window = 0;
    verdict = krw_zone_window_from_bucket(PCB_ADDR, PCB_ADDR + FIELD_SPAN, 0x1234, &window);
    check(verdict == KRW_WINDOW_FIELD_SPAN && window == FIELD_SPAN,
          "a bucket that is not a size class keeps the field span");

    // The field span is rounded to a whole 0x20 block by the caller
    // (krw_zone_window_for_field_end) - a field ending at 0x158 implies 0x160.
    check(krw_zone_window_for_field_end(0x158) == 0x160,
          "the field span is rounded up to a whole block (0x158 -> 0x160)");
    check(krw_zone_window_for_field_end(0x150) == 0x160,
          "the 17.x layout's filt+8 (0x158) also lands on 0x160");

    // Nothing to declare: base 0 or an empty span is a refusal, not a window.
    window = 0xdead;
    verdict = krw_zone_window_from_bucket(0, FIELD_SPAN, 0x200, &window);
    check(verdict == KRW_WINDOW_REFUSE_BUCKET_SMALLER && window == 0,
          "a zero base is refused (an unusable pcb declares nothing)");
    window = 0xdead;
    verdict = krw_zone_window_from_bucket(PCB_ADDR, PCB_ADDR, 0x200, &window);
    check(verdict == KRW_WINDOW_REFUSE_BUCKET_SMALLER && window == 0,
          "an empty field span is refused");

    // The three verdicts are distinguishable in the log.
    check(strcmp(krw_zone_window_verdict_name(KRW_WINDOW_FIELD_SPAN),
                 krw_zone_window_verdict_name(KRW_WINDOW_BUCKET)) != 0 &&
          strcmp(krw_zone_window_verdict_name(KRW_WINDOW_FIELD_SPAN),
                 krw_zone_window_verdict_name(KRW_WINDOW_REFUSE_BUCKET_SMALLER)) != 0,
          "each verdict has its own log name (a refusal is readable in a device log)");
    check(krw_zone_window_verdict_name((krw_zone_window_verdict)99) != NULL,
          "an unknown verdict still names something (no NULL in the log)");
}

// ---------------------------------------------------------------------------
// 5. end to end: the chain's answer decides what the writer may emit
// ---------------------------------------------------------------------------
static void test_chain_feeds_the_writer(void)
{
    printf("the chain's verdict is what the clamp is given:\n");

    // A zone that says 0x200 for an inpcb whose fields reach 0x160: the block the
    // probe's put-back writes (the qword at filt+8 and its aligned block) is
    // inside the bucket.
    kmem_wire_chain(0x200);
    uint64_t bucket = krw_zone_bucket_for_pcb(PCB_ADDR, OFF_PCBINFO, OFF_IPI_ZONE,
                                              OFF_ELEM_SIZE, fake_read64);
    uint64_t window = 0;
    krw_zone_window_verdict verdict =
        krw_zone_window_from_bucket(PCB_ADDR, PCB_ADDR + FIELD_SPAN, bucket, &window);
    check(verdict == KRW_WINDOW_BUCKET, "a healthy chain promotes to the bucket window");

    krw_zone_verdict bounds = krw_zone_check_bounds(PCB_ADDR + 0x140, 0x20, PCB_ADDR, window, true, NULL);
    check(bounds == KRW_ZONE_OK, "the put-back qword's aligned block inside the bucket window is allowed");

    // The same object if the zone had said 0x60 (the SE's kalloc.96): the field
    // span and the bucket contradict each other, the window is empty, and the
    // write that panicked the SE is refused instead of shifted backwards.
    kmem_wire_chain(0x60);
    bucket = krw_zone_bucket_for_pcb(PCB_ADDR, OFF_PCBINFO, OFF_IPI_ZONE,
                                     OFF_ELEM_SIZE, fake_read64);
    window = 0;
    verdict = krw_zone_window_from_bucket(PCB_ADDR, PCB_ADDR + FIELD_SPAN, bucket, &window);
    check(verdict == KRW_WINDOW_REFUSE_BUCKET_SMALLER && window == 0,
          "the SE's bucket (0x60) against the 0x160 field span is refused");
    bounds = krw_zone_check_bounds(PCB_ADDR + 0x50, 0x20, PCB_ADDR, window, true, NULL);
    check(bounds == KRW_ZONE_REFUSE_PAST_END || bounds == KRW_ZONE_REFUSE_UNDECLARED,
          "and the SE's exact write shape is refused, not emitted");
}

int main(void)
{
    printf("BUG.7 (0.13) host test - the kalloc bucket from the zone\n\n");

    test_qword_extraction();
    test_size_classes();
    test_chain();
    test_window_decision();
    test_chain_feeds_the_writer();

    printf("\nchecks=%d failures=%d\n", g_checks, g_failures);
    if (g_failures == 0) {
        printf("KRW_ZONE_SIZE_HOST_TEST PASS\n");
        return 0;
    }
    printf("KRW_ZONE_SIZE_HOST_TEST FAIL\n");
    return 1;
}
