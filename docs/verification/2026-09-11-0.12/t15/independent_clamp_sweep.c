//
//  independent_clamp_sweep.c - T15 independent check of the BUG.1 clamp.
//
//  Written for this closing pass, NOT a re-run of the project's own harness: it
//  links the shipped clamp (kexploit/krw_zone_write.c, the same source the
//  engine archive builds) against ITS OWN monitor and sweeps the address/length
//  space around a kalloc.96-sized object, asserting the one property that
//  matters on device:
//
//      a block the writer emits is never outside the object it declared,
//      and a refused call emits nothing at all.
//
//  The monitor here is deliberately not the project's: it records every block
//  and every byte the primitives touch and reports any 0x20 window that is not
//  fully inside the declared object. A violation is printed with the exact
//  address pair; a clean sweep prints the counts.
//
//  Host only. No device, no exploit, no kernel.
//
//    cc -std=gnu99 -Wall -Wextra -Wno-unused-parameter -I. -o /tmp/indep_clamp
//       docs/verification/2026-09-11-0.12/t15/independent_clamp_sweep.c
//       kexploit/krw_zone_write.c
//    /tmp/indep_clamp
//
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "kexploit/krw_zone_write.h"

#define FAKE_BASE 0xffffffe000000000ULL
#define WINDOW    0x4000u
#define OBJ_OFF   0x100u
#define FILL      0x5A

static uint8_t g_mem[WINDOW];
static uint64_t g_obj_base;
static uint64_t g_obj_size;

static unsigned long g_blocks;
static unsigned long g_oob_blocks;
static unsigned long g_oob_reads;
static unsigned long g_changed_bytes;

static void reset(uint64_t obj_size)
{
    memset(g_mem, FILL, sizeof g_mem);
    g_obj_base = FAKE_BASE + OBJ_OFF;
    g_obj_size = obj_size;
    g_blocks = g_oob_blocks = g_oob_reads = g_changed_bytes = 0;
}

static bool block_inside(uint64_t where)
{
    return where >= g_obj_base && where + KRW_ZONE_BLOCK_LEN <= g_obj_base + g_obj_size;
}

void krw_zone_read_block(uint64_t where, uint8_t *buf)
{
    if (where < FAKE_BASE || where - FAKE_BASE + KRW_ZONE_BLOCK_LEN > WINDOW || !block_inside(where)) {
        g_oob_reads++;                      // on device: a read outside the object
        memset(buf, 0, KRW_ZONE_BLOCK_LEN);
        return;
    }
    memcpy(buf, g_mem + (where - FAKE_BASE), KRW_ZONE_BLOCK_LEN);
}

void krw_zone_write_block(uint64_t where, const uint8_t *buf)
{
    g_blocks++;
    if (where < FAKE_BASE || where - FAKE_BASE + KRW_ZONE_BLOCK_LEN > WINDOW || !block_inside(where)) {
        g_oob_blocks++;                     // on device: zalloc.c:1322 and a reboot
        return;
    }
    uint8_t *dst = g_mem + (where - FAKE_BASE);
    for (size_t i = 0; i < KRW_ZONE_BLOCK_LEN; i++) {
        if (dst[i] != buf[i]) g_changed_bytes++;
    }
    memcpy(dst, buf, KRW_ZONE_BLOCK_LEN);
}

int main(void)
{
    printf("independent clamp sweep (BUG.1 step 3/3b) - kexploit/krw_zone_write.c, own monitor\n");
    unsigned long shapes = 0, allowed = 0, refused = 0, violations = 0;

    // The object the SE panicked on: kalloc.96 = 0x60 bytes. The sweep also runs
    // the neighbours (0x20 and 0x40, the buckets whose blocks tile exactly) and
    // a bigger object, so a pass is not an artifact of one size.
    const uint64_t sizes[] = { 0x20, 0x40, 0x60, 0x80, 0x160 };
    uint8_t src[0x120];
    memset(src, 0xC3, sizeof src);

    // 1. every (offset, length) shape: -0x40 .. +0x80 around the object, lengths
    //    0x08..0x100 in 8-byte steps, object declared and undeclared.
    for (size_t s = 0; s < sizeof(sizes) / sizeof(sizes[0]); s++) {
        for (int64_t rel = -0x40; rel <= 0x80; rel += 8) {
            for (uint64_t len = 0x08; len <= 0x100; len += 8) {
                for (int declared = 0; declared <= 1; declared++) {
                    for (int qword = 0; qword <= 1; qword++) {
                        reset(sizes[s]);
                        uint64_t dst = g_obj_base + (rel < 0 ? 0 : (uint64_t)rel);
                        if (rel < 0) dst = g_obj_base - (uint64_t)(-rel);
                        uint64_t base = declared ? g_obj_base : 0;
                        uint64_t size = declared ? sizes[s] : 0;

                        krw_zone_verdict v;
                        if (qword) {
                            v = krw_zone_write_qword(dst, 0x1122334455667788ULL, base, size);
                        } else {
                            v = krw_zone_write(dst, src, len, base, size);
                            if (v == KRW_ZONE_REFUSE_LEN) continue;   // < one block: documented
                        }
                        shapes++;
                        if (v == KRW_ZONE_OK) {
                            allowed++;
                        } else {
                            refused++;
                            if (g_blocks != 0) {
                                violations++;
                                printf("  VIOLATION: refused call emitted %lu block(s)"
                                       " (obj %#llx+%#llx dst %#llx len %#llx qword %d)\n",
                                       g_blocks, (unsigned long long)base,
                                       (unsigned long long)size, (unsigned long long)dst,
                                       (unsigned long long)(qword ? 8 : len), qword);
                            }
                            if (g_changed_bytes != 0) {
                                violations++;
                                printf("  VIOLATION: refused call changed %lu byte(s)\n", g_changed_bytes);
                            }
                        }
                        if (g_oob_blocks != 0) {
                            violations++;
                            printf("  VIOLATION: %lu emitted block(s) left the object"
                                   " (obj %#llx+%#llx dst %#llx len %#llx qword %d)\n",
                                   g_oob_blocks, (unsigned long long)base,
                                   (unsigned long long)size, (unsigned long long)dst,
                                   (unsigned long long)(qword ? 8 : len), qword);
                        }
                        if (g_oob_reads != 0) {
                            violations++;
                            printf("  VIOLATION: %lu RMW read(s) left the object\n", g_oob_reads);
                        }
                    }
                }
            }
        }
    }

    // 2. the SE write, named: 0x20 at +0x50 of a 0x60 object, declared and not.
    struct { int declared; uint64_t len; } se[] = { { 1, 0x20 }, { 0, 0x20 } };
    for (size_t i = 0; i < sizeof(se) / sizeof(se[0]); i++) {
        reset(0x60);
        shapes++;
        krw_zone_verdict v = krw_zone_write(g_obj_base + 0x50, src, se[i].len,
                                            se[i].declared ? g_obj_base : 0,
                                            se[i].declared ? 0x60 : 0);
        int ok = (v == KRW_ZONE_REFUSE_PAST_END || v == KRW_ZONE_REFUSE_UNDECLARED);
        if (!ok || g_blocks != 0 || g_oob_blocks != 0) {
            violations++;
            printf("  VIOLATION: the SE write shape (declared=%d) verdict=%d blocks=%lu oob=%lu\n",
                   se[i].declared, (int)v, g_blocks, g_oob_blocks);
        } else {
            refused++;
            printf("  ok   SE write shape (0x20 at +0x50 of a 0x60 object, declared=%d):"
                   " refused, 0 blocks emitted\n", se[i].declared);
        }
    }

    // 3. the largest legal shape inside the smallest object: 0x20 at +0x40 of a
    //    0x60 object must be WRITTEN (a sweep that only refuses proves nothing).
    reset(0x60);
    shapes++;
    krw_zone_verdict legal = krw_zone_write(g_obj_base + 0x40, src, 0x20, g_obj_base, 0x60);
    if (legal == KRW_ZONE_OK && g_blocks == 1 && g_oob_blocks == 0) {
        allowed++;
        printf("  ok   the last legal block (0x20 at +0x40 of a 0x60 object) is written,"
               " 1 block, inside\n");
    } else {
        violations++;
        printf("  VIOLATION: the legal block was not written cleanly (verdict=%d blocks=%lu oob=%lu)\n",
               (int)legal, g_blocks, g_oob_blocks);
    }

    printf("\nshapes=%lu allowed=%lu refused=%lu violations=%lu\n", shapes, allowed, refused, violations);
    printf("INDEPENDENT_CLAMP_SWEEP %s\n", violations == 0 ? "PASS" : "FAIL");
    return violations == 0 ? 0 : 1;
}
