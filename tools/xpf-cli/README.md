# xpf-cli — XPF offset resolver for the host (Linux/macOS)

Runs the repo's **XPF patchfinder** (`XPF/src`) against a kernelcache on the
host machine — no device, no jailbreak. Built for K4.1: verifying iOS 26.1
kernel struct offsets against the 26.0.1 table in `kexploit/offsets.m`.

## Usage

```bash
./build.sh                          # needs clang + lzfse/blocksruntime/ssl
./xpf-cli kernelcache.img4          # print every resolved offset/symbol
./xpf-cli kernelcache.img4 out.macho # decompress kernel to raw Mach-O
```

Feed it the **IMG4 kernelcache** (e.g. extracted from an IPSW). Modern
Apple-CDN kernelcaches for A12+ are unencrypted; XPF's `kdecompress` handles
IMG4→IM4P→krnl + LZFSE/LZSS. Encrypted ones need firmware keys first.

## K4.1 findings (iPhone18,1 / T8150, 2026-08-14)

| Build | Darwin | xnu | XPF result |
|-------|--------|-----|------------|
| 26.0.1 (23A355) | 25.0.0 | 12377.2.9~1 | baseline |
| 26.1 (23B85) | 25.1.0 | 12377.42.6~55 | compared |

Struct constants **identical** between 26.0.1 and 26.1:

| Item | Value |
|------|-------|
| `kernelStruct.proc.struct_size` | 0x748 |
| `kernelStruct.task.itk_space` | 0x310 |
| `kernelStruct.vm_map.pmap` | 0x40 |
| `kernelStruct.thread.machine_CpuDatap` | 0x1a0 |
| `kernelConstant.nsysent` / `mach_trap_count` | 0x22e / 0x80 |
| kernel base (both builds) | 0xfffffe0007004000 |

30 symbol-address shifts = code changes between builds (expected, does not
affect struct offsets). Conclusion: **the offsets.m 26.0.x block applies to
26.1** — no new block needed. The kernel exploit itself stays gated on
iOS < 26.1 (CVE-2025-43520 fixed in 26.1; offsets ≠ exploit availability).

**Flagged discrepancy:** XPF resolves `task.itk_space = 0x310` on T8150
(arm64e) for BOTH builds, but `offsets.m` sets 0x318 (verified on an SE3).
Possibly a per-SoC delta — needs on-device confirmation before changing;
see the note at `offsets.m` line ~864.

## Limitations

- Both builds are **SPTM arm64e filesets**: PPL items (`ppl_enter`,
  `pointer_mask`, `T1SZ_BOOT`) don't resolve and print `[UNRESOLVED/crash]`
  (guarded per-item by SIGSEGV recovery).
- `mac_label_set` / `proc_apply_sandbox` symbols don't resolve on SPTM
  builds either — MACF label-walk offsets (label+0x10, ucred+0x78) were
  verified indirectly via the proc/task struct identity above.
- The shims under `shims/` emulate Apple headers (xpc, mach-o/loader,
  libkern/OSByteOrder, compression, CommonCrypto, os/log) — Linux-only
  conveniences; macOS builds don't need most of them.
