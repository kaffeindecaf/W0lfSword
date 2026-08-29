# xpf-cli - XPF offset resolver for the host (Linux/macOS)

Runs the repo's **XPF patchfinder** (`XPF/src`) against a kernelcache on the
host machine - no device, no jailbreak. Built for K4.1: verifying iOS 26.1
kernel struct offsets against the 26.0.1 table in `kexploit/offsets.m`.

## Usage

```bash
./build.sh                          # needs clang + lzfse/blocksruntime/ssl
./xpf-cli kernelcache.img4          # print every resolved offset/symbol
./xpf-cli kernelcache.img4 out.macho # decompress kernel to raw Mach-O
```

Debian/Ubuntu build deps: `sudo apt install liblzfse-dev libblocksruntime-dev`
(plus clang). The shipped `xpf-cli` binary is linked against liblzfse.so.1  - 
install `liblzfse1` if you run the prebuilt one instead of rebuilding.

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
26.1** - no new block needed. The kernel exploit itself stays gated on
iOS < 26.1 (CVE-2025-43520 fixed in 26.1; offsets ≠ exploit availability).

## K4.1 follow-up (2026-08-24) - A13/t8030 18.4.1 (SE 2nd gen)

Pulled `kernelcache.release.iphone12c` from the iPhone12,8 18.4.1 (22E252)
IPSW via the ranged-download method (8.45GB IPSW, ~19MB fetched; zip64
central dir + local-header offset resolved from the entry extra field).
Matches the running kernel on the phone: xnu-11417.102.9~20/RELEASE_ARM64_T8030.

| Item | 17.1 A13/t8030 | 18.4.1 A13/t8030 | 26.0.1 A13/t8030 | Verdict |
|------|----------------|------------------|------------------|---------|
| `task.itk_space` | 0x300 | 0x318 | **0x310** | **per-VERSION, not per-SoC**: 17.x=0x300, 18.x=0x318 (A13+A15), 26.x=0x310 (A13+A18). offsets.m 26.0 block FIXED 0x318→0x310 (2026-08-24) |
| `proc.struct_size` | 0x730 | 0x740 | 0x748 | grows +8 per major version - kcwatch signal |
| `thread.machine_CpuDatap` | 0x148 | 0x148 | UNRESOLVED | SoC delta, expected |
| `vm_map.pmap` | 0x40 | 0x40 | 0x40 | identical across all three |
| sptm | 0 | 0 | **0** | t8030 never has SPTM; T8150/26.x has sptm=1 - per-SoC after all |

Note: kernelcache name is per-board (`kernelcache.release.iphone12c` for
D79AP), not the SoC - grep the IPSW central dir for `kernelcache.release.*`.

**Resolved discrepancy (see table above):** the earlier T8150-vs-offsets.m
flag is now fully explained - itk_space is a **per-VERSION** offset, not
per-SoC: 17.x = 0x300, 18.x = 0x318 (A13 + A15), 26.x = 0x310 (A13 + A18,
verified on t8030 AND T8150). The offsets.m iOS 26.0 block previously said
0x318 - **corrected to 0x310 on 2026-08-24** after XPF resolution of the
t8030 26.0.1 kernelcache.

## Limitations

- Both builds are **SPTM arm64e filesets**: PPL items (`ppl_enter`,
  `pointer_mask`, `T1SZ_BOOT`) don't resolve and print `[UNRESOLVED/crash]`
  (guarded per-item by SIGSEGV recovery).
- `mac_label_set` / `proc_apply_sandbox` symbols don't resolve on SPTM
  builds either - MACF label-walk offsets (label+0x10, ucred+0x78) were
  verified indirectly via the proc/task struct identity above.
- The shims under `shims/` emulate Apple headers (xpc, mach-o/loader,
  libkern/OSByteOrder, compression, CommonCrypto, os/log) - Linux-only
  conveniences; macOS builds don't need most of them.
