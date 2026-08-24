# Device Testing Record

When: 2026-08-24 (evening)
Devices: iPhone SE 2nd gen (A13/t8030, D79AP) on iOS 18.4.1 (22E252) —
Dopamine rootless, Filza 4.0.1-4, ElleKit 1.2, OpenSSH 9.7p1 (key auth)
Second unit: same model, iOS 17.1 (21B74) — not yet jailbroken, used for
host-side kernel research only.

## What was tested and PASSED

### Live device (18.4.1, over USB tunnel)

1. **USB data path** — `usbtest` 10/10 reads, lockdown diagnostics
   round-trip OK, syslog stream received over USB, pairing valid.
2. **SSH over USB tunnel** — iproxy 2222→22, root key auth, BatchMode
   (what W0lfSword's deploy pipeline uses). Full root shell confirmed.
3. **Deploy prerequisites on phone** — /var/jb present (rootless JB),
   Filza 4.0.1-4 installed (com.tigisoftware.Filza), ElleKit 1.2,
   preferenceloader 2.2.8, OpenSSH server 9.7p1-1.
4. **Adderall Phase 6 config flow** — prompts now visible (stderr fix),
   values captured clean, Filza bundle auto-detected from the phone
   (`com.tigisoftware.Filza` — matches Info.plist CFBundleIdentifier).
5. **`audit`** — AUDIT PASSED (all source files present, structure ok).
6. **Read-only kernel introspection** — Darwin 24.4.0 / iPhone12,8,
   uptime sane, no panic logs on device (never panicked).

### Host-side kernel research (both firmwares, zero device risk)

7. **Kernelcache retrieval** — ranged zip64 fetch (18.4.1: 19.2MB of an
   8.45GB IPSW; 17.1: 17.6MB), new script `scripts/fetch_kernelcache.py`
   (zip64 EOCD + zip64 local-header via entry extra field — fixed a
   multi-placeholder bug found while testing 17.1).
8. **XPF resolution, 18.4.1 (A13/t8030)** — xnu-11417.102.9~20,
   RELEASE_ARM64_T8030; matches the RUNNING kernel on the phone.
   `task.itk_space = 0x318`, `machine_kstackptr = 0xf8`,
   `proc.struct_size = 0x740`, `vm_map.pmap = 0x40`, sptm=0.
9. **XPF resolution, 17.1 (A13/t8030)** — xnu-10002.42.9~2.
   `task.itk_space = 0x300` (matches offsets.m 17.0-17.7 claim),
   `proc.struct_size = 0x730`, `vm_map.pmap = 0x40`, sptm=0.
10. **Cross-version kernel diff (17.1 → 18.4.1, both t8030)** —
    identical 14, changed 49. Struct deltas: itk_space 0x300→0x318,
    proc.struct_size 0x730→0x740, nsysent 0x22c→0x22e (2 new syscalls),
    cdevsw resolved→UNRESOLVED. Machine_CpuDatap 0x148 on both.

## What was NOT tested (needs your presence / go-ahead)

- **Adderall full deploy + exploit run** — builds, installs into Filza,
  resprings, fires DarkSword. It's Tier 2 (can panic/reboot the phone);
  crash_monitor gate + confirm are armed but the run itself was not
  performed while unattended.
- **iOS 26.5 SE2 kernel exploit** — DarkSword is dead there (patched
  26.1+); userspace modules only.
- **17.1 unit** — not jailbroken yet; only host-side kernel research done.

## Findings from this session (already committed)

- K4.1 per-SoC flag RESOLVED: itk_space 0x318 on A13+A15, 0x310 is
  T8150/A18-only (offsets.m comment + xpf-cli README updated).
- offsets.m 18.4 A13 block values verified against real kernelcache.
- offsets.m 17.x claims verified: itk_space 0x300 confirmed on 17.1.
- proc.struct_size grows 0x730 → 0x740 → 0x748 (17.1 → 18.4.1 → 26.x).
