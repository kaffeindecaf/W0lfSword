# How to Add a New Device or iOS Version

> Step-by-step checklist for adding support for a new SoC or iOS release.

---

## New iOS Version (Same SoC)

### 1. Get the Kernelcache

- [ ] Download IPSW from [ipsw.me](https://ipsw.me) or pull from device via SSH
- [ ] Extract the kernelcache (largest file in the IPSW, usually `kernelcache.release.*`)

### 2. Decompress

- [ ] Run XPF decompressor: `XPF/src/decompress kernelcache.raw kernelcache.dec`
- [ ] Or use `jtool2 --dec kernelcache.raw`

### 3. Run XPF

- [ ] `cd XPF/src && ./xpf kernelcache.dec`
- [ ] Compare output with the nearest existing iOS version in `offsets.m`
- [ ] Identify any changed offsets

### 4. Add to offsets.m

- [ ] Copy the nearest version's offset block
- [ ] Update the `SYSTEM_VERSION_GREATER_THAN_OR_EQUAL_TO` guard
- [ ] Update changed offsets, verify unchanged ones against XPF output
- [ ] Add a comment with the iOS build number

### 5. Verify

- [ ] `python3 validate_offsets.py` — no zero values, no range violations
- [ ] `./W0lfSword offsets` — new version shows in list
- [ ] Build: `make package`
- [ ] Deploy with safe mode first: `sudo ./W0lfSword adderall --safe`

### 6. Test

- [ ] `./W0lfSword safe off` and restart Filza
- [ ] Check `/tmp/FilzaTweak.log` for `SANDBOX ESCAPED`
- [ ] Run `regression_test.sh` on device

---

## New SoC (e.g. A19, M5)

### 1. Add CPU Family Constant

- [ ] Find the CPU family ID for the new SoC (from XNU source or device sysctl)
- [ ] Add to `kexploit/machine_info.h`: `#define CPUFAMILY_ARM_CODENAME 0x...`

### 2. Add Detection in offsets.m

```c
bool isA19 = (cpuFamily == CPUFAMILY_ARM_CODENAME);
```

### 3. Determine MMU Config

- [ ] **T1SZ:** Check translation table setup in XNU source
- [ ] **SMR base:** Verify against KDK struct dump
- [ ] **PAC mask:** Based on T1SZ: `PTR_MASK = ONES(64 - t1sz_boot)`

### 4. Add Per-SoC Offset Overrides

Add an `if (isA19)` block for any offset that differs:
```c
if (isA19) {
    off_thread_options = 0x80;  // Different on A19
} else if (isA18Above) {
    off_thread_options = 0x78;
} else {
    off_thread_options = 0x70;
}
```

### 5. Exploit Method

- [ ] Determine if `pe_v1` or `pe_v2` is appropriate
- [ ] Test socket spray behavior (zone exhaustion still works?)
- [ ] Check for MTE — if enabled, the entire heap spray technique is broken

### 6. Test Matrix

| iOS Version | USB | WiFi | Safe Mode | Full Exploit | Verified |
|-------------|-----|------|-----------|-------------|----------|
| 26.0 | | | | | |
| 26.1 | | | | | |

---

## Device-Specific Issues

### iPad Differences

- **Page size:** iPads with 16K pages need larger spray allocations
- **Kernelcache:** iPads may have different `kernelcache` paths
- **USB:** iPad USB is more reliable than iPhone (no MFI authentication issues)

### Apple TV / HomePod

- **No Filza:** Need a standalone test app
- **Different kernel config:** Some sysctl OIDs may differ
- **tvOS versioning:** Different numbering than iOS

### M-series Macs

- **No touchscreen:** Input via VNC or SSH only
- **Different kernel:** macOS kernel has different offsets despite shared XNU base
- **SSV is macOS SIP:** Different bypass mechanism needed

---

## Commit Template

```
offsets: add iOS XX.X + iPhone XX (AXX) support

- Added SYSTEM_VERSION_GREATER_THAN_OR_EQUAL_TO block for iOS XX.X
- Per-SoC overrides for AXX (T1SZ, SMR, thread options)
- Verified against KDK struct dump build XXXXX
- Tested on: iPhone XX, X, X — safe mode pass
```

---

*Last updated: 2026-08-10*
