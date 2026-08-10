# Offset Resolution Guide — Adding New iOS Versions

> How to find kernel struct offsets for a new iOS version and add them to W0lfSword.

---

## Prerequisites

- iOS device on the target version (jailbreak not required for kernelcache extraction)
- macOS or Linux with jtool2/XPF/Ghidra installed
- SSH access to device (or IPSW download)

---

## Step 1: Get the Kernelcache

### Method A: From Device (SSH)

```bash
# SSH into device, copy kernelcache
ssh root@<device-ip>
dd if=/dev/disk0s1s1 of=/tmp/kc bs=1M count=40
# Transfer to laptop
scp root@<device-ip>:/tmp/kc ./kernelcache.raw
```

### Method B: From IPSW

```bash
# Download the IPSW from ipsw.me
unzip iPhone_*.ipsw
# Find the kernelcache (largest file in the IPSW)
ls -laS | head -5
```

---

## Step 2: Decompress

XNU kernelcaches use LZFSE or LZVN compression.

```bash
# Using XPF's decompressor
cd XPF/src
make decompress
./decompress kernelcache.raw kernelcache.dec
```

Or use `jtool2 --dec`:
```bash
jtool2 --dec kernelcache.raw
```

---

## Step 3: Find Struct Offsets

### Option A: XPF Pattern Matching (Automated)

XPF scans the kernelcache for known instruction patterns that access specific struct fields.

```bash
cd XPF/src
./xpf kernelcache.dec
# Output: JSON with all resolved offsets
```

XPF works by pattern matching the ARM64 instructions that access struct fields:
- `LDR w9, [x8, #0x60]` → `off_proc_p_pid = 0x60`
- `STR x10, [x9, #0x18]` → `off_proc_p_proc_ro = 0x18`

### Option B: Manual with Ghidra

1. Open kernelcache in Ghidra (Mach-O, ARM64)
2. Search for known function names (`proc_find`, `kauth_cred_proc_ref`)
3. Find the struct offset operands in the disassembly
4. Cross-reference with the KDK struct dump to verify

### Option C: KDK Struct Dump

Apple publishes Kernel Development Kits with DWARF debug info:

```bash
# From KDK .dSYM bundle
dwarfdump --lookup=0x... KDK.dSYM | grep proc
```

---

## Step 4: Add to offsets.m

Open `kexploit/offsets.m`. Find the section for your iOS version range,
or add a new block:

```c
if (SYSTEM_VERSION_GREATER_THAN_OR_EQUAL_TO(@"26.1")) {
    // iOS 26.1+ offsets
    off_proc_p_pid = 0x60;
    off_proc_p_proc_ro = 0x18;
    // ... all offsets ...
}
```

### Offset Categories

| Category | Example fields | How to find |
|----------|---------------|-------------|
| proc fields | `off_proc_p_pid`, `off_proc_p_proc_ro` | `proc_find` disassembly |
| thread fields | `off_thread_t_tro`, `off_thread_ast` | `thread_set_ast` disassembly |
| vnode fields | `off_vnode_v_data`, `off_vnode_v_parent` | `vnode_get` / `vnode_lookup` |
| mount fields | `off_mount_mnt_flag` | `mount_common` disassembly |
| task fields | `off_task_itk_space`, `off_task_map` | `task_create_internal` |
| socket/inpcb | `off_inpcb_inp_socket`, various | `in_pcbconnect` disassembly |
| file/fileproc | `off_fileproc_fp_glob`, `off_fileglob_fg_data` | `fo_read`/`fo_write` |

### Per-SoC Offsets

Some offsets differ between SoC families. Check `isA13Above`, `isA15Above` etc.:

```c
if (isA18Above) {
    off_thread_options = 0x78;  // Different on A18/M4
} else {
    off_thread_options = 0x70;  // A12-A17
}
```

### Thread/Machine Offsets

These are the **most dangerous** to get wrong — a bad `off_thread_machine_kstackptr`
will corrupt kernel memory.

**Always verify** by reading a known-good value after setting:

```c
uint64_t test_thread = kread64(proc_self() + off_proc_p_list_le_next);
uint64_t kstackptr = kread64(test_thread + off_thread_machine_kstackptr);
// Must be 16-byte aligned and within VM_MIN/VM_MAX
assert(kstackptr >= VM_MIN_KERNEL_ADDRESS && kstackptr <= VM_MAX_KERNEL_ADDRESS);
assert((kstackptr & 0xF) == 0);
```

---

## Step 5: Verify with validate_offsets.py

```bash
python3 validate_offsets.py
```

Checks:
- All offsets are non-zero (0 = uninitialized)
- 0xdeaddead sentinel values are intentional
- Pointer-type offsets are within kernel address range
- sizeof fields are reasonable (< 4096)

---

## Step 6: Test on Hardware

1. Build: `./W0lfSword build`
2. Deploy with safe mode: `sudo ./W0lfSword adderall --safe`
3. Verify the tweak loads without crashing
4. Disable safe mode: `./W0lfSword safe off`
5. Restart Filza and check logs: `./W0lfSword log`
6. Watch for `SANDBOX ESCAPED` confirmation

---

## Common Pitfalls

| Mistake | Symptom | Fix |
|---------|---------|-----|
| Wrong `off_proc_p_proc_ro` | `proc_self` returns 0 | Check KDK dump for struct layout |
| Wrong `off_thread_machine_kstackptr` | Kernel panic on first `kwrite` | Always verify via thread offset check |
| Wrong T1SZ | All pointers appear invalid | Check SoC detection: A16+ uses 0x11 |
| Wrong SMR base | SMR pointers decode to garbage | Verify `smr_base` for SoC family |
| New field added | Old offset now points to wrong field | Compare KDK struct dump between versions |
| Field removed/reordered | Garbage values from `kread` | Struct may have been reorganized — find new offset |

---

## Automated Validation

After adding offsets, run the full test suite:

```bash
./W0lfSword audit           # Static analysis
python3 validate_offsets.py  # Offset integrity
./W0lfSword offsets          # Visual coverage check
```

---

*Last updated: 2026-08-10*
