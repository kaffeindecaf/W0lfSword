# Sandbox Extension Patching - Technical Reference

> **Files:** `sandbox_escape.m`, `kexploit/sandbox.m`  
> **Origin:** Technique by CrazyMind90 (sandbox token acquisition via kernel R/W),
> opa334 (sandbox extension structures), extended by kaffeindecaf

---

## Overview

The iOS sandbox (MACF - Mandatory Access Control Framework) restricts file access per-process
via a policy stored in kernel memory. Each process has a `sandbox_label` structure containing
an `extension_set` - a hash table of path prefixes the process is allowed to access.

By achieving kernel R/W, we can walk the kernel structures from our process descriptor to the
sandbox extension table and patch it to grant full filesystem access.

---

## Kernel Structure Walk

```
proc (process descriptor)
  └─ p_proc_ro → proc_ro (read-only process data)
       └─ p_ucred → ucred (credentials)
            └─ cr_label → label (MAC label)
                 └─ l_perpolicy_sandbox → sandbox_label
                      └─ extension_set
                           └─ type_buckets[9] → extension_class_node[]
                                └─ ext_list_head → extension
                                     └─ data_ptr → path buffer
```

### Offset Stability

These offsets have been verified via IDA binary analysis across 6 kernelcaches:
- iOS 17.0 (21A329) through macOS 26.2 (25C56)
- All verified against KDK struct dumps where available

| Field | Offset | Stable? |
|-------|--------|---------|
| `proc.p_proc_ro` | 0x18 | Yes, 17.0–26.x |
| `proc_ro.p_ucred` | 0x20 | Yes, verified all versions |
| `ucred.cr_label` | 0x78 | Yes, KDK verified |
| `label.l_perpolicy_sandbox` | 0x10 | Yes, MAC slot 1 |
| `sandbox_label.extension_set` | 0x10 | Yes, community verified |
| `extension.data_ptr` | 0x40 | Yes |
| `extension.data_len` | 0x48 | Yes |

---

## Patching Strategy

### Primary Method: Extension Table Rewrite

1. Walk the struct chain to find `extension_set`
2. Iterate all 16 hash buckets
3. For each bucket with a valid extension class node:
   - Read the extension's path buffer from `data_ptr`
   - Check if it's a container class (`com.apple.sandbox.container`)
   - Overwrite the path to `"/"` (root)
   - Change the class to `com.apple.app-sandbox.read-write`
   - Update `path_len` to 1, `consumed` flag, and stat info
4. Fill empty hash slots with a working extension

### Fallback: Borrow from System Daemons

If direct patching fails, copy extensions from privilege daemons:

```
cfprefsd → securityd → notifyd → lsd
```

Each daemon has its own sandbox with different extension sets. We:
1. Find the daemon's `proc` via `proc_find_by_name()`
2. Walk to its `extension_set`
3. Copy all 9 `type_buckets` entries to our process

Daemons are tried in order until one succeeds.

---

## Extension Class Names

The kernel uses these class name strings:

| Class | Purpose |
|-------|---------|
| `com.apple.sandbox.container` | Container path access |
| `com.apple.app-sandbox.read-write` | Full R/W on path |
| `com.apple.app-sandbox.read` | Read-only on path |

We change the class to `read-write` for maximum access.

---

## Verification

After patching, verify with:

```c
// Kernel-level check
sandbox_check(pid, "file-read-data", SANDBOX_FILTER_PATH, "/private/var");
sandbox_check(pid, "file-write-data", SANDBOX_FILTER_PATH, "/private/var");
// Both should return 0

// Userspace verification
open("/private/var/tmp/.sbx_test", O_WRONLY | O_CREAT | O_TRUNC, 0644);
// Should succeed
```

W0lfSword tests 3 paths: `/var/mobile/`, `/private/var/tmp/`, `/usr/lib/`.
If >=2 succeed, the escape is considered successful.

---

## SMR Pointer Handling

The `ucred` pointer in `proc_ro` is SMR-encoded on newer iOS. The sandbox_escape
code tries both:

1. **SMR decode:** `kread_smrptr(proc_ro + off)` - decodes the SMR encoding
2. **PAC strip:** `xpaci(kread64(proc_ro + off))` - strips PAC bits

Both paths are validated by reading `cr_label` at `+0x78` and checking it's a valid
kernel pointer.

---

## Limitations

1. **Requires kernel R/W first** - this is an exploit chain component, not standalone.
2. **Offset-dependent** - wrong `off_proc_ro_p_ucred` = read garbage kernel memory.
3. **SMR keys change per-boot** - `kread_smrptr()` must use the correct `smr_base`.
4. **Extension table is live** - concurrent sandbox operations could observe partially patched state.
5. **Not persistent** - changes are in-memory only, lost on process exit/reboot.

---

## Apple's Fix Path

- Add integrity checks on `extension_set` data (hash at process init)
- Validate extension paths at access time, not just consume time
- Store extension data in read-only pages after initialization
- Move sandbox policy to a more privileged context (PPL)

---

*Last updated: 2026-08-10*
