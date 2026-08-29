# SSV Bypass via Vnode Data Pointer Swap

> **Files:** `SSV/SSVUtils.m`, `kexploit/vnode.m`, `kexploit/file.m`  
> **Origin:** XEmaz (SSV bypass integration, root chown)

---

## Overview

The Signed System Volume (SSV) mounts `/System/`, `/usr/`, `/bin/`, `/sbin/` as read-only
APFS snapshots with cryptographic seal verification. Normal writes to these paths fail with
`EROFS` (read-only filesystem).

W0lfSword bypasses SSV by swapping the `v_data` pointer of a sealed file's vnode with the
`v_data` pointer of a writable temp file. The kernel reads the temp file's data when accessing
the sealed path, allowing writes to appear to go to `/System/`.

---

## SSV Architecture

```
┌─────────────────────────────────────┐
│         APFS Volume                 │
│                                     │
│  ┌───────────────────────────────┐  │
│  │  SSV Snapshot (read-only)     │  │  ← sealed, verified
│  │  /System/  /usr/  /bin/       │  │
│  │  MNT_RDONLY flag set          │  │
│  └───────────────────────────────┘  │
│                                     │
│  ┌───────────────────────────────┐  │
│  │  Data Volume (read-write)     │  │
│  │  /private/var/  /tmp/         │  │
│  │  (unsealed, writable)         │  │
│  └───────────────────────────────┘  │
└─────────────────────────────────────┘
```

The SSV seal is verified at mount time. After mount, the kernel trusts that sealed
paths are immutable. This trust is the vulnerability.

---

## The Vnode Structure

```c
struct vnode {
    // ... locking, flags, refcounts ...
    uint64_t v_data;        // → pointer to APFS fsnode (file metadata + data)
    uint64_t v_parent;      // → parent directory vnode
    uint64_t v_mount;       // → mount structure
    uint64_t v_name;        // → pointer to filename string
    // ...
};
```

The `v_data` field points to an `apfs_fsnode` structure containing:
- File data (encrypted, inline or extent-based)
- Metadata (UID, GID, mode, flags)
- The file's actual content blocks

**Key insight:** The kernel never verifies that `v_data` belongs to the correct APFS volume
or snapshot. By swapping this pointer, we can redirect reads/writes to a different file.

---

## The Swap Technique

### Step 1: Create Temp File

```c
char tmp[] = "/private/var/tmp/ssv_tmp_XXXXXX";
int fd = mkstemp(tmp);
write(fd, new_content, content_len);
close(fd);
```

### Step 2: Get Both Vnodes

```c
uint64_t target_vnode = get_vnode_for_path_by_open("/System/Library/Target.plist");
uint64_t temp_vnode   = get_vnode_for_path_by_open(tmp);
```

### Step 3: Swap v_data

```c
uint64_t saved_v_data = kread64(target_vnode + off_vnode_v_data);
uint64_t temp_v_data  = kread64(temp_vnode   + off_vnode_v_data);

kwrite64(target_vnode + off_vnode_v_data, temp_v_data);

// The kernel now reads temp file data when accessing the system path
```

### Step 4: Restore

```c
kwrite64(target_vnode + off_vnode_v_data, saved_v_data);
unlink(tmp);  // Clean up temp file
```

---

## What This Bypasses

- **MNT_RDONLY flag:** Irrelevant - we're not writing through the mount.
- **APFS seal verification:** Only checked at mount time, not per-read.
- **Code signing:** Kernel extensions and bins are validated at exec time, not at v_data swap.

## What It Doesn't Bypass

- **KTRR:** Can't modify running kernel code.
- **Boot-time verification:** Changes to v_data are in-memory only, lost on reboot.
- **Snapshot diffing:** A tool comparing the snapshot to the live volume would see the change.

---

## Path Classification

W0lfSword classifies paths for different handling:

| Path | Classification | Handling |
|------|---------------|----------|
| `/System/Library/` | `ssvProtectedPath` + `sealedSystemPath` | vnode swap |
| `/usr/lib/` | `ssvProtectedPath` | vnode swap |
| `/bin/`, `/sbin/` | `sealedSystemPath` | vnode swap |
| `/Applications/` | `ssvProtectedPath` | vnode swap |
| `/var/`, `/private/var/` | `ssvProtectedPath` only | Direct write (unsealed) |

After a successful swap, `force_chown_root_wheel(path)` sets the file to `root:wheel` ownership
and `apply_parent_permissions(path)` matches the parent directory's mode.

---

## Limitations

1. **Requires kernel R/W** - same prerequisite as sandbox escape.
2. **Race window** - another thread accessing the target path during the swap will see temp data.
3. **Not persistent** - v_data changes are in-memory only.
4. **Data pointer lifetime** - if the temp file is deleted while the v_data swap is active, reads return garbage.
5. **Vnode reuse** - the kernel may recycle the temp vnode between the read and the restore.

---

## Apple's Fix Path

- Validate v_data ownership against the vnode's mount structure
- Lock v_data against modification after vnode creation
- Check APFS seal at read time (not just mount time)
- Use per-page integrity verification (like dm-verity on Android)

---

## See Also

- `SSV/SSVUtils.m` - implementation
- `kexploit/vnode.m` - `vnode_redirect_file`, `vnode_get_child_vnode`
- `kexploit/file.m` - `overwrite_system_file` using vnode swap
- Apple documentation: SSV architecture (WWDC 2020 session)

---

*Last updated: 2026-08-10*
