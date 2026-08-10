# ADR 0002 — Vnode Redirection for SSV Instead of Remount

**Status:** Accepted  
**Date:** 2025 (inherited from XEmaz)  

---

## Context

The Signed System Volume prevents writes to `/System/`, `/usr/`, `/bin/`, `/sbin/`
by mounting them as read-only APFS snapshots with cryptographic seals.

Two approaches exist:
1. Remount the volume as read-write (temporarily disable `MNT_RDONLY`)
2. Redirect the vnode data pointer to a writable temp file

## Decision

Use vnode data pointer redirection because:
1. Remount requires modifying the mount structure, which may be protected
2. Remount triggers APFS seal verification on the next access
3. Vnode pointer swap is transparent — the kernel trusts `v_data` unconditionally
4. No mount flag changes needed — avoids triggering seal checks
5. The technique works per-file rather than system-wide

## Alternatives Considered

- **Remount via `MNT_UPDATE`** — would trigger seal re-verification, likely failing
- **Direct block device write** — requires bypassing APFS encryption, much harder
- **Snapshot manipulation** — APFS snapshot management is complex and error-prone

## Consequences

- **Pro:** Per-file granularity — only the target file's data is redirected
- **Pro:** No mount state changes — clean restore after operation
- **Con:** Race window — another thread accessing the file during swap sees temp data
- **Con:** Not persistent — v_data is in-memory only, lost on unmount/reboot
- **Con:** Requires kernel R/W to modify vnode structures
