# Kernel Primitive API Reference

> Every function in `krw.h`, `kutils.h`, `vnode.h`, and `sandbox.h`
> with calling context requirements and side effects.

---

## Read/Write Primitives (`krw.h` / `krw.m`)

### `kread64(uint64_t addr)` → `uint64_t`

Read 8 bytes from kernel address. **Does NOT strip PAC.**
Use `kread_ptr` for kernel pointers, `xpaci(kread64(...))` for raw reads.

- **Context:** Must hold kernel R/W (after `kexploit_opa334` succeeds).
- **Side effects:** None (read-only).
- **PAC:** Returns PAC-signed value on arm64e. Caller must strip.

### `kread_ptr(uint64_t addr)` → `uint64_t`

Read a kernel pointer with PAC stripping. Equivalent to `xpaci(kread64(addr))`.

- **Context:** Same as kread64.
- **Side effects:** None.
- **Preferred over:** `xpaci(kread64(...))` — use this for all kernel pointers.

### `kread_smrptr(uint64_t addr)` → `uint64_t`

Read and decode an SMR-encoded pointer. Used for `ucred` and similar SMR-protected fields.

- **Context:** Same as kread64. Must know `smr_base` for correct decoding.
- **Side effects:** None.

### `kread32/kread16` → `uint32_t/uint16_t`

Read 4 or 2 bytes from kernel address. No PAC/SMR handling needed (integer fields).

### `kwrite64(uint64_t addr, uint64_t val)`

Write 8 bytes to kernel address. **DANGER: no validation.** Wrong address = kernel panic.

- **Context:** Must hold kernel R/W.
- **Side effects:** Modifies kernel memory. Irreversible. No rollback.
- **Safety:** Always verify address with `is_kaddr_valid()` first.

### `kreadbuf(uint64_t addr, void *buf, size_t len)` / `kwritebuf`

Bulk read/write of arbitrary-size kernel buffers.

- **Context:** Same as kwrite64.
- **Side effects:** Buffer overflow if len exceeds kernel allocation.

---

## Process/Task Functions (`kutils.h` / `kutils.m`)

### `proc_self(void)` → `uint64_t`

Returns the kernel address of our own `proc` structure.
Cached after first call — thread-safe with `__atomic_load_n`.

- **Context:** Must hold kernel R/W.
- **Side effects:** None.

### `proc_find(pid_t pid)` → `uint64_t`

Walk the `proc` linked list to find a process by PID.
Returns the `proc` address or `-1` if not found.

- **Context:** Must hold kernel R/W.
- **Side effects:** Linear scan — O(n) in number of processes.
- **PAC:** Uses `xpaci(kread64(...))` for list traversal pointers.

### `proc_find_by_name(const char *name)` → `uint64_t`

Same as `proc_find` but matches by process name (`p_name` field).

- **Context:** Same as proc_find.
- **Side effects:** Reads `p_name` (32 bytes) per process.

### `proc_task(uint64_t proc)` → `uint64_t`

Get the `task` structure from a process.

### `proc_get_cred_label(uint64_t proc)` → `uint64_t`

Walk `proc_ro → ucred → cr_label`. Used by sandbox escape.

- **PAC:** Uses `kread_ptr` for all pointer reads.

---

## Vnode Functions (`vnode.h` / `vnode.m`)

### `get_vnode_for_path_by_chdir(const char *path)` → `uint64_t`

Get a vnode by changing the current directory, reading `fd_cdir`, then restoring `/`.

- **Context:** Must hold kernel R/W. Must have filesystem access.
- **Side effects:** **Changes process CWD** during execution (restored after).
- **Return:** Vnode address, or `-1` on failure. **Check for sentinel before use.**

### `get_vnode_for_path_by_open(const char *path)` → `uint64_t`

Get a vnode by opening the file, reading the file descriptor's vnode, then closing.

- **Context:** Same as above.
- **Side effects:** Creates and closes a file descriptor.

### `vnode_get_child_vnode(uint64_t vnode, const char *name, uint64_t blacklist)` → `uint64_t`

Scan the vnode's child namecache chain to find a child by name.

- **Context:** Must hold kernel R/W.
- **Side effects:** Iterates up to 4096 namecache entries.
- **Thread safety:** Uses caller-provided buffer for name comparison.

### `vnode_redirect_folder(const char *to, const char *from)` → `uint64_t`

Swap `v_data` pointers between two directory vnodes. Returns the original `v_data` of `to`.

- **Context:** Must hold kernel R/W. Used for SSV bypass.
- **Side effects:** Redirects all access to `to` to `from`'s data.

---

## Sandbox Functions (`sandbox.h` / `sandbox.m`)

### `patch_sandbox_ext(void)` → `int`

Main SSV write activation. Walks sandbox structures, patches extension paths to `"/"`.

- **Context:** Must hold kernel R/W. `g_exploitDone` must be true.
- **Side effects:** Modifies kernel sandbox data. Calls `borrow_sandbox_ext` as fallback.
- **Thread safety:** Uses `g_patch_sandbox_ext_done` flag. Not fully atomic — avoid concurrent calls.

### `check_sandbox_var_rw(void)` → `int`

Test if the current process has R/W access to `/private/var`.

- **Context:** No kernel R/W needed (uses `sandbox_check` syscall).
- **Return:** 0 = R+W confirmed, -1 = denied.

### `borrow_sandbox_ext(const char *daemon)` → `int`

Copy sandbox extensions from a system daemon to our process.
Tries `cfprefsd`, `securityd`, `notifyd`, `lsd` in order.

- **Context:** Must hold kernel R/W.
- **Side effects:** Overwrites our extension_set with the daemon's.

---

## Exception/Thread Functions

### `inject_guard_exception(uint64_t thread, uint64_t code)` → `bool`

Set `AST_GUARD` on a thread to trigger `EXC_GUARD` exception.

- **Context:** Must hold kernel R/W.
- **Side effects:** Thread will receive EXC_GUARD on next AST check.

### `clear_guard_exception(uint64_t thread)`

Clear `AST_GUARD` from a thread's AST and reset the exception info.

- **Context:** Must hold kernel R/W.
- **Side effects:** None (restores thread to normal state).

---

## Common Pitfalls

| Mistake | Symptom |
|---------|---------|
| Using `kread64` for a kernel pointer without `xpaci` | Garbage addresses, SIGBUS |
| Not checking vnode functions for `-1` sentinel | Wraparound read from address 0xDF |
| Writing to kernel address without `is_kaddr_valid` | Kernel panic |
| Concurrent calls to `patch_sandbox_ext` | Kernel memory corruption |
| Using `vnode_get_v_name` return after another call | Stale data (static buffer) |

---

*Last updated: 2026-08-10*
