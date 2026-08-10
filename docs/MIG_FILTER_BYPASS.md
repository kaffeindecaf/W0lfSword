# MIG Filter Bypass — Technical Reference

> **File:** `kexploit/MigFilterBypassThread.m`  
> **Origin:** Port of MigFilterBypassThread.js from DarkSword-RCE

---

## Overview

The MIG (Mach Interface Generator) filter prevents sandboxed processes from making
certain kernel syscalls via Mach IPC. When a sandboxed process sends a restricted MIG
message, the kernel checks the sandbox policy and returns an error.

The MIG filter bypass patches three kernel variables to allow all MIG messages through,
regardless of sandbox policy. This enables:

- Creating Mach exception ports (needed for RemoteCall)
- Accessing task/thread ports of other processes
- Bypassing `mig_sandbox_check` for restricted operations

---

## Patched Kernel Variables

### 1. `migLock` — MIG serialization lock

**Offset resolved at:** `g_MFB_migLockOff` via XPF pattern match

The MIG subsystem uses a global `lck_rw_t` lock to serialize MIG message processing
across threads. The bypass thread:

1. Waits for a target thread to enter the kernel (via `wait_for_mig_syscall`)
2. Reads the thread's kernel stack to find the `mig_lock` address (stored at `kstack + KERNEL_SP_OFFSET`)
3. Writes `LCK_RW_CAN_SLEEP | LCK_RW_WANT_EXCL` to release the lock if held
4. This prevents the MIG filter from blocking while we patch `migSbxMsg`

### 2. `migSbxMsg` — Sandbox check enable flag

**Offset resolved at:** `g_MFB_migSbxMsgOff`

A kernel variable that controls whether MIG messages are subject to sandbox checks.
When set to 0, all MIG messages bypass sandbox verification.

```
kwrite32(migSbxMsg_addr, 0);   // Disable sandbox check
```

Impact: All processes on the system (not just ours) can send any MIG message.
This is restored after we're done.

### 3. `migKernelStackLR` — Kernel stack return address

**Offset resolved at:** `g_MFB_migKernelStackLR`

The saved Link Register (LR) on the kernel stack during MIG processing. The bypass thread
overwrites this with a gadget address to redirect execution flow after MIG processing.

This is used to prevent the kernel from restoring the sandbox check flag after we disable it.

---

## Bypass Thread Lifecycle

```
1. Start bypass thread (pthread_create)
2. Main thread: set g_MFB_monitorThread1/2 to target thread addresses
3. Main thread: set g_MFB_runFlag = RUN_FLAG_RUN
4. Bypass thread:
   a. wait_for_mig_syscall(thread1 or thread2) — spin until thread enters kernel
   b. Read kernel stack to find mig_lock address
   c. Release mig_lock if held
   d. kwrite32(migSbxMsg, 0) — disable sandbox check
   e. Overwrite kernel_stack_LR with gadget address
   f. Exit loop
5. Main thread proceeds with Restricted MIG operations
```

---

## Key Structures

### Kernel Stack Layout (arm64)

The `arm_kernel_saved_state` structure is at the top of the kernel stack. Key offsets:

```
+0x00: x[0]              // GPR x0
+0x08: x[1]              // GPR x1
...
+0x60: sp                 // Stack Pointer (KERNEL_SP_OFFSET = 0x60)
+0x68: pc                 // Program Counter (not directly used)
+0x70: cpsr               // CPU State Register
+0x78: lr                 // Link Register (used for return gadget)
```

### lck_rw_t Lock Structure

```
Bit 16: LCK_RW_INTERLOCK    — lock is held
Bit 19: LCK_RW_WANT_EXCL    — exclusive access requested
Bit 22: LCK_RW_CAN_SLEEP    — thread can sleep waiting for lock
```

---

## Current Limitations

1. **Volatile without _Atomic** — `g_MFB_monitorThread1/2` use `volatile` but not `_Atomic`.
   On ARM weak memory model, the bypass thread may read stale (zero) values.

2. **Unbounded kernel stack scan** — `kreadbuf(startAddr, buf, KSTACK_READ_SIZE)` reads
   0x1000 bytes. If the kernel stack is smaller (some configs have 0x2000), this reads
   past the stack into adjacent memory.

3. **migSbxMsg offset may change** — resolved via XPF pattern match per iOS version.
   Not guaranteed stable across XNU builds.

4. **System-wide impact** — disabling sandbox checks affects ALL processes. Any crash or
   timeout during the bypass window leaves the system in a weakened state.

---

## See Also

- `kexploit/MigFilterBypassThread.m` — implementation
- `kexploit/MigFilterBypassThread.h` — function declarations
- `kexploit/Thread.m` — `inject_guard_exception` used to trigger MIG entry
- XNU source: `osfmk/kern/lock_rw.h` — lock structure definitions
- XNU source: `osfmk/ipc/mig.c` — MIG filter implementation

---

*Last updated: 2026-08-10*
