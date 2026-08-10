# W0lfSword — Bug Bounty Research Writeup

> **Purpose:** Document vulnerability findings from the DarkSword exploit ecosystem
> for Apple Security Bounty submission. Each section maps to an Apple bounty category.
>
> **Status:** Research-only. No PoC has been tested on hardware.

---

## 1. KASLR Info Leak via physical_oob_read_mo Race Window

**Bounty Category:** Kernel Info Leak / KASLR Bypass  
**Estimated Bounty:** $5,000–$25,000  
**CVE Reference:** TBD — DarkSword exploit unnamed

### Summary

The DarkSword exploit's `physical_oob_read_mo()` function creates a race window between
`pwritev()` and `mach_vm_map()` that allows reading freed physical pages. This is
fundamentally a KASLR bypass — physical pages contain kernel pointers.

### Technical Detail

```
1. Allocate physical page A via mach_vm_allocate
2. mloc k page A to prevent reuse
3. Write known marker to page A
4. Start race:
   a. pwritev() from fd → copies data to virtual address
   b. mach_vm_deallocate() + mach_vm_map() remaps virtual address to different physical page
5. If pwritev wins: data goes to freed page A (exposed via IOSurface)
6. If mach_vm_map wins: data goes to new page (marker unchanged)
7. The marker check at line 374 distinguishes the cases
```

The key insight: freed physical pages are reallocated to kernel zones. By reading freed
pages through the IOSurface/dangling mapping, kernel heap data (including kernel pointers
and KASLR-revealing values) leaks to userspace.

### Impact

- **KASLR slide calculation**: Kernel pointers in freed heap pages reveal the slide
- **Heap layout discovery**: Zone allocator patterns become visible
- **No kernel R/W required**: This is a pure info leak — the OOB read race works without
  the full DarkSword socket corruption chain

### Apple's Likely Fix

- Add physical page zeroing before reuse in `vm_page_free()` paths
- IOSurface: validate that backing physical pages are still owned by the surface

---

## 2. Sandbox Escape via Kernel Extension Table Patching

**Bounty Category:** Sandbox Escape / Privilege Escalation  
**Estimated Bounty:** $100,000–$250,000  
**CVE Reference:** TBD

### Summary

After achieving kernel R/W (via DarkSword ICMPv6 + IOSurface chain), the sandbox_escape()
function walks `proc_ro → ucred → cr_label → sandbox_label → extension_set` and patches
sandbox extension paths to `"/"` with read-write class. This grants an app-sandboxed process
full filesystem access.

### Technical Detail

The kernel stores sandbox extensions in a hash table within the process's `struct sandbox_label`.
Each extension has:
- A path prefix (e.g., `/var/mobile/Containers/Data/Application/UUID/`)
- A class name (e.g., `com.apple.app-sandbox.read-write`)
- Additional metadata (flags, stat info)

The exploit:
1. Reads the extension_set from kernel memory
2. Overw rites extension paths to `"/"` (root)
3. Changes the class to `com.apple.app-sandbox.read-write`
4. Copies extensions from system daemons (cfprefsd, securityd, notifyd, lsd) as fallback

### Impact

Full filesystem read/write from a sandboxed app. This bypasses:
- Container sandbox restrictions
- App group limitations
- All file-access entitlements

### Apple's Likely Fix

- Add integrity checks on sandbox extension data (hash/checksum)
- Store extension table in read-only memory after process initialization
- Validate extension paths at access time (not just at consume time)

---

## 3. Signed System Volume (SSV) Bypass via Vnode Data Pointer Swap

**Bounty Category:** System Integrity Protection Bypass  
**Estimated Bounty:** $50,000–$150,000  
**CVE Reference:** TBD

### Summary

After sandbox escape, the SSV bypass redirects vnode data pointers to write to sealed
system paths (`/System/`, `/usr/`, `/bin/`, `/sbin/`). This circumvents the SSV's
cryptographic integrity verification.

### Technical Detail

The SSV mounts `/System/` as a read-only snapshot with signed hashes. The exploit:
1. Creates a temporary file in an unsealed location (`/private/var/tmp/`)
2. Writes content to the temp file
3. Swaps the sealed file's vnode data pointer to point to the temp file's data
4. The kernel now reads the temp data when accessing the sealed path
5. After the write, swaps the pointer back

This works because the kernel trusts vnode data pointers without verifying they belong to
the correct APFS volume or snapshot.

### Impact

Permanent modification of system binaries, libraries, and configuration:
- `/System/Library/` — system frameworks and daemons
- `/usr/lib/` — dynamic libraries
- `/bin/` and `/sbin/` — command-line tools

### Apple's Likely Fix

- Add vnode data pointer validation against the owning mount/volume
- Prevent vnode data pointer modification after vnode creation
- Add APFS seal verification at read time (not just mount time)

---

## 4. Kernel R/W via ICMPv6 Socket PCB Corruption

**Bounty Category:** Kernel Arbitrary Read/Write  
**Estimated Bounty:** $150,000–$250,000  
**CVE Reference:** TBD — DarkSword unnamed  

### Summary

The core DarkSword exploit achieves kernel read/write through:
1. ICMPv6 socket spray to control physical page layout
2. IOSurface physical OOB to corrupt socket PCB structures
3. Overwriting `icmp6_filter` pointer to create a kernel R/W gadget

### Technical Detail

The exploit chain:
1. Spray thousands of ICMPv6 sockets to exhaust the zone allocator
2. Use IOSurface to create physical OOB read/write primitives
3. Scan physical memory for sprayed socket PCBs (identified by generation counters)
4. Corrupt the `in6p_icmp6filt` pointer to point back into the socket PCB
5. Use `getsockopt(ICMP6_FILTER)` to read kernel memory through the corrupted pointer
6. Use `setsockopt(ICMP6_FILTER)` to write kernel memory

### Impact

Full kernel memory access:
- Read any kernel address (bypass KASLR)
- Write to any kernel address (patch kernel code/data)
- Build arbitrary R/W primitives for further exploitation

### Apple's Likely Fix

- Add bounds checking on `icmp6_filter` pointer in `getsockopt`/`setsockopt`
- Add zone allocator hardening (randomized freelist, guard pages)
- Validate socket PCB integrity before accessing filter data

---

## 5. Thread Exception Hijack → Remote Code Execution in Kernel Context

**Bounty Category:** Kernel Code Execution  
**Estimated Bounty:** $250,000  
**CVE Reference:** TBD

### Summary

The RemoteCall module injects EXC_GUARD exceptions into target threads, hijacks the
exception handler, and executes arbitrary functions in the target thread's context.
This enables:
- Calling kernel functions from userspace (via thread state manipulation)
- Modifying kernel memory with the target's privileges
- Escalating from kernel R/W to kernel code execution

### Technical Detail

1. Create a dummy thread with `pthread_create_suspended_np`
2. Set EXC_GUARD on the dummy thread's AST
3. When the thread triggers EXC_GUARD, capture the exception message
4. Overwrite the thread state registers (x0-x7, PC, LR, SP)
5. Set PC to the target kernel function, LR to a return gadget
6. Reply to the exception — the kernel resumes the thread at the target function
7. The target function executes with kernel privileges

### Impact

- Call arbitrary kernel functions from userspace
- Execute kernel code with the victim thread's credentials
- Bypass PAC (return-oriented programming doesn't require signing new pointers)

### Apple's Likely Fix

- Add PAC signing to exception reply state
- Validate thread state on exception return
- Restrict EXC_GUARD to system threads only

---

## Bounty Ranges Summary

| # | Finding | Category | Low | High |
|---|---------|----------|-----|------|
| 1 | KASLR leak via OOB read race | Info Leak | $5,000 | $25,000 |
| 2 | Sandbox extension table patching | Sandbox Escape | $100,000 | $250,000 |
| 3 | SSV bypass via vnode data swap | SIP Bypass | $50,000 | $150,000 |
| 4 | Kernel R/W via ICMPv6 socket corruption | Kernel R/W | $150,000 | $250,000 |
| 5 | Thread exception hijack → kernel code exec | Kernel Code Exec | $250,000 | $250,000 |

**Total estimated value:** $555,000 – $925,000

---

## Submission Notes

All findings require:
1. Working PoC on supported hardware (iOS 17.0–26.0.1)
2. Clear reproduction steps
3. Impact demonstration (e.g., reading a protected file, writing to /System)
4. Suggested fix (some provided above)

**Current blocker:** No real-device testing. All analysis is static (binary reverse engineering,
code audit). A PoC on hardware is required for submission.

**Priority order for submission:**
1. #4 (Kernel R/W) — highest value, clearest impact
2. #2 (Sandbox Escape) — demonstrates practical attack chain
3. #5 (Kernel Code Exec) — escalates #4 to full compromise

---

*Last updated: 2026-08-10 — Research phase, no PoC.*
