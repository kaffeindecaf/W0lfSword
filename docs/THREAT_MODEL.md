# W0lfSword — Threat Model

> **Purpose:** Identify what Apple could change to break each component of the exploit chain.
> This helps prioritize what to fix when new iOS versions drop.

---

## Component Breakdown

### 1. ICMPv6 Socket Spray (DarkSword — kexploit_opa334.m)

**What it exploits:** The kernel ICMPv6 `inpcb` zone allocator's deterministic behavior.
Spraying ~10,000 sockets exhausts the zone and forces predictable physical page layout.

**Apple's fix options:**
- Add randomized freelist to the inpcb zone
- Limit ICMPv6 socket count per-process
- Add guard pages between socket PCB allocations
- Move ICMPv6 filter data out of PCB (separate allocation)

**Detection difficulty:** Moderate. Socket creation is a normal operation.
Apple could add rate limiting or entropy to the allocator without breaking anything.

**Survival risk:** HIGH. Zone allocator hardening is an active area of kernel development.

---

### 2. IOSurface Physical OOB (DarkSword)

**What it exploits:** `IOSurfaceCreate` with a physical address creates a mapping that
survives `mach_vm_deallocate`. The race between `pwritev` and `mach_vm_map` creates
a window where freed physical pages can be read/written.

**Apple's fix options:**
- Zero freed physical pages before reuse (already partially done in iOS 18+)
- Validate IOSurface backing physical pages are still owned by the surface
- Add physical page ownership tracking
- Reduce the race window by changing zone allocator behavior

**Detection difficulty:** Difficult. The race uses standard Mach VM operations.
Hard to detect without deep kernel introspection.

**Survival risk:** MEDIUM-HIGH. Physical page zeroing is already being deployed.

---

### 3. Kernel R/W via Corrupted ICMPv6 Filter (krw.m)

**What it exploits:** Overwriting the `icmp6_filter` pointer in the socket PCB to point
back into the PCB structure. `getsockopt(ICMP6_FILTER)` then reads kernel memory through
the corrupted pointer; `setsockopt` writes.

**Apple's fix options:**
- Add bounds checking on `icmp6_filter` pointer in getsockopt/setsockopt
- Validate filter pointer is within the socket's own allocation
- Use a separate copy of the filter data in kernel space (don't trust in-pcb pointer)
- Sign the filter pointer with PAC and verify on access

**Detection difficulty:** Easy. `setsockopt(ICMP6_FILTER)` with a non-standard value
is unusual. Apple could add a check that the filter address is within expected ranges.

**Survival risk:** HIGH. This is the most fragile component — a single bounds check kills it.

---

### 4. Sandbox Escape (sandbox_escape.m)

**What it exploits:** Walking `proc_ro → ucred → cr_label → sandbox_label → extension_set`
in kernel memory and patching extension paths to `"/"` and classes to `read-write`.

**Apple's fix options:**
- Store sandbox extension data in read-only memory after process init
- Add integrity checks (hash/checksum) on extension data
- Validate extension paths at access time (not just consume time)
- Move sandbox policy enforcement to a more privileged context (PPL/SPTM)

**Detection difficulty:** Easy if integrity checks exist. Currently none.

**Survival risk:** MEDIUM. Kernel struct layout changes every iOS version (offsets shift),
but the technique of patching in-kernel data structures is fundamental to kernel exploits.

---

### 5. SSV Bypass (SSVUtils.m)

**What it exploits:** Swapping `vnode.v_data` pointers between a temp file (writable) and
a sealed system file. The kernel trusts the v_data pointer without verifying it belongs
to the correct APFS volume/snapshot.

**Apple's fix options:**
- Add vnode data pointer validation against owning mount/volume
- Prevent v_data modification after vnode creation
- Add APFS seal verification at read time (not just mount time)

**Detection difficulty:** Moderate. vnode manipulation is invisible to userspace.

**Survival risk:** LOW-MEDIUM. vnode structure is old and stable. Adding validation would
require significant kernel refactoring.

---

### 6. RemoteCall — Thread Exception Hijack (RemoteCall.m)

**What it exploits:** Injecting `EXC_GUARD` into a thread's AST, capturing the exception
message, overwriting thread state (PC, LR, x0-x7), and replying — causing the kernel to
resume the thread at an attacker-chosen kernel function.

**Apple's fix options:**
- Add PAC signing to exception reply state
- Validate thread state before resuming from exception
- Restrict EXC_GUARD to system threads only
- Zero unused state registers on exception return

**Detection difficulty:** Difficult. Thread state manipulation via Mach exception ports
is a legitimate debugging mechanism. Hard to distinguish from GDB/LLDB.

**Survival risk:** LOW. Exception-based debugging primitives are fundamental to Mach.
Radically changing them would break Xcode debugging.

---

### 7. Offset Table (offsets.m)

**What it exploits:** Hardcoded per-iOS-version kernel struct offsets. These change every
iOS release as the kernel is recompiled.

**Apple's "fix":** Not a vulnerability, just a maintenance burden. Apple naturally changes
struct layouts with each XNU build.

**Survival risk:** N/A — this is the maintenance cost, not a vulnerability. Each new iOS
version requires running XPF on the kernelcache to find new offsets.

---

## Attack Surface Summary

| Component | Apple's Fix Difficulty | Survival Rating |
|-----------|----------------------|-----------------|
| Socket spray | Easy | HIGH risk |
| ICMPv6 filter R/W | Easy | HIGH risk |
| IOSurface OOB | Medium | MEDIUM-HIGH risk |
| Sandbox patching | Medium | MEDIUM risk |
| SSV vnode swap | Hard | LOW-MEDIUM risk |
| Thread hijack | Hard | LOW risk |
| Offset table | N/A | Maintenance only |

---

## Apple's Most Likely Response Order

1. **Fix ICMPv6 filter pointer dereference** — smallest change, biggest impact.
   One bounds check in `rip6_ctloutput` kills the entire chain.

2. **Harden zone allocator** — already in progress across iOS 17-26.

3. **Add sandbox integrity checks** — low-hanging fruit, especially with `borrow_sandbox_ext`
   patching documented by the community.

4. **SSV vnode hardening** — requires filesystem changes, least likely short-term.

---

## Mitigation for W0lfSword

To survive future iOS releases:

1. **Diversify exploit primitives** — add PUAF fallback (kfd-style PhysPuppet/Landa).
   Socket spray will eventually be killed.

2. **Dynamic offset resolution** — run XPF on-device instead of relying on hardcoded tables.
   This survives minor struct layout changes.

3. **Decouple the chain** — make each component work independently so Apple fixing one
   doesn't kill the entire chain.

4. **Monitor KC releases** — track iOS kernelcache changes via [theapplewiki](https://theapplewiki.com)
   and update offsets before each release.

---

*Last updated: 2026-08-10*
