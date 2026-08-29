# W0lfSword - Bug Bounty Research Writeup

> **Purpose:** Document vulnerability findings from the DarkSword exploit ecosystem
> for Apple Security Bounty submission. Each section maps to an Apple bounty category.
>
> **Status:** Research-only. No PoC has been tested on hardware.

---

## 1. KASLR Info Leak via physical_oob_read_mo Race Window

**Bounty Category:** Kernel Info Leak / KASLR Bypass  
**Estimated Bounty:** $5,000–$25,000  
**CVE Reference:** TBD - DarkSword exploit unnamed

### Summary

The DarkSword exploit's `physical_oob_read_mo()` function creates a race window between
`pwritev()` and `mach_vm_map()` that allows reading freed physical pages. This is
fundamentally a KASLR bypass - physical pages contain kernel pointers.

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
- **No kernel R/W required**: This is a pure info leak - the OOB read race works without
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
- `/System/Library/` - system frameworks and daemons
- `/usr/lib/` - dynamic libraries
- `/bin/` and `/sbin/` - command-line tools

### Apple's Likely Fix

- Add vnode data pointer validation against the owning mount/volume
- Prevent vnode data pointer modification after vnode creation
- Add APFS seal verification at read time (not just mount time)

---

## 4. Kernel R/W via ICMPv6 Socket PCB Corruption

**Bounty Category:** Kernel Arbitrary Read/Write  
**Estimated Bounty:** $150,000–$250,000  
**CVE Reference:** TBD - DarkSword unnamed  

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
6. Reply to the exception - the kernel resumes the thread at the target function
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
1. #4 (Kernel R/W) - highest value, clearest impact
2. #2 (Sandbox Escape) - demonstrates practical attack chain
3. #5 (Kernel Code Exec) - escalates #4 to full compromise

---

## Apple Bounty Eligibility Classification

> Each finding below is classified against the Apple Security Bounty eligibility checklist.
> All findings currently lack human validation on real hardware - see Section 4 of the checklist.

---

### Finding #1: KASLR Info Leak via physical_oob_read_mo Race Window

```
Finding:        KASLR slide disclosure via freed physical page read race
Affected component: IOSurface / mach_vm_map / vm_page_free path
Affected OS/build: iOS 17.0–26.0.1 (all supported targets)
Affected hardware: A12–A18 Pro, M1–M4
Apple bounty category: Kernel Info Leak / KASLR Bypass
Security boundary affected: Kernel ASLR - attacker learns kernel slide
Attacker prerequisites: App sandbox, ability to create IOSurface, socket access
Victim interaction: None
Demonstrated impact: Reading data from freed physical pages (theoretical)
Exploitability: THEORETICAL
Human validation: NO
Reliable reproduction: NO
Working PoC: NO
Target Flag required: UNKNOWN
Target Flag demonstrated: N/A
Publicly disclosed: YES - DarkSword exploit is public on GitHub
Third-party component: NO
Apple scope exclusion: NO
Duplicate/known issue: UNKNOWN - similar race patterns known (PhysPuppet, landa)

Eligibility: DO NOT SUBMIT YET

Reason:
  No hardware testing. All analysis is static code audit. The DarkSword exploit code
  is already public, which may disqualify this finding regardless. Requires:
  - Real-device PoC demonstrating KASLR slide extraction
  - Proof that the leak works independently of the full exploit chain
  - Check if Apple has already classified public DarkSword as a known issue

Missing evidence:
  - Device model + iOS build number
  - Crash logs or sysdiagnose showing the leak
  - Before/after KASLR slide values
  - Isolated PoC (OOB read race only, without socket corruption chain)
```

---

### Finding #2: Sandbox Escape via Kernel Extension Table Patching

```
Finding:        Container sandbox bypass via in-kernel extension table modification
Affected component: Kernel sandbox_label.extension_set + MACF sandbox policy
Affected OS/build: iOS 17.0–26.0.1
Affected hardware: A12–A18 Pro, M1–M4
Apple bounty category: Sandbox Escape / Privilege Escalation ($100K–$250K)
Security boundary affected: App sandbox → full filesystem R/W
Attacker prerequisites: Kernel R/W (via DarkSword chain or equivalent)
Victim interaction: None
Demonstrated impact: Full filesystem read/write from sandboxed app (code claims, untested)
Exploitability: THEORETICAL (code exists, no hardware validation)
Human validation: NO
Reliable reproduction: NO
Working PoC: NO
Target Flag required: UNKNOWN
Target Flag demonstrated: N/A
Publicly disclosed: YES - sandbox_escape.m is in this repo
Third-party component: NO
Apple scope exclusion: NO
Duplicate/known issue: UNKNOWN - sandbox extension patching documented by opa334/CrazyMind90

Eligibility: DO NOT SUBMIT YET

Reason:
  This requires kernel R/W as a prerequisite (Finding #4). Apple typically considers
  this an "exploit chain" component. The sandbox escape code exists but has never
  been tested on hardware. Even if it works, it requires the kernel R/W exploit
  which is already public knowledge. May be classified as a known technique.

Missing evidence:
  - Device model + iOS build number
  - Proof of sandbox_check() returning 0 for /var after escape
  - Demonstration of file creation in /System/ from a non-entitled app
  - Sysdiagnose showing sandbox extension table before/after
  - Independent human validation on real hardware
```

---

### Finding #3: SSV Bypass via Vnode Data Pointer Swap

```
Finding:        Signed System Volume write bypass via vnode data pointer redirection
Affected component: APFS vnode / SSV mount layer
Affected OS/build: iOS 17.0–26.0.1
Affected hardware: A12–A18 Pro, M1–M4
Apple bounty category: System Integrity Protection / SSV Bypass ($50K–$150K)
Security boundary affected: Signed System Volume integrity → writable /System
Attacker prerequisites: Kernel R/W + sandbox escape (Findings #4 + #2)
Victim interaction: None
Demonstrated impact: Writing to /System/Library/, /usr/lib/, /bin/, /sbin/
Exploitability: THEORETICAL
Human validation: NO
Reliable reproduction: NO
Working PoC: NO
Target Flag required: UNKNOWN
Target Flag demonstrated: N/A
Publicly disclosed: YES - SSVUtils.m is in this repo
Third-party component: NO
Apple scope exclusion: NO
Duplicate/known issue: UNKNOWN

Eligibility: DO NOT SUBMIT YET

Reason:
  Deep in the exploit chain (requires K R/W + sandbox escape first). Even if the
  technique works, it's a component of a multi-stage chain. The chain's entry
  point (DarkSword) is public. Apple may consider SSV bypass via kernel R/W as
  "expected behavior given kernel compromise." Requires demonstration that the
  vnode manipulation persists across reboots or survives SSV seal checks.

Missing evidence:
  - Device model + iOS build number
  - Proof of persistent file in /System/Library/ after SSV write
  - Before/after APFS seal verification output
  - Demonstration that the written file survives a reboot
```

---

### Finding #4: Kernel R/W via ICMPv6 Socket PCB Corruption

```
Finding:        Arbitrary kernel read/write via ICMPv6 socket spray + PCB corruption
Affected component: Kernel ICMPv6 / in6pcb / getsockopt(ICMP6_FILTER) path
Affected OS/build: iOS 17.0–26.0.1
Affected hardware: A12–A18 Pro, M1–M4
Apple bounty category: Kernel Arbitrary Read/Write ($150K–$250K)
Security boundary affected: Userspace → kernel memory access
Attacker prerequisites: App sandbox, socket creation, IOSurface access
Victim interaction: None
Demonstrated impact: Full kernel memory read/write
Exploitability: THEORETICAL (code exists, claimed by DarkSword authors)
Human validation: NO (in this repo - original authors may have tested)
Reliable reproduction: NO
Working PoC: NO (in this repo - original exploit may work on specific versions)
Target Flag required: YES (likely - kernel R/W category)
Target Flag demonstrated: NO
Publicly disclosed: YES - DarkSword exploit public since 2025/2026
Third-party component: NO
Apple scope exclusion: HIGH RISK - already publicly disclosed pre-submission
Duplicate/known issue: LIKELY - DarkSword is a known public exploit

Eligibility: LIKELY INELIGIBLE

Reason:
  **Already publicly disclosed.** The DarkSword exploit (ICMP6 + IOSurface technique)
  has been publicly available on GitHub since 2025. Apple's terms state that findings
  publicly disclosed before Apple releases a fix are ineligible for bounty.
  
  The exploit is the entry point for the entire W0lfSword project, which is a public
  fork of the public FilzaJailedDS project. Even if a new bug is found within the
  chain, the core primitive is public knowledge.
  
  Exception possibility: If this specific ICMPv6 socket technique is different from
  what Apple has seen, and Apple hasn't fixed it yet, it MIGHT qualify. But the
  timeline is against us - the code has been public for months.

Missing evidence:
  - Proof that Apple has NOT already fixed this (check iOS 26.x KDK, sysctl diffs)
  - Demonstration on latest iOS 26.x public release
  - Target Flag (if applicable)
```

---

### Finding #5: Thread Exception Hijack → Kernel Code Execution

```
Finding:        Kernel function call via EXC_GUARD injection + thread state manipulation
Affected component: Kernel exception handling / thread_set_state / Mach exception ports
Affected OS/build: iOS 17.0–26.0.1
Affected hardware: A12–A18 Pro, M1–M4
Apple bounty category: Kernel Code Execution ($250K)
Security boundary affected: Userspace → kernel code execution
Attacker prerequisites: Kernel R/W (Finding #4) + remote thread access
Victim interaction: None
Demonstrated impact: Calling arbitrary kernel functions from userspace
Exploitability: THEORETICAL
Human validation: NO
Reliable reproduction: NO
Working PoC: NO
Target Flag required: YES (for max reward)
Target Flag demonstrated: NO
Publicly disclosed: YES - RemoteCall.m is in this repo
Third-party component: NO
Apple scope exclusion: NO
Duplicate/known issue: UNKNOWN

Eligibility: DO NOT SUBMIT YET

Reason:
  Requires Findings #4 and #3 as prerequisites. This is the deepest component of the
  exploit chain. Even if it works, demonstrating kernel code execution as distinct
  from kernel R/W is challenging - Apple may consider it "just another use of kR/W."
  Needs to demonstrate something that kR/W alone cannot achieve (e.g., calling a
  PAC-protected function, or executing in a context kR/W can't reach).

Missing evidence:
  - Device model + iOS build number
  - Demonstration of calling a kernel function that cannot be achieved via kR/W alone
  - Proof of code execution in kernel context (not just data write)
  - Target Flag (if applicable)
```

---

## Overall Assessment

| Finding | Status | Reason |
|---------|--------|--------|
| #1 KASLR leak | DO NOT SUBMIT YET | No hardware PoC, DarkSword already public |
| #2 Sandbox escape | DO NOT SUBMIT YET | Requires #4, no hardware validation |
| #3 SSV bypass | DO NOT SUBMIT YET | Requires #4+#2, deep in chain |
| #4 Kernel R/W | LIKELY INELIGIBLE | Already publicly disclosed (DarkSword) |
| #5 Kernel code exec | DO NOT SUBMIT YET | Requires #4+#3, no hardware PoC |

**To make any of these submittable, you need:**
1. A jailbroken iPhone on iOS 17.x–26.x (the checklist requirement)
2. Reproduce the exploit and capture evidence
3. For #4 specifically: determine if Apple has already classified DarkSword (check their CVE list)
4. For #1: extract it from the chain and demonstrate as a standalone info leak

**Golden rule applied:** None of these findings meet the minimum bar for Apple submission.
All require human validation on real hardware before any "READY" classification is possible.

---

*Last updated: 2026-08-10 - All findings: DO NOT SUBMIT YET or LIKELY INELIGIBLE*
*Requires human researcher validation on real hardware before reclassification.*
