# iOS Kernel Exploitation - Glossary

> Quick reference for terms used in the W0lfSword codebase.

---

## A

**AMFI** - Apple Mobile File Integrity. Kernel module that enforces code signing. Controls which binaries can run via `CS_VALID`, `CS_PLATFORMIZED`, and related flags on `proc.p_flag`.

**APFS fsnode** - The APFS filesystem's in-memory inode structure. Contains file metadata (UID, GID, mode, flags like `UF_IMMUTABLE`). Stored at `vnode.v_data`. W0lfSword patches the `bsd_flags` field at `+0x70` to clear the immutable flag.

**arm64e** - ARM 64-bit architecture with Pointer Authentication Code (PAC) support. A12+. Uses `xpaci()` to strip PAC bits from kernel pointers.

**AST** - Asynchronous Software Trap. A per-thread flag (`thread.ast`) that triggers exception delivery. W0lfSword sets `AST_GUARD` to inject EXC_GUARD exceptions.

---

## D

**DART** - Device Address Resolution Table. Apple's IOMMU for M1+. Maps device physical addresses to CPU physical addresses. Kernel exploit relevant when manipulating DMA.

**DarkSword** - The kernel exploit engine used by W0lfSword. Combines ICMPv6 socket spray with IOSurface physical OOB (out-of-bounds) read/write to achieve kernel R/W. Named after wh1te4ever's original exploit.

---

## E

**EXC_GUARD** - Mach exception type for guarded file descriptors. W0lfSword abuses it to inject exceptions into target threads for RemoteCall (kernel function calling from userspace).

**extension_set** - Kernel structure (`struct extension_set`) containing the sandbox extension hash table. Located at `sandbox_label.extension_set`. W0lfSword patches this to grant `"/"` access with `com.apple.app-sandbox.read-write` class.

---

## I

**ICMPv6** - Internet Control Message Protocol version 6. Used by DarkSword for socket spray: creates thousands of ICMPv6 sockets to exhaust the zone allocator and control physical page layout.

**IOMMU** - See DART.

**IOSurface** - Framework for sharing graphics buffers between processes. DarkSword abuses `IOSurfaceCreate` with physical address to create mappings that survive deallocation, enabling the physical OOB primitive.

---

## K

**KASLR** - Kernel Address Space Layout Randomization. Randomizes kernel slide at boot. Leaked via freed physical page reads in the DarkSword race window.

**kalloc** - XNU kernel memory allocator (zone-based). Socket spray targets the `inpcb` zone to place controlled data at predictable physical addresses.

**kread64/kwrite64** - Kernel read/write primitives. After DarkSword achieves kernel R/W, these functions read/write arbitrary kernel memory via the corrupted ICMPv6 filter pointer in the socket PCB.

**KTRR** - Kernel Text Read-only Region. Hardware-enforced (via MMU) on A10+. Prevents modification of kernel code even with kernel R/W. Data-only attacks (like sandbox patching) are still possible.

---

## M

**Mach port** - IPC endpoint in XNU. Every thread/task has a port. W0lfSword uses exception ports for RemoteCall thread hijacking.

**MIG** - Mach Interface Generator. RPC mechanism for kernel syscalls. W0lfSword's `MigFilterBypassThread` patches kernel MIG filter variables (`migLock`, `migSbxMsg`, `migKernelStackLR`) to bypass sandbox restrictions on MIG calls.

**MobileSubstrate** - Jailbreak framework for hooking ObjC methods at runtime. W0lfSword is a MobileSubstrate tweak injected into Filza.

**MTE** - Memory Tagging Extension. ARMv8.5-A feature on A19/M5. Tags all heap allocations with 4-bit tags, breaking DarkSword's heap spray technique. Not yet deployed in iOS as of 26.x.

---

## P

**PAC** - Pointer Authentication Code. ARMv8.3-A feature on A12+. Signs pointers with a cryptographic hash in the upper bits. W0lfSword uses `xpaci()` to strip PAC before reading, and tries to re-sign via gadgets for writes.

**PCB** - Protocol Control Block. Per-socket kernel structure (`inpcb`). DarkSword corrupts the `in6p_icmp6filt` pointer in the ICMPv6 PCB to create a kernel R/W gadget.

**pe_v1 / pe_v2** - Two exploit paths in DarkSword. `pe_v1`: A12-A17, mass socket spray + brute force search. `pe_v2`: A18 only, wired page marker technique (allocates 2GB of tagged pages).

**PPL** - Page Protection Layer. Separate kernel memory protection on A12+. not directly relevant to W0lfSword since it operates below PPL level.

**PUAF** - Physical Use-After-Free. Exploit class used by kfd (felix-pb). Frees a physical page while a dangling PTE still maps it, enabling physical read/write. DarkSword uses a similar primitive via IOSurface.

---

## S

**SEP** - Secure Enclave Processor. Isolated coprocessor for cryptographic keys. Not directly attacked by W0lfSword.

**SMMU** - System Memory Management Unit. See DART.

**SMR** - Signed Memory Region. Apple's mitigation for use-after-free in kernel heap. Pointers in certain structs are encoded with `base << shift`. W0lfSword uses `kread_smrptr()` to decode SMR pointers.

**SPTM** - Secure Page Table Monitor. Hardware-enforced page table integrity on A14+. Prevents page table manipulation from kernel context.

**SSV** - Signed System Volume. APFS snapshot with cryptographic seal on `/System/`. W0lfSword bypasses SSV by swapping `vnode.v_data` pointers to redirect writes from a temp file to the sealed path.

---

## T

**T1SZ** - Translation table level 1 size. ARM MMU configuration value that defines the virtual address space split. `0x19` on A12-A15, `0x11` on A16+. Wrong T1SZ means wrong PAC mask → all kernel pointer reads return garbage.

**TCC** - Transparency, Consent, and Control. iOS privacy database (`/var/mobile/Library/TCC/TCC.db`). Controls app access to camera, mic, contacts, etc. W0lfSword could modify this with full filesystem access.

**tweak** - In jailbreak context, a MobileSubstrate dylib that hooks methods in other apps. W0lfSword is a tweak injected into Filza.

---

## V

**vnode** - Virtual node. Kernel structure representing an open file/directory. W0lfSword manipulates `vnode.v_data` and `vnode.v_parent` for SSV bypass and file redirection.

**VM_MIN / VM_MAX** - Kernel virtual address range. `0xFFFFFFDC00000000` to `0xFFFFFFFBFFFFFFFF` on iOS 17-26. Used to validate kernel pointers before dereference.

---

## X

**XNU** - X is Not Unix. The macOS/iOS kernel. Darwin kernel based on Mach + BSD.

**XPF** - X PF (X PatchFinder). Offset resolution engine that decompresses kernelcaches and pattern-matches struct offsets. Used to find offsets for new iOS versions.

**xpaci** - XPAC Instruction. ARM64 instruction that strips PAC bits from a pointer. W0lfSword's inline assembly `0xDAC143E0` executes this instruction.

---

## Z

**zone allocator** - XNU's kernel heap allocator (zalloc). Socket spray targets the `inpcb` zone to place controlled data. Zone exhaustion is the foundation of the DarkSword heap manipulation.
