# iOS 26.1+ Kernel CVEs (2025–2026): LPE Candidates for a 26.1+ Kernel Stage (W0lfSword K5.6 / ROADMAP C5.1)

**Date:** 2026-08-29 · **Author:** W0lfSword research agent · **Scope:** xnu/kernel bugs fixed in iOS 26.1 → 26.6.1 (all builds shipped Nov 2025 → Aug 2026), evaluated as **local privilege-escalation candidates usable from a sandboxed app** for re-opening the kernel gate closed by the DarkSword patch in 26.1.

**Verification legend:** `[V]` = verified against primary source (Apple security page / NVD / vendor blog). `[U]` = unverified / third-party claim, no primary confirmation.

---

## 1. Release map (builds & xnu)

| iOS | Release date | Build (where known) | xnu | Primary source |
|---|---|---|---|---|
| 26.0 | 2025-09-15 | 23A355 | xnu-12377.2.9 | repo K4.1; support.apple.com/en-us/125108 |
| 26.0.1 | 2025-09-29 | — | — | support.apple.com/en-us/100100 |
| **26.1** | 2025-11-03 | 23B85 | xnu-12377.42.6~55 | repo K4.1; support.apple.com/en-us/125632 |
| **26.2** | 2025-12-12 | 23C55 | xnu-12377.62.10~1 | repo K4.7; support.apple.com/en-us/125884 |
| **26.3** | 2026-02-11 | 23D125 (RC tested) | xnu-12377.81.4 | support.apple.com/en-us/126346; zeroxjf PoC repo |
| 26.3.1 | 2026-03-17 | — | — | Background Security Improvements (WebKit only) — 126604 |
| **26.4** | 2026-03-24 | — | — | support.apple.com/en-us/126792 |
| **26.5** | 2026-05-11 | — | (macOS 26.5 beta: xnu-12377.120.72.0.4) | support.apple.com/en-us/127110 |
| **26.5.2** | 2026-06-29 | — | (macOS 26.5.2 = 25F84, xnu-12377.121.10) | support.apple.com/en-us/127594; gracecondition writeup |
| **26.6** | 2026-07-27 | beta 23G5028e; final 23Gxx `[U]` | — | support.apple.com/en-us/128066 |
| **26.6.1** | 2026-08-17 | 23G83 | — | support.apple.com/en-us/148282 |

iOS 26.6.1 fixes were first made available in the iOS 27 betas. iOS 27 in beta as of 2026-08.

---

## 2. Master CVE table — Kernel-component bugs fixed in iOS 26.1 → 26.6.1

Format: **CVE** · component · class (CWE) · impact · live window (vulnerable iOS) · fixed in · public PoC/writeup · LPE-from-app assessment.

### iOS 26.1 (2025-11-03) — support.apple.com/en-us/125632
| CVE | Class | Impact | PoC/writeup | LPE from sandboxed app? |
|---|---|---|---|---|
| CVE-2025-43398 (Cristian Dinca) | memory handling | unexpected system termination | none public | DoS-grade, low value |
| CVE-2025-43510 (Apple) | memory corruption (improved lock-state checking) | malicious app → unexpected changes in memory shared between processes | none | Shared-memory corruption; **kernel-stage value unclear**; no detail |
| **CVE-2025-43520** (Apple) `[V] NVD CVSS 5.5 AV:L` | memory corruption (CWE-120) | app → unexpected system termination **or write kernel memory** | none | **Kernel write from app**, but Apple-internal (no researcher credit, no detail). Also fixed 18.7.2 |

Also kernel-driver area in 26.1: **Apple Neural Engine** CVE-2025-43447, CVE-2025-43462 (app → termination or corrupt kernel memory) — 125632.

### iOS 26.2 (2025-12-12) — support.apple.com/en-us/125884
| CVE | Class | Impact | PoC/writeup | LPE from sandboxed app? |
|---|---|---|---|---|
| **CVE-2025-46285** (Kaitao Xie & Xiaolong Bai, Alibaba) | **integer overflow (CWE-190) — "adopted 64-bit timestamps"** | **app → root privileges** | **no public exploit/writeup** (see §3) | **YES — the repo's tracked K4.7 bug.** Live on 26.1 only (fixed 26.2). Function-level detail not public; repo XPF diff narrowed it. |

(26.2 also fixed userspace AppleJPEG CVE-2025-43539 — bounds checks, file→memory corruption; tracked separately in repo as userspace escape, NOT kernel.)

### iOS 26.3 (2026-02-11) — support.apple.com/en-us/126346
| CVE | Class | Impact | PoC/writeup | LPE from sandboxed app? |
|---|---|---|---|---|
| CVE-2026-20654 (Jian Lee @speedyfriend433) | memory handling | termination | none | DoS-grade |
| **CVE-2026-20626** (Keisuke Hosoda) `[V] NVD CWE-862; CVSS 7.8 (OpenCVE)` | **missing authorization check** | **malicious app → root privileges** | none public | **YES — root LPE, "app" attacker model.** Live 26.1–26.2 only. Zero public detail (no component/function). |
| CVE-2026-20671 (Zhou/Qian/Tan/Krishnamurthy/Vanhoef, UCR+KU Leuven) | logic issue | privileged network position → intercept traffic | none | network-layer, not LPE |

26.3 kernel acknowledgements: Joseph Ravichandran (MIT CSAIL), Xinru Chi (Pangu Lab) — kernel researchers active in 26.x window.

### iOS 26.4 (2026-03-24) — support.apple.com/en-us/126792
| CVE | Class | Impact | PoC/writeup | LPE from sandboxed app? |
|---|---|---|---|---|
| CVE-2026-28868 (Gor Aleksanyan et al.) | logging → redaction | app → disclose kernel memory | none | info-leak only |
| CVE-2026-28867 (Jian Lee) | auth issue | app → leak sensitive kernel state | none | info-leak only |
| CVE-2026-20698 (DARKNAVY) | memory handling | app → termination or **corrupt kernel memory** | none public | possible LPE seed; no detail |
| **CVE-2026-20687** (Johnny Franks @zeroxjf; entry updated 2026-08-20) | **UAF (CWE-416) — AppleJPEGDriver `startDecoder` timeout path** | app → termination **or write kernel memory** | **YES — public PoC + analysis** (github.com/zeroxjf/CVE-2026-20687-AppleJPEGDriver-UAF; github.com/enfilade-labs/...). Timeout in `startDecoder_sync` frees request without dequeuing embedded queue-node; later `fullSpeedRequestExist()` walk derefs stale node → MTE fault panic (deferred; triggered by opening Camera). **Panic-only PoC today; UAF itself = kernel R/W potential.** | **YES-ish — reachable via `IOServiceOpen("AppleJPEGDriver")` from an app, no entitlements.** Live 26.1–26.3.x (fixed 26.4). Most-documented kernel bug in range. |
| CVE-2026-28896 (Dave G.) — **ppp** (entry added 2026-08-20) | memory handling | attacker → termination **or read kernel memory** | none | PPP networking; attack surface unclear `[U]` |
| CVE-2026-28858 (Hazem Issa, Yongdae Kim, KAIST) — **Telephony** | buffer overflow | **remote user → termination or corrupt kernel memory** | none | remote (telephony stack), not local app |

### iOS 26.5 (2026-05-11) — support.apple.com/en-us/127110
| CVE | Class | Impact | PoC/writeup | LPE from sandboxed app? |
|---|---|---|---|---|
| CVE-2026-43654 (Vaagn Vardanian, Nathaniel Oh) | memory handling | app → disclose kernel memory | none | info-leak |
| CVE-2026-28897 (popku1337, STAR Labs, Robert Tran, Aswin Gokulakannan) `[V] CWE-121 stack bof` | **stack buffer overflow** | local user → termination **or read kernel memory** | none | local; read+DoS; no write |
| **CVE-2026-28951** (Csaba Fitzl @theevilbit, Iru) `[V] CWE-863; CVSS 7.8 (CISA-ADP)` | **incorrect authorization** | **app → root privileges** | none public | **YES — root LPE from app.** Live 26.1–26.4.x (widest root-LPE window in range). No detail. |
| **CVE-2026-28972** (STAR Labs — Billy Jheng Bing Jhong & Pan Zhenpeng; Ryan Hileman via Xint Code) `[V] CWE-787` | **out-of-bounds write** | app → termination **or write kernel memory** | none public (STAR Labs may publish later) | **YES — kernel write from app.** Live 26.1–26.4.x. No detail. |
| CVE-2026-28986 (Chris Betz, Tristan Madani, Ryan Hileman) | race condition | app → termination | none | DoS-grade race |
| CVE-2026-28987 (Dhiyanesh Selvaraj) | logging | app → leak sensitive kernel state | none | info-leak |

### iOS 26.5.2 (2026-06-29) — support.apple.com/en-us/127594
| CVE | Class | Impact | PoC/writeup | LPE from sandboxed app? |
|---|---|---|---|---|
| **CVE-2026-43724** (impost0r (ret2plt), Hyunwoo Kim @v4bel) `[V] CWE-20; NVD CVSS 7.8 AV:L (after CISA-ADP correction; GHSA initially scored AV:N 9.8)` | **missing in-page bounds check in `vm_shared_region_slide_page_v5()` (dyld shared-cache slide walker) → 8-byte OOB read+write into adjacent frame; syscall 536 `shared_region_map_and_slide_2_np`, no suser/entitlement gate** | app → termination **or write kernel memory** | **YES — full public LPE "DirtySlide": writeup gracecondition.github.io/posts/dirtyslide + PoC github.com/gracecondition/DirtySlide, github.com/khanhduytran0/DirtySlide, github.com/impost0r/Rie** | **YES on macOS (unpriv → root, full physical R/W via forged PTE). On iPhone: author states sandbox-bypass + SPTM needed; worked only in macOS VMs (VMAPPLE kernel, no SPTM).** See §4. Fixed 26.5.2 → live 26.0–26.5.1. |
| CVE-2026-43722 (Feng Xue/XGPT ThreatBook, Hyunwoo Kim) | input sanitization | app → leak sensitive kernel state | none | info-leak |
| **CVE-2026-39868** (Vladislav Shevchenko/Positive Technologies, Ye Zhang/Baidu Security, STAR Labs) `[V] CWE-20; reported 9.1 by third parties, plausibly AV:L ~7.8` | improper input validation | app → termination **or corrupt kernel memory** | none public | **YES — kernel memory corruption; ZDI: "elite attribution … weaponizable, possibly Pwn2Own-grade".** Live 26.1–26.5.1. |
| CVE-2026-43743 — **IOGPUFamily** | — | app → termination | none | DoS-grade |

### iOS 26.6 (2026-07-27) — support.apple.com/en-us/128066 (+ ZDI July 2026 review cross-platform matrix)
| CVE | Class | Impact | PoC/writeup | LPE from sandboxed app? |
|---|---|---|---|---|
| CVE-2026-64749 (STAR Labs, Ashish Kunwar, Hiroki Imai/LAC, hxr1, Peterpan0927) | memory handling | app → termination or **corrupt kernel memory** | none | possible; no detail |
| **CVE-2026-43778** (f0r/MurphySec, Feng Xue & XGPT/ThreatBook, DARKNAVY, Hiroki Imai/LAC, et al.) | **UAF** | app → termination **or write kernel memory** | none | **YES — kernel write from app, many co-credits.** Live 26.1–26.5.2. |
| CVE-2026-64709 (Pasquale Scola, STAR Labs) | memory handling | app → disclose kernel memory | none | info-leak |
| CVE-2026-64735 (Gor Aleksanyan) | state mgmt | remote attacker → bypass network filters | none | network, not LPE |
| CVE-2026-43739 + CVE-2026-43816 (STAR Labs, impost0r, Ruslan Dautov, UIUC, Blackwing, zeroxjf, 34306, et al. — huge co-credit) | **OOB write (CWE-787)** | app → termination | none | possible LPE seed (OOB write, app); no detail |
| CVE-2026-43822 / 64729 / 43814 / 64700 / 43799 (STAR Labs, Josh Maine, beist, Adam Doupé, 34306, odinshell…) | **UAF** | app → termination | none | UAF cluster; likely same/similar bug family; no write impact stated |
| CVE-2026-28931 (Redon Gashi, Abhijeet Singh, Peter Malone, Omar Cerrito) | **buffer overflow — NFS client** | connecting to malicious NFS server → **kernel memory corruption** | none | remote-ish (NFS server), not local app |
| CVE-2026-43817 (Huy Nguyen @34306) | OOB read | app → termination | none | DoS-grade |
| CVE-2026-43769 (STAR Labs) | integer overflow | app → termination | none | DoS-grade |
| CVE-2026-43810 (STAR Labs) | memory handling | **remote user → termination or corrupt kernel memory** | none | remote |
| CVE-2026-64775 (Ryan Hileman / Xint Code) | memory init | app → termination | none | DoS-grade |
| CVE-2026-64720 (anon, odinshell, Jian Zhou, Ye Zhang) | race | app → termination | none | DoS-grade |
| CVE-2026-64751 (N.M.Praveen Nawarathne) | **UAF** | app → termination **or write kernel memory** | none | **YES — kernel write from app**; live 26.1–26.6.0 |
| CVE-2026-64721 (Lukas Gerlach) | state mgmt | app → sensitive data | none | not LPE |
| **CVE-2026-43805 — IOKit** (이재영) | **race condition** | app → termination **or write kernel memory** | none | **YES — IOKit race → kernel write**; live 26.1–26.5.2 |
| **CVE-2026-64747 — AVEVideoEncoder** (Franco Belman, Blackwing Intelligence) `[V] CWE-120 buffer overflow; also fixed 18.7.10` | **buffer overflow (size validation)** | **app → arbitrary code execution with kernel privileges** | none public (Blackwing historically publishes) | **YES — the only kernel-CODE-EXEC impact in range.** Video-encoder kext reachable via app APIs. Live 26.1–26.5.x (fixed 26.6). |
| CVE-2026-64762 — AVEVideoEncoder (Blackwing, Dun) | OOB read | app → termination | none | DoS-grade |

### iOS 26.6.1 (2026-08-17) — support.apple.com/en-us/148282 (fixes first shipped in iOS 27 betas)
| CVE | Class | Impact | PoC/writeup | LPE from sandboxed app? |
|---|---|---|---|---|
| **CVE-2026-65343** (Drinor Selmanaj/Sentry, Surya Narayan Kushwaha) | **UAF** | **remote attacker → unexpected system termination** | none | remote-triggered UAF (network path); not local-app LPE |
| CVE-2026-65349 (anonymous) | OOB read | app → termination **or read kernel memory** | none | local read+DoS; no write |
| CVE-2026-65330 (Bhaswanth Chigurupati, STAR Labs) | memory handling | app → termination **or corrupt kernel memory** | none | possible LPE seed; live 26.1–26.6.0 |
| CVE-2026-64788 — IOGPUFamily (f00l, 3ndy1, Y1nkoc, 云散花折, Arjanit Isufi) | memory handling | processing web content → memory corruption | none | IOGPU (GPU) — interesting surface; no detail |

**Cross-platform note:** macOS-only kernel bugs in the same window (e.g. CVE-2026-28982, 43754, 43782, 64723, 64727 type confusion — Ye Zhang/Baidu, 43809, 64744 — AppleRAID CVE-2026-43681, afpfs CVE-2026-64767, IOSkywalkFamily CVE-2026-39877) do **not** appear on the iOS pages and are excluded from the iOS candidate set (verify per-platform before reuse).

---

## 3. Deep dive — CVE-2025-46285 (the repo's tracked K4.7 bug)

**All public detail collected (2026-08-29):**

- **Apple text (all platforms):** "An integer overflow was addressed by adopting 64-bit timestamps. An app may be able to gain root privileges." Fixed in iOS/iPadOS **26.2** (and 18.7.3), macOS Tahoe 26.2 / Sequoia 15.7.3 / Sonoma 14.8.3, tvOS 26.2, watchOS 26.2, visionOS 26.2. Credit: **Kaitao Xie and Xiaolong Bai of Alibaba Group**. `[V] support.apple.com/en-us/125884`
- **CWE-190** (integer overflow/wraparound); CVSS 3.1 **7.8** `AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`; EPSS ~0.00175; **not** in CISA KEV; no in-the-wild reports. `[V] NVD/GHSA`
- **No public exploit, PoC, or patch analysis exists.** Two GitHub repos (0xcrypto/apple-cves, tralsesec/AnatomyOfABug) merely catalog the CVE. `[V]`
- **One video** ("CVE-2025-46285 Apple's Kernel Time Bomb", Gray Hat Security, 16 subs, 2025-12-30) claims a 32-bit `time_t` → `int64_t` widening in a security `if` check (year-2038 narrative). **This is low-quality/AI-flavored content and contradicts the repo's own binary diff** — treat as unreliable. `[U]`
- **Repo K4.7 evidence (primary, from kernelcache diff):** 26.1 = xnu-12377.42.6~55 (23B85) vs 26.2 = xnu-12377.62.10~1 (23C55), T8110 kcs, XPF-resolved. The 1e9 seconds→ns conversion helper and all 6 W-const callers are **byte-semantically identical** between builds; **zero 32-bit multiply sites** in either kernel → the fix is **not** in seconds→ns multiply paths. Conclusion: overflow lives in a **struct field / non-multiply path** (e.g. 32-bit truncation of a tv_sec/timestamp field used in a deadline/expiry check, or a widened timestamp struct member). Function-level attribution (kern_time.c vs clock.c vs scheduler timers) **not publicly identified**.
- **Assessment for K5.6:** genuine kernel **root LPE from an app**, but live window is only **26.1** (patched 26.2); hardware-gated (needs a 26.1 device); root cause location still unknown → risk-adjusted: valuable if a 26.1 test device exists, otherwise deprioritize vs bugs with wider windows.

---

## 4. Deep dive — CVE-2026-43724 "DirtySlide" (only fully public kernel-write LPE in range)

- **Bug:** `vm_shared_region_slide_page_v5()` in `osfmk/vm/vm_shared_region.c` walks an attacker-supplied pointer chain (dyld shared-cache v5 slide-info) **without the in-page bounds check** that v1–v4 and the chained-fixup pager have → walks off the page → **8-byte OOB read+write into the next physical frame**. `[V] gracecondition.github.io/posts/dirtyslide`
- **Reachability:** syscall **536** `shared_region_map_and_slide_2_np` (`bsd/vm/vm_unix.c`); no `suser`/`priv_check`/entitlement gate; reachable unprivileged by spawning a `_POSIX_SPAWN_RESLIDE` child with shimmed libdyld/libSystem (fresh shared region; `sr_first_mapping == -1`). Child is ad-hoc-signed, unentitled. `[V]`
- **Exploitation (macOS):** groom leaf **page-table page** physically adjacent → OOB write forges a PTE → virtual page maps arbitrary physical RAM → march aperture in 32 MB windows → **full physical R/W** → find own `posix_cred` (uid==ruid==svuid==501) → zero uid/gid → park in `select()`, `chmod 04755 suidwrap` → root shell. `[V]`
- **Vulnerable builds:** macOS 26.5 beta `25F5042g` (xnu-12377.120.72.0.4~13) exploited; vulnerable through 26.5.x, **fixed 26.5.2 (macOS 25F84, xnu-12377.121.10; iOS/iPadOS 26.5.2, iOS 18.7.10, Sequoia 15.7.8, Sonoma 14.8.8, tvOS/visionOS/watchOS 26.6)**. `[V]`
- **iPhone caveats (author's own):** (1) triggering 536 in the vulnerable context needs an **application sandbox bypass**; (2) **SPTM** (Secure Page Table Monitor, A17 Pro/M3+ and later) locks page tables → the PTE-forgery path fails on SPTM devices; author: "In its current state, probably not [jailbreakable on iPhone]… this exploit only worked on macOS virtual machines." Devices **without SPTM (≤ A16)** may not be protected by caveat (2) — unverified whether the rest of the chain survives the iOS memory manager. `[V] author; [U] iOS portability`
- **Why it still ranks #1:** only public PoC + full writeup + kernel memory write in the entire 26.1+ window; the missing-bounds-check class means iOS 26.0–26.5.1 iPhones carry the same `vm_shared_region_slide_page_v5` defect; macOS-first porting (shim/`_POSIX_SPAWN_RESLIDE` technique) is the immediate next step, with SPTM-free iPhones (A16/iPhone 15 and earlier) as the realistic iOS target.

---

## 5. Project Zero & ZDI status (2025–2026)

- **Project Zero:** no 2025–2026 P0-tracked iOS **kernel** finding with a public writeup found for the 26.x window (P0's 2025–26 public work: Pixel 9 0-click chain blog posts — Android; older iOS kernel posts). No P0 issue numbers map to the CVEs in §2. **Note:** the "unexpected kernel" series referenced in the task brief could not be located via public search `[U]` — if it exists it is not indexed; recommend a follow-up via the P0 tracker (issues.oss-fuzz.com) directly. Sources checked: projectzero.google (blog index), googleprojectzero.github.io (0days-in-the-wild).
- **ZDI:** no ZDI-bought advisories for these kernel CVEs (ZDI advisory feed for 2026 covers macOS userspace USD/ImageIO/CoreAudio + Safari — e.g. ZDI-26-310…314, 490–494; none target the xnu bugs above). ZDI **monthly reviews** are the useful secondary source: June 2026 review (26.5.2) flags **CVE-2026-43724** ("kernel memory write… privilege-escalation half of a full exploit chain") and **CVE-2026-39868** ("elite roster… weaponizable, possibly Pwn2Own-grade"); July 2026 review (26.6) flags **CVE-2026-64747** (AVEVideoEncoder kernel code exec) and CVE-2026-43810 (remote kernel corruption). `[V] thezdi.com/blog/2026/6/30/… and /2026/7/29/…`
- **Unofficial public kernel finding in window (unverified):** github.com/crazymind90/CVE-2026-XNU-AIO-KEVENT-UAF — claims a **kern_aio.c kevent UAF** (missing `aio_entry_ref()` in `filt_aioattach()`, register-after-enqueue, missing unref in `filt_aiodetach()`), panic/double-free from app sandbox, no entitlements, ~70% reliable, **iOS 26.2 (xnu-12377.62.10) and earlier, fixed in iOS 26.3 (xnu-12377.81.4)**; 141 lines changed in `bsd/kern/kern_aio.c`. PoC claims primitive table incl. `aio_proc_lock` arbitrary lock + `TAILQ_REMOVE` write (`*(tqe_prev)=tqe_next`). **No Apple CVE assigned (placeholder CVE-2026-XXXX)** — treat as unverified third-party research, but it is the only public kernel-write-ish PoC with source for the 26.1–26.2 window besides DirtySlide. `[U]`

---

## 6. TOP-10 LPE candidates for the 26.1+ kernel stage (ranked)

| # | CVE | Live window | Fixed in | Primitive / impact | Public PoC? | One-line rationale |
|---|---|---|---|---|---|---|
| 1 | **CVE-2026-43724** (DirtySlide) | 26.0–26.5.1 | 26.5.2 | 8-byte OOB R/W (dyld slide v5, syscall 536) → full phys R/W | **YES** (full writeup + PoC) | Only fully public kernel-write LPE in range; port to iOS = sandbox-bypass + SPTM-free (≤A16) targets |
| 2 | **CVE-2026-64747** (AVEVideoEncoder) | 26.1–26.5.x | 26.6 | **kernel arbitrary code exec** (bof, CWE-120) | no (Blackwing may publish) | Only kernel-CODE-EXEC impact in range; app-reachable video-encoder kext; fixed latest of the top tier |
| 3 | **CVE-2026-28951** | 26.1–26.4.x | 26.5 | **root LPE** (CWE-863 auth) | no | Widest live window of the three confirmed root-LPEs; theevilbit is a known macOS researcher |
| 4 | **CVE-2026-20626** | 26.1–26.2 | 26.3 | **root LPE** (CWE-862 auth) | no | Root from "malicious app" per Apple; earliest-documented 26.1+ root LPE |
| 5 | **CVE-2026-28972** | 26.1–26.4.x | 26.5 | **OOB write → kernel memory write** (CWE-787) | no | Explicit "write kernel memory" from app; STAR Labs + Ryan Hileman credits |
| 6 | **CVE-2026-39868** | 26.1–26.5.1 | 26.5.2 | kernel memory corruption (CWE-20) | no | "Pwn2Own-grade" per ZDI; STAR Labs/PT/Baidu attribution = weaponizable |
| 7 | **CVE-2025-46285** | **26.1 only** | 26.2 | **root LPE** (CWE-190 timestamp overflow) | no | Repo's tracked K4.7 bug; genuine app→root but 26.1-only + root cause unfound (hardware-gated) |
| 8 | **CVE-2026-43805** (IOKit) | 26.1–26.5.2 | 26.6 | **race → write kernel memory** | no | IOKit race with kernel-write impact; widest window of the IOKit-class bugs |
| 9 | **CVE-2026-20687** (AppleJPEGDriver) | 26.1–26.3.x | 26.4 | UAF → "write kernel memory" (CWE-416) | **YES** (trigger PoC + mechanics) | Best-documented kernel bug in range; public trigger code; UAF→R/W needs heap-groom work; deferred-panic PoC proves app reachability |
| 10 | **CVE-2026-43778** | 26.1–26.5.2 | 26.6 | UAF → **write kernel memory** | no | UAF with write impact + DARKNAVY/ThreatBook credits; wide window |

**Honorable mentions:** CVE-2026-64751 (UAF→write, 26.6, window 26.1–26.6.0), CVE-2026-64749 / 65330 (corrupt kernel memory, 26.6/26.6.1), CVE-2026-65349 (OOB read, 26.6.1 — leak+DoS), CVE-2025-43520 (26.1, kernel write, Apple-internal), unofficial XNU AIO kevent UAF (26.1–26.2, public PoC with double-free/write primitives, no CVE).

---

## 7. Bottom line for K5.6 / C5.1

1. **DirtySlide (CVE-2026-43724) is the only viable *public-knowledge* path to a 26.1+ kernel stage** — everything else is an Apple credit with no detail, requiring original RE of the patched diff. Immediate work: port the macOS PoC to iPhone semantics; investigate app-sandbox reachability of syscall 536 (the `_POSIX_SPAWN_RESLIDE` shim trick inside the iOS app sandbox) and SPTM-free device set (iPhone ≤15 / A16 and earlier).
2. **Highest-impact unknown:** AVEVideoEncoder CVE-2026-64747 (kernel code exec, app-reachable, fixed only in 26.6) — a 26.1–26.5.x live window; diff 26.5.x vs 26.6 kernelcache (AVEVideoEncoder kext) for the size-validation fix.
3. **Root-LPE trio (20626/28951/46285)** — all authorization/timestamp logic bugs, no public detail; each needs the Apple 26.x kernelcache diff (XPF workflow already proven in repo K4.1/K4.7).
4. **Watch:** iOS 27 betas are where the 26.6.1 fixes came from; new kernel bugs fixed in 27 betas will keep the 26.6.x window alive for porting.
5. All CVE ids, versions, and credits above are cited; anything marked `[U]` requires primary confirmation before use in the repo.

---

## 8. Sources (primary)

- Apple security pages: 125632 (26.1), 125884 (26.2), 126346 (26.3), 126604 (26.3.1 BSI), 126792 (26.4), 127110 (26.5), 127594 (26.5.2), 128066 (26.6), 148282 (26.6.1), 100100 (index), 125108 (26.0)
- NVD: CVE-2025-46285, CVE-2026-20626, CVE-2026-20687, CVE-2026-28951, CVE-2026-28972, CVE-2026-28897, CVE-2026-43724, CVE-2026-39868, CVE-2026-64747, CVE-2025-43520, CVE-2026-65349
- DirtySlide writeup: https://gracecondition.github.io/posts/dirtyslide ; PoCs: github.com/gracecondition/DirtySlide, github.com/khanhduytran0/DirtySlide, github.com/impost0r/Rie
- AppleJPEG UAF PoCs: github.com/zeroxjf/CVE-2026-20687-AppleJPEGDriver-UAF, github.com/enfilade-labs/CVE-2026-20687-AppleJPEGDriver-UAF
- ZDI reviews: thezdi.com/blog/2026/6/30/the-june-2026-apple-security-update-review ; /2026/7/29/the-july-2026-apple-security-update-review
- W0lfSword repo: ROADMAP.md (K4.1, K4.7, C5.1), tools/xpf-cli diff data
- Unofficial AIO kevent UAF: github.com/crazymind90/CVE-2026-XNU-AIO-KEVENT-UAF `[U]`
- Advisory pages (secondary aggregators, all cross-checked against Apple/NVD): sentinelone.com, cvefeed.io, app.opencve.io, notcve.org, mallory.ai, vulners.com
