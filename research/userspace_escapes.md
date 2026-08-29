# iOS userspace escapes 2025-2026 (C5.2)
Sandbox escapes, TCC bypasses, SSV bypasses. CVE + technique survey with live-vs-patched status.

> **Purpose:** Research inventory for W0lfSword (kaffeindecaf) - hunting NEW userspace escapes for iOS 18.x–26.x
> (esp. the post-DarkSword 26.1+ world where userspace escapes are the kernel-independent path).
> 2026-08-29. **Baseline versions:** iOS **18.4.1** (released 2025-04-16) and the **26.x** line (26.0 Sep 2025 → 26.6.1).
> Sources: Primary sources = Apple security release pages (fetched & parsed directly), NVD, GTIG/iVerify/Lookout disclosures, researcher blogs. No CVE is invented; anything not directly verifiable is marked **UNVERIFIED**.
> **Already ported in W0lfSword (excluded from top-10, kept as context):** bad_query containermanagerd path-traversal read escape (26.0–26.6.1/K4.10), MCM container access via MobileHouseArrest re-sign (K4.12), FilzaSlop.

### Legend
| Status | Meaning |
|---|---|
| **LIVE on 18.4.1** | fixed in a release after 2025-04-16, or never fixed → exploitable on iOS 18.4.1 |
| **PATCHED on 18.4.1** | fixed in iOS ≤ 18.4.1 |
| **LIVE on 26.x** | fixed in a 26.x release newer than the one checked, or never fixed |
| **PATCHED on 26.x** | fixed in iOS 26.0–26.6.1 |
| UNKNOWN | could not be determined from public sources |

---

## 1. SANDBOX ESCAPES - iOS (2025–2026)

### 1.1 Apple-assigned CVEs ("An app may be able to break out of its sandbox")

| CVE | Component | Root cause (Apple text) | Fixed in | LIVE on 18.4.1? | LIVE on 26.x? | PoC / notes |
|---|---|---|---|---|---|---|
| **CVE-2025-43329** | Sandbox | "permissions issue … additional restrictions" (anonymous) | **iOS 26.0 only** (also macOS 26/tvOS 26/watchOS 26) - NOT backported to 18.x | **LIVE** | **PATCHED** (26.0+) | CVSS 8.8 (CISA-ADP). No public writeup. **Highest-value unpatched-18.x item.** [Apple 125108](https://support.apple.com/en-us/125108) · [NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-43329) |
| **CVE-2025-43358** | Shortcuts | "permissions issue … additional sandbox restrictions" | iOS 18.7 + 26.0 | **LIVE** (fixed 18.7, Sep 2025) | PATCHED | Shortcut-sandbox bypass class; live on 18.4.1 |
| **CVE-2025-43407** | Assets | "improved entitlements" (JZ) | iOS 18.7.2 + 26.1 | **LIVE** | **PATCHED** (26.1+) | Public repo `mranonymous234/Sandbox-Escape-iOS-18.0-26.0` claims to use it (testing-only, UNVERIFIED). Assets.framework entitlement bug |
| **CVE-2025-43448** | CloudKit | "improved validation of symlinks" (Hikerell / Loadshine Lab) | iOS 18.7.2 + 26.1 | **LIVE** | **PATCHED** (26.1+) | Symlink-validation sandbox escape; Mallory.ai flags it "CloudKit symlink validation sandbox escape" [Mallory](https://mallory.ai/vulnerabilities/019ab956-30f9-7839-a986-09037a14d29e) |
| **CVE-2026-20628** | Sandbox | "permissions issue … additional restrictions" (Noah Gregory, wts.dev) | iOS 18.7.5 + 26.3 | **LIVE** | **PATCHED** (26.3+; LIVE ≤26.2.x) | Second Sandbox-component escape in a year |
| **CVE-2026-28995** | App Intents | "logic issue … improved restrictions" (Vamshi Paili, Tony Gorez - Reverse Society) | iOS 18.7.9 + 26.5 | **LIVE** | **PATCHED** (26.5+; LIVE ≤26.4.x) | The "iOS 26.5 sandbox escape" widely reported; app→breakout |
| **CVE-2026-20688** | Printing | "path handling issue … improved validation" (wdszzml + Atuin AVDE) | iOS 26.4 | **LIVE** | **PATCHED** (26.4+) | path-handling breakout |
| **CVE-2026-64740** | Game Center | "parsing issue in handling of directory paths" (Manuel Fernandez, Stackhopper) | iOS 18.7.10 + 26.6 | **LIVE** | **PATCHED** (26.6+) | directory-path parsing breakout |
| **CVE-2026-64738** | Maps | "permissions issue … additional restrictions" | iOS 18.7.10 + 26.6 | **LIVE** | **PATCHED** (26.6+) | |
| **CVE-2026-28973** | libc | "integer overflow … improved input validation" (anonymous) | iOS 18.7.10 + 26.6 | **LIVE** | **PATCHED** (26.6+) | **libc integer overflow → sandbox escape**: rare primitive class (integer overflow in libc enabling breakout) - high research value |
| **CVE-2025-30429** | Calendar (path handling) | path handling, improved validation (Denis Tokarev @illusionofcha0s) | iOS 18.4 | PATCHED | - | fixed before baseline |
| **CVE-2025-24212** | (18.4) | improved checks (Denis Tokarev) | iOS 18.4 | PATCHED | - | |
| **CVE-2025-24178** | (18.4) | improved state management (anonymous) | iOS 18.4 | PATCHED | - | |
| **CVE-2025-24173** | (18.4) | additional entitlement checks (Mickey Jin @patch1t) | iOS 18.4 | PATCHED | - | |
| **CVE-2025-30469** | Power Services | (Dalibor Milanovic) | iOS 18.4 | PATCHED | - | |
| **CVE-2026-20677** | Messages (Shortcuts-labeled) | "race condition … improved handling of symbolic links" (Ron Masas, BreakPoint.SH) | iOS 18.7.5 + 26.3 | **LIVE** | **PATCHED** (26.3+) | symlink race → sandbox-bypass; **symlink-race class = closest cousin of bad_query/MCM traversal** |

**Trend:** Apple fixes 1–3 sandbox escapes per point release through 2025–2026; the *Sandbox* and *Sandbox Profiles* components themselves were patched twice (43329/26.0, 20628/26.3) - both anonymous/wts.dev findings, neither with public writeups. All are **LIVE on iOS 18.4.1** unless fixed ≤18.4. **26.x line: everything ≤ 26.2 is still vulnerable to 43407/43448 (fixed 26.1) and 20628/20677/20678 (fixed 26.3).**

### 1.2 Public techniques without Apple CVE (daemon / logic bugs)

| Technique | Component(s) | Root cause | Affected range | LIVE status | PoC |
|---|---|---|---|---|---|
| **itunesstored & bookassetd SQLite-trust escape ("bl_sbx")** | `itunesstored` (downloads.28.sqlitedb `asset` table) → `bookassetd` (BLDatabaseManager.sqlite `ZBLDOWNLOADINFO`) | daemons trust user-writable SQLite metadata; `local_path`/`ZPLISTPATH` path traversal + attacker URLs → arbitrary **mobile-owned** file writes across `/private/var` (SystemGroup caches incl. MobileGestalt, FairPlay, Media) | iOS ≤ **26.2b1** (tested 26.0.1, iPhone 12) | **LIVE on 18.4.1 and 26.0–26.2** (not a fixed CVE; survives reboots) | [github.com/hanakim3945/bl_sbx](https://github.com/hanakim3945/bl_sbx) · [writeup](https://hanakim3945.github.io/posts/download28_sbx_escape/) · [HackTricks](https://hacktricks.wiki/en/mobile-pentesting/ios-pentesting/itunesstored-bookassetd-sandbox-escape.html). Needs AFC/USB or any prior foothold under /var/mobile/Media |
| **Geod MCM traversal** (0xjohnnydev) | containermanagerd MCM class-12 (`com.apple.geod`) + unsanitized `partDomain` | MCM trust + path traversal - same family as bad_query/MCM | iOS 18–26 (public PoC) | **LIVE** (no CVE; same family as already-ported K4.10/K4.12) | [Geod-MCM-PoC](https://github.laiyagushi.com/0xjohnnydev/Geod-MCM-PoC) |
| **MCM/MHA identity-trust** (FilzaSlop) | containermanagerd + MobileHouseArrest identity | daemon trusts `com.apple.mobile.MobileHouseArrest` bundle/codesign id | iOS 18–27b | **LIVE** | **Already ported (K4.12)** - context only |
| **XPC daemon looser-sandbox pivot** (classic) | e.g. QuickLook providers, assetsd, photosd, mediaplaybackd, bookassetd | RCE-in-daemon → use daemon's broader profile | version-dependent | per-bug | DarkSword's sbx1 stage (below) is the 2025-26 canonical example |

### 1.3 WebContent / Safari-process sandbox escapes (2025–2026)

| CVE | Component | Role | Fixed in | LIVE on 18.4.1 | LIVE on 26.x |
|---|---|---|---|---|---|
| **CVE-2025-24201** | WebKit | OOB write → web content escapes WebContent sandbox; **ITW** (Mar 2025, "extremely sophisticated attack"; supplementary fix to earlier targeted activity) | iOS 18.3.2 | PATCHED | - |
| **CVE-2025-14174** | ANGLE (WebGL) | memory corruption → **WebContent → GPU process sandbox escape** (DarkSword `sbox0_main_18.4.js`); ITW | iOS 18.7.3 + 26.2 | **LIVE** | **PATCHED** (26.2+; LIVE ≤26.1) |
| **CVE-2025-43510** | Kernel / AppleM2ScalerCSCDriver (per Broadcom) | memory mgmt (copy-on-write) → **GPU process → mediaplaybackd sandbox escape** (DarkSword `sbx1_main.js`); ITW | iOS 18.7.2 + 26.1 | **LIVE** | **PATCHED** (26.1+) |
| **CVE-2026-43725** | WebKit | "malicious website may process restricted web content outside the sandbox" (Luke Francis) | iOS 18.7.10 + 26.5.2 | **LIVE** | **PATCHED** (26.5.2+) |
| **CVE-2026-43701** | WebKit | same impact (Aaron Grattafiori, NVIDIA AI Red Team) | iOS 18.7.10 + 26.5.2 | **LIVE** | **PATCHED** (26.5.2+) |
| **CVE-2026-28859** | WebKit | "restricted web content outside the sandbox" (Bugzilla 308248) | iOS 26.4 (+18.7.8) | **LIVE** | **PATCHED** (26.4+) |
| **CVE-2026-43821** | WebKit Process Model | "app may read files outside of its sandbox" (Brian Carpenter) | iOS 18.7.10 + 26.6 | **LIVE** | **PATCHED** (26.6+) |

**Pattern:** Apple has shipped a WebKit/ANGLE-content sandbox-escape fix in **every** 26.x point release 26.2→26.6 - WebContent escapes are a continuously refreshed surface.

---

## 2. TCC BYPASSES (2025–2026)

### 2.1 iOS-side TCC / sensitive-data entries

| CVE | Component | Root cause | Fixed in | LIVE on 18.4.1 | LIVE on 26.x | Notes |
|---|---|---|---|---|---|---|
| **CVE-2025-43530** | Settings (iOS); scrod/ScreenReader private API (macOS) | private API abuse - `scrod` signed with `kTCCServiceAppleEvents`; TCC entitlement trust (Mickey Jin @patch1t) | iOS 18.7.3 + 26.2; macOS 15.7.3/26.2 | **LIVE** | **PATCHED** (26.2+) | Fully documented macOS-side [jhftss blog](https://jhftss.github.io/CVE-2025-43530); iOS "Settings" entry same CVE - iOS applicability UNVERIFIED but Apple lists it |
| **CVE-2025-43500** | Sandbox Profiles | "privacy issue … improved handling of user preferences" (Stanislav Jelezoglo) | iOS 26.1 (not backported) | **LIVE** | **PATCHED** (26.1+) | Sandbox-profiles/TCC-adjacent; no writeup |
| **CVE-2026-20678** | Sandbox Profiles | "authorization issue … improved state management" (Ó. García Pérez, S. Jelezoglo) | iOS 18.7.5 + 26.3 | **LIVE** | **PATCHED** (26.3+; LIVE ≤26.2) | second Sandbox Profiles TCC-adjacent fix |
| **CVE-2026-28866** | Clipboard | "improved validation of symlinks" (Cristian Dinca) | iOS 18.7.7 + 26.4 | **LIVE** | **PATCHED** (26.4+) | symlink class again |
| **CVE-2026-28876** | DeviceLink | "parsing issue in handling of directory paths" (Nosebeard Labs) | iOS 18.7.7 + 26.4 | **LIVE** | **PATCHED** (26.4+) | |
| **CVE-2026-20653** | Shortcuts | "parsing issue in handling of directory paths" (Enis Maholli) | iOS 18.7.5 + 26.3 | **LIVE** | **PATCHED** (26.3+) | |
| **CVE-2025-43190** | Spell Check | directory-path parsing (Noah Gregory, wts.dev) | iOS 26.0 | **LIVE** | PATCHED | spellcheck API file access (sibling: CVE-2025-43518 Foundation, 26.2) |
| **CVE-2025-43317** | AMFI | permissions (Mickey Jin) | iOS 26.0 | **LIVE** | PATCHED | |
| CVE-2024-44131 (context) | TCC (Files app) | symlink redirect of copy/move → TCC bypass incl. iCloud/Photos/Health; Jamf Threat Labs | iOS 18.0 / 17.7 (Sep 2024) | PATCHED | - | **canonical iOS TCC symlink bypass**; 2024 but the class persists (see 20677/28866) [Jamf](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud) |

### 2.2 macOS-side TCC (research-grade, some class-transferable to iOS)

| CVE / tech | Component | Root cause | Fixed | Notes |
|---|---|---|---|---|
| CVE-2025-31250 | TCC prompt | permission pop-up spoof/confusion (wts.dev) | macOS 15.5 | popup-trust abuse - [wts.dev](https://wts.dev/posts/tcc-who) |
| CVE-2025-24103 | osinstallersetupd | general TCC bypass via install-assistant path (imlzq) | macOS 15.4 | [writeup](https://imlzq.com/apple/macos/tcc/2025/08/07/CVE-2025-24103-General-TCC-Bypass.html) |
| CVE-2025-24204 | gcore entitlement | `com.apple.system-task-ports.read` on gcore → read any process mem → TCC bypass + keychain + FairPlay (FFRI, tsunek0h) | macOS 15.4 | **excessive-entitlement class** - [FFRI PoC](https://github.com/FFRI/CVE-2025-24204) |
| CVE-2025-4412 | Viscosity (3rd-party) | Launch Agent dylib load w/ TCC (CERT Polska) | app update | 3rd-party |
| CVE-2025-8597 / CVE-2025-8700 | notarized apps | get-task-allow misconfig → code injection → TCC (afine survey) | various | [afine](https://afine.com/threat-of-tcc-bypasses-on-macos) |
| CVE-2025-10015 | Sparkle updater | unvalidated XPC clients → TCC bypass | app update | 3rd-party |
| TCC.db symlink/race (technique) | tccd | swap TCC.db or use `~/Library` symlink to redirect tccd writes | class | classic macOS technique, still recurring on iOS via Files-app paths (2024-44131 class) |

### 2.3 Technique notes
- **iOS TCC surface is thin vs macOS** - no 2025-26 iOS CVE explicitly names tccd/TCC.db; Apple's phrasing is "sensitive user data" + component (Settings/Clipboard/Sandbox Profiles). The recurring **symlink-validation** and **directory-path-parsing** fixes (20677, 28866, 28876, 20653) are the de-facto iOS TCC-bypass class of 2025–26 - worth auditing Files/Clipboard/DeviceLink path handling for siblings.
- post-escape TCC.db INSERT (kTCCService*) remains the standard post-exploit (W0lfSword sandbox skill §5).

---

## 3. SSV (SIGNED SYSTEM VOLUME) BYPASSES

### 3.1 What exists publicly on iOS (2025–2026)
- **No iOS CVE in 2025–2026 explicitly targets SSV/sealed-system-volume.** Apple does not publish SSV-specific iOS CVEs; iOS SSV bypasses remain kernel-mediated (mount-flag/vnode/APFS-snapshot manipulation - already implemented in W0lfSword via DarkSword; vnode data-pointer swap & MNT_RDONLY clear per ios-sandbox-escape skill §3).
- The **mobile-owned file-write** primitives (bl_sbx bookassetd, CVE-2025-43407/43448) reach SystemGroup caches (MobileGestalt etc.) but **cannot** write the sealed `/System` - they are SSV-adjacent (system-group tampering), not SSV bypasses.

### 3.2 macOS rootless/SSV-class CVEs (the "protected parts of the file system" set - class-relevant)

| CVE | Component | Root cause | Fixed in (macOS) | Class relevance |
|---|---|---|---|---|
| CVE-2025-24203 | Kernel (Ian Beer, P0) | kernel bug → modify protected FS | 15.4 | kernel-mediated SSV write |
| CVE-2025-24272 | AMFI | checks (Mickey Jin) | 15.4 | rootless policy |
| CVE-2025-31187 | Dock | removed vulnerable code (eisw0lf) | 15.4 | |
| CVE-2025-24261 / CVE-2025-24164 | PackageKit | logic/checks (Mickey Jin) | 15.4 | installer-class SSV write |
| CVE-2025-24282 / CVE-2025-24231 | Software Update | library injection/checks (Cisco Talos) | 15.4 | privileged-helper injection → SSV write |
| CVE-2025-24191 | RPAC | env-var validation (Cisco Talos) | 15.4 | env-var class |
| CVE-2025-31247 | SharedFileList | logic (anonymous) | 15.5 | |
| CVE-2025-43194 / CVE-2025-43243 | PackageKit / Software Update | checks/permissions (Mickey Jin, Sea Security) | 15.6 | |
| CVE-2025-43290 / CVE-2025-43291 | CoreServices / SharedFileList | permissions (ByteDance IES, Baidu) | 15.7 / 26.0 | |
| CVE-2025-43446 | Assets | **symlink validation** (ByteDance IES) | 26.1 | sibling of iOS CVE-2025-43448 (CloudKit symlink) |
| CVE-2026-28825 / CVE-2026-28829 | SMB / WebDAV | OOB write / permissions | 26.4 | **network daemons → SSV write** (new attack surface) |
| CVE-2026-28844 | SystemMigration | file access (Pedro Tôrres) | 26.4 | |
| CVE-2026-28892 | Diagnostics | permissions (binary_fmyy) | 26.4 | |
| CVE-2026-28908 | Kernel | DoS removal (beist) | 26.5 | |
| CVE-2026-43765 | PackageKit | symlink handling (Mickey Jin) | 26.6 | |

**Takeaway for iOS:** SSV-by-CVE is a macOS-dominated field; the **symlink-validation** fixes (43446/43448) show Apple hardening one shared code path (Assets/CloudKit) on both platforms in 26.1 - a strong audit target on iOS for SystemGroup tampering. No public *iOS* SSV CVE → any iOS SSV work stays kernel-mediated.

---

## 4. IN-THE-WILD CHAINS 2025–2026 with sandbox-escape / TCC / SSV stages

### 4.1 DarkSword (GTIG · iVerify · Lookout, disclosed 2026-03-18) - six CVEs, three 0-days
Delivery: Safari 1-click via compromised legitimate sites; **pure JavaScript**; active since ~Nov 2025; used by UNC6353 (Russian), PARS Defense (commercial), UNC6748. Affected: iOS 18.4–18.7.x / <26.3. CISA KEV: 31277, 43510, 43520 (added 2026-03-20).

| Stage | Exploit file | CVE | Component / role | Fixed |
|---|---|---|---|---|
| 1. WebContent RCE (≤18.5) | `rce_worker_18.4.js` | CVE-2025-31277 | JavaScriptCore JIT type confusion | 18.6 |
| 1'. WebContent RCE (18.6–18.7) | `rce_worker_18.6.js` | CVE-2025-43529 | JavaScriptCore DFG JIT UAF | 18.7.3 / 26.2 |
| 2. PAC bypass | (dyld trusted-path RO) | CVE-2026-20700 | dyld user-mode PAC bypass (~20-yr-old bug) | 26.3 (backported 18.7.7) |
| 3. **Sandbox escape #1** (WebContent→GPU) | `sbox0_main_18.4.js` / `sbx0_main.js` | **CVE-2025-14174** | ANGLE (WebGL) memory corruption | 18.7.3 / 26.2 |
| 4. **Sandbox escape #2** (GPU→mediaplaybackd) | `sbx1_main.js` | **CVE-2025-43510** | kernel / AppleM2ScalerCSCDriver COW | 18.7.2 / 26.1 |
| 5. Kernel R/W + kcall (in mediaplaybackd) | `pe_main.js` | CVE-2025-43520 | kernel memory corruption | 18.7.2 / 26.1 |
| (supporting WebKit bug) | - | CVE-2025-14174 fix pair | also CVE-2025-46285 (kernel int-overflow, Alibaba; 18.7.3/26.2) and CVE-2026-20627 (CoreServices env-var, ITW-report, 26.3) | - |

Sources: [GTIG](https://cloud.google.com/blog/topics/threat-intelligence/darksword-ios-exploit-chain) · [iVerify](https://iverify.io/press-releases/iverify-details-darksword-second-mass-attack-against-ios-disclosed-in-two-weeks) · [Broadcom (CVE map)](https://www.broadcom.com/support/security-center/protection-bulletin/protection-highlight-darksword-ios-exploit-kit) · [The Hacker News](https://thehackernews.com/2026/03/darksword-ios-exploit-kit-uses-6-flaws.html?m=1) · [The Apple Wiki](https://theapplewiki.com/wiki/DarkSword)

**No TCC/SSV stage in DarkSword** - it stops at kernel R/W + in-memory data theft (Wi-Fi passwords, messages, calls). Apple retro-backported fixes to iOS 18.7.7 (Mar 2026) and referenced "web attacks called DarkSword".

### 4.2 Coruna (GTIG, disclosed 2026-03-03)
iOS 13–17.2.1 kit, 23 exploits / 5 chains (buffout CVE-2021-30952, jacurutu CVE-2022-48503, terrorbird, cassowary CVE-2024-23222, …) - **reuses 2020–2024 CVEs; no new 2025-26 CVEs; no effect on 18.4.1/26.x.** Crypto-wallet/seed-phrase theft focus. Apple backported CVE-2023-41974/2024-23222/2023-43000/2023-43010 to iOS 15.8.7/16.7.15 (Mar 2026). [GTIG Coruna](https://cloud.google.com/blog/topics/threat-intelligence/coruna-powerful-ios-exploit-kit) · [Apple Wiki](https://theapplewiki.com/wiki/Coruna)

### 4.3 Other 2025 ITW activity
- **Mar 2025:** CVE-2025-24200 (USB Restricted Mode bypass, Citizen Lab) + **CVE-2025-24201** (WebKit **sandbox escape**, supplementary) - targeted spyware-grade chain. Fixed 18.3.1/18.3.2 → PATCHED on 18.4.1.
- **Apr 2025:** CVE-2025-31200 (CoreAudio memory corruption, RCE) + CVE-2025-31201 (RPAC bypass) - "extremely sophisticated attack against specific targeted individuals"; fixed **18.4.1** itself.
- **Jun–Aug 2025:** CVE-2025-43300 (ImageIO DNG, **ITW**, fixed 18.6.1) chained with WhatsApp CVE-2025-55177 (linked-device authorization bypass) → spyware via WhatsApp 0-click-ish image delivery. (43300 = the Glass Cage family already in W0lfSword SandboxEscape.md.)
- **2026 mass-criminalization:** Black Hat USA 2026 (iVerify): ~17,000 domains hosting Coruna/DarkSword 2nd-gen variants; kits now rented by conventional cybercriminals. [deafnews](https://deafnews.it/en/article/ios-coruna-and-darksword-proliferation-exposes-17000-domains-to-risk)
- **P0 BLASTPASS retroanalysis (2026-04-27):** in-depth writeup of the 2023 NSO WebP→BlastDoor-sandbox-escape chain - still the best public reference for iMessage-adjacent sandbox-escape technique (heap groom + extension). [P0](http://projectzero.google/archive.html)

---

## 5. The findings that matter (live status flagged)

1. **CVE-2025-43329 - Sandbox permissions escape** - **LIVE on 18.4.1 (and all 18.x)**, PATCHED only in 26.0 (not backported). CVSS 8.8, anonymous, zero public writeup. Highest-value unpatched iOS-18 sandbox escape. (Apple 125108 / NVD)
2. **bl_sbx - itunesstored+bookassetd SQLite-trust write-escape** - **LIVE through 26.2b1**, no CVE, full public PoC (GitHub + writeup + HackTricks). Arbitrary mobile-owned file writes incl. MobileGestalt cache; reboot-persistent; needs AFC/foothold. Directly reusable in W0lfSword's post-escape file-write toolkit. 
3. **DarkSword sandbox-escape stage pair** - CVE-2025-14174 (ANGLE; WebContent→GPU; **LIVE on 18.4.1**, PATCHED 26.2) + CVE-2025-43510 (AppleM2ScalerCSCDriver; GPU→mediaplaybackd; **LIVE on 18.4.1**, PATCHED 26.1) - the canonical 2025-26 WebContent sandbox-escape architecture (GTIG/iVerify/Broadcom).
4. **CVE-2025-43448 CloudKit symlink-validation sandbox escape** - **LIVE on 18.4.1**, PATCHED 26.1. Symlink class; macOS sibling CVE-2025-43446 (Assets) fixed same cycle → shared-code audit target.
5. **CVE-2025-43407 Assets entitlement sandbox escape** - **LIVE on 18.4.1**, PATCHED 26.1; public (unverified-quality) exploit repo `Sandbox-Escape-iOS-18.0-26.0`.
6. **CVE-2026-28973 libc integer-overflow → sandbox escape** - **LIVE on 18.4.1 & 26.0–26.5**, PATCHED 26.6. Rare libc-level breakout primitive; anonymous; unexplored publicly.
7. **CVE-2025-43530 TCC bypass (scrod/kTCCServiceAppleEvents private-API)** - macOS fully documented (jhftss); iOS "Settings" entry in 18.7.3/26.2 → **LIVE on 18.4.1**, PATCHED 26.2. Private-API/TCC-entitlement trust class.
8. **iOS TCC class of 2025-26: symlink-race & path-parsing fixes** - CVE-2026-20677 (symlink race, **LIVE 18.4.1/≤26.2**), CVE-2026-28866 (Clipboard symlink, **LIVE 18.4.1/≤26.3**), CVE-2026-28876 (DeviceLink paths, **LIVE 18.4.1/≤26.3**) - recurring Files/daemon path-handling surface, best hunting ground for a new iOS TCC bypass.
9. **CVE-2025-24201 WebKit OOB-write sandbox escape (ITW)** - PATCHED on 18.4.1 (18.3.2); pattern now repeats every 26.x point release (43725/43701/28859/43821 all **LIVE on 18.4.1**, fixed 26.4–26.6).
10. **SSV status: no iOS SSV CVE in 2025-26** - iOS SSV bypass stays kernel-mediated (W0lfSword's existing vnode/mount primitives); macOS rootless set (24203, 24272, 31187, 43446, 28825/28829 SMB/WebDAV…) shows Apple hardening symlink+network-daemon paths that reach system-volume writes - relevant class if iOS equivalent daemons are audited.

---

## Sources
- Apple security release pages (fetched 2026-08-29): iOS 18.3.2 (122281), 18.4 (122371), 18.4.1 (122282), 18.5 (122404), 18.6 (124147), 18.6.2 (124925), 18.7 (125109), 18.7.1 (125327), 18.7.2 (125633), 18.7.3 (125885), 18.7.5 (126347), 18.7.7 (126793), 18.7.8 (127003), 18.7.9 (127111), 18.7.10 (148287); 26.0 (125108), 26.1 (125632), 26.2 (125884), 26.3 (126346), 26.4 (126792), 26.4.2 (127002), 26.5 (127110), 26.5.2 (127594), 26.6 (128066), 26.6.1 (148282); macOS 15.4–26.6 (122373…128067); Apple security releases index (100100)
- NVD: CVE-2025-43329, CVE-2025-43407, CVE-2025-43448, CVE-2025-43358, CVE-2025-30429, CVE-2025-24178
- GTIG: [DarkSword](https://cloud.google.com/blog/topics/threat-intelligence/darksword-ios-exploit-chain) · [Coruna](https://cloud.google.com/blog/topics/threat-intelligence/coruna-powerful-ios-exploit-kit) · iVerify [PR](https://iverify.io/press-releases/iverify-details-darksword-second-mass-attack-against-ios-disclosed-in-two-weeks) · Lookout · [Broadcom bulletin](https://www.broadcom.com/support/security-center/protection-bulletin/protection-highlight-darksword-ios-exploit-kit)
- Research blogs: [hanakim3945 bl_sbx](https://hanakim3945.github.io/posts/download28_sbx_escape/) · [jhftss CVE-2025-43530](https://jhftss.github.io/CVE-2025-43530) · [wts.dev TCC](https://wts.dev/posts/tcc-who) · [imlzq CVE-2025-24103](https://imlzq.com/apple/macos/tcc/2025/08/07/CVE-2025-24103-General-TCC-Bypass.html) · [FFRI CVE-2025-24204](https://github.com/FFRI/CVE-2025-24204) · [Jamf CVE-2024-44131](https://www.jamf.com/blog/tcc-bypass-steals-data-from-icloud) · [HackTricks itunesstored/bookassetd](https://hacktricks.wiki/en/mobile-pentesting/ios-pentesting/itunesstored-bookassetd-sandbox-escape.html) · [The Apple Wiki: DarkSword/Coruna/SSV](https://theapplewiki.com/wiki/DarkSword)
- UNVERIFIED items flagged inline: exact CVE→stage mapping for DarkSword sbox stages (per GTIG table; Broadcom corroborates), iOS applicability of CVE-2025-43530, quality of mranonymous234 repo, no public writeup exists for 43329/28973/20628.
