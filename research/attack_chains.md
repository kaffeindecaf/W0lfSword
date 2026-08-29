# Attack chains (C5.3)

> **Repo:** W0lfSword (kaffeindecaf) - DarkSword kernel-R/W toolkit, v1.1.0
> **Test device:** iPhone SE2 (A13, arm64e), jailbroken iOS 18.4.1 - kernel gate OPEN there via DarkSword (CVE-2025-43520 is live on 18.4.1, fixed in 18.7.2/26.1)
> **Companion doc:** this feeds ROADMAP items C5.1–C5.5 (`chains` + `cve` CLI commands, BUG_BOUNTY entries)

---

## 0. Capability inventory (what the repo can do TODAY)

| Capability | Technique / bug | Version range | Repo status |
|---|---|---|---|
| Kernel R/W | DarkSword: ICMPv6 socket spray + IOSurface physical OOB (CVE-2025-43520, CWE-120, CISA KEV) | iOS 17.0–26.0.1 (A10–A18, M1–M4); **patched 26.1+** | ✅ IMPLEMENTED (`kexploit/`, deployed as Filza MobileSubstrate tweak, `adderall`/`deploy`) |
| Sandbox escape (kernel path) | patch `proc→ucred→cr_label→sandbox→ext_set` → extension to `/` | 17.0–26.0.1 | ✅ IMPLEMENTED (`sandbox_escape.m`, `sandbox.m`) |
| SSV write | vnode data-pointer redirect (`overwrite_system_file`, MNT_RDONLY/FWRITE/v_writecount juggling) | 17.0–26.0.1 | ✅ IMPLEMENTED (`SSV/SSVUtils.m`, `file.m`, `vnode.m`) |
| Root (in-process) | posix_cred uid/gid/groups → 0 patch | 17.0–26.0.1 | ✅ IMPLEMENTED (K4.13) |
| Userspace read-escape | **bad_query** containermanagerd traversal (class 13 SystemGroup / class 7 App-Group, part 3, `../../` part-domain → consumed sandbox extension) | 26.0–26.6.1 / 27.0b4 (upstream); repo wired into safe mode + exploit-exhaustion fallback | ✅ IMPLEMENTED (`kexploit/bad_query_escape.m`) |
| Userspace container access | **MCM** container leases via `mcm_api` dlopen bridge; `com.apple.lsd` service-container app discovery; **MobileHouseArrest** identity re-sign (`mha` command) | iOS 18–27b | ✅ IMPLEMENTED (`kexploit/mcm_bridge.m`, `container_access.m`, `scripts/re-sign_mha.sh`) |
| Host-side kernel diffing | kcwatch kernelcache watcher + XPF offset resolution + panic analyzer | any build (no device) | ✅ IMPLEMENTED (K4.14/M2 feed, `kcwatch`, `kernelcache`, `panic`) |
| ImageIO/EXR fuzzing | deterministic mutator + imgio_probe headless decode + crash attribution | host + device | ✅ IMPLEMENTED (K4.2/K4.8a/K4.13, `fuzz`) |
| ALAC audio audit | ASAN-verified heap overflow (BB-038) + cookie OOB read (BB-039) in apple/ALAC reference decoder | host-side only (production CoreAudio binary not yet confirmed) | 🔬 RESEARCH (`research/alac_poc/`) |
| FontParser | **CVE-2025-43400 OOB write - LIVE on 18.4.1** (fixed 18.7.1/26.0.1), no public PoC; fix recoverable by diffing libFontParser 18.4.1 vs 18.7.1 | live on 18.4.1 device; patched 26.0.1+ | 🔬 RESEARCH (BB-040, `research/other_frameworks.md`) |
| 26.1+ kernel candidates | CVE-2025-46285 (fixed 26.2 - live on 26.1), CVE-2026-20687 (fixed 26.4), DirtySlide CVE-2026-43724 (iOS unverified) | 26.1–26.4.x | 🔬 RESEARCH (K4.7 diff done; PoCs panic-only, Xcode-gated) |

---

## 1. Grounded vulnerability landscape (2025–2026)

| CVE / bug | Component | Root cause | Fixed in | Status vs test device / repo |
|---|---|---|---|---|
| **CVE-2025-43520** (DarkSword) | kernel (ICMPv6 + IOSurface) | memory corruption / classic buffer overflow → kernel R/W | iOS 18.7.2 / 26.1 | **LIVE ≤26.0.1 and on 18.4.1** - the repo's kernel stage. CISA KEV. [NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-43520) · [Google Cloud DarkSword writeup](https://cloud.google.com/blog/topics/threat-intelligence/darksword-ios-exploit-chain/) |
| **CVE-2025-31200** | CoreAudio (APAC/AAC decoder, AudioConverterService) | heap corruption from malformed audio (APAC HOA channel-remap OOB; AMR/AAC cookie/bitsream variants) - zero-click iMessage | iOS 18.4.1 (Apr 2025) | **LIVE < 18.4.1**; PATCHED on the 18.4.1 SE2. CISA KEV. [Apple 18.4.1 notes](https://support.apple.com/en-us/121250) · [CISA vulnrichment #200](https://github.com/cisagov/vulnrichment/issues/200) |
| **CVE-2025-31201** | kernel (AppleBCMWLAN AMPDU) | **RPAC bypass** → kernel R/W from media-process foothold | iOS 18.4.1 | PATCHED on 18.4.1; the in-the-wild kernel-escalation partner for 31200. Same sources |
| **CVE-2025-43400** | FontParser (libFontParser) | out-of-bounds **write**, crafted font | iOS 18.7.1 / 26.0.1 | **LIVE on the 18.4.1 SE2** (BB-040, no public PoC - find by diffing). [NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-43400) · [Apple 18.7.1 notes](https://support.apple.com/en-us/125327) |
| **CVE-2025-46285** | kernel (timestamp handling) | integer overflow (CWE-190) → root privileges from an app | iOS 18.7.3 / **26.2** | **LIVE on 26.1** (and 18.4.1!) - the best 26.1+ kernel-LPE candidate. No public PoC. [NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-46285) · [GHSA-p5pj-g9wc-c3v2](https://github.com/advisories/GHSA-p5pj-g9wc-c3v2) |
| **CVE-2026-20687** | kernel (AppleJPEGDriver IOKit user client) | timeout UAF on `JpegRequest` (panic + PC-control potential) | iOS 26.4 | LIVE 26.1–26.3 (A19/MTE-tested PoC, panic-only today). [Apple 26.4 notes](https://support.apple.com/en-us/126792) (via repo research) |
| **CVE-2026-28990** | ImageIO (EXR decode) | integer overflow → heap overflow (decodeBlockAppleEXR) | iOS 26.5 | LIVE ≤ 26.4.2 incl. 26.1; `poc exr` deploys trigger. [zygosec writeup](https://zygosec.com/blog) (via repo) |
| **CVE-2026-43724** (DirtySlide) | dyld shared-cache slide (vm_shared_region_slide_page_v5) | missing in-page bounds check → 8-byte kernel OOB R/W via `posix_spawn` RESLIDE (syscall 536) | macOS 26.5.2; iOS unverified | kernel OOB-R/W candidate for 26.x; iOS build panics. [writeup](https://gracecondition.github.io/posts/dirtyslide/) |
| **bad_query** (no CVE) | containermanagerd (libsystem_containermanager) | part-domain path traversal → sandbox extension for arbitrary path | unpatched through 26.6.1/27.0b4 | LIVE 26.0–26.6.1 - repo module ready. [forcequitOS/bad_query](https://github.com/forcequitOS/bad_query) |
| **MCM identity trust** (no CVE) | MobileContainerManager | CodeDirectory identifier trusted as auth key (`com.apple.mobile.MobileHouseArrest`) | unpatched 18–27b | LIVE - repo `mha` + MCM bridge ready. [MobileHouseArrest-PoC](https://github.com/0xjohnnydev/MobileHouseArrest-PoC) · [FilzaSlop](https://github.com/0xjohnnydev/FilzaSlop) · [Geod-MCM-PoC](https://github.com/0xjohnnydev/Geod-MCM-PoC) |
| **CVE-2021-30860** (FORCEDENTRY) | CoreGraphics PDF/JBIG2 | integer overflow → heap overflow; 0-click iMessage via "fake .gif" | iOS 14.8 | PATCHED everywhere modern; **the canonical 0-click chain template** (delivery + weird-machine + sandbox escape). [P0 RCE deep dive](https://projectzero.google/2021/12/a-deep-dive-into-nso-zero-click.html) · [P0 sandbox escape](https://projectzero.google/2022/03/forcedentry-sandbox-escape.html) |
| **CVE-2025-24085** | CoreMedia | UAF in media pipeline (used by "Glass Cage" chain per repo research) | iOS 18.4 | PATCHED on 18.4.1; sibling-hunt template. [Apple 18.4 notes](https://support.apple.com/en-us/125327) (via repo) |
| **CVE-2025-43539** | AppleJPEG (userspace codec) | OOB-write decode family | post-18.4.1 | not reproduced on 18.4.1 (307-sample campaign = 0 crashes); hunt target for 26.x. [repo research](research/applejpeg_cve-2025-43539.md) |

**Landscape takeaways**
- 2025 in-the-wild chains (31200+31201, DarkSword) prove: **media/font parser memory corruption → kernel** is the viable shape; Apple fixes parsers piecemeal and adjacent bugs keep landing (audio: CVE-2020-9884/9889, CVE-2021-30957, CVE-2025-43277, CVE-2026-43744*; fonts: the 2020 Type-1 cluster; PDF/JBIG2: FORCEDENTRY).
- The repo's userspace stack (bad_query + MCM) is exactly what the 2025-2026 chains lacked publicly: a **no-kernel sandbox escape** for 26.x. Combining it with a parser RCE closes the loop on 26.1+ without any kernel bug.
- *CVE-2026-43744 (audio OOB write, fixed 26.6) is repo-catalogued but **unverified** - listed for completeness only, not used in any chain below.

---

# CHAIN A - "ContainerKey" - userspace read-escape → other-app data exfiltration

**Goal:** read arbitrary other apps' data containers (Messages `chat.db`, third-party app Documents/Library, keychain-adjacent plists) with **no kernel R/W**, from a plain (or re-signed) app.

**Stage-by-stage**

| # | Stage | Bug/technique | Delivery surface | Prerequisites | Status |
|---|---|---|---|---|---|
| A1 | Obtain container lease on target path | **bad_query** traversal: class-13 SystemGroup (`systemgroup.com.apple.mobilegestaltcache`, flags `0x800000000`) or class-7 App-Group sacrifice (`0x80000000`), part 3, part-domain `../../../../../../../..<abs-path>` → containermanagerd issues a sandbox extension for the *traversed* path | any app calling `container_query_*` (dlopen'd `libsystem_containermanager`) | sideloaded/tweaked app; **26.0–26.6.1** (SystemGroup route); App-Group route needs an owned app-group id | ✅ IMPLEMENTED - `kexploit/bad_query_escape.m` (`bad_query_escape()`, `bad_query_probe()` probes `/var/mobile/Containers/Data/Application`, `InternalDaemon`, `PluginKitPlugin`, `Shared/AppGroup`) |
| A2 | Alternate lease route (iOS 18 / no traversal) | **MCM identity trust**: re-sign IPA as `com.apple.mobile.MobileHouseArrest` → class-2 lookups + activation for *any* app container; `com.apple.lsd` service container for app discovery | `./W0lfSword mha Filza.ipa` (Makefile `make mha`) | dev-signed/MHA identity; iOS 18–27b | ✅ IMPLEMENTED - `container_access.m` (`mcm_activate_container`, `userspace_container_probe`, `mcm_lsd_discover_apps`), `scripts/re-sign_mha.sh` |
| A3 | Resolve container UUIDs → bundle IDs | lsd LaunchServices-store byte-scan (`mcm_lsd_discover_apps`) + `bad_query_list()` fsgetpath inode enumeration | on-device | A2 lease or bad_query handle | ✅ IMPLEMENTED (lsd scan); UUID→bundle resolution on 26.1+ via lsd container only |
| A4 | Consume + walk target container | `sandbox_extension_consume` (dlsym) keeps the extension alive for the process lifetime; standard POSIX read of target DBs/plists | on-device | A1/A2 handle | ✅ IMPLEMENTED (`bad_query_escape` returns consumed handle; `bad_query_release`) |
| A5 | Bulk exfiltration | tar/zip the target container (Filza minizip hooks or plain `tar`), pull over SSH (repo `deploy`/`log` pipeline) | host CLI | SSH (jailbroken) or app-side upload | ⚠️ PLANNED - needs a `chains exfil` wrapper (C5.4) |

**Per-version applicability**

| Version | A1 bad_query | A2 MCM/MHA | A5 exfil | Chain verdict |
|---|---|---|---|---|
| 18.x (jailbroken SE2) | untested upstream ("might work", unverified) | ✅ (MHA identity, 18–27b) | ✅ | **works today** via A2+A5 |
| 26.0.x (kernel open) | ✅ | ✅ | ✅ | **works today** (both routes) |
| 26.1+ (kernel closed) | ✅ (26.1–26.6.1) | ✅ | ⚠️ (needs sideload path for exfil) | **works today - the flagship no-kernel data-theft chain** |

**Final impact:** read-only cross-app data access (Messages, WhatsApp/Telegram containers, photos metadata, app preferences) from a sandboxed process - the exact impact class Apple pays for under *Sandbox Escape* ($100k tier for novel techniques; MCM/bad_query are unpatched-as-of-now but public, so realistic payout is the *combination* novelty).
**Bounty category:** Sandbox escape / privacy boundary (process-level data of other apps).
**Implementation status:** **~75%** - A1/A2/A3/A4 fully implemented and wired (safe mode + exploit-exhaustion fallback); A5 (bulk exfil + `chains` command) planned.
**CLI automation needed:** `chains exfil <bundle-or-uuid> [--tar]` → (1) `mcm_lsd_discover_apps`/`bad_query_list` to map targets, (2) `bad_query_escape(<container>, 0, NULL, 0)` or `mcm_activate_container(class 2, id, ...)`, (3) tar via existing minizip/`ssh` pipeline, (4) pull to `.w0lfsword/exfil/<date>/`. Reuse `fuzz`'s device-connect + `panic`'s report plumbing.

---

# CHAIN B - "TCC-Key" - kernel R/W ≤26.0.1 → TCC.db modification → persistent permission grant

**Goal:** grant an arbitrary bundle ID persistent `kTCCService*` permission (camera, mic, photos, contacts, location, Bluetooth) by writing the TCC database, without any user prompt.

**Stage-by-stage**

| # | Stage | Bug/technique | Delivery surface | Prerequisites | Status |
|---|---|---|---|---|---|
| B1 | Kernel R/W | DarkSword (CVE-2025-43520): ICMPv6 socket spray + IOSurface physical OOB race → kread/kwrite | Filza tweak via MobileSubstrate (jailbroken) or TrollStore-signed Filza (non-jailbroken ≤26.0.1) | iOS 17.0–26.0.1, A10–A18/M1–M4 | ✅ IMPLEMENTED (`kexploit_opa334.m` pe_v1/pe_v2, retry ladder, PAC handling) |
| B2 | Sandbox escape (kernel ext patch) | patch ext_set to `/` (BB-002) | same process | B1 | ✅ IMPLEMENTED (`sandbox_escape.m`) |
| B3 | Root creds | posix_cred uid/gid/groups→0 | same process | B2 | ✅ IMPLEMENTED (K4.13) |
| B4 | TCC.db write | SQLite `INSERT INTO access(service, client, client_type, auth_value, auth_reason, ...)` into `/private/var/mobile/Library/TCC/TCC.db` (route per `research/TCC_BYPASS.md` Phase 1) | in-tweak module | B2+B3 (file is mobile-owned, outside sandbox) | 🔬 RESEARCH - doc'd (`TCC_BYPASS.md`, roadmap C2.1), **no PoC** |
| B5 | tccd cache invalidation | `killall tccd` (root via B3) → daemon relaunches and re-reads the DB; or TCC reset/`access_overrides` row for MDM-style force | same process | B4 | 🔬 RESEARCH (Phase 2 in TCC_BYPASS.md) |
| B6 | (alt) in-memory tccd cache patch | kernel R/W into tccd heap cache structures | same process | B1 + tccd struct RE | 🔬 RESEARCH (Phase 3, hardest) |

**Per-version applicability**

| Version | B1 kernel | B4/B5 TCC | Chain verdict |
|---|---|---|---|
| 18.x (jailbroken SE2) | ✅ (exploit live; jailbreak also provides root) | possible; jailbroken device already root - chain value = **non-jailbroken** 18.x via TrollStore | works end-to-end once B4/B5 built; trivially testable on SE2 |
| 26.0.x (kernel open) | ✅ | ✅ (same path) | **full chain** - highest value (non-jailbroken 26.0.x + TrollStore) |
| 26.1+ (kernel closed) | ❌ | blocked | **not applicable** until Chain D lands a kernel primitive |

**Final impact:** persistent privacy-permission grant without consent → camera/mic/photos/location/contacts access for a chosen app. Bounty: *TCC bypass from sandbox* $100k–$250k; from kernel (this chain) lower tier $50k–$100k (Apple treats kernel→everything as expected).
**Bounty category:** Privacy / TCC boundary.
**Implementation status:** **~55%** - B1–B3 (the hard 60% of the exploit work) implemented and production-proven; B4/B5 are a ~1-day SQLite module + `killall` once root exists, never built.
**CLI automation needed:** `chains tcc grant <service> <bundle-id>` → adderall-style deploy (build tweak with TCC stage flag) → tweak logs "TCC WRITTEN" → verify via `AVCaptureDevice requestAccessForMediaType:` echo, then `chains tcc list` (read-only viewer). Reuse `history`/`log` plumbing for evidence capture. New files: `kexploit/tcc_escape.m` + `scripts/tcc_sql.py` (host-side SQL builder).

---

# CHAIN C - "MediaLock" - media/font parser RCE → sandbox escape → data (iMessage-style)

**Goal:** remote or near-remote code execution in a media/font parser process → escape sandbox → steal data. The in-the-wild 2025 template (CVE-2025-31200 → CVE-2025-31201) applied to what is actually **live on the repo's test device** (FontParser 18.4.1) and the repo's 26.x userspace escape.

**Stage-by-stage**

| # | Stage | Bug/technique | Delivery surface | Prerequisites | Status |
|---|---|---|---|---|---|
| C1 | Parser RCE (pre-18.4.1, iMessage) | **CVE-2025-31200** CoreAudio APAC/AAC heap corruption - zero-click via malformed audio attachment (AMR/AAC/APAC cookie); BlastDoor bypass via valid container + codec-bitstream payload | iMessage/SMS auto-processing; Safari/AVFoundation media | iOS < 18.4.1 | 🔬 RESEARCH (external; public PoC repos exist; repo `research/audio_frameworks.md` documents the family + APAC channel-remap root cause) |
| C2 | Kernel escalation (pre-18.4.1) | **CVE-2025-31201** RPAC bypass in AppleBCMWLAN/AMPDU → kernel R/W | IOKit from media-process foothold | C1 | 🔬 RESEARCH (external template) |
| C3 | Parser RCE (18.4.1 device - **LIVE**) | **CVE-2025-43400** FontParser OOB write (CWE-787); no public PoC → find by diffing libFontParser 18.4.1 vs 18.7.1; siblings in Type-1/CFF/COLR paths (2020 cluster: CVE-2020-27930/27943/27944/29624 as templates) | Safari web fonts, Mail, Messages, Quick Look, PDF fonts (UI-required) | font file reaches CTFont/CTLine | 🔬 RESEARCH (BB-040; diff plan in `research/other_frameworks.md` §2) |
| C4 | Sandbox escape post-RCE (18.x) | **DarkSword kernel R/W** (CVE-2025-43520) from the code-exec foothold - or, on 26.1+, **bad_query/MCM** userspace escape (Chain A) | same process | kernel open ≤26.0.1, or 26.1–26.6.1 for userspace route | ✅ IMPLEMENTED (both routes) |
| C5 | Data access / persistence | repo SSV write + root + exfil (Chain A5) | same process | C4 | ✅ IMPLEMENTED (SSV/root); exfil ⚠️ planned |

**Supporting repo research (live hunt, feeds C1/C3):**
- ALAC reference decoder: BB-038 heap overflow (partialFrame `numSamples` override vs frameLength-sized buffers), BB-039 cookie OOB read - ASAN-verified harnesses in `research/alac_poc/`. Caveat: production CoreAudio ALAC plugin must be disassembly-confirmed (next step in `audio_frameworks.md`). If confirmed → **new CVE-class finding** = a C1-equivalent audio RCE entry for 18.4.1+.
- ImageIO/EXR: CVE-2026-28990 trigger deployed (`poc exr`), CVE-2025-43539 family recipes (`fuzz probe`) - 0 crashes on 18.4.1 to date; live window 26.1–26.4.x.

**Per-version applicability**

| Version | C1 (31200) | C3 (43400) | C4 escape | Chain verdict |
|---|---|---|---|---|
| <18.4.1 | ✅ live (zero-click) | ✅ live | ✅ DarkSword | **full remote chain** (the 2025 in-the-wild shape) |
| 18.4.1 SE2 | ❌ patched | ✅ **live** (UI-required) | ✅ DarkSword + jailbreak | **weaponizable now**: font → RCE → kernel → data |
| 26.0.x | ❌ | ❌ patched 26.0.1 | ✅ DarkSword | userspace CVE hunt (ALAC/EXR) → escape |
| 26.1+ | ❌ | ❌ | ✅ bad_query/MCM (userspace) | parser RCE → **no-kernel** data theft (Chain A) - the novel 26.1+ shape |

**Final impact:** remote code execution in media/font parsing process (coreaudiod/imagent/SpringBoard-class) → full device data access. Bounty: *RCE + kernel escalation chain* up to $250k (kernel); parser RCE alone ~$50k–$100k depending on process privileges.
**Bounty category:** RCE (remote/zero-click) + kernel; or sandbox escape when paired with Chain A on 26.1+.
**Implementation status:** **~30%** - C4/C5 implemented; C1/C3 exploitation is research (repo contributes: fuzz infra, ALAC ASAN findings, FontParser diff plan, panic analyzer for crash triage).
**CLI automation needed:** `fuzz audio` (extend `imageio_fuzz.sh` mutator with CAF/M4A/ALAC recipes + `alac_poc` seeds) → `probe audio` (new Theos tool: ExtAudioFile/AVAudioPlayer headless decode, mirror `imgio_probe`; C4.3) → crash attribution via existing `panic analyze` → `chains media-rce <sample>` (auto-attribute crash → classify reachable-from-Safari/Messages). FontParser: `kernelcache`-style diff script for **userspace** dylibs carved from the 18.4.1 vs 18.7.1 shared caches (repo C4.5 notes rootfs DMG is encrypted - use on-device dyld cache extraction).

---

# CHAIN D - "Kernel26" - 26.1+ kernel LPE candidate → full chain (research)

**Goal:** regain kernel R/W on iOS 26.1+ where DarkSword (CVE-2025-43520) is patched, then replay the repo's entire proven post-exploitation stack (offsets.m 26.x block verified by K4.1, ext-set escape, SSV writes, TCC).

**Stage-by-stage**

| # | Stage | Bug/technique | Delivery surface | Prerequisites | Status |
|---|---|---|---|---|---|
| D1 | Kernel primitive (primary: **CVE-2025-46285**) | integer overflow in 64-bit timestamp adoption → root privesc from an app (AV:L/PR:L/UI:N) | malicious app (sideload/dev-signed) | **26.1 only** (fixed 26.2); also live <18.7.3 | 🔬 RESEARCH - K4.7 diff done (26.1 vs 26.2 XPF: offsets identical; fix NOT in seconds→ns multiply paths; zero 32-bit multiplies found - remains hardware-gated) |
| D1b | Kernel primitive (alt: **CVE-2026-20687**) | AppleJPEGDriver `JpegRequest` timeout UAF - freed `req+0x78` queue node re-read by `finish_io_gated`; layout shows PC control `*(*(req+0)+40)()`; PoC panic-only | IOKit user client (`IOUserClient2022` selectors) from any app; Camera-app JPEG decode primes driver | 26.1–26.3 (fixed 26.4); A19/MTE-tested | 🔬 RESEARCH - PoC in `referenceforAI/moreprojects/CVE-2026-20687-AppleJPEGDriver-UAF/` (Xcode, macOS host required) |
| D1c | Kernel primitive (alt: **DirtySlide CVE-2026-43724**) | v5 dyld slide walk OOB → 8-byte kernel OOB R/W; PTE-oracle + physical cred-patch tech proven on macOS | `posix_spawn` with `_POSIX_SPAWN_RESLIDE` (syscall 536) | 26.x if iOS-alive (macOS patched 26.5.2); iOS build panics | 🔬 RESEARCH - iOS status unverified |
| D2 | Primitive → R/W | reclaim/UAF-to-R/W; **PAC/RPAC handling** - note CVE-2025-31201 was the RPAC bypass Apple removed; any 26.x primitive needs its own PAC story (kernel pointers are signed; repo's `kread_ptr`/xpaci discipline applies) | - | D1 | 🔬 RESEARCH |
| D3 | Replay post-exploitation stack | offsets.m 26.x block (K4.1-verified identical 26.0.1↔26.1) → ext-set sandbox escape → SSV write → root | in-process after D2 | D2 | ✅ IMPLEMENTED (version-verified; K4.1, A1.2 PAC audit) |
| D4 | Keep hunting (26.4+) | kcwatch kernel-delta watcher (K4.14/M2 feed live) flags new kernelcache deltas → diff → new CVE candidates; CVE-2026-20687 fixed 26.4, DirtySlide unverified | host-side automation | 26.4+ kernelcaches | ✅ IMPLEMENTED (kcwatch M2); hunting loop planned (C5.1) |

**Per-version applicability**

| Version | D1 46285 | D1b 20687 | D1c DirtySlide | D3 replay | Verdict |
|---|---|---|---|---|---|
| 26.1 | ✅ live | ✅ live | unverified | ✅ ready | **best research target** (two live candidates) |
| 26.2–26.3 | ❌ patched | ✅ live | unverified | ✅ ready | 20687 focus |
| 26.4+ | ❌ | ❌ | unverified | ✅ ready | needs kcwatch-led hunt (C5.1) |

**Final impact:** kernel R/W + root + full FS on 26.1+ → everything Chains B/E enable, on the newest devices. Bounty: *kernel code execution* up to $250k (46285 alone is "root from app" ≈ $100k+ if a novel root cause with clean trigger).
**Bounty category:** Kernel LPE / kernel code execution.
**Implementation status:** **~35%** - K4.7 (46285 diff), K4.14 (kcwatch), panic analyzer, offsets verification all done; D1 trigger/exploitation is research-only and **hardware-gated** (no 26.1 device attached).
**CLI automation needed:** `chains kernel26` orchestrates: `kcwatch poll` (implemented) → auto `kernelcache diff` on each delta (implemented) → `cve-hunt` subcommand (new: flag suspicious symbol shifts; feed CVE-2025-46285-class "fixed between N and N+1" analysis) → `exploits` matrix update (K1.5) → crash-triage via `panic analyze` when a trigger panics the 26.x test device. Trigger validation (D2) needs the SE2 upgraded to 26.1 or a 26.1 device.

---

# CHAIN E - "SealBreaker" - SSV tamper → system binary modification

**Goal:** overwrite sealed system binaries (launch daemons, `/usr/libexec/*`, system framework dylibs) on-device - the repo's flagship differentiator - and, in the research extension, make it survive reboot.

**Stage-by-stage**

| # | Stage | Bug/technique | Delivery surface | Prerequisites | Status |
|---|---|---|---|---|---|
| E1 | Kernel R/W | DarkSword (CVE-2025-43520) | Filza tweak (jailbroken) or TrollStore Filza (≤26.0.1) | 17.0–26.0.1 | ✅ IMPLEMENTED |
| E2 | SSV write activation | `patch_sandbox_ext()` (SSVUtils) + `borrow_sandbox_ext` fallback; vnode redirect makes `/System`, `/usr`, `/bin` writable (BB-003) | in-tweak, `ensureSSVActive` gated NSFileManager hooks | E1 | ✅ IMPLEMENTED (`SSV/SSVUtils.m`, `Tweak.m` hooks) |
| E3 | System file overwrite | `overwrite_system_file()` (file.m): clear MNT_RDONLY, FWRITE on fileglob, bump v_writecount, mmap+memcpy, restore flags | any SSV-writable path | E2 | ✅ IMPLEMENTED |
| E4 | Implant construction | patch a target (e.g. inject `LC_LOAD_DYLIB` into a launch daemon via `scripts/add-load-dylib.py` + re-sign, or drop a modified binary) | host builds the patched binary | E2+E3 | ⚠️ PLANNED - the add-load-dylib/MHA tooling exists; no `chains ssv-implant` wrapper |
| E5 | Reboot persistence (research) | naive write dies on next boot (SSV remounts from sealed APFS snapshot) → persistence candidates: (a) modify the sealed snapshot via vnode/APFS fsnode ops; (b) pair with **usbliter8-arctic tethered jailbreak** (repo `scripts/usbliter8_arctic/`) for a boot-time foothold that re-tampers after each boot; (c) CVE-2026-43724-style post-restore implant is out of scope | - | E1–E3 | 🔬 RESEARCH |

**Per-version applicability**

| Version | E1 | E2/E3 | E4/E5 | Verdict |
|---|---|---|---|---|
| 18.x (SE2) | ✅ | ✅ | E4 yes; E5 research | **works now** for session-lifetime tamper; persistence = research |
| 26.0.x | ✅ | ✅ | same | **works now** (best non-jailbroken demo surface via TrollStore) |
| 26.1+ | ❌ | blocked | blocked | needs Chain D first |

**Final impact:** write access to the sealed system volume - implant modified launch daemons / framework dylibs / system tools; with E5, reboot-persistent compromise. Bounty: *SSV/rootfs integrity bypass* (repo BUG_BOUNTY: up to $100k; Apple may rate the snapshot-level persistence variant higher).
**Bounty category:** Kernel / Signed System Volume bypass (integrity boundary).
**Implementation status:** **~70%** - E1–E3 production-proven (v1.0.0 SSV writes); E4 tooling half-built (dylib injection + re-sign exist for the MHA path); E5 open research.
**CLI automation needed:** `chains ssv-implant <target> <payload-binary>` → host: `scripts/add-load-dylib.py` inject → ldid re-sign (vendored `scripts/ldid`) → deploy → tweak `overwrite_system_file` call → verify checksum on device → `chains ssv-verify` (reboot + hash check for E5 experiments). Reuse `adderall` deploy + `crashlog` monitoring.

---

# NOVEL CHAINS (combining the repo's live bugs)

## Chain F - "GestaltForge" - userspace **write**-escape via bad_query+MCM → device-identity/feature spoofing (26.1+, no kernel)

The repo's `bad_query_escape(path, create, ...)` already supports **create=true**; combined with MCM leases and the class-13 SystemGroup route, the traversal grants a *consumed sandbox extension* on the traversed path - and consumed extensions are not read-only. Public precedent: **GestaltEdit** uses the identical class-13+traversal constants to open `.../systemgroup.com.apple.mobilegestaltcache/Library/Caches/com.apple.MobileGestalt.plist` with `O_RDWR` (DeepWiki analysis of `BadQueryBridge.m`). Repo-specific twist: the **Geod-MCM class-12 partDomain traversal** (0xjohnnydev/Geod-MCM-PoC) reaches the same MobileGestalt cache via a *built-in daemon container* route, and the repo's `mcm_bridge`/`container_access.m` already dlopens the exact API surface.

- **Stages:** (F1) MCM/bad_query lease on the MobileGestalt cache path (IMPLEMENTED pieces: `bad_query_escape(path, create=true, NULL, false)`, `mcm_activate_container(class 13/12, ...)`); (F2) O_RDWR rewrite of `com.apple.MobileGestalt.plist` - feature flags (Apple Intelligence gating, device-class spoofing, privacy-misleading identifiers) - research PoC on 26.1 (repo has no Gestalt module yet); (F3) extend to other systemgroup containers (e.g. TCC-adjacent group data, healthd group) - research.
- **Applicability:** 26.0–26.6.1 (bad_query), 18–27b (MCM route). **No kernel, no jailbreak.**
- **Impact:** persistent (until cache rebuild) device-identity/feature spoofing + systemgroup data tamper. Bounty: sandbox write-escape / privacy boundary (~$100k class if the *write* variant is novel vs public read-only PoCs).
- **Status:** ~40% (lease machinery implemented; Gestalt write + systemgroup target matrix research-only).
- **CLI:** `chains gestalt list|set <key> <value>` → wraps bad_query lease + plist edit + verify; feed `exploits` matrix.

## Chain G - "FontStrike" - FontParser RCE → DarkSword kernel → TCC+SSV implant (the SE2's complete live chain)

Everything in this chain is **live on the repo's test device today** (18.4.1, jailbroken): CVE-2025-43400 (FontParser OOB write, live) + CVE-2025-43520 (DarkSword kernel R/W, live) + the repo's TCC/SSV post-exploitation. The novel step is the **RCE weaponization of 43400** - no public PoC exists, so the diff (18.4.1 vs 18.7.1 libFontParser) → trigger → exploit is a *research deliverable that unlocks a fully local, self-contained chain*: malicious font delivered via Filza preview/Mail/Quick Look → code exec in the parsing process → DarkSword (or, on non-jailbroken ≤26.0.1 via TrollStore, the same tweak) → TCC grant (Chain B) + SSV implant (Chain E). Variant: **ALAC audio** (BB-038, ASAN-verified) if the production CoreAudio plugin disassembly confirms the reference-decoder bug - same shape, different parser.
- **Stages:** G1 FontParser diff+trigger (research; `other_frameworks.md` §2 plan); G2 RCE (research); G3 DarkSword kernel (IMPLEMENTED); G4 TCC+SSV (research/implemented mix per Chains B/E); G5 verify end-to-end on SE2 (hardware available).
- **Applicability:** 18.x ≤18.7.0 and ≤26.0.1 (43400 live); the kernel stage caps at 26.0.1. On 26.1+, G1-G2 + Chain A escape = no-kernel data theft variant.
- **Impact:** a *complete local attack chain* (font → root → persistent grants) that is fully demonstrable on the attached SE2 - the single best repo demo + bounty story (RCE + kernel).
- **Status:** ~25% (all building blocks exist; the 43400 weaponization is the missing ~75%).
- **CLI:** `chains fontdiff` (shared-cache diff automation), `fuzz font` (CTFont corpus strategy on `imageio_mutate.py`), `probe font` (Theos CTFont harness on device, mirroring `imgio_probe`).

---

## 2. How the chains compare

| Chain | Goal | 18.x SE2 (jailbroken, kernel open) | 26.0.x (kernel open) | 26.1+ (kernel closed) | Repo implemented | Missing work |
|---|---|---|---|---|---|---|
| **A ContainerKey** | other-app data exfil, no kernel | ✅ MCM route | ✅ both routes | ✅ bad_query+MCM | **~75%** | `chains exfil` bulk stage |
| **B TCC-Key** | persistent TCC grant | ✅ full | ✅ full | ❌ needs D | **~55%** | TCC.db module + tccd restart |
| **C MediaLock** | parser RCE → escape → data | ⚠️ FontParser live (UI), kernel open | ⚠️ patched parsers | ⚠️ RCE→Chain A (novel) | **~30%** | 43400/31200-class weaponization, audio probe |
| **D Kernel26** | 26.1+ kernel primitive | n/a | n/a | 🔬 46285 (26.1) / 20687 (≤26.3) | **~35%** | trigger validation (hardware-gated), PAC story |
| **E SealBreaker** | SSV system-binary tamper | ✅ session / 🔬 persist | ✅ session / 🔬 persist | ❌ needs D | **~70%** | implant wrapper, reboot-persistence |
| **F GestaltForge** (novel) | no-kernel write-escape → Gestalt spoof | ✅ MCM route | ✅ | ✅ | **~40%** | Gestalt plist write + systemgroup targets |
| **G FontStrike** (novel) | font RCE → kernel → TCC+SSV (SE2 live) | ✅ full | ✅ (≤26.0.1) | ⚠️ RCE→A variant | **~25%** | **43400 weaponization (diff→trigger→exploit)** |

**ROADMAP mapping:** C5.1 (kernel hunt → Chain D) · C5.2 (userspace hunt → Chains A/C/F) · C5.3 (this doc) · C5.4 (`chains` + `cve` CLI - all chains) · C5.5 (BUG_BOUNTY entries for BB-038/039/040 + 46285 live-status) · K4.8/C4.3 (Chain C hardware items).

**Priority recommendation (effort vs. payoff):**
1. **Chain A `chains exfil`** - 1-2 days, everything live, demo on 26.x (and SE2 via MCM).
2. **Chain G G1 (FontParser diff 18.4.1↔18.7.1)** - best single return research action; unlocks the complete SE2 chain.
3. **Chain B TCC module** - 1 day on the jailbroken SE2 once kernel path re-verified; high demo value.
4. **Chain D trigger validation** - hardware-gated; cheapest path is a 26.1 device + K4.7 46285 syscall/trigger fuzzing.

---

## 3. Sources

- NVD CVE-2025-43520: https://nvd.nist.gov/vuln/detail/CVE-2025-43520 · Google Cloud DarkSword analysis: https://cloud.google.com/blog/topics/threat-intelligence/darksword-ios-exploit-chain/
- NVD CVE-2025-43400: https://nvd.nist.gov/vuln/detail/CVE-2025-43400 · Apple iOS 18.7.1: https://support.apple.com/en-us/125327
- CVE-2025-31200/31201 (in-the-wild iMessage chain): CISA vulnrichment https://github.com/cisagov/vulnrichment/issues/200 · Apple iOS 18.4.1: https://support.apple.com/en-us/121250
- NVD CVE-2025-46285: https://nvd.nist.gov/vuln/detail/CVE-2025-46285 · GHSA: https://github.com/advisories/GHSA-p5pj-g9wc-c3v2
- FORCEDENTRY (CVE-2021-30860) P0: https://projectzero.google/2021/12/a-deep-dive-into-nso-zero-click.html · https://projectzero.google/2022/03/forcedentry-sandbox-escape.html
- bad_query: https://github.com/forcequitOS/bad_query · GestaltEdit BadQueryBridge (write-route precedent): https://github.com/frs0n/GestaltEdit/blob/c3cf6596/GestaltEdit/BadQueryBridge.m
- MCM/MobileHouseArrest: https://github.com/0xjohnnydev/MobileHouseArrest-PoC · https://github.com/0xjohnnydev/FilzaSlop · https://github.com/0xjohnnydev/Geod-MCM-PoC
- Repo-internal (CVE-2026-20687, CVE-2026-28990, CVE-2026-43724, CVE-2025-43539, CVE-2025-24085 catalog): `research/moreprojects_deep_dive.md`, `research/audio_frameworks.md`, `research/other_frameworks.md`, `research/applejpeg_cve-2025-43539.md`, `BUG_BOUNTY.md`, `ROADMAP.md` (K4.x/C4.x/C5.x)
- Repo implementation refs: `kexploit/bad_query_escape.m`, `kexploit/container_access.m`, `kexploit/mcm_bridge.m`, `research/TCC_BYPASS.md`, `README.md` (commands table), `CONTEXT.md`
