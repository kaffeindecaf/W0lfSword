# ROADMAP.md — Master Task File

> **Purpose:** Every day, pick one item. Complete it. Check it off.  
> **Format:** `[ ] #ID — Status` = unchecked. `[x] #ID — Status` = done.  
> **Priority:** 🔴 Critical → 🟠 High → 🟡 Medium → 🟢 Low → ⚪ Research

---

# ★ SECTION 0 — START HERE (next session)

> The rest of this file is the full backlog. Do these first, in order.

## 0.1 — Quick wins (under 30 min each, no hardware needed)

- [x] `A3.2` 🔴 — **pe_v2 2GB mach_vm_allocate retry ladder** (kexploit_opa334.m ~line 684)
  _Done 2026-08-14: 2GB → 1GB → 512MB → 256MB ladder with logged attempts. Mid-loop VM_FLAGS_FIXED failures are now bounded (1000 tries) and fall back to the next size with partial-page cleanup instead of hanging._
- [x] `V1.1` 🟡 — **Version plumbing to 1.0.0**: single `VERSION="1.0.0"` var in W0lfSword used by header (line 3), `version` command (line ~2033), bump `control` → 1.0.0, README/CONTEXT references
  _Done 2026-08-14: VERSION var drives show_header + version command; control bumped to 1.0.0; no stale version refs remain in README/CONTEXT._
- [x] `V1.2` 🟡 — **Restore README "Known Issues"** (removed in reform): 26.1+ kernel cap, padlock/SSV best-effort, MTE/A19 unsupported
  _Done 2026-08-14: README Known Issues section restored — 26.1+ cap, best-effort padlock/SSV, MTE/A19, probabilistic race, panic risk + auto-disable._
- [x] `V1.3` 🟡 — **Release build + tag**: `make package FINALPACKAGE=1`, verify .deb, `git tag v1.0.0` + push
  _Done 2026-08-14: FINALPACKAGE=1 now defines NDEBUG + strips KPRINTF (verified: address-leak strings absent in final dylib, present in debug); v1.0.0 .deb built; tag pushed._

## 0.2 — Device/research work (needs iOS 26.1+ hardware or kernelcache)

> **v1.0 scope note:** these are post-v1.0 research items, NOT release blockers.
> v1.0 ships for iOS 17.0–26.0.1 (A10–A18, M1–M4). K4.7/K4.8/K5.6 need a 26.1+
> device (K4.1's kernelcache work is done — see tools/xpf-cli) — they stay open
> as documented future research.

- [x] `K4.1` 🔴 — Verify 26.1 kernel struct offsets (sandbox, MACF label) vs 26.0.1 — pull 26.1 kernelcache, run XPF, add offsets.m block if shifted
  _Done 2026-08-14: XPF diff of 26.0.1 vs 26.1 (iPhone18,1 kc) — structs identical, no new block needed. See K4.1 in Section K4._
  _Follow-up 2026-08-24: three-way A13/t8030 XPF diff (17.1/18.4.1/26.0.1) — itk_space is per-VERSION (0x300/0x318/0x310), offsets.m 26.0 block had a real bug, FIXED to 0x310. Details in Section K4._
- [ ] `K4.7` 🔴 — Reproduce CVE-2025-46285 (kernel root privesc on 26.1, integer overflow in 64-bit timestamps) — diff 26.1 vs 26.2 kernelcaches around timestamp handling  \
  _Research 2026-08-25 (T8110 kcs, no device): fetched + XPF-resolved 26.1 (xnu-12377.42.6~55) and 26.2 (xnu-12377.62.10~1) — offset table identical, itk_space 0x310 confirmed live on both. The 1e9 seconds→ns conversion helper (0xfffffff00814a600 → 0xfffffff00814ed2c) and all 6 W-const callers are semantically IDENTICAL between builds (only branch/relocation deltas) — the fix is NOT in the seconds→ns multiply paths. Neither kernel contains ANY 32-bit multiply instruction (zero W-mul/madd sites; umull counts 720→730) — the "adopt 64-bit timestamps" fix did not convert 32→64 multiplies, so it's a struct/field or non-multiply path. Public xnu tags (12377.41.6/61.12) don't match build numbers (42.6/62.10) so no clean source diff. Remains hardware-gated: needs a 26.1 device for on-device syscall fuzzing/trigger validation._
- [x] `K4.8a` 🔴 — Point the K4.2 fuzzer at AppleJPEG decode paths (CVE-2025-43539 campaign)  \
  _Done 2026-08-21 (no hardware): `jpeg` strategy in research/imageio_mutate.py (SOF/DQT/DHT/SOS/EXIF/scan recipes across the OOB-write families), research/gen_jpeg_seed.py (6 codec shapes), harness `--strategy jpeg` + auto-detect. 307-sample corpus verified. See research/applejpeg_cve-2025-43539.md._  \
  _Campaign 2026-08-25 (SE2/A13 on 18.4.1): 307-sample run via uiopen AND imgio_probe (full + thumbnail + metadata paths) plus the CVE-2026-28990 EXR trigger — ZERO crashes, ImageIO 18.4.1 hardened vs the recipes. Live window stays 26.1–26.4.x; re-run `fuzz probe` on 26.x hardware when available (K4.13)._
- [x] `K4.13` 🟡 — **imgio_probe headless decode harness + Dopamine trust-cache recipe** (new fuzz entry point)  \
  _Done 2026-08-25: pocs/imgio_probe (Theos tool) decodes full image + thumbnail + container/per-frame metadata in a bare CLI process — no SpringBoard/Filza involvement, no resprings, one batch call for the whole corpus, unambiguous crash attribution. Wired as `fuzz probe`: auto Theos build → Procursus ldid sign (vendored at scripts/ldid) → `jbctl trustcache add <cdhash>` → run; crash = SIGSEGV in probe, sample named by last `[*]` line + CrashReporter snapshot. Also fixed: harness ssh loop ate its stdin (ssh -n — loop died after 1 sample on real hardware, mock shims never caught it) and `fuzz --yes` passthrough (main() consumed the flag; re-injected after the subcommand)._
- [ ] `K4.8` 🔴 — Reproduce CVE-2025-43539 on 26.1 hardware + escalate (Chain B)  \
  _Hardware-gated (fuzzer targeting done — K4.8a): run the JPEG campaign on iOS 26.1 arm64e, extract minimal trigger, then SandboxEscape.md Phase 3._
- [x] `K4.2` 🟠 — Build the ImageIO fuzzing harness (referenceforAI/CVE-2025-43300-hunters analyzer + hex_modifier + Filza viewer crash capture)  \
  _Done 2026-08-21: `research/imageio_fuzz.sh` (prepare → push → run → collect → report) + `research/imageio_mutate.py` (validated DNG/TIFF parser, deterministic recipes incl. CVE-43300 mismatch; TSV manifest). Run loop attributes crashes per sample via CrashReporter snapshots; report dedupes .ips signatures and flags UNIQUE ones. Wired as `./W0lfSword fuzz` (menu `f`). Verified end-to-end with mock device + reference-analyzer cross-check._

## 0.3 — High-value features (userspace direction)

- [x] `K4.10` 🟡 — Port bad_query containermanagerd traversal into W0lfSword as 26.1+ userspace read-escape module (works 26.0–26.6.1, unpatched)  \
  _Done 2026-08-21: kexploit/bad_query_escape.m + .h — port of Taj C's bad_query on the existing mcm_api bridge: `bad_query_escape(path, create, group_identifier, is_group)` (SystemGroup class-13 or App-Group class-7 route, part 3 + `../../` traversal, consumed sandbox-extension handle, original error codes), `bad_query_release`, `bad_query_list` (fsgetpath enumeration), `bad_query_probe` (4 target paths, logs which opened). Wired into safe mode (Tweak.m) + exploit-exhaustion fallback (TweakExploit.m). Guards: refuses if query_set_part/part_domain symbols missing. Build verified._
- [x] `K4.12` 🟡 — MobileHouseArrest re-sign mode: optional build producing an MHA-identity Filza IPA for pre-exploit container access  \
  _Done 2026-08-21: `make mha IPA=Filza.ipa` (Makefile MHA_IDENTITY=1 CFLAG + target) → scripts/re-sign_mha.sh (inject tweak dylib via scripts/add-load-dylib.py Mach-O LC_LOAD_DYLIB patch, CFBundleIdentifier + CodeDirectory → com.apple.mobile.MobileHouseArrest, ldid re-sign, repackage). Tweak logs MHA mode at init. CLI: `./W0lfSword mha <ipa> [out]`. Injector verified on a real arm64 Mach-O; prereq gates tested._
- [x] `K3.2` 🟠 — Tweak installer backend (build dylib from templates/catalog, deploy via existing pipeline) — unlocks the tweak menu
  _Done 2026-08-14: see K3.2 in Section K3 — build_tweak.sh + 3 templates + `tweaks install <id>`._
- [x] `K4.14` 🟡 — **kcwatch kernel-delta watcher M1** (research/kcwatch.md)  \
  _Done 2026-08-25: scripts/kczip.py (zip64 remote range reader: EOCD/zip64 locator, retries, CRC-32 over UNCOMPRESSED data, auto raw-deflate), scripts/kcwatch.py (poll → fetch → resolve → diff → render + offsets.m verdict; --board/--version/--dry-run/--json), CLI `./W0lfSword kcwatch` (menu `w`, 5-place wiring). Validated live on t8030: 26.6 → 26.6.1 (xnu-12377.162.13~2 → .14~4) = 51 identical / 12 symbol shifts / 0 struct moves, verdict YES. xpf_diff.py gained the degraded (resolved↔UNRESOLVED) category. M2 staged: scripts/kcwatch.feed-workflow.yml for the public kernel-deltas feed repo._

---

## LEGEND

| Icon | Meaning |
|------|---------|
| 🔴 | Crash / data loss / kernel panic risk |
| 🟠 | Major feature missing, affects many users |
| 🟡 | Nice to have, code quality, edge case |
| 🟢 | Polish, convenience, minor |
| ⚪ | Research / exploratory / bug bounty |

---

# SECTION A: Bugs & Stability Fixes

## A1 — Thread Safety

- [x] `A1.1` 🔴 — Make `g_exploitDone`, `g_patching_in_progress` atomic (`_Atomic bool` or `os_atomic`)  
  _Prompt:_ "Change g_exploitDone and g_patching_in_progress in Tweak.m to use _Atomic bool or os_atomic_store/os_atomic_load. These are read from multiple dispatch queues and the main thread without any memory barrier."

- [x] `A1.2` 🔴 — Audit all `proc_self()`, `kread64`, `kwrite64` call sites for missing PAC strip  
  _Done 2026-08-13: audited kutils.m, vnode.m, sandbox.m, file.m, kexploit_opa334.m, krw.m, permission_utils.m, vnode_research.m, SSVUtils.m, Tweak.m, TweakExploit.m, FilzaPadlockBypass.xm. kread64/kread32/kreadbuf do NOT strip PAC — only kread_ptr/xpaci do. Fixed 9 sites: file.m to_fileproc; sandbox.m self/victim ext_set (borrow path); permission_utils.m v_data ×2; vnode_research.m v_data; kexploit_opa334.m KASLR chain (controlSocketPcb, pcbinfo_pointer, ipi_zone, zv_name) + rwSocketPcb base uses ×3. vnode.m v_data swap/comparison sites verified CORRECT (write-back of signed values). Full Theos build passes._

- [x] `A1.3` 🟠 — `borrow_sandbox_ext()` null-pointer safety + multi-daemon (cfprefsd, securityd, notifyd, lsd)
  _Prompt:_ "In sandbox.m, borrow_sandbox_ext() calls proc_find_by_name('cfprefsd') without checking if the result is NULL. Add a guard that returns -1 if proc_find_by_name fails. Then extend it to try 'securityd', 'notifyd', 'cfprefsd' in a loop."

- [x] `A1.4` 🟠 — `minizip` function pointer validation — check all 13, not just 2  
  _Prompt:_ "In Tweak.m loadMinizip(), g_minizipLoaded is set to (p_zipOpen64 && p_unzOpen64). Change boolean to true only if ALL 13 function pointers are non-NULL. Add TweakLog for each missing function."

- [x] `A1.5` 🟡 — Wild pointer deref in `vnode_get_child_vnode` infinite loop (maxIter=4096 guard)  
  _Prompt:_ "In vnode.m vnode_get_child_vnode(), if the namecache chain loops (corrupted data), the while(1) loop never exits. Add a max iteration counter (e.g. 4096) and return -1 if exceeded."

- [ ] `A1.6` 🟡 — `ensureSSVActive` mutex deadlock possibility with `g_patching_in_progress`  
  _Prompt:_ "Analyze the call graph of ensureSSVActive() → patch_sandbox_ext() → back to ensureSSVActive(). If any code path re-enters the mutex, we deadlock. Document or add a re-entrancy guard."

- [x] `A1.7` 🟡 — Hardcoded APFS fsnode offsets → named constants in offsets.h (v_data+0x70/0x80/0x84/0x88)  
  _Prompt:_ "Move v_data+0x80 (uid), +0x84 (gid), +0x88 (mode) from hardcoded magic numbers in permission_utils.m into named constants in offsets.h. Add per-iOS-version overrides. Same for FilzaPadlockBypass.xm v_data+0x70 (UF_IMMUTABLE)."

- [x] `A1.8` 🟡 — `runSSVDiagnosticsOnce` doesn't clean up on crash  
  _Fixed as A5.4: @try/@catch around NSFileManager ops in TweakExploit.m diagnostics._

- [x] `A1.9` 🟢 — `scheduleExploitOnce` double-registers notification observers  
  _Verified: the `dispatch_once` gate prevents double registration. Observer lifecycle is handled by NSNotificationCenter._

- [x] `A1.10` 🟢 — `TweakLog` is NOT thread-safe (fopen/fclose race) → pthread_mutex_t guard  
  _Prompt:_ "The shared TweakLog() in utils/tweak_log.h can have two threads calling fopen on the same path simultaneously. Add a pthread_mutex_t guard around the entire function."

- [x] `A1.11` 🟡 — `TweakLog` mutex deadlock if signal handler calls TweakLog (BB-008) → use trylock with stderr fallback  
  _Prompt:_ "Add pthread_mutex_trylock() to TweakLog. If the lock fails (held by another thread during signal handling), write to stderr instead. This prevents deadlock if an exception handler thread calls TweakLog while the main thread holds the lock."

- [x] `A1.12` 🔴 — `_Atomic bool` reads/writes need `memory_order_acquire`/`memory_order_release` for cross-thread visibility (BB-009)  
  _Prompt:_ "Replace bare `g_exploitDone = true` with `atomic_store_explicit(&g_exploitDone, true, memory_order_release)` and `if (g_exploitDone)` with `if (atomic_load_explicit(&g_exploitDone, memory_order_acquire))`. Same for g_patching_in_progress. Include <stdatomic.h>."

- [x] `A1.13` 🟡 — Add sanity check: verify APFS fsnode `mode & 0777` is ≤ 0777 before writing ownership fields (BB-012)  
  _Prompt:_ "In apply_permissions_kernel() in permission_utils.m, read the current mode from v_data+off_apfs_fsnode_mode before writing. Verify it's a valid POSIX mask (0-0777). If it's garbage, the offset is wrong and we should abort instead of corrupting kernel memory."

- [x] `A1.14` 🔴 — Verify thread/machine offsets for A16/A17/A18 on iOS 26.0.1 before any writes (BB-011)  
  _Prompt:_ "Add a 'known good' verification in kexploit_opa334.m: after offset resolution but before any kwrite, read the value at off_thread_machine_kstackptr. It should be a valid kernel stack address (aligned to 16, within VM_MIN/VM_MAX). If it fails, log and return -1. This prevents corrupting kernel memory with wrong offsets."

---

## A2 — Filza Compatibility

- [x] `A2.1` 🟠 — Investigate and fix Filza 4.0.2 crash  
  _IPA analysis 2026-08-10: Both IPAs extracted and compared._  
  **Root cause: Bundle ID mismatch.** Filza 4.0.0 = `com.tigisoftware.Filza`, Filza 4.0.2 = `com.tigisoftware.Filza000`. MobileSubstrate plist filters on `com.tigisoftware.Filza` — so the dylib never injects into 4.0.2. All class names (TGRootFileManager, TGAlertController, NewActivationViewController, etc.) and selectors (`spawnRoot:args:pid:`, `showAlertWithTitle:text:cancelButton:otherButtons:completion:`, `isRootHelperAvailable`, `sendObjectWithReplySync:` etc.) are **identical** between both versions. The NZ* classes (NZFileBrowserController, NZDirectoryController, NZFileItem, NZFileManager, NZTextEditor, NZFileViewer) do NOT exist in **either** binary — those hooks are dead code for both versions.  
  **Fix:** Update `FilzaApplySandboxExt.plist` Filter Bundles array to include `com.tigisoftware.Filza000`.  
  **Remaining risk:** 4.0.0 binary is actually newer (2025-03-02) than 4.0.2 (2024-07-24) — versioning is misleading. Consider adding both bundle IDs and a wildcard fallback.

- [x] `A2.2` 🟡 — Padlock bypass: detect if target classes exist at load time  
  _Prompt:_ "In FilzaPadlockBypass.xm, add a %ctor that does NSClassFromString for every hooked class (NZFileBrowserController, NZDirectoryController, NZFileItem, NZFileManager, NZTextEditor, NZFileViewer). Log which classes are missing. If all are missing, set a flag to skip all hooks."

- [ ] `A2.3` 🟢 — Test with Filza 4.0.0 on iOS 17.0 and 18.0 for regression  
  _Prompt:_ "Create a test matrix: Filza 4.0.0 × iOS 17.0, 17.7, 18.0, 18.7, 26.0. For each combo, test: launch, browse /System, create a file, delete a file, zip Documents, unzip to /var/tmp. Mark pass/fail."

- [x] `A2.4` 🟠 — FilzaPadlockBypass NZ* hooks are dead code — replace with TG* equivalents  
  _Fixed 2026-08-10: Replaced all 17 dead NZ* hooks with hooks on real TG/TIGI classes (TIGIBrowserView, TGPageViewController, TGFileSystemListViewController). TIGIBrowserView forces readOnly:NO, TGPageViewController allows delete without confirmation._

- [ ] `A2.5` 🟠 — PadlockBypass removeItemAtPath kreads before exploit_is_done guard → kernel panic
- [ ] `A2.6` 🟡 — Tweak.m zip hooks: unconditional (NSString*) cast on id → crash if non-NSString
- [ ] `A2.7` 🟡 — Tweak.m unzip: char filename[512] may be unterminated → add null guard
- [ ] `A2.8` 🟡 — FilzaPadlockBypass: 11 sites pass [nil UTF8String] to TweakLog %s → SIGSEGV
- [ ] `A2.9` 🟡 — hook_createFileAtPath/writeToFile call ensureSSVActive AFTER %orig — too late
- [ ] `A2.10` 🟢 — Zip hooks block main thread on large archives — no background dispatch

- [ ] `A2.11` 🟡 — TweakInit: stale /var/mobile/.sbx_check falsely skips exploit (H2,H3)

---

## A5 — SSV & Sandbox Escape Stability (audit 2026-08-10)

- [x] `A5.1` 🔴 — sandbox_escape.m:114 — non-null-terminated string written to kernel memory  
  _Fixed 2026-08-13: prior state was KRW_LEN=0x21 (33) — which itself violated the early_kread primitive limit (EARLY_KRW_LENGTH=32 → FAILURE on every patch_ext/set_rw_class call). Now: KRW_LEN = EARLY_KRW_LENGTH (32), the 32 name chars are written at da+32 and the NUL terminator is supplied by the zeroed buffer written at da+64. Added `_Static_assert` that the class name is exactly 32 chars, memset hardening on all buffers, and aligned uint64 hb buffer. Verified: full Theos build passes._

- [x] `A5.2` 🔴 — SSV/SSVUtils.m:35 — patch_sandbox_ext() called with zero exploit guard  
  _Fixed 2026-08-13 (hardening; base guard existed but was incomplete): exploit_is_done() moved to the TOP of ssv_write (before temp-file work, no leaked tmp), patch_sandbox_ext() return value now checked (abort + cleanup before kernel vnode writes on failure), and the truly ungated paths got guards: ssv_chown_root, ssv_dump_fsnode, apply_permissions_kernel (permission_utils.m), research_vnode_apfs_fsnode (vnode_research.m). No more kernel-memory access without a live exploit._

- [ ] `A5.3` 🟠 — TweakExploit.m attemptCount race: static int without synchronization  
  _Multiple dispatch_after blocks fire in parallel, all increment same static int. 2 blocks see attemptCount==2 → both proceed as attempt 3 → parallel sandbox_escape corrupts kernel memory._

- [ ] `A5.4` 🟠 — TweakExploit.m diagnostics: NSFileManager ops lack @try/@catch → SIGABRT  
  _dispatch_once block calls createDirectory/removeItem without exception handler. Exception in block = process kill._

- [ ] `A5.5` 🟡 — utils/tweak_log.h: localtime() not thread-safe + can return NULL → crash  
  _Switch to localtime_r with stack-allocated struct tm._

- [ ] `A5.6` 🟡 — utils/tweak_log.h: no NULL check on format param → vfprintf(NULL) SIGSEGV

- [ ] `A5.7` 🟡 — sandbox_escape.m: ucred scan does ptr_in_kernel() but not mapping-aware  
  _ptr_in_kernel checks range+alignment only — unmapped kernel VA causes data abort on read._

- [ ] `A5.8` 🟢 — SSV/SSVUtils.m: fd leak on rename fallback failure → ulimit exhaustion
- [x] `A5.9` 🟢 — sandbox_escape.m: uint64_t* cast on uint8_t[32] may be unaligned → arm64 fault  
  _Fixed: uint64_t __attribute__((aligned(8))) chunk[4] replaces uint8_t[32]._
- [x] `A5.10` 🟢 — permission_utils.m: fsnode sanity check only rejects >0777, doesn't check UID/GID  
  _Fixed: Added UID/GID ≤ 65535 bounds check before writing._

---

## A6 — Production Readiness (audit 2026-08-10)

- [x] `A6.1` 🔴 — Replace `exit()` in `FAILURE()` macro with error return path  
  _FAILURE(0) calls exit() — kills Filza on any exploit failure. 34 call sites. Use longjmp or return._

- [x] `A6.2` 🔴 — 40+ `printf()` sites leak kernel addresses (ASLR slide, PCB addrs)  
  _Fixed 2026-08-13: added kexploit/klog.h with KPRINTF() — prints only in DEBUG builds, compiled out in release. Converted all 74 address-leaking printf sites (kexploit_opa334.m 20, vnode_research.m 36, RemoteCall.m 11, MigFilterBypassThread.m 4, PAC.m 1, patchfinder.m 2), including the PRINT_VAR macro. Verified: debug + release (FINALPACKAGE=1) builds both pass._
  _kexploit_opa334.m, RemoteCall.m, krw.m all print kernel addresses to stdout. Wrap in #ifdef DEBUG._

- [x] `A6.3` 🔴 — sandbox_escape.m: KRW_LEN=0x20 truncates class name "read-writ\0" missing 'e'  
  _Fixed 2026-08-10: KRW_LEN increased to 0x21 (33). Verified the class name now fits with null._

- [x] `A6.4` 🟠 — utils/tweak_log.h: static mutex in header → each TU gets own copy  
  _Move g_log_mutex to a .m file. Cross-TU log calls use different mutexes → race on file write._

- [x] `A6.5` 🟠 — Tweak.m: loadMinizip() not thread-safe (non-atomic flag + unsynchronized dlsym)  
  _Use dispatch_once or pthread_once for one-time initialization._

- [ ] `A6.6` 🟠 — W0lfSword script: `eval` in retry() → code injection surface  
  _Replace with array-based command execution._

- [x] `A6.7` 🟠 — kexploit_opa334.m: 15+ file-scope vars missing `static` → pollute namespace  
  _Add static to readFd, writeFd, controlSocket, rwSocket, socketPorts, etc._

- [x] `A6.8` 🟡 — kexploit_opa334.m: hardcoded `sleep(8)` for A18 — undocumented delay  
  _Document why 8 seconds is needed, or investigate if still required._

- [x] `A6.9` 🟡 — kexploit/offsets.m:631 `printf("hello from roooot!\n")` debug joke in production  
  _Remove or wrap in #ifdef DEBUG._

- [ ] `A6.10` 🟡 — Tweak.m: 6+ `NSLog()` sites should be TweakLog for unified logging
- [ ] `A6.11` 🟡 — kutils.m: proc_get_p_name static buffer not thread-safe
- [x] `A6.12` 🟡 — control: version 0.7.6 vs script v0.9, placeholder maintainer/author  \
  _Done 2026-08-14 (V1.1) + verified 2026-08-21: control is 1.0.0 with real Maintainer/Author, matches the script's VERSION var._
- [x] `A6.13` 🟡 — CONTEXT.md: stale line counts, stale architecture, wrong fixes count  \
  _Done 2026-08-21: full refresh — line counts, architecture (pocs/, research/, tools/xpf-cli, fuzz/poc/exploits commands), current state._
- [x] `A6.14` 🟢 — Makefile: kexploit/sandbox_backup.m dead code not compiled  \
  _Verified 2026-08-21: file no longer exists; Makefile has no reference._
- [x] `A6.15` 🟢 — kutils.h:29 `amfi_cslot_get` declared but never defined  \
  _Done 2026-08-21: declaration removed (never referenced in this repo)._
- [x] `A6.16` 🟢 — xpaci.h: double #include <stdbool.h> (lines 2-3)  \
  _Done 2026-08-21: duplicate include removed._
- [x] `A6.17` 🟢 — W0lfSword: `seq` not on macOS → hline/section broken output  \
  _Done 2026-08-14: replaced seq with bash-native repeat_char() loops. Full macOS audit in A6.21._
- [x] `A6.18` 🟢 — W0lfSword: `sleep 0.05` (fractional) doesn't work on busybox  \
  _Verified 2026-08-21: the only fractional sleep is the host-side spinner (GNU and BSD sleep both support fractions); no fractional sleep is ever sent to the device over SSH._
- [x] `A6.21` 🟠 — Full macOS support for the W0lfSword script + assets  \
  _Done 2026-08-14: platform detection (IS_MACOS) + portable helpers replacing GNU-isms — repeat_char (seq), ping_check (macOS -W is ms, not s), version_sort_first (no sort -V), sort -u -t. k1,1n..., mktemp template, eval-tilde instead of getent. cmd_setup: brew-aware packages (libimobiledevice, dpkg; clang via Xcode CLT with xcode-select gate), no-sudo brew path with $SUDO only for /opt/theos, theos at /opt/theos + Homebrew paths in check_theos. cmd_doctor: Xcode iPhoneOS SDK check. adderall Phase 2: OS-aware installer. usbliter8 hints, dpkg hint, build_and_extract.sh THEOS detection, BUILD.md + README updated._
- [x] `A6.19` 🟢 — krw.m + vnode_research.m: debug functions with no #ifdef guards  \
  _Done 2026-08-21: dead khexdump wrapped in #ifdef DEBUG (def + decl). vnode_research.m's apfs_fsnode dump is a live, exploit-gated (A5.2) run-once SSV diagnostics utility — kept, with addresses already KPRINTF-gated._
- [x] `A6.20` 🟢 — build_and_extract.sh: missing pipefail → silent build failures  \
  _Done 2026-08-21: set -euo pipefail + ${1:-} guard + build pipeline now fails loudly with a doctor hint._

---

## A3 — Kernel Exploit Robustness

- [x] `A3.1` 🔴 — Kernel panic recovery: detect previous crash, disable exploit  
  _Done 2026-08-13: Tweak.m TweakInit checks .filza_last_success + .filza_crash_count — after 3 crashes without a success flag it creates TWEAK_DISABLE_FLAG. TweakExploit.m mark_exploit_success() records success + resets the counter; runExploit re-arms the sentinel (unlinks the flag) on attempt 1._

- [x] `A3.2` 🔴 — A18 device pe_v2: handle mach_vm_allocate failure for 2GB  
  _Done 2026-08-14: retry ladder 2GB → 1GB → 512MB → 256MB with logging. Mid-loop VM_FLAGS_FIXED failures are now bounded (1000 tries ≈ 100ms) and fall back to the next size with partial wired-page cleanup — no more infinite hang._

- [x] `A3.3` 🟠 — Socket spray failure: handle `socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6)` returning -1  
  _Fixed 2026-08-10: spray_socket returns MACH_PORT_NULL on failure, both callers check for it._

- [x] `A3.4` 🟠 — `physical_oob_write_mo` async corruption detection  
  _Fixed 2026-08-10: function returns kern_return_t, read-back verification added._

- [ ] `A3.5` 🟡 — Wired page leak in pe_v2 error path  
  _Prompt:_ "In pe_v2(), if the exploit succeeds, the cleanup loop `for (NSNumber *addr in wiredAddrs)` deallocates remaining wired pages. But if mach_vm_allocate fails mid-loop or the function returns early due to a failure, wiredAddrs may contain pages that were mlock'd but never freed. Add a cleanup block on all return paths."

- [x] `A3.6` 🟡 — `highestSuccessIdx` grows unbounded across exploit attempts → reset per call  
  _Prompt:_ "highestSuccessIdx is a global that tracks the best try index for the OOB read race. It grows across multiple exploit attempts. On iOS 26 with potentially different kernel memory layout, this could cause infinite retry (tryIdx goes up to highestSuccessIdx+100 which is now a huge number). Reset to 100 on each new exploit attempt."

- [x] `A3.7` 🔴 — Thread.m:48 AST_GUARD never cleared due to operator precedence (C1 audit)  
  _Verified fixed 2026-08-13: current code is `ast = (ast & ~AST_GUARD) | 0x80000000` — parenthesized correctly (fix landed in 9840344). Mask semantics confirmed: clears 0x1000, sets 0x80000000._

- [x] `A3.8` 🔴 — sandbox.m:229 heap buffer overflow in kernel: 34B write into 2B allocation (C3)  
  _Fixed 2026-08-13: rewrites now check `ext.path_len` (kernel allocation size) against the 35-byte path+class payload. If too small, only the 3-byte "/" path is written and the class-node rewrite is skipped — the overflow is impossible. Class rename is best-effort by design._

- [x] `A3.9` 🔴 — vnode.m: returned -1 sentinel wraps 64-bit addr → reads from 0xDF (C4,C5)  
  _Fixed 2026-08-13: kpf/patchfinder.m now checks `== (uint64_t)-1` on both vnode lookups (kc_copysrc_vnode, kc_folder_vnode) before any `+off_vnode_v_data` deref. Defense in depth: get_vnode_by_fd() rejects fd < 0. Other callers (file.m, permission_utils.m, vnode_research.m) verified to already check the sentinel._

- [x] `A3.10` 🔴 — kexploit_opa334.m:316 checks !surface instead of mach_make_memory_entry_64 status (C2)  
  _Fixed 2026-08-13: removed the dead `!surface` re-check (surface is guaranteed non-NULL by then); replaced with a real `memoryObject == MACH_PORT_NULL` guard after the kr != KERN_SUCCESS check._

- [x] `A3.11` 🔴 — kexploit_opa334.m:567 infinite while(true) on write verify failure (C6)  
  _Fixed 2026-08-13: the `while (raceSync == 1)` spin in physical_oob_write_mo is now bounded (10M iterations); on timeout it FAILUREs with "raceSync timed out" instead of hanging forever._

- [ ] `A3.12` 🟠 — kexploit_opa334.m:461, RemoteCall.m:273 — while(1){} hangs on invalid address  
  _Use FAILURE(0) or return error instead of permanent hang._

- [ ] `A3.13` 🟠 — kexploit_opa334.m:95-101 — volatile without _Atomic for cross-thread sync race  
  _goSync, raceSync, targetObject etc. use volatile not _Atomic. ARM weak memory → stale reads → race lost._

- [ ] `A3.14` 🟠 — RemoteCall.m:242 — unhandled exception leaves target thread suspended (H7)  
  _No reply sent on timeout → thread stuck with pending EXC_GUARD forever._

- [ ] `A3.15` 🟠 — vnode.m:22 — static vp_name[256] buffer race across threads (M1)  
  _vnode_get_v_name returns pointer to file-scope static. Concurrent callers see corrupted names._

- [ ] `A3.16` 🟡 — RemoteCall.m:368 — SHMEM cache full with no eviction after 100 pages (M2)
- [ ] `A3.17` 🟡 — sandbox.m:172 — unvalidated class_name kernel pointer in kreadbuf (M3)
- [ ] `A3.18` 🟡 — offsets.m — 0xdeaddead sentinel could alias valid offset (M4)
- [ ] `A3.19` 🟡 — kutils.m:17 — gSelfProc/gSelfTask cached without atomic reads/writes (M5)
- [ ] `A3.20` 🟢 — kexploit_opa334.m:175 — calloc result unchecked for NULL (L4)
- [ ] `A3.21` 🟢 — RemoteCall.m:549 — pthread_create_suspended_np failure unchecked (L5)
- [ ] `A3.22` 🟢 — VM.m:186 — memoryObject mach port leaked on entry validation failure (L6)

---

# SECTION B: Feature Additions

## B1 — Multi-App Support

- [ ] `B1.1` 🟠 — Generic sandbox escape for any app, not just Filza  
  _Prompt:_ "Modify FilzaApplySandboxExt.plist to accept an array of bundle IDs (or a wildcard). The Tweak.m hooks for TGRootFileManager, Zipper, NZFileBrowserController are Filza-specific, so they should be guarded by a `if (isFilzaProcess)` check. All NSFileManager, sandbox_escape, and kexploit hooks work universally. Add a separate .plist key 'SkipAppSpecificHooks'."

- [ ] `B1.2` 🟠 — Config file for per-app settings  
  _Prompt:_ "Create /var/mobile/Documents/.filza_tweak_config.plist with keys: EnabledBundles (array of strings), RetryAttempts (int), EnableSSV (bool), LogLevel (string: debug/info/warn). Read at TweakInit. If EnabledBundles is empty or contains current bundle, proceed; otherwise unload."

- [ ] `B1.3` 🟡 — Test with: Santander, iFile, iExplorer, terminal emulators  
  _Prompt:_ "Test the generic sandbox escape + kexploit with these apps. Document which ones work and which crash. For each non-Filza app: does the app's own file manager pick up the sandbox escape? Or does it need custom hooks?"

- [ ] `B1.4` 🟢 — Standalone .ipa with embedded dylib (no jailbreak required?)  
  _Prompt:_ "Research: Can we build an .ipa that includes FilzaApplySandboxExt.dylib + a minimal file browser, signed with ldid, and installed via TrollStore or sideloading? This would remove the jailbreak requirement. The kernel exploit works from any process — the only constraint is the sandbox being tight enough to run the exploit."

---

## B2 — Runtime Control

- [x] `B2.1` 🟠 — Runtime disable toggle via flag file (TWEAK_DISABLE_FLAG checked in TweakInit + runExploit)  
  _Prompt:_ "Add a check at the top of every hook function: if /var/mobile/Documents/.filza_tweak_disable exists, call %orig and return immediately. Also check in runExploit before starting. Add a convenience function `bool tweak_is_disabled(void)`."

- [ ] `B2.2` 🟡 — Reload config without killing Filza  
  _Prompt:_ "Add a file monitor using dispatch_source (Vnode/DISPATCH_VNODE_WRITE) on the config plist at /var/mobile/Documents/.filza_tweak_config.plist. When it changes, re-read and apply new settings (debug bypass, SSV enable, retry count)."

- [ ] `B2.3` 🟢 — In-app status bar showing exploit state  
  _Prompt:_ "Add a small UIWindow overlay (like FLEX) that shows: exploit status (running/done/failed), SSV active (yes/no), sandbox escaped (yes/no), current log tail (last 5 lines). Toggle with a gesture or notification."

---

## B3 — Power User Features

- [ ] `B3.1` 🟡 — Built-in terminal emulator / command runner  
  _Prompt:_ "Add a hidden URL scheme handler (filza-tweak://run?cmd=ls+/) that runs a shell command with the escaped sandbox and returns output. This effectively turns Filza into a root shell. Consider security implications: anyone with the URL can run commands."

- [ ] `B3.2` 🟡 — Process list with kill/suspend capability  
  _Prompt:_ "Use kutils.h proc_find() + proc_get_p_name() to enumerate all processes from kernel memory. Display in a table view. Add swipe-to-kill (task_terminate via kernel write). This is an iOS task manager without any entitlement."

- [ ] `B3.3` 🟡 — Keychain viewer / dumper  
  _Prompt:_ "Research the keychain SQLite database at /private/var/Keychains/keychain-2.db. With kernel R/W, can we bypass the keychain access control and read raw rows? Can we decrypt keychain items that are protected by the device UID?"

- [ ] `B3.4` 🟡 — TCC database viewer / modifier  
  _Prompt:_ "The TCC (Transparency Consent Control) database at /private/var/mobile/Library/TCC/TCC.db controls which apps can access camera, mic, photos, contacts, etc. With full filesystem R/W from the sandbox escape, we can: read all entries, add new entries granting our app all permissions, or delete entries to bypass consent prompts. Write a SQLite browser for this."

- [ ] `B3.5` 🟢 — Hex editor for binary files  
  _Prompt:_ "Add a hex dump view to Filza's file viewer. Use hexdump.c as the backend. Allow editing individual bytes and writing back with SSV bypass. This enables binary patching of system binaries."

- [ ] `B3.6` 🟢 — File diff viewer  
  _Prompt:_ "Add a 'diff' button in Filza that compares two selected files side-by-side. Simple line-based diff algorithm. Useful for before/after comparison when editing system plists."

- [ ] `B3.7` 🟢 — Network traffic capture (pcap)  
  _Prompt:_ "Create a raw socket or use BPF to capture network traffic from within the sandbox-escaped process. Dump to .pcap file. This enables network debugging of any iOS app without a proxy."

---

## B4 — Developer / Debug Features

- [ ] `B4.1` 🟡 — Kernel memory hex dump UI  
  _Prompt:_ "Add a UI text field where the user enters a kernel address (hex), and the app displays a 256-byte hex dump using kreadbuf. This is a kernel debugger built into Filza. Add a guard that validates the address against VM_MIN/VM_MAX before reading."

- [ ] `B4.2` 🟡 — Export kernel struct offsets as JSON  
  _Prompt:_ "After offsets_init() completes, dump all offset values as a JSON file to /var/mobile/Documents/kernel_offsets.json. Include device info (hw.machine, iOS version, kernel version). Useful for sharing offset tables with the community."

- [ ] `B4.3` 🟢 — XPF integration: run patchfinder from within the app  
  _Prompt:_ "Currently init_xpf() is in kpf/patchfinder.m but never called from Tweak.m (offsets are hardcoded). Add a button or config flag that runs init_xpf() to dynamically resolve offsets instead of using the hardcoded table. Compare results against hardcoded values and log discrepancies."

- [ ] `B4.4` 🟢 — System info panel  
  _Prompt:_ "Display: iOS version, build number, kernel version, device model, CPU family, PAC support, T1SZ, kernel base, kernel slide, exploit success rate. Useful for one-glance diagnostics."

---

# SECTION C: Security Research & Bug Bounty

## C1 — iOS Kernel Vulnerability Hunting

- [ ] `C1.1` ⚪ — Analyze DarkSword's ICMPv6 + IOSurface technique for additional primitives  
  _Prompt:_ "The DarkSword exploit uses getsockopt on ICMPv6 sockets to leak kernel memory. Study: can we extend this to arbitrary free (UaF)? Can we corrupt the ICMPv6 filter pointer for write-what-where? Document the exact kernel structures involved and look for additional attack surface in inpcb, socket, and icmp6_filter handling."

- [ ] `C1.2` ⚪ — Investigate `physical_oob_read_mo` race window for info leak  
  _Prompt:_ "The race between pwritev and mach_vm_map creates a window where the physical page backing is freed but the virtual mapping is still accessible. This is a classic info leak primitive. Can we use this to leak kernel ASLR slide without any kernel R/W? Write a clean proof-of-concept."

- [ ] `C1.3` ⚪ — IOSurface race condition research  
  _Prompt:_ "The exploit uses IOSurfaceCreate with a physical address to create a mapping that survives deallocation. Research: are there other IOSurface properties that can be abused? Look at IOSurfaceRootUserClient external methods for potential arbitrary kernel free or reference count bugs."

- [x] `C1.4` ⚪ — MIG filter bypass: document the gadget chain  
  _Documented in docs/MIG_FILTER_BYPASS.md: migLock, migSbxMsg, migKernelStackLR, kernel stack layout, bypass thread lifecycle, lck_rw_t structure._

- [ ] `C1.5` ⚪ — Search for new kernel vulns: sysctl OOB  
  _Prompt:_ "Audit all sysctls accessible from the sandbox. Use syz-repro or manual fuzzing to find sysctl handlers that have OOB reads/writes. Focus on networking sysctls (net.inet.*, net.inet6.*) since the exploit already touches these. Use the kernel R/W to verify any suspected vulnerabilities."

- [ ] `C1.6` ⚪ — Search for new kernel vulns: IOUserClient external method dispatch  
  _Prompt:_ "Enumerate all IOKit services accessible from the container sandbox. For each, enumerate external methods via IOConnectCallMethod. Look for scalar/struct input validation failures that could lead to kernel OOB or type confusion. Use KTRR/KERNEL RW to verify."

- [ ] `C1.7` ⚪ — Search for new kernel vulns: XPC service handlers  
  _Prompt:_ "Use the sandbox escape to enumerate all XPC services. Fuzz each service's protocol with crafted messages. Look for: unvalidated integer types leading to allocation size errors, missing bounds checks on array indices, or use-after-free in async reply handlers."

---

## C2 — Apple Bug Bounty: Specific Targets

- [x] `C2.1` ⚪ — TCC bypass via kernel-level .db modification (up to $100,000)  
  _Prompt:_ "Research Apple Security Bounty categories for TCC bypass. With kernel R/W + filesystem access, we can modify TCC.db directly. Create an automated PoC that: 1) escapes sandbox, 2) modifies TCC.db to add a camera/mic permission entry, 3) demonstrates the permission is active without any user prompt. Document the full chain. Submit to Apple if novel (they may consider this 'requires kernel access' and thus out of scope — check)."

- [ ] `C2.2` ⚪ — Secure Enclave / SEP attack surface (up to $250,000)  
  _Prompt:_ "Research: Can kernel R/W be used to attack the Secure Enclave Processor? Look at SEP driver (AppleSEPManager) communication path. What happens if we corrupt the shared memory ring buffer between AP and SEP? Can we cause a SEP panic that reveals secure data? This is high-value bug bounty territory."

- [ ] `C2.3` ⚪ — AMFI / code signing bypass (up to $150,000)  
  _Prompt:_ "With kernel R/W, modify AMFI flags for our process (proc->p_flag bit P_AMFI_DISABLED). Then attempt to load unsigned code or bypass library validation. Document the exact kernel memory write needed. If this allows arbitrary unsigned dylib loading on a non-jailbroken device, it qualifies for bug bounty."

- [ ] `C2.4` ⚪ — Kernel code execution via ROP chain (up to $250,000)  
  _Prompt:_ "Current exploit gives kernel R/W. Can we escalate to kernel code execution? Research: overwrite a function pointer (sysent table, IOKit vtable, mach trap table) with a gadget address. Build a ROP chain that calls copyout() to send kernel memory to userspace, or modifies the root vnode to give us file access. This demonstrates full kernel compromise."

- [ ] `C2.5` ⚪ — PAC bypass technique research (up to $150,000)  
  _Prompt:_ "On arm64e devices, kernel pointers are PAC-signed. Our exploit uses xpaci() to strip PAC bits for reads, but writes need re-signing. Research: can we leverage the PACIA gadget found in PAC.m to re-sign arbitrary pointers? Or can we find a signing oracle in the kernel (a function that signs pointers for us based on controlled input)? This would enable arbitrary kernel object forgery."

- [ ] `C2.6` ⚪ — MTE (Memory Tagging Extension) bypass for A19/M5  
  _Prompt:_ "iPhone 17 and M5 added MTE which tags all heap allocations. The DarkSword exploit relies on heap spraying with fake kernel objects — MTE breaks this because the tags won't match. Research: can we leak the MTE tag generation key? Can we coerce the allocator to reuse a specific tag? Is there a deterministic tag prediction weakness? This is the next frontier."

- [ ] `C2.7` ⚪ — Kernel info leak for KASLR bypass (up to $25,000)  
  _Prompt:_ "Can we leak the kernel slide without the full exploit? Look for: /proc interfaces that expose kernel addresses, sysctl OIDs that return kernel pointers, kdebug events with kernel addresses, or IOSurface properties that leak physical addresses. A clean KASLR bypass qualifies for a lower-tier bug bounty."

- [ ] `C2.8` ⚪ — Code signing bypass via kernelcache remount  
  _Prompt:_ "The SSV mounts the root filesystem as read-only with signed hashes. Our overwrite_system_file() changes the mount flag to writable, writes, then restores it. Can we do this permanently? What if we modify the trustcache to trust our own code hash? Research the trustcache structure and see if kernel R/W can add entries."

---

## C3 — Practical Attack Chains

- [ ] `C3.1` ⚪ — Full chain: app install → sandbox escape → persistence → exfiltration  
  _Prompt:_ "Document a complete attack scenario: user installs a malicious .ipa (via enterprise cert or social engineering), the app exploits DarkSword to escape sandbox, then: installs a launch daemon plist in /Library/LaunchDaemons/, copies a payload dylib to /usr/lib/, and sets up a reverse shell that survives reboot. This demonstrates impact for a bug bounty report."

- [ ] `C3.2` ⚪ — iCloud Keychain exfiltration  
  _Prompt:_ "With kernel R/W, locate the iCloud Keychain sync daemon's process. Read its memory to extract the keychain decryption keys. Then read /private/var/Keychains/keychain-2.db and decrypt entries. This extracts Safari passwords, Wi-Fi passwords, credit cards, and app credentials stored in iCloud Keychain."

- [ ] `C3.3` ⚪ — iMessage database exfiltration  
  _Prompt:_ "With filesystem R/W, copy /private/var/mobile/Library/SMS/sms.db (iMessage/SMS database). This contains all messages including deleted ones (SQLite retains data until VACUUM). Parse it and extract all conversations. This is a privacy-critical data exfiltration path."

- [ ] `C3.4` ⚪ — Apple Pay / Wallet NFC emulation  
  _Prompt:_ "Research: can kernel R/W be used to interact with the NFC controller? Look at the NFC driver in IOKit (PN548, etc.). Can we read card data that's been provisioned to Apple Pay? Can we emulate a payment? This is extremely sensitive and potentially high-value for bug bounty."

---

# SECTION D: Code Quality & Architecture

## D1 — Refactoring

- [ ] `D1.1` 🟡 — Split Tweak.m into multiple files  
  _Prompt:_ "Tweak.m is 1218 lines and does too many things: hooks, exploit orchestration, SSV activation, diagnostics, logging, UI bypass. Split into: TweakHooks.m (all method swizzling), TweakExploit.m (runExploit + retry), TweakDiagnostics.m (runSSVDiagnosticsOnce), TweakUI.m (uiDebugBypass flag). Keep Tweak.m as the %ctor entry point only."

- [ ] `D1.2` 🟡 — Create a `state.h` for all global state  
  _Prompt:_ "Move g_exploitDone, g_patching_in_progress, g_ssv_active, g_ui_debug_bypass, and all static globals scattered across files into a single state.h/state.m module with getter/setter functions. This makes state transitions auditable and prevents extern spaghetti."

- [x] `D1.3` 🟡 — Replace printf()/NSLog() with TweakLog() in sandbox.m borrow + sandbox_escape.m (all 18 calls)  
  _Prompt:_ "Offsets.m, sandbox.m, vnode.m, file.m, kutils.m, krw.m all use printf() for debug output. These go to stdout which in Filza goes nowhere (the app doesn't have a TTY). Replace all with TweakLog() so debug output actually reaches the log file. Add a compile-time flag to disable verbose kernel debug in release builds."

- [ ] `D1.4` 🟢 — Add error code enum for all functions  
  _Prompt:_ "Right now functions return 0, -1, or a magic number. Create an error code enum: TWEAK_OK, TWEAK_ERR_EXPLOIT_FAILED, TWEAK_ERR_SANDBOX_ESCAPE_FAILED, TWEAK_ERR_SSV_ACTIVATION_FAILED, TWEAK_ERR_KERNEL_PTR_INVALID, etc. Use consistently."

- [x] `D1.5` 🟢 — Add `__attribute__((cleanup))` for fd/port cleanup  
  _Added utils/scoped.h with scoped_fd, scoped_port, scoped_free macros._

---

## D2 — Testing Infrastructure

- [ ] `D2.1` 🟡 — Unit tests for offset table  
  _Prompt:_ "Write a test script (Python or Swift) that reads /var/mobile/Documents/kernel_offsets.json (from B4.2) and validates: all offsets are non-zero, ptr fields are within VM_MIN/VM_MAX, sizeof fields are reasonable (<4096), no duplicates. Run after each iOS version bump."

- [ ] `D2.2` 🟡 — Regression test script  
  _Prompt:_ "Write a shell script that runs inside Filza (via the command runner from B3.1 if implemented, or via a standalone test dylib). Tests: write to /var/tmp, write to /System/Library/.test, create dir in /usr/lib/.test, chmod a file, delete a file, stat a vnode. All should pass. Output pass/fail to /tmp/filza_tests.log."

- [ ] `D2.3` 🟢 — Fuzzing harness for vnode operations  
  _Prompt:_ "Write a fuzzer that randomly calls vnode_redirect_folder, vnode_redirect_file, hide_path, reveal_path on random paths. Run in a tight loop. Goal: trigger a kernel panic via corrupted vnode data pointer. If you find one, you have a new kernel bug."

- [ ] `D2.4` 🟢 — Memory pressure test  
  _Prompt:_ "While the exploit is running (socket spray + 2GB wired pages), simultaneously allocate 100MB in the app process. Does the exploit still succeed or does it fail gracefully? If the app is killed by jetsam, the exploit didn't handle low memory properly."

---

## D3 — Documentation

- [x] `D3.1` 🟢 — Architecture decision records  
  _Prompt:_ "Create docs/adr/ directory. Write one ADR for each major decision: why ICMPv6 socket technique was chosen, why vnode redirection for SSV instead of remount, why offset tables are hardcoded instead of always using XPF, why pthread_mutex over dispatch_semaphore for SSV."

- [x] `D3.2` 🟢 — API documentation for kernel primitives  
  _Prompt:_ "Document every function in krw.h, kutils.h, vnode.h, sandbox.h with: what it does, kernel side effects, calling context requirements (must hold mutex? PAC stripped? safe to call from main thread?), return value semantics."

- [x] `D3.3` 🟢 — Threat model document  
  _Written in docs/THREAT_MODEL.md: component breakdown, Apple fix options, survival ratings, mitigation strategy._

---

# SECTION E: iOS Version / Device Expansion

- [ ] `E1.1` 🟠 — iOS 26.1 preparation  
  _Prompt:_ "Set up monitoring: when iOS 26.1 beta drops, immediately obtain the kernelcache. Run XPF on it. Compare all offsets with the 26.0 table. Document every changed offset. Add a new block in offsets.m for 26.1+. Test on a real device if available."

- [ ] `E1.2` 🟡 — iOS 25.x backport  
  _Prompt:_ "Does iOS 25 exist? If yes, does our offset table cover it? The offsets_init range check allows 17.0–26.0.x. If there's a 25.x, we need a block for it. Check the kernel version from the XNU source code drop."

- [ ] `E1.3` 🟡 — iPad-specific testing  
  _Prompt:_ "Test on iPad Pro (M1/M2/M4), iPad Air, iPad mini. Some iPads have different kernel cache layouts (larger page sizes, different device tree). Verify offsets are correct for iPad-specific SoCs."

- [ ] `E1.4` 🟢 — Apple TV / HomePod  
  _Prompt:_ "tvOS uses the same XNU kernel. Can the exploit run on Apple TV? The socket spray + IOSurface technique should work. But tvOS has no Filza. Test with a standalone test app to verify kernel R/W works."

- [ ] `E1.5` 🟢 — visionOS  
  _Prompt:_ "Apple Vision Pro runs visionOS which is based on iOS. Could the exploit work there? The UI is different (no Filza equivalent), but the kernel is similar. Research for curiosity / bug bounty."

---

# SECTION F: Daily Prompts (Copy-Paste Ready)

Use these prompts directly with the AI each day. Format: `Fix A1.1 in [filename]`

### Week 1: Thread Safety & Stability

```
Day 1: "Implement A1.1 — Make g_exploitDone and g_patching_in_progress use _Atomic bool in Tweak.m. Review all reads/writes to ensure they go through atomic operations."

Day 2: "Implement A1.2 — Audit every kread64/kwrite64 call in kexploit/, sandbox_escape.m, SSVUtils.m, and permission_utils.m for missing xpaci() or kread_ptr() on PAC devices."

Day 3: "Implement A1.3 — Add null-pointer safety to borrow_sandbox_ext() in sandbox.m. Extend to try multiple daemons: cfprefsd, securityd, notifyd."

Day 4: "Implement A1.10 — Add pthread_mutex_t to TweakLog() in utils/tweak_log.h for thread-safe file appending."

Day 5: "Implement A1.4 — Fix minizip validation in Tweak.m: check all 13 function pointers, not just 2. Log which ones are missing."
```

### Week 2: Filza Compatibility

```
Day 1: "Implement A2.2 — In FilzaPadlockBypass.xm, add %ctor class existence checks for all hooked classes. Log missing classes."

Day 2: "Implement A2.1 — Research Filza 4.0.2 vs 4.0.0 class differences. Document what changed and why it crashes."

Day 3: "Implement A3.1 — Add crash detection and automatic disable after 3 consecutive kernel panics."

Day 4: "Implement A1.5 — Add max iteration guard to vnode_get_child_vnode() infinite loop."

Day 5: "Implement A3.4 — Add read-back verification to physical_oob_write_mo()."
```

### Week 3: Feature Additions

```
Day 1: "Implement B1.1 — Add multi-app support to FilzaApplySandboxExt.plist. Guard Filza-specific hooks with isFilzaProcess check."

Day 2: "Implement B1.2 — Create config plist reader at TweakInit. Support: EnabledBundles, RetryAttempts, EnableSSV, LogLevel."

Day 3: "Implement B2.1 — Add runtime disable toggle via .filza_tweak_disable flag file. Check in every hook + runExploit."

Day 4: "Implement B4.2 — Export all kernel offsets as JSON after offsets_init() completes."

Day 5: "Implement B4.4 — Display system info panel: iOS version, device, CPU family, kernel base, exploit success rate."
```

### Week 4: Bug Bounty Research

```
Day 1: "Research C2.1 — TCC bypass via kernel-level TCC.db modification. Write a proof of concept that grants camera access without user consent."

Day 2: "Research C2.3 — AMFI bypass via kernel memory write. Can we set P_AMFI_DISABLED flag for our process?"

Day 3: "Research C2.7 — Find a KASLR info leak. Audit /proc, sysctl, and IOSurface for kernel pointer exposure."

Day 4: "Research C1.2 — Document the physical_oob_read_mo race window as an info leak primitive. Write a clean PoC."

Day 5: "Research C2.4 — Kernel ROP chain building. Find a gadget in the kernelcache that gives us code execution from kernel R/W."
```

### Week 5+: Device Matrix Testing

```
Day 1: "Implement D2.2 — Write a regression test script that validates sandbox escape + SSV write after exploit."

Day 2: "Implement E1.1 — Prepare for iOS 26.1: write a script that compares XPF output between 26.0.1 and 26.1 kernelcaches."

Day 3: "Implement D1.1 — Split Tweak.m into TweakHooks.m + TweakExploit.m + TweakDiagnostics.m + TweakUI.m."

Day 4: "Implement B3.4 — TCC database viewer: read /private/var/mobile/Library/TCC/TCC.db and display in a table."

Day 5: "Research C3.2 — iCloud Keychain exfiltration: locate keychain daemon, read decryption keys from its memory, decrypt keychain.db entries."
```

---

# SECTION F: New Exploit Techniques (inspired by kfd, TrollStore, opainject)

## F1 — PUAF as Fallback Exploit

- [ ] `F1.1` ⚪ — Study kfd's PhysPuppet (CVE-2023-23536, $52.5K) for A12-A15 fallback  
  _Prompt:_ "Read felix-pb/kfd/writeups/physpuppet.md. The exploitation is through IOSurface manipulation. Can we implement physpuppet as a fallback if pe_v1 fails? Our codebase already has IOSurface framework linked. Write a puaf_physpuppet.c file that fits into our kexploit/ directory."

- [ ] `F1.2` ⚪ — Study kfd's Landa (CVE-2023-41974, $70K) — reachable from App Sandbox  
  _Prompt:_ "Read felix-pb/kfd/writeups/landa.md. Landa uses a vulnerability in IOSurface event handling. Check if this was fixed in iOS 17.0. If our target is 17.0+, it's patched — but the writeup is valuable for understanding PUAF primitives."

- [ ] `F1.3` ⚪ — Implement `kopen()`-style clean API for our exploit  
  _Prompt:_ "Refactor kexploit_opa334() to match kfd's clean API: kopen(puaf_pages, puaf_method, kread_method, kwrite_method). Hide the complexity behind a function that returns success/failure. This makes the exploit reusable for other projects."

- [ ] `F1.4` ⚪ — Write detailed DarkSword writeup (like kfd's writeups/)  
  _Prompt:_ "Write a dark-sword.md document explaining: (1) ICMPv6 socket spray technique, (2) physical OOB read/write via IOSurface, (3) how the race between pwritev and mach_vm_map creates the primitive, (4) how socket PCB corruption enables kernel R/W. Use kfd's writeup style as reference. Include diagrams."

## F2 — Cross-Process Injection (opainject-style)

- [ ] `F2.1` ⚪ — Extract sandbox_escape into standalone dylib injectable into any process  
  _Prompt:_ "Study opa334/opainject — it uses ROP chains to call dlopen() in a remote process. Can we build a standalone dylib that: (1) achieves kernel R/W via DarkSword, (2) walks the target process's sandbox extension table, (3) patches it to '/'. Make it work WITHOUT MobileSubstrate (just as a dylib you inject)."

- [ ] `F2.2` ⚪ — Implement ROP-based dylib injection for iOS 26  
  _Prompt:_ "opainject's ROP method (rop_inject.m) constructs a ROP chain on the target thread's stack. Study the gadget finding technique. Can we use our kernel R/W to find gadgets in the kernelcache instead of userspace? This would bypass PAC on arm64e."

- [ ] `F2.3` ⚪ — Inject into a system daemon to get CS_PLATFORMIZED  
  _Prompt:_ "TrollStore notes that `CS_PLATFORMIZED` is needed for tweak injection into system processes. With kernel R/W, can we set the flag on our process or disable the check? Research: proc.p_flag CS_PLATFORMIZED bit position, AMFI trust cache structure."

## F3 — Standalone App (TrollStore-style)

- [ ] `F3.1` ⚪ — Package the exploit as a standalone .ipa installable via TrollStore  
  _Prompt:_ "Build a minimal SwiftUI app (like kfd's ContentView.swift) that has a single button: 'Exploit'. When pressed, it runs kexploit_opa334() → sandbox_escape() → displays a file browser. Bundle as .ipa, sign with ldid, test with TrollStore."

- [ ] `F3.2` ⚪ — Add arbitrary entitlements via TrollStore's ldid signing  
  _Prompt:_ "Research TrollStore's entitlement injection: it signs binaries with ldid -S<entitlements.plist> preserving custom entitlements. What entitlements would a standalone kernel exploit app need? com.apple.private.security.no-sandbox? task_for_pid-allow? IOKit access?"

- [ ] `F3.3` ⚪ — Implement persistence: re-exploit on app launch  
  _Prompt:_ "Unlike the tweak (which loads with Filza), a standalone app must re-run the exploit on each launch. Add a fast path: if /var/mobile/.sbx_check is writable (sandbox already escaped from a previous run), skip the exploit and just re-enable SSV. Store kernel slide across launches."

## F4 — MTE Bypass Research (iPhone 17+)

- [ ] `F4.1` ⚪ — Research MTE tag generation in iOS 26 kernel  
  _Prompt:_ "iPhone 17 and M5 iPads have MTE (Memory Tagging Extension) which tags all heap allocations with 4-bit tags stored in the top byte of pointers. Our exploit relies on heap spraying (fake kernel objects) — MTE breaks this because object tags won't match. Research: How does XNU select MTE tags? Is the tag deterministic? Can we leak the tag seed from a kernel info leak?"

- [ ] `F4.2` ⚪ — Check if kfd has any MTE workarounds  
  _Prompt:_ "Search felix-pb/kfd issues and commits for MTE discussion. Does kfd work on M2/M3 Macs with MTE enabled? If so, what technique do they use? Adapt to iOS."

- [ ] `F4.3` ⚪ — MTE tag oracle: find a kernel path that returns allocated heap tags  
  _Prompt:_ "If we can find any kernel API that returns allocated object pointers to userspace (retain/release pattern, zone statistics, mach port names), we can extract the tag bits and predict future allocations. Search for: kernel pointers leaked via sysctl, proc_info, or IOKit registry properties."

---

# SECTION G: Other App Targets (Beyond Filza)

## G1 — File Managers

- [ ] `G1.1` 🟡 — Add Santander file manager support  
  _Prompt:_ "Santander (open source iOS file manager) uses different classes than Filza. Reverse-engineer its file browsing controller. Add hooks for its equivalent of NZFileBrowserController. The sandbox escape + SSV bypass should work identically."

- [ ] `G1.2` 🟡 — Add iFile support  
  _Prompt:_ "iFile was the classic jailbreak file manager. Check if it still compiles for iOS 17+. If so, add hooks for its file operation classes. May need different root helper bypass logic."

## G2 — System Apps

- [ ] `G2.1` ⚪ — Inject into Safari for WebContent sandbox escape  
  _Prompt:_ "Safari's renderer runs in the WebContent sandbox (tighter than App Sandbox — no file access, no IOKit). Can DarkSword's ICMPv6 spray work from WebContent? kfd's Smith method works from WebContent. Test: can we create sockets from WebContent sandbox?"

- [ ] `G2.2` ⚪ — Inject into SpringBoard for system-wide access  
  _Prompt:_ "SpringBoard runs as root with full platformization. If we can inject our dylib into SpringBoard (via jailbreak or exploit), the kernel R/W already gives us everything. The sandbox escape is unnecessary for SpringBoard."

- [ ] `G2.3` ⚪ — Inject into installd for permanent IPA sideloading  
  _Prompt:_ "installd is the daemon that installs IPAs. With kernel R/W from a process injected into installd, we could bypass code signature checks completely. This is like having TrollStore with kernel privileges."

## G3 — Terminal / Shell

- [ ] `G3.1` 🟡 — Test with NewTerm / MobileTerminal  
  _Prompt:_ "If kernel R/W is achieved from a terminal emulator, can we call system() or posix_spawn() with full filesystem access? The sandbox escape should make /bin/sh accessible. Test: run 'ls /System/Library' after exploit."

- [ ] `G3.2` 🟡 — Embedded SSH server in the tweak  
  _Prompt:_ "Bundle dropbear SSH server. After sandbox escape, spawn it on port 2222. Connect from any machine. This gives remote root shell via Filza acting as a trojan."

---

# SECTION H: Architecture & Writing

## H1 — Writeup Documentation (kfd-style)

- [x] `H1.1` ⚪ — Write dark-sword-technique.md  
  _Prompt:_ "Follow kfd's writeup format: (1) abstract, (2) vulnerability description, (3) primitive achieved, (4) exploitation steps with code snippets, (5) Apple's fix. Include the ICMPv6 socket spray technique and the IOSurface physical OOB race window."

- [x] `H1.2` ⚪ — Write sandbox-extension-patching.md  
  _Prompt:_ "Document: (1) how the kernel stores sandbox extensions (struct layout), (2) how we walk from proc to ext_set, (3) what each field patch does, (4) the borrow_sandbox_ext fallback, (5) how Apple could prevent this (integrity check on sandbox data)."

- [x] `H1.3` ⚪ — Write ssv-bypass-via-vnode.md  
  _Prompt:_ "Document the SSV architecture (APFS snapshots, MNT_RDONLY flag, seal verification). Explain how vnode data pointer swap bypasses all protections. Discuss why this is possible even with SSV enforcement."

## H2 — Knowledge Base

- [x] `H2.1` 🟡 — Create iOS kernel exploitation glossary  
  _Prompt:_ "Write docs/glossary.md defining: PUAF, PPL, KTRR, SPTM, MTE, PAC, SMR, AP, SEP, KASLR, DART, SMMU, IOMMU, AMFI, TCC, SIP, SSV, APFS fsnode. Each entry should be 2-3 sentences with a 'why it matters' note."

- [x] `H2.2` 🟡 — Create offset resolution guide  
  _Prompt:_ "Document how to find new kernel struct offsets: (1) get kernelcache from device, (2) decompress with XPF decompress.c, (3) run jtool2 --analyze, (4) use IDA/Ghidra to find struct access patterns, (5) verify against KDK struct dump. Include example walkthrough for one offset."

- [x] `H2.3` 🟡 — Create a 'how to add a new device/iOS version' checklist  
  _Prompt:_ "Step-by-step: 1) get kernelcache, 2) run offsets_init locally with print debugging, 3) find which offsets changed, 4) add new block in offsets.m, 5) test on device, 6) commit with device name + iOS version in commit message."

---

# SECTION I: External References & Research Materials

## I1 — Must-Read Repos

| Repo | Stars | Key Takeaway |
|------|-------|-------------|
| [felix-pb/kfd](https://github.com/felix-pb/kfd) | 1K | PUAF primitive, clean API, detailed writeups |
| [opa334/TrollStore](https://github.com/opa334/TrollStore) | 21.9K | CoreTrust AMFI bypass, permasigned IPAs, arbitrary entitlements |
| [opa334/opainject](https://github.com/opa334/opainject) | 272 | ROP-based dylib injection into remote processes |
| [opa334/Dopamine](https://github.com/opa334/Dopamine) | — | Modern jailbreak for iOS 15-16 using kfd |
| [opa334/XPF](https://github.com/opa334/XPF) | — | Kernel offset finder (already integrated in our project) |
| [34306/FilzaJailedDS](https://github.com/34306/FilzaJailedDS) | — | Original repo this project was forked from |

## I2 — Key CVEs in This Space

| CVE | Name | Bounty | Technique |
|-----|------|--------|-----------|
| CVE-2023-23536 | PhysPuppet | $52,500 | IOSurface dangling PTEs |
| CVE-2023-32434 | Smith | — | WebContent-reachable PUAF |
| CVE-2023-41974 | Landa | $70,000 | IOSurface event handling UAF |
| CVE-2022-46689 | MacDirtyCow | — | Kernel write via page table manipulation |
| — | CoreTrust #1 | — | First AMFI multiple-signers bug |
| — | CoreTrust #2 | — | Second AMFI bug (TrollStore 2.0) |
| DarkSword | (unnamed) | Not submitted | ICMPv6 + IOSurface socket corruption → kernel R/W |

---

# SECTION J: W0lfSword-Beta — iOS Exploit Menu

> **W0lfSword-Beta was fully merged into the main `W0lfSword` script
> (2026-08-10); the legacy `W0lfSword-Beta` stub file was removed in the
> 2026-08-14 cleanup. Items below are the Beta work log, all implemented in
> the merged script.

## J1 — Interactive Menu (no-args mode)

- [x] `J1.1` 🟠 — Main menu: arctic wolf theme, numbered menu, spinner, verbose mode  
  _Done 2026-08-10: checkra1n-style ╔═╗ header, 8-option menu with dim subtitles, 0.5s spinner on every action, -v/--verbose flag, `W0lfSword ▸` prompt._

- [x] `J1.2` 🟠 — Quick Exploit — one-button exploit chain  
  _Done: 4-stage progress (Build → Deploy → Wait → Verify), dot animation during device wait, ╔══ SUCCESS ══╗ box on escape confirmed, auto-log success/fail to history.json._

- [x] `J1.3` 🟡 — Configure menu (basic: via profile save/load)  
  _Done 2026-08-10: profile save captures current device/target/retry settings, profile load restores. Full interactive configure wizard still pending._

## J2 — Profile System

- [x] `J2.1` 🟠 — Save/load exploit profiles (JSON in .w0lfsword/profiles/)  
  _Done: cmd_profile save|load|list with JSON storage, active profile tracking._

- [x] `J2.2` 🟡 — Profile list with colored status  
  _Done: table with * active marker, device IP, saved date._

- [ ] `J2.3` 🟢 — Auto-detect profile on startup  
  _Prompt:_ "On launch, check .w0lfsword/profiles/ for a 'default' profile. If found, auto-load it."

## J3 — Device Manager

- [x] `J3.1` 🟠 — Multi-device management  
  _Done: cmd_device add|list|switch with ping-based online/offline status._

- [x] `J3.2` 🟡 — Device info: iOS version, model, kernel version  
  _Done: cmd_device info SSHs to device, shows sw_vers + sysctl hw.machine + kern.osversion._

## J4 — Live Exploit Monitoring

- [x] `J4.1` 🟠 — Real-time log monitor with exploit state detection  
  _Done: cmd_monitor tails /tmp/FilzaTweak.log via SSH, color-codes lines (▓ success, ✗ error, ▸ retry, ✓ escaped)._

- [x] `J4.2` 🟡 — Exploit stage progress bar  
  _Done: cmd_quick shows [1/4]...[4/4] stages with in-place dot animation._

## J5 — Exploit History & Stats

- [x] `J5.1` 🟡 — Exploit attempt logger  
  _Done: cmd_quick writes {timestamp, device, result} to history.json on every run._

- [x] `J5.2` 🟢 — Success rate dashboard  
  _Done: cmd_history stats shows attempts/success/fail/rate with █░ ASCII bar chart._

## J6 — Original W0lfSword Commands (all preserved)

- [x] `J6.1` 🟠 — Route all original W0lfSword commands through W0lfSword-Beta  
  _Done: all 12 commands (build, extract, deploy, status, audit, log, toggle, offsets, targets, clean, doctor, help) are fully reimplemented in W0lfSword-Beta._

- [x] `J6.2` 🟡 — Add --json flag to status/audit/offsets for machine-readable output
  _Done 2026-08-24: `--json` flag parsed in main() (any command position); status emits {version, git, roadmap, device, exploit_methods, offset_blocks}; audit emits {files[], issues, passed}; offsets emits {version_blocks[], soc_coverage, total_blocks}. Pure bash→python3 json.dumps, no deps._

- [x] `J6.4` 🟡 — Panic log analyzer: `panic analyze` classifies .ips/panic logs (kernel/SEP/MTE/userspace) and maps to known CVEs + BB-032..037
  _Done 2026-08-24: scripts/panic_analyzer.py (pure stdlib) — rules for SEP exhaustion (0x0006fe9x/0x6fea7), AppleJPEGDriver UAF (CVE-2026-20687), DirtySlide (CVE-2026-43724), DarkSword class (CVE-2025-43520), EXR (CVE-2026-28990), MCM activity. CLI: `panic list|fetch [ip]|analyze <file>` (menu `p`)._

- [x] `J6.5` 🟢 — Kernelcache diff: offline XPF offset research (K4.1 automation) — resolve/diff kernelcaches, extract from IPSW
  _Done 2026-08-24: `kernelcache resolve|diff|extract` (menu `k`) — runs tools/xpf-cli on IMG4 kernelcaches (no device), scripts/xpf_diff.py compares resolved tables (identical/changed/one-sided), extract pulls kernelcache.release.* from an IPSW zip with auto board detection._

## J7 — Polish

- [x] `J7.1` 🟢 — Arctic wolf ASCII art + themed header  
  _Done: show_header() with ╔═╗ box, arctic palette consistent with main W0lfSword._

- [ ] `J7.2` 🟢 — Sound on exploit success (optional, macOS only)

- [ ] `J7.3` 🟢 — Colored diff output comparing builds

## J8 — Beta UX (newly added 2026-08-10)

- [ ] `J8.1` 🟡 — Clear screen on menu entry / re-draw support  
  _The `draw_menu()` function calls `clear` but on some terminals this causes flicker. Switch to `tput` or ANSI cursor-home for smoother redraw._

- [ ] `J8.2` 🟢 — Default profile auto-load on startup  
  _Check for `default` profile in .w0lfsword/profiles/ and load it automatically if present._

- [ ] `J8.3` 🟢 — Verbose mode remembers state across menu sessions  
  _Currently -v only works on direct commands, not in the interactive menu. Add a `:verbose` toggle command in the menu._

- [ ] `J8.4` 🟢 — ASCII progress bar during Quick Exploit wait period  
  _Replace the 10 dots with a smooth filling bar: [▓▓▓▓░░░░░░] 40%._

- [ ] `J8.5` 🟢 — Exploit profile: per-app target selection  
  _Allow profile to specify target bundle ID, so different profiles can target different Filza versions (Filza vs Filza000)._

- [ ] `J8.6` 🟢 — Color-coded diff subcommand  
  _`./W0lfSword-Beta diff` shows uncommitted changes with syntax-aware coloring for .m/.xm/.h files._

---

# SECTION K: Exploit Menu & Beginner-Friendly Reform (added 2026-08-13)

> **Goal:** Turn the `./W0lfSword` CLI from a Filza-only tool into a true exploit
> menu — pick an exploit, pick a target app, guided from first launch to success.
> At the same time, make every command understandable to someone who has never
> read the source.

## K1 — Exploit Menu (multi-exploit selection)

- [x] `K1.1` 🟠 — Plain-English disclaimers in every device command (Filza prerequisite, jailbreak requirement, non-persistence)  
  _Done 2026-08-13: new `disclaimer()` helper + notes in deploy, quick, adderall, safe, toggle, reboot, setup, first-run welcome, help._

- [x] `K1.2` 🟡 — Filza presence check in `adderall` Phase 1  
  _Done 2026-08-13: SSH check for Filza.app in /var/containers/Bundle/Application and /Applications, friendly warning if missing (USB-only = informational note)._

- [x] `K1.3` 🟢 — `help` shows a "What You Need First" requirements block  
  _Done 2026-08-13: jailbreak, Filza installed, OpenSSH, build tools — in plain English._

- [x] `K1.4` 🟢 — Adderall success screen lists "what you can do now" in Filza  
  _Done 2026-08-13: full filesystem access, sealed-volume writes, chown/chmod, hide/unhide, padlock bypass — plus persistence reminder._

- [x] `K1.5` 🟠 — Add an `exploits` subcommand listing available techniques + support matrix  \
  _Done 2026-08-21: `cmd_exploits` — full technique matrix (DarkSword pe_v1/pe_v2, kfd PhysPuppet/Smith/Landa, checkm8, AppleJPEGDriver UAF, dyld slide, EXR ImageIO, SEP exhaustion) with iOS range / SoC / bug class / status. Wired to `./W0lfSword exploits` (+ `e` shortcut) and menu option 8 (Targets & Exploits)._
- [x] `K1.5b` 🟠 — Panic-PoC deploy commands (`poc` lab)  \
  _Done 2026-08-21: `./W0lfSword poc list|sep-panic|exr|applejpeg|dirtyslide` — builds sep_panic via Theos (pocs/sep_panic/), generates the CVE-2026-28990 EXR trigger (pocs/exr/gen_exr_trigger.py, stdlib-only, byte-identical to zygosec's), deploys over SSH, arms the crash-monitor, gates every run behind a confirm prompt. applejpeg/dirtyslide print the macOS+Xcode manual flow. See research/moreprojects_deep_dive.md._

- [ ] `K1.6` 🟠 — Add kfd/PUAF fallback options as menu choices beside DarkSword  
  _Prompt: "Extend adderall Phase 4 exploit prompt to accept puaf-physpuppet / puaf-smith / puaf-landa in addition to pe_v1/pe_v2/auto. Store in profile JSON. Backend: port kfd primitives (kopen/kread/kwrite) into kexploit/ as fallback engine — see SECTION F1."_

- [ ] `K1.7` 🟡 — Auto-select best exploit per device in adderall  
  _Prompt: "Enhance the DEV_MODEL case statement: A12-A17 → pe_v1, A18 → pe_v2, A10-A11 → puaf fallback, unsupported → warn and offer kernelcache-pull + XPF route."_

- [ ] `K1.8` 🟡 — Menu shows compatibility per exploit and greys out unsupported choices  
  _Prompt: "In the interactive exploit picker, dim options that don't support the connected device's iOS/SoC instead of letting the user pick a guaranteed-to-fail combo."_

- [ ] `K1.9` 🟢 — Expose exploit method in `profile save/load`  
  _Prompt: "cmd_profile save currently hardcodes retry_count 5 and no exploit_method. Add an optional `profile save <name> --exploit pe_v2 --retries 7` flag set and show the values in `profile list`."_

- [ ] `K1.10` ⚪ — Research: checkm8/palera1n bootchain entry as separate menu branch (A11 and below)  
  _Prompt: "Evaluate integrating usbliter8-arctic's PWN DFU + bootchain tooling into the exploit menu as a 'Bootchain' section for checkm8-vulnerable devices."_

- [ ] `K1.11` ⚪ — Research: WebKit exploit chain entry for SSH-less deployment  
  _Prompt: "Investigate a Safari→dylib-injection deployment path (e.g. via opainject ROP injection) so devices without OpenSSH can still receive the tweak. Document feasibility in research/."_

## K2 — Beginner-Friendly Reform

- [x] `K2.1` 🟠 — Add `disclaimer()` helper printing "── In plain English ──" notes in device commands  
  _Done 2026-08-13: helper + global FILZA_NOTE / JAILBREAK_NOTE / PERSIST_NOTE strings used by deploy, quick, adderall, safe, toggle, reboot, setup._

- [x] `K2.2` 🟡 — First-run welcome shows prerequisites (Filza, jailbreak, non-persistence)  
  _Done 2026-08-13: draw_menu first-run block now includes the disclaimer box after "Welcome to W0lfSword!"._

- [x] `K2.3` 🟢 — Restructure README for beginners: what-you-can-do → requirements → quick start  
  _Done 2026-08-13: full README reform — plain-English capability list up top, explicit "what it does NOT do" section, simplified command table._

- [x] `K2.4` 🟡 — Guided first-run wizard instead of raw menu  
  _Done 2026-08-13: first_run_wizard() runs on first menu launch — 3 steps: (1) checks build tools, offers setup, (2) looks for a phone over USB/saved IP, (3) recommends adderall --safe first. Prerequisite disclaimers shown first._

- [x] `K2.5` 🟡 — Add `--explain` flag printing longer plain-English descriptions  
  _Done 2026-08-13: explain_text() catalog covers adderall, deploy, build, quick, safe, toggle, setup, doctor, status, monitor, log, reboot, offsets, help. Available as `./W0lfSword explain <cmd>`, `-x <cmd>` flag, and menu shortcut `x`._

- [x] `K2.6` 🟢 — Label each adderall phase with what/where it runs  
  _Done 2026-08-13: phase headers now say "(on this computer)", "(computer → phone)" etc.; quick/adderall stages tagged with where each step runs (computer vs phone)._

- [x] `K2.7` 🟢 — Translate cryptic errors into actionable advice  
  _Done 2026-08-13: new hint() helper; actionable follow-up lines added after deploy/quick/adderall/safe/toggle/setup errors (SSH, SCP, build, THEOS, no-device, no-IP paths)._

- [x] `K2.8` 🟢 — `status` gains a plain-English readiness checklist  
  _Done 2026-08-13: cmd_status "Deploy Readiness" block: build tools ✓/✗, device online?, offsets coverage, SSH to phone works, Filza installed on phone — each with a one-line fix._

- [ ] `K2.9` 🟡 — Guided full installer: `./W0lfSword install` wizard that handles EVERYTHING  
  _Prompt: "Upgrade cmd_setup into a guided installer. Steps: (1) detect the OS (macOS / Debian / Arch / Fedora) and pick the right package-manager commands, (2) install THEOS + the correct iOS SDK for that platform, (3) install sideloading tooling (libimobiledevice, AltServer/SideStore-style IPA install hints, TrollStore links), (4) optionally download/point to Filza IPA and side-load it, (5) deploy W0lfSword tweak, (6) offer the tweak menu (K3). Show a summary of what WILL be installed before doing anything, and respect --yes. Note: `install` currently aliases cmd_setup (tools only) — this item turns it into the full guided experience."_

- [x] `K2.10` 🟠 — adderall zero-question setup: auto-install deps, auto-pair, USB cable test  
  _Done 2026-08-14: adderall reorganized — Phase 1 auto-installs clang/dpkg/git/python3/libimobiledevice + THEOS with NO prompts (apt/brew/pacman; macOS Xcode CLT gate with dialog note); Phase 2 discovery auto-pairs via idevicepair (TRUST hint); new Phase 3 test_usb_cable() does 10 rapid usbmuxd reads and scores the cable (good/flaky/bad with MFI-cable guidance, blocks USB-only runs on a bad cable); old env-check became Phase 4 informational. macOS no longer requires root (brew refuses root; $SUDO only for /opt/theos). Phases renumbered 1-7._

## K3 — Tweak Menu (choose a tweak from the CLI and install it)

> **Goal:** Inside the main W0lfSword script, pick a tweak (5-icon dock, custom
> icons, hide home bar...) and let the script figure out which exploit applies
> to your device, run it, and install that tweak — like a mini package manager
> powered by exploits instead of a jailbreak.

- [x] `K3.1` 🟠 — Add a `tweaks` subcommand listing the available tweak catalog  
  _Done 2026-08-13: tweaks/catalog.json with 6 seed entries (5-icon dock, custom icons, hide home bar, badge colors, passcode theming, hide dock) each with iOS/SoC range, required exploit, substrate target, status. cmd_tweaks renders a colored table; wired to `./W0lfSword tweaks`, menu shortcut `tw`, help, and explain. Installer backend is K3.2._

- [x] `K3.2` 🟠 — Tweak installer backend: build dylib from template + install via MobileSubstrate  
  _Done 2026-08-14: tweaks/build_tweak.sh generates a Theos project (Makefile, control, Filter.plist → com.apple.springboard) from tweaks/templates/*.xm, builds with FINALPACKAGE=1 DEBUG=0, verifies dylib+plist in the .deb, outputs to tweaks/packages/. W0lfSword `tweaks install <id>` wires it to the deploy pipeline (scp + dpkg + respring). Three templates compile end-to-end (five_icon_dock, hide_home_bar, hide_dock)._

- [x] `K3.3` 🟠 — Auto-pick the right exploit for the connected device before installing a tweak  
  _Done 2026-08-14: shared select_exploit()/soc_family() (also used by adderall now): A12-A16/A17/M1-M4 → pe_v1, A18 → pe_v2, A9-A11 → puaf (refused with "PUAF port pending — K1.6"), unknown → refuse. Installer checks the tweak's required_exploit against the selected method, blocks darksword tweaks on iOS 26.1+ (DarkSword cap), and validates ios_min/max + SoC set before building. Fixed a latent case-pattern bug where iPhone10,* (A11) matched iPhone1[0-6],*._

- [x] `K3.4` 🟡 — Tweak catalog format with compatibility + required capabilities  
  _Done 2026-08-14: tweaks/catalog.json schema v1 — id, name, description, ios_min, ios_max, socs, required_exploit (darksword/puaf/checkm8/userspace), files_modified, dylib_template, substrate_target, status. 6 entries: 3 available (with templates), 3 planned._

- [ ] `K3.5` 🟡 — SpringBoard injection path (excalibur technique) as tweak delivery mechanism  
  _Prompt: "Study referenceforAI/projects/excalibur (Springboard injection TODO list) and kexploit/RemoteCall.m. Implement injecting a dylib into SpringBoard via DarkSword thread hijack, so tweaks can apply without a jailbreak-level substrate."_

- [ ] `K3.6` 🟡 — Implement the 5-icon dock tweak as first catalog entry  
  _Prompt: "Write tweaks/templates/five_icon_dock.xm hooking SBIconListView/ SBRootFolderView to allow 5 icons per dock row (adjust icon layout constraints). Target iOS 17-26, SpringBoard."_

- [ ] `K3.7` 🟢 — Implement custom icon design tweak as second catalog entry  
  _Prompt: "Write tweaks/templates/custom_icons.xm: swap app icon rendering (via Assets.car override or SBIconImageView image provider hook) to load themed icons from /var/mobile/Documents/Icons/<bundleid>.png. Document safe revert."_

- [ ] `K3.8` 🟢 — Feature-parity list vs Mugunghwa + iDevice-Toolkit  
  _Prompt: "From referenceforAI/projects/Mugunghwa (badge colors, home gesture, passcode theming, icon theming) and iDevice-Toolkit (hide dock/home bar/folder backgrounds, custom tweaks), create tweaks/parity.md listing which features W0lfSword's tweak menu should replicate and in what order."_

- [ ] `K3.9` ⚪ — Research CVE-2025-24203 (Ian Beer) as a no-jailbreak tweak install path  
  _Prompt: "Study referenceforAI/projects/iDevice-Toolkit and the CVE-2025-24203 Project Zero issue. Evaluate porting its primitive into kexploit/ as a 'userspace tweak installer' option for devices where DarkSword is unavailable."_

## K4 — iOS 26.1 Sandbox Escape Research (see referenceforAI/SandboxEscape.md)

- [x] `K4.1` 🔴 — Verify 26.1 kernel struct offsets (sandbox, MACF label) vs 26.0.1  \
  _Done 2026-08-14 (offline, kernelcache): pulled iPhone18,1 (T8150) kernelcaches for 26.0.1 (23A355, xnu-12377.2.9) and 26.1 (23B85, xnu-12377.42.6) via ranged IPSW downloads from the Apple CDN. Built a host-side XPF resolver (tools/xpf-cli — Linux shims for xpc/mach-o/compression/CommonCrypto, SIGSEGV-guarded item resolution, SPTM-aware) and diffed all 64 resolvable items. Struct constants IDENTICAL: proc.struct_size 0x748, task.itk_space 0x310, vm_map.pmap 0x40, thread.machine_CpuDatap 0x1a0, nsysent 0x22e — so the offsets.m 26.0.x block applies to 26.1, no new block needed (documented at offsets.m gate). Gate stays CLOSED: DarkSword patched in 26.1; A1.14 kstackptr validation guards the flip when a new primitive lands (K5.6). FLAGGED: XPF task.itk_space=0x310 on T8150 arm64e vs 0x318 in offsets.m (SE3-verified) — possible per-SoC delta, needs on-device confirmation._ \
  _Follow-up 2026-08-24 (SE 2nd gen, A13/t8030): pulled kernelcaches for 17.1 (21B74), 18.4.1 (22E252) and 26.0.1 (23A355) with the new ranged fetcher (scripts/fetch_kernelcache.py — zip64 EOCD + zip64 local-header + multi-placeholder extra fields) and ran xpf-cli on all three. Three-way same-SoC diff (17.1→18.4.1→26.0.1) shows itk_space is per-VERSION, not per-SoC: 0x300 / 0x318 / 0x310 — and the offsets.m 26.0 block had a REAL BUG (said 0x318, kernel resolves 0x310 on both t8030 AND T8150) → FIXED to 0x310. Also: proc.struct_size 0x730→0x740→0x748, nsysent 0x22c→0x22e (stable 18.4.1→26.0.1), machine_CpuDatap 0x148 on 17.x+18.x A13 then UNRESOLVED on 26.x, sptm=0 on all t8030 builds (per-SoC: T8150 has sptm=1). Full table in tools/xpf-cli/README.md._

- [x] `K4.2` 🟠 — Build the ImageIO fuzzing harness (SandboxEscape.md Phase 1)  \
  _Done 2026-08-21: research/imageio_fuzz.sh (full pipeline) + research/imageio_mutate.py (validated DNG/TIFF parser — filters the reference analyzer's garbage-IFD false positives; SOF3 precision whitelist fixed for camera precision=14 — deterministic recipes: SamplesPerPixel, SOF3 components/dims/precision, compression, CVE-43300 combined mismatch, generic flips/truncations; TSV manifest). Run loop snapshots CrashReporter before/after each uiopen to attribute crashes to the exact sample; report dedupes .ips signatures and flags UNIQUE (1x) ones. Wired as `./W0lfSword fuzz` (menu `f`, explain, help). Verified: mutator output re-parsed cleanly by the reference analyzer; pipeline tested end-to-end with a mock device (attribution + signature dedup + UNIQUE flag working). Seeds: hunters dng_images corpus (+ any DNG/HEIF/TIFF via --seeds)._

- [ ] `K4.3` 🟠 — Port bad_query's containermanagerd traversal to iOS 26.1  
  _Prompt: "Study referenceforAI/projects/bad_query. Reproduce the container path traversal on 26.1 hardware (or VMApple), document which mitigations changed since iOS 26.0, and report whether it still grants outside-container writes."_

- [ ] `K4.4` 🟡 — XPC surface audit for file-capable services on 26.1  
  _Prompt: "class-dump private frameworks from the 26.1 dyld cache (assetsd, photosd, filecoordinationd, UserNotificationsServer). List XPC handlers that perform file reads/writes and are reachable from a sandboxed app. Output to research/xpc_surface_26.1.md."_

- [ ] `K4.5` ⚪ — Chain assembly: ImageIO RCE → sandbox escape (SandboxEscape.md Phase 3)  
  _Prompt: "If Phase 1 yields a crash primitive in QuickLook/UserNotifications, escalate: enumerate that process's sandbox extensions, use them for file reads, and document the full chain in research/imageio-sandbox-chain.md using the Glass Cage report as the template."_

- [ ] `K4.6` 🟡 — Wire the userspace escape into W0lfSword as a fallback engine  
  _Prompt: "Add 'userspace' to the EXPLOIT_METHOD enum in adderall and kexploit/. If selected (or kernel exploit fails all retries), run the userspace chain and verify filesystem access before reporting success. Update the exploit menu (K1.5) accordingly."_

- [ ] `K4.7` 🔴 — iOS 26.1: reproduce CVE-2025-46285 (kernel root privesc, integer overflow in 64-bit timestamps)  \
  _Prompt: "iOS 26.2 advisory: 'An app may be able to gain root privileges — integer overflow addressed by adopting 64-bit timestamps' (Alibaba, Kaitao Xie/Xiaolong Bai). This bug is ALIVE on 26.1 (patched in 26.2). Recover the vulnerable syscall/interface by diffing 26.1 vs 26.2 kernelcaches around timestamp handling, write a trigger PoC, then verify privesc. Root from an app = instant sandbox escape + SSV access."_  \
  _Research 2026-08-25: 26.1/26.2 T8110 kcs fetched + XPF-resolved (see Section 0.2 K4.7). Negative: 1e9 conversion helper + callers identical, zero 32-bit multiply sites — fix is a struct/field or non-multiply path. Hardware-gated: needs a 26.1 device._

- [x] `K4.8a` 🔴 — iOS 26.1: point the fuzzer at AppleJPEG decode paths (CVE-2025-43539 campaign)  \
  _Done 2026-08-21 (no hardware needed): `jpeg` strategy in research/imageio_mutate.py — validated JPEG marker scanner (skips stuffed 0x00/RST, no false segments) + structure-aware recipes across the OOB-write families: SOF precision 8↔16 / dims →0,1,0xFFFF / component count 3↔1↔4 / sampling factors / quant table selectors; DQT 8-bit↔16-bit precision + table-id flips; DHT class flip; SOS component mismatch + spectral→63 + approx→0; APP1 EXIF IFD tag flips (endian-aware value bytes via the DNG/TIFF walker); scan-data stuffing-removal desync, mid-scan/scan-start truncation, byte→0xFF; APPn declared-length inflation. `research/gen_jpeg_seed.py` (Pillow) bootstraps 6 codec shapes: baseline 420/444, grayscale, progressive (SOF2), optimized, EXIF. Harness `--strategy jpeg` + magic auto-detect (FFD8). Verified: 29–88 mutations/seed, 307-sample corpus, manifest attribution, PIL cross-decode. Full writeup: research/applejpeg_cve-2025-43539.md._
- [ ] `K4.8` 🔴 — iOS 26.1: reproduce CVE-2025-43539 (AppleJPEG memory corruption) + escalate  \
  _Hardware-gated (fuzzer targeting DONE — K4.8a): on an iOS 26.1 arm64e device run `./W0lfSword fuzz prepare --seeds .w0lfsword/fuzz/seeds --strategy jpeg` → push → run (--wait 8) → collect → report. Extract the minimal trigger from sample_crashes.tsv + manifest, then follow SandboxEscape.md Phase 3 to escalate the corruption (parser-process RCE → that process's sandbox extensions → file reads; Glass Cage report as the template). If a dyld-cache diff of 26.1 vs 26.2 becomes practical, locate the AppleJPEG bounds-check patch sites to guide the campaign._

- [ ] `K4.9` 🟡 — iOS 26.1: study CVE-2025-43518 (spellcheck file-access bypass) + CVE-2025-43537 (Books path handling)  
  _Prompt: "Both fixed in 26.2, both alive on 26.1. 43518: Foundation spellcheck API allowed inappropriate file access (logic bug) — check if it grants read/write beyond the sandbox from an app. 43537: backup restore path handling could modify protected system files. Add both to research/xpc_surface_26.1.md as userspace escape candidates."_

- [x] `K4.10` 🟡 — Port bad_query into W0lfSword as the 26.1+ userspace read-escape module  \
  _Done 2026-08-21: kexploit/bad_query_escape.m + .h — port of Taj C's bad_query on the existing mcm_api bridge (class-13 SystemGroup / class-7 App-Group routes, part 3 + `../../` traversal, consumed sandbox-extension handle with the original error codes -1..-255), `bad_query_release`, `bad_query_list` (fsgetpath enumeration), `bad_query_probe` (targets /var/mobile/Containers/Data/Application + InternalDaemon + PluginKitPlugin + Shared/AppGroup, logs which opened). Wired into safe mode (Tweak.m) + exploit-exhaustion fallback (TweakExploit.m). Refuses cleanly when query_set_part/part_domain symbols are missing. Build verified. Original's "obtain tokens for /var/mobile/Containers/** and TCC.db, verify reads" = the probe targets + `bad_query_escape("/var/mobile/Library/TCC/TCC.db", ...)` on-device._
- [x] `K4.11` 🟠 — Port FilzaSlop's MCM userspace container-access bridge (comparison task)  
  _Done 2026-08-13: analyzed 0xjohnnydev/FilzaSlop v1.0.2 (242★, FilzaJailedDS fork with userspace container escape for iOS 18/26/27b). Ported: kexploit/mcm_bridge.m (dlopen libsystem_containermanager, zero private headers), kexploit/container_access.m (class 2/4/6/7/10/12/13/15 activation, com.apple.lsd LaunchServices store byte-scan app discovery for iOS 26, userspace_container_probe). Wired into safe mode + exploit-exhaustion paths. Clone kept in referenceforAI/projects/FilzaSlop/._

- [x] `K4.12` 🟡 — MobileHouseArrest identity mode: optional re-sign path for pre-exploit container access  \
  _Done 2026-08-21: `make mha IPA=Filza.ipa [OUT=...]` — Makefile MHA_IDENTITY=1 CFLAG (tweak logs the mode at TweakInit) + `mha` target → scripts/re-sign_mha.sh: extracts the IPA, injects the tweak dylib with scripts/add-load-dylib.py (Mach-O LC_LOAD_DYLIB patch, ported from DirtySlide), sets CFBundleIdentifier + CodeDirectory identifier to com.apple.mobile.MobileHouseArrest, ldid re-signs, repackages. CLI wrapper: `./W0lfSword mha <ipa> [out]` (needs ldid). MHA mode is observable via userspace_container_probe() → '[MCM] *** CONTAINER ACCESS ACTIVE'. Injector verified on a real arm64 Mach-O (LC_LOAD_DYLIB present, file intact); prereq gates tested. Docs: BUILD.md._

- [x] `K4.13` 🟡 — Port FilzaSlop's dormant posix_cred root patch (OFF_UCRED_CR_POSIX=0x18, uid/gid groups)  \
  _Done 2026-08-21: `set_root_credentials(ucred)` in sandbox_escape.m — patches ucred+0x18 posix_cred via per-field `kwrite32` read-modify-write (uid/ruid/svuid @ 0x00-0x0B, groups[0] @ 0x10, gid/rgid/svgid/gmuid @ 0x50-0x5B → 0; ngroups, gmuid/flags, and cr_label right after the 0x60-byte struct are NEVER touched — no oversized buffer writes), read-back verified, best-effort (doesn't fail the escape). Called on both sandbox_escape success paths. Logs before/after + ROOT CREDENTIALS ACTIVE. FilzaSlop's layout notes documented in-file. Build + audit verified; DEBUG_TRACKING updated._


  _Prompt: "bad_query's containermanagerd traversal is confirmed working iOS 26.0-26.6.1 + 27.0b4. Port it from referenceforAI/projects/bad_query into kexploit/ (or utils/) as a no-kernel-rw escape stage: obtain extension tokens for /var/mobile/Containers/** and TCC.db, verify reads, log results. Use as the fallback when DarkSword retries are exhausted."_

## K5 — Exploit Chains (recipes to add)

> **Goal:** Catalog every exploit→escape→payload chain we can offer in the
> exploit menu, with each stage's iOS range, so the CLI can auto-select the
> longest viable chain for the connected device.

### The chain matrix

| Chain | Stage 1 (code exec) | Stage 2 (sandbox escape) | Stage 3 (payload) | iOS range | Status |
|-------|---------------------|--------------------------|-------------------|-----------|--------|
| **A — DarkSword** | DarkSword kernel R/W (CVE-2025-43520 TOCTOU) | ext-set patch (`sandbox_escape.m`) | SSV + Filza hooks | 17.0–26.0.1 | **implemented** |
| **B — ImageIO userspace** | NEW ImageIO bug → RCE in parser process | that process's looser sandbox / XPC file ops | Filza-capable file access | target 26.1–26.4.1 | research (K4) |
| **C — WebKit entry** | WebKit RCE (CVE-2024-23222 class) | ImageIO/BlastDoor stage | inject W0lfSword payload | varies | research |
| **D — Bootchain** | checkm8 (A11 and below) | kernel sandbox hooks NOP'd | full jailbreak | 15.6–27.0b | usbliter8-fun2 |
| **E — PUAF fallback** | kfd PhysPuppet/Smith/Landa | ext-set patch (same as A) | SSV + hooks | 16.x only | port pending |
| **F — CoreTrust** | CoreTrust bug → arbitrary entitlements | entitlement-driven app escape | standalone .ipa | needs NEW bug | research |
| **G — 26.1+ kernel** | unpublished/new kernel OOB R/W | ext-set patch (same as A) | SSV + hooks | 26.1+ | needs bug + offsets |

- [x] `K5.1` 🟠 — Document the chain matrix in ROADMAP + SandboxEscape.md  
  _Done 2026-08-13: matrix above, cross-referenced with K4 research phases._

- [x] `K5.2` 🟠 — Chain A (DarkSword → ext-patch → SSV) — the working baseline  
  _Done: implemented end-to-end in kexploit/ + sandbox_escape.m + SSV/, verified 17.0–26.0.1._

- [ ] `K5.3` 🟡 — Chain E: port kfd PUAF primitives as fallback for 16.x devices  
  _Prompt: "Port kfd's PhysPuppet/Smith/Landa into kexploit/ as an alternate kernel R/W provider. After kopen succeeds, reuse the EXISTING sandbox_escape.m unchanged — the escape stage is identical to Chain A."_

- [ ] `K5.4` 🟠 — Chain B stage 1: find a NEW ImageIO bug valid on 26.1/26.4.1  
  _Prompt: "CVE-2025-43300 is patched since 18.6.1 — its value now is the attack pattern (metadata/stream inconsistency). Fuzz RawCamera.bundle (DNG/JPEG-Lossless SOF3), CoreSVG, and HEIF decode paths on 26.1/26.4.1 using the K4.2 harness. Log any unique panic signature."_

- [ ] `K5.5` 🟡 — Build the tweak-based ImageIO trigger testbed  
  _Prompt: "Add an 'imagetrigger' mode to W0lfSword: a small tweak (or Filza hook) that programmatically opens crafted images through the QuickLook/UserNotifications/Files decode paths and records which daemon crashes. This is how we map which parser processes are reachable from a tweak on 26.1."_

- [ ] `K5.6` 🔴 — If any kernel OOB R/W is obtained on 26.1/26.4.1, escape immediately  
  _(Post-v1.0: needs a 26.1+ kernel R/W primitive — see v1.0 scope note in Section 0.2.)_  
  _Prompt: "When a new kernel primitive lands, FIRST re-verify offsets for 26.1+ (K4.1), THEN run the existing ext-set escape — kernel R/W makes sandbox escape nearly free. Don't spend time on userspace chains once a kernel bug exists."_

- [ ] `K5.7` ⚪ — Chain C: WebKit entry for no-SSH/no-jailbreak deployment  
  _Prompt: "Study referenceforAI/projects/CVE-2024-23222-Coruna-Exploit-Kit-Deobfuscated (WASM addrof/fakeobj → PAC bypass → sandbox escape). Evaluate using a WebKit RCE to deploy the W0lfSword payload onto devices without OpenSSH."_

- [ ] `K5.8` ⚪ — Study CVE-2025-55177 chain structure for BlastDoor insights  
  _Prompt: "Read referenceforAI/projects/zero-click-exploit-analysis (paper + patch diffs). Extract exactly how the WhatsApp chain crossed from ImageIO corruption to wider file access, and whether any analogous BlastDoor/thumbnail-provider hop exists on 26.1."_

- [ ] `K5.9` 🟡 — CLI: auto-select the best chain per device in the exploit menu  
  _Prompt: "In cmd_adderall (or the new exploits subcommand, K1.5), implement chain selection: if DarkSword offsets exist → Chain A; else if 16.x → Chain E; else if A11- → Chain D; else if a userspace bug is available for that version → Chain B; else print the matrix and what's missing."_

---

# STATS

| Section | Total Items | Completed | Remaining |
|---------|------------|-----------|-----------|
| A1 — Thread Safety | 14 | 13 | 1 |
| A2 — Filza Compatibility | 11 | 3 | 8 |
| A3 — Kernel Exploit Robustness | 22 | 10 | 12 |
| A5 — SSV & Sandbox Stability | 10 | 4 | 6 |
| A6 — Production Readiness (new) | 21 | 10 | 11 |
| B1 — Multi-App Support | 4 | 0 | 4 |
| B2 — Runtime Control | 3 | 1 | 2 |
| B3 — Power User Features | 7 | 0 | 7 |
| B4 — Developer Features | 4 | 0 | 4 |
| C1 — Kernel Vuln Hunting | 7 | 1 | 6 |
| C2 — Bug Bounty Targets | 8 | 1 | 7 |
| C3 — Attack Chains | 4 | 0 | 4 |
| D1 — Refactoring | 5 | 2 | 3 |
| D2 — Testing | 4 | 0 | 4 |
| D3 — Documentation | 3 | 3 | 0 |
| E1 — Version/Device Expansion | 5 | 0 | 5 |
| F1 — PUAF Fallback | 4 | 0 | 4 |
| F2 — Cross-Process Injection | 3 | 0 | 3 |
| F3 — Standalone App | 3 | 0 | 3 |
| F4 — MTE Bypass | 3 | 0 | 3 |
| G1 — File Managers | 2 | 0 | 2 |
| G2 — System Apps | 3 | 0 | 3 |
| G3 — Terminal / Shell | 2 | 0 | 2 |
| H1 — Writeups | 3 | 3 | 0 |
| H2 — Knowledge Base | 3 | 3 | 0 |
| I1 — Reference Repos | — | — | — |
| I2 — Key CVEs | — | — | — |
| J1 — Interactive Menu | 3 | 3 | 0 |
| J2 — Profile System | 3 | 2 | 1 |
| J3 — Device Manager | 2 | 2 | 0 |
| J4 — Live Monitoring | 2 | 2 | 0 |
| J5 — History & Stats | 2 | 2 | 0 |
| J6 — Original Commands | 2 | 1 | 1 |
| J7 — Polish | 3 | 1 | 2 |
| J8 — Beta UX (new) | 6 | 0 | 6 |
| K1 — Exploit Menu | 11 | 4 | 7 |
| K2 — Beginner-Friendly Reform | 10 | 9 | 1 |
| K3 — Tweak Menu | 9 | 4 | 5 |
| K4 — iOS 26.1 Sandbox Escape Research | 13 | 2 | 11 |
| K5 — Exploit Chains | 9 | 2 | 7 |
| V1 — v1.0 Release | 3 | 3 | 0 |
| **TOTAL** | **236** | **91** | **145** |

---

*Last updated: 2026-08-14 — K4.1 closed: XPF offline diff of 26.0.1 vs 26.1 kernelcaches (tools/xpf-cli) — structs identical, offsets.m 26.0.x block applies; task.itk_space 0x310-vs-0x318 discrepancy flagged for on-device check*
