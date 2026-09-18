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
- [x] `V1.4` 🟡 — **Menu config + boot animation**: `.w0lfsword/config` (key=value, `config` CLI to show/set/edit/reset) controlling animations, anim_speed, show_wolf, menu_compact, device_scan, color, confirm_risky, prompt_symbol, loading_time. Interactive menu opens with the wolf's own characters scrambling (spinner + "loading..."), settling into the real art, then the menu text materializes below with the same scramble cascade (dim → frost → real colors); experimental tab got the same red-wolf scramble + text reveal, its menu entry moved to the bottom of the research group with a [beta] tag (show_wolf=menu default; =loading boot-only, =never hidden). Config-gated spinner, typed "howl later" on quit, red wolf gated in experimental. Version bumped 1.1.0 → 1.2.0.
  _Done 2026-08-30: config system + scramble animations wired, `./W0lfSword config` verified (set/validate/reload/reset), PTY smoke test of wolf scramble → settled wolf → text cascade → menu with wolf → animated quit, experimental red-wolf + text reveal. Audit passes. Bugs found+fixed along the way: config_write_template clobbered config_set's local `k` via bash dynamic scoping (loop var not declared local); draw_menu consumed FIRST_DRAW before the reveal check (captured first)._

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
  _Campaign 2026-08-25 (SE2/A13 on 18.4.1): 307-sample run via uiopen AND imgio_probe (full + thumbnail + metadata paths) plus the CVE-2026-28990 EXR trigger — ZERO crashes, ImageIO 18.4.1 hardened vs the recipes. Extended the same day: TIFF/DNG (112 samples, dng strategy) + raster PNG/GIF/BMP/WebP (311 samples, generic strategy) — ZERO crashes across all four codec families. Live window stays 26.1–26.4.x; re-run `fuzz probe` on 26.x hardware when available (K4.13)._
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
- [x] `K4.14` 🟡 — **kcwatch kernel-delta watcher M1 + M2** (research/kcwatch.md)  \
  _Done 2026-08-25: scripts/kczip.py (zip64 remote range reader: EOCD/zip64 locator, retries, CRC-32 over UNCOMPRESSED data, auto raw-deflate), scripts/kcwatch.py (poll → fetch → resolve → diff → render + offsets.m verdict; --board/--version/--dry-run/--json; KCWATCH_DIR env for feed deployments), CLI `./W0lfSword kcwatch` (menu `w`, 5-place wiring). Validated live on t8030: 26.6 → 26.6.1 (xnu-12377.162.13~2 → .14~4) = 51 identical / 12 symbol shifts / 0 struct moves, verdict YES. xpf_diff.py gained the degraded (resolved↔UNRESOLVED) category. M2: public feed repo **kaffeindecaf/kernel-deltas** live — README, kernel-deltas.md feed, vendored pipeline, committed state, GitHub Actions cron (run validated green)._

## 0.4 — Framework research campaign (2026-08-29, audio + media)

> Full detail in Section C4. Started from the buffer-overflow / decoder
> angle: Apple's audio frameworks (AudioToolbox, CoreAudio, CoreMedia
> audio), then other userspace frameworks. Host-side audits + fuzz where
> possible; hardware-gated parts stay open for later.

- [x] `C4.1` ⚪ — Audio framework attack surface map + CVE catalog
  _Done 2026-08-29: map in research/audio_frameworks.md (AudioToolbox/CoreAudio/CoreMedia entry points, formats, open-source status). CVE catalog merged from NVD/P0 research — see research/audio_frameworks.md + other_frameworks.md._
- [x] `C4.2` ⚪ — Open-source code audit: ALAC decoder, apple-oss-distributions/CoreAudio
  _Done 2026-08-29: apple-oss-distributions has NO CoreAudio (verified via git ls-remote; org = ICU/Libiconv/libxml2/mDNSResponder only). Audited apple/ALAC instead: two ASAN-verified bugs (ALAC partialFrame numSamples heap overflow + Init cookie OOB read) + unbounded bitstream reads. Harnesses in research/alac_poc/._
- [x] `C4.3` ⚪ — Audio fuzz harness (host + SE 18.4.1 probe)
  _Done 2026-08-30 (host side): libFuzzer target over ALACDecoder
  (research/alac_poc/fuzz_alac.cpp, structure-aware mutator on
  partialFrame/numSamples) + encoder-based seed generator
  (gen_seeds.cpp), wired as `./W0lfSword poclab test alac-fuzz [secs]`.
  Finds in 30-60s: unpc_block READ OOB (dp_dec.c:99), dyn_decomp WRITE
  (ag_dec.c:345 = compressed path), BitBufferRead OOB
  (ALACBitUtilities.c:48). On-device probe stays hardware-gated: no
  phone attached this session._
- [x] `C4.4` ⚪ — Other framework targets (CoreMedia/CoreText/PDFKit/libxml2/ICU/mDNSResponder)
  _Done 2026-08-29: research/other_frameworks.md — 8 ranked targets, verified CVE catalog (41 CVEs cited), dyld-cache RE workflow. Top lead: CVE-2025-43400 FontParser OOB write LIVE on the 18.4.1 test device, fix recoverable by diffing libFontParser 18.4.1 vs 18.7.1._
- [x] `C4.5` ⚪ — IPSW userspace extraction feasibility (rootfs DMG encryption)
  _Done 2026-08-29: rootfs DMG is encrypted; kernel-deltas pipeline extracts only the kernelcache (20MB of an 8.45GB IPSW). Userspace frameworks come from the on-device dyld shared cache instead (blacktop/ipsw). No kernel offsets needed for the userspace findings so far._
- [x] `C4.6` ⚪ — Tracker entries for confirmed findings
  _Done 2026-08-29: ALAC heap overflow (ASAN-verified), ALAC cookie OOB read (ASAN-verified), FontParser OOB write live on 18.4.1. Next-steps list extended with the audio probe + FontParser diff plan._

## 0.5 — CVE hunting + attack chains campaign (2026-08-29, 26.1+ direction)

> Full detail in Section C5. Goal: find CVEs across exploit types (kernel
> 26.1+, sandbox escape, TCC bypass, SSV bypass), chain the live bugs into
> usable attack chains, wire the catalog into the W0lfSword CLI.

- [x] `C5.1` ⚪ — Kernel CVE hunt: xnu bugs fixed in iOS 26.1–26.6.x (LPE candidates for a 26.1+ kernel stage, incl. CVE-2025-46285)
  _Done 2026-08-29: research/kernel26_cves.md — full catalog 26.1→26.6.1. Top candidates: DirtySlide (CVE-2026-43724, only public kernel-write PoC), CVE-2026-64747 AVEVideoEncoder (kernel CODE EXEC, live 26.1–26.5.x), CVE-2026-28951 (root LPE, widest window), CVE-2026-20687 (AppleJPEG UAF, public trigger). CVE-2025-46285 confirmed fixed 26.2/18.7.3 → live 26.1 AND 18.4.1._
- [x] `C5.2` ⚪ — Userspace CVE hunt: sandbox escape + TCC bypass + SSV bypass (2025-2026), live-vs-patched on 18.4.1 / 26.x
  _Done 2026-08-29: research/userspace_escapes.md — top finds: CVE-2025-43329 (sandbox escape, LIVE all 18.x, fixed only in 26.0), bl_sbx itunesstored/bookassetd write-escape (ALIVE ≤26.2b1), CVE-2025-14174/43510 (DarkSword kit escape stages), CVE-2026-28973 (libc int overflow escape). No iOS SSV CVEs in 2025-26 (kernel-mediated only)._
- [x] `C5.3` ⚪ — Attack chain designs from live bugs (bad_query / MCM / FontParser / kernel ≤26.0.1)
  _Done 2026-08-29: research/attack_chains.md — 7 chains (A ContainerKey ~75%, B TCC-Key ~55%, C MediaLock ~30%, D Kernel26 ~35%, E SealBreaker ~70%, F GestaltForge novel ~40%, G FontStrike novel ~25%)._
- [x] `C5.4` ⚪ — W0lfSword CLI: `chains` + `cve` commands, exploits matrix update
  _Done 2026-08-29: cmd_chains (7 chains, per-chain stages) + cmd_cve (kernel/userspace/sandbox/tcc/ssv/live filters) wired in 5 places (dispatch, menu, menu_opt n, help, explain). exploits matrix gained bad_query/MCM/ALAC/FontParser/APAC rows. README commands table updated. bash -n + audit pass._
- [x] `C5.5` ⚪ — Documentation: research doc + BUG_BOUNTY entries for confirmed live findings
  _Done 2026-08-29: bl_sbx write-escape (ALIVE ≤26.2b1) + CVE-2025-43329 sandbox escape (LIVE all 18.x)._

## 0.6 — PoC lab campaign (2026-08-29, test the found bugs)

> Full detail in Section C6. Goal: turn the found-but-unimplemented bugs
> into tested proof-of-concepts, document why each works or doesn't on
> this host, and expose them through a new `poclab` CLI tab.

- [x] `C6.1` ⚪ — Re-verify ALAC PoCs end-to-end under ASAN
- [x] `C6.2` ⚪ — libxml2 fork-diff test (apple-oss-distributions vs upstream)
- [x] `C6.3` ⚪ — mDNSResponder Linux build + smoke test
- [x] `C6.4` ⚪ — DirtySlide / bl_sbx / FontParser: why-not-testable analysis
- [x] `C6.5` ⚪ — `poclab` CLI tab (list / test / status)
- [x] `C6.6` ⚪ — research/poclab docs (human style, per-bug explanations)

## 0.7 — Full audit + adderall hardening + experimental (2026-08-29)

> Full detail in the AUDIT section at the bottom. ShellCheck 0.11 pass
> over W0lfSword: 0 warnings/errors left. Fixed this session: the
> criticals. Everything else is listed in the AUDIT section for later.

- [x] `AU.1` — ShellCheck pass (0 warnings/errors), bash -n, py_compile all
- [x] `AU.2` — dead code removed: progress_bar, hline, D, C_MOON
- [x] `AU.3` — critical fixes: cd||exit, SC2155 x4, SC2015 rewrite, run_menu "$@"
- [x] `AU.4` — SoC map corrected: iPhone17,x=A18→pe_v2, iPhone18,x=A19→mte, iPad17,x=M5→mte; MTE/puaf gates in adderall + tweak install
- [x] `AU.5` — adderall: compat matrix + exploit_compat_check warnings, ProductType model detection, env checks (make/curl/unzip/zip/scp)
- [x] `AU.6` — experimental section (red theme, menu ex)
- [x] `AU.7` — non-critical findings → AUDIT section (for later)

## 0.8 — MobileGestalt editing round (2026-09-02, Chain F kernel-route impl)

> GestaltForge (Chain F) flips from "research-only" to implemented on the
> kernel route. The bl_sbx / SparseBoxPlus / Erosion repos landed in
> referenceforAI/Projects/ prove the gestalt cache plist in
> systemgroup.com.apple.mobilegestaltcache/Library/Caches/ is writable
> through iOS 26.2b1 (mobile-owned, edits stick after a respring) — so the
> earlier "gestalt editing not possible on 26.0.1" verdict is overturned:
> the missing piece was the mobile-userland/root write route, which the
> DarkSword escape already provides on the iPhone14,7/26.0.1 Filza Arctic
> path. Implemented as an on-device module + CLI command.

- [x] `MG.1` — on-device module `mobilegestalt/mobilegestalt.m`: cache path
  discovery (26.x + 18.x container names), atomic CacheExtra edits (temp +
  rename, mobile:mobile ownership/mode preserved, fsync + read-back verify),
  known-key catalog + arbitrary raw-key support, rolling backup, backboardd
  respring. Polls `Documents/mg-cmd-*.json`, answers `mg-result-*.json` +
  `mg-state-*.json` (full CacheExtra). Wired into the tweak's 0.5s HUD timer
  (`mg_poll_commands()` in Tweak.m), included in MHA + JB builds.
- [x] `MG.2` — CLI `mobilegestalt` (menu mg): list | status | get | set |
  unset | apply <batch.json> | dump | backup | restore | respring, with
  --type and --respring. USB/AFC transport into the Filza Arctic app
  (non-JB, no SSH) + --ssh <ip> transport for jailbroken devices
  (plistlib pull/edit/push, mobile:mobile chown, killall backboardd).
- [x] `MG.3` — Filza-Arctic.ipa rebuilt with the module (kaffeindecaf
  identity); shipped dylib verified: mg markers present, substrate-free,
  LC_DYLD_INFO_ONLY (no chained fixups). Audit PASSED, shellcheck clean.
- [x] `MG.4` — docs: research/attack_chains.md Chain F status, README
  commands row, DEBUG_TRACKING [MG] layer, referenceforAI/RESEARCH.md
  (6 new repos + verdict).
- [x] `MG.5` — FilzaJailedDS comparison (2026-09-10, "why does MG work
  there and not in our app"): the repo has ZERO MobileGestalt code
  (`grep -rn MobileGestalt` → no hits, no MG strings in its tweak).
  Its MG capability is purely emergent — the same sandbox escape we use
  (ext paths → "/", class com.apple.app-sandbox.read-write, 16 hash
  slots filled) plus a launchd-ucred uid=0 elevate, which together let
  Filza's own file browser and plist editor open and edit
  systemgroup.com.apple.mobilegestaltcache/Library/Caches/com.apple.MobileGestalt.plist
  directly. So there is nothing MG-specific to port. Our app ships the
  same escape (hardened: pointer-range validation) but its MG support
  is a host-driven command channel (Documents/mg-cmd-*.json), not an
  in-app plist UI — expecting to "find" the plist in the app is a
  category error. Practical routes: `./W0lfSword mobilegestalt status |
  dump` over USB/AFC while the app is open (works whether or not the
  escape is live), or browse the path above in Filza once the escape
  stage has completed. If status reports "gestalt cache NOT FOUND"
  (DEBUG_TRACKING line 147) the module never located the container —
  check the escape stage and the container name (26.x cache vs 18.x).
  Base versions match (both Filza 4.0), so the IPA base is not a factor.

## 0.9 — SpringBoard live tweaks round (2026-09-02, TaskRop RemoteCall driver)

> lara (referenceforAI/Projects/lara, AGPL — studied, not copied) lists
> 5 App Dock + live SB tweaks on iOS 17-18.7.1 + 26.0-26.0.1 via
> RemoteCall/TaskRop into the running SpringBoard. The 5-icon dock was
> previously rated not possible on 26.0.1 from our side: the dock column
> count is a live SpringBoard object property (gridSize / layout
> configuration portrait columns), not a gestalt/plist value. The W0lfSword
> tree already shipped the machinery (kexploit/RemoteCall.m, ported from
> darksword-kexploit-fun, dormant since the 2026-08 port session) — the
> missing piece was a driver. On-device verification still required
> (RemoteCall is finicky; no device attached this session).

- [x] `SBT.1` — kexploit/RemoteCall.h/.m: export `remote_call_scratch()`
  (the mmap'd target-process scratch page) so callers can stage remote
  strings. Additive, no behavior change.
- [x] `SBT.2` — sbtweak/sbtweak.m (new): remote ObjC layer on the flat
  RemoteCall API (sel_registerName/objc_getClass/objc_msgSend via
  do_remote_call_stable) + dock column setter (SBIconController ->
  iconManager -> dockListView -> model gridSize + layoutConfiguration
  portrait columns, live re-layout). Fresh implementation over Apple API
  facts — no lara code copied (AGPL). sb-cmd-*.json / sb-result-*.json
  Documents channel, bg queue, status/dock/reset ops.
- [x] `SBT.3` — CLI `sbtweak` (menu sbt): status | dock <1-12> | reset.
  Reuses the mobilegestalt AFC transport helpers.
- [x] `SBT.4` — Filza-Arctic.ipa rebuilt (module verified in shipped
  dylib); audit PASSED, shellcheck clean.
- [x] `SBT.5` — docs: README row, DEBUG_TRACKING [SBT] layer, RESEARCH.md
  lara entry (Section G, when lara analysis lands).

## 0.10 — Staged auto-mode exploit (2026-09-02, main-device safety)

> Filza-Arctic.ipa is the iPhone 14 daily-driver build. Prior behavior: the
> release IPA ran the full chain immediately on every launch. Now the release
> default is STAGED (mode 0): the exploit only reaches the destructive end
> (sandbox escape / cred patch / SSV) after two gates pass, and a failed gate
> is a FINAL verdict with the device left clean — no retry storm.

- [x] `SG.1` — mode semantics: release default 0 = staged auto (test IPA
  default stays 1 = readonly). Runtime override via Documents/w0lf_test_mode:
  1 = readonly-only stop, 2 = writetest-only stop, 3 = full immediate (old
  behavior). CLI help texts updated.
- [x] `SG.2` — stage 0 (cheap readonly manifest): offsets_init fail in staged
  mode returns -6 (nothing touched, no retries) instead of the generic -1
  retry path.
- [x] `SG.3` — stage 1 (deep readonly check): the existing mid-scan PCB
  layout validation (filt/gencnt verified with no kernel writes) becomes a
  PASS log in staged mode and falls through to the single restorable socket
  corruption (mode 1 still stops there).
- [x] `SG.4` — stage 2 (light write probe): post-corruption krw chain +
  bounded kernel-magic walk; on PASS logs and continues the full chain; on
  FAIL restores the socket (restore_corrupted_socket, writetest order:
  neighbor qword then filt pointer) and returns -5.
- [x] `SG.5` — runExploit handles -5/-6 as FINAL verdicts → HUD status 6
  ("compatibility check failed — device left untouched/restored"), no
  retries; -4 (race rejected) unchanged at status 5.
- [x] `SG.6` — Filza-Arctic.ipa rebuilt (all [STAGED] markers verified in the
  shipped dylib), audit PASSED. On-device verification still required: one
  launch on the 26.0.1 daily driver should log stage 1/2 pass → stage 2/2
  pass → escape.

- [ ] `SG.7` 🔴 — **ON-DEVICE FINDING 2026-09-11: the staged path panicked the
  26.0.1 daily driver.** W0lfTerm 0.2 (the standalone terminal .ipa, which
  links the same engine and let the engine's default `wolf_test_mode = 0`
  staged ladder run automatically at launch) was launched on the iPhone14,7 /
  iOS 26.0.1 main device. The phone went dark and stopped enumerating on USB
  (no 05ac:* device, lockdown dead, usbmuxd exited with it); a forced restart
  (vol up, vol down, hold side) brought it straight back, so it was a panic +
  reboot, not a brick. Nothing is written to disk by either build (kernel R/W
  and the extension patch are in-memory), which is why a reset recovers it.
  Open questions, in order:
  1. Which stage died? Read the device's panic log (Settings → Privacy &
     Security → Analytics & Improvements → Analytics Data, newest
     `panic-full-*`), or pull it over USB with `idevicecrashreport -e <dir>`
     once the phone enumerates. The panic string names the subsystem and says
     whether the write probe (stage 2) or the escape/cred patch was at fault.
  2. Did stage 1 (readonly) report pass first, and stage 2/2 fail, or did the
     process never reach a verdict? The tweak/HUD log has the [STAGED] lines
     for the same run only if Filza was the host — W0lfTerm's log is in its own
     container (Documents/FilzaTweak.log, pullable with
     `afcclient --documents com.kaffeindecaf.w0lfterm cat Documents/FilzaTweak.log`).
  3. Does the same run panic on the SE bed (iPhone14,6/SE3, A15) where the race
     is known to land? That separates "staged ladder is broken" from "26.0.1
     offsets/primitive are unproven (K5.6)".
  Until 1-3 are answered: **do not run the staged/writetest/full modes on the
  daily driver.** W0lfTerm 0.4 defaults to no auto-run and readonly mode, and
  prints an explicit warning before any mode that writes kernel memory.

- [ ] `SG.8` 🔴 — **ON-DEVICE FINDING 2026-09-11 (same day, second device):
  the SE bed panicked too, and this time the log names the fault.** W0lfTerm
  0.5 on the iPhone12,8 (SE2, A13/T8030) / iOS 18.4.1 (22E252), user typed
  `exploit`; the SE rebooted and came back on USB in ~20 s. Panic pulled with
  `idevicecrashreport -e` (saved: `~/Desktop/w0lf-crashlogs/se-panic-18.4.1/`):

      panic-full-2026-09-11-173836.0002.ips
      panic(cpu 2 caller 0xfffffff019274fec): zone bound checks: buffer
      0xffffffe0d0254a50 of length 32 overflows object 0xffffffe0d0254a00 of
      size 96 in zone 0xfffffff01b167340[data.kalloc.96] @zalloc.c:1322
      Panicked task 0xffffffe0ce04de30: 5033 pages, 6 threads: pid 544: W0lfTerm

  Reading: the faulting task is OUR app (pid 544 W0lfTerm) and the fault is a
  **32-byte kernel write that started 0x50 bytes into a 96-byte kalloc object
  and ran 16 bytes past its end** — i.e. the fixed-width `early_kwrite32bytes`
  primitive (the only 32-byte writer) wrote past the target allocation, and
  XNU's zone bound check caught it and panicked instead of corrupting silently.
  Two things follow:
  1. The run was NOT readonly. `wolf_test_mode == 1` returns -2 (kexploit
     `#877`) strictly before the socket corruption, with a logged
     "[TEST] READONLY: ... skipping corruption" line, and it performs no
     `kwritebuf` at all. A 32-byte write means the staged/full ladder ran.
  2. The capacity guard added for exactly this overflow (A3.8 in
     `kexploit/sandbox.m`, `bufCapacity = ext.path_len` before the 35-byte
     `kwritebuf(path_buf, new_ext_data, totalLen)`) trusts a struct field as if
     it were the allocation size, and the write primitive makes even a short
     write dangerous: `kwrite_zone_element` RMWs in 32-byte blocks, shifting
     the block backwards to "stay within the zone" — an assumption about the
     object boundary that does not hold when the target is not at the object's
     tail. `path_len`, `data_ptr` and the enclosing object size are all
     reverse-engineered per iOS; 18.4.1 is not a version this path was
     validated on.
  Answer to SG.7 question 3: the same class of run panics on the SE bed where
  the race does land, so this is the write path itself, not only "26.0.1
  offsets are unproven".
  Next, in order:
  1. Pin the exact write. The app logs `[SSV] Path buf: 0x...` and
     `[SSV] Wrote root path + class name (N bytes)` before it; compare the
     logged address with `0xffffffe0d0254a50` to see which chunk (offset 0 or
     the shifted tail) landed there, and whether the panic happened in
     `patch_sandbox_ext` or in the staged socket corruption. Log pull:
     `afcclient --documents com.kaffeindecaf.w0lfterm.J8T95UQMW2 cat
     Documents/FilzaTweak.log` — requires the app to have been launched once
     since the reboot, otherwise house_arrest answers `Permission denied (10)`.
  2. Fix the write path, not the guard: bound every extension write by the
     ORIGINAL string length read from the kernel (`strlen(originalPath) + 1`)
     and refuse the write when the new content is longer; never treat
     `path_len` as a capacity; treat a < 32-byte write as "read 32 bytes
     ending at target+len, RMW, write back" ONLY after proving target+len is
     the allocation end (or add a kalloc-size probe for the object header).
  3. Until then: readonly mode only on both the SE and the daily driver.
     One panic rotated the SE's log set; a second on the daily driver would
     rotate the SG.7 evidence too.

- [ ] `SG.9` 🔴 — **ON-DEVICE FINDING 2026-09-11 (third run, and the log now
  names the stage).** W0lfTerm 0.7 on the SE (18.4.1/A13), user picked
  `staged` and typed `exploit`. Device rebooted; both the app log and the panic
  survived this time (the app log because 0.7 fsyncs it - worth having). App
  log tail before the reboot:

      18:04:55 [+] pcbStartOffset: 0 (filt=0x148 gencnt=0x78)
      18:04:55 [+] inpListNextPointer: 0xffffffdf02ebc400
      18:04:55 [+] icmp6Filter: 0xffffffe0d1ee0640
      18:04:55 [STAGED] stage 1/2 pass — readonly layout validated on-device
               (filt=0x148 gencnt=0x78), zero writes so far; corrupting single socket
      18:05:00 [-] physical_oob_read retry #50 still failing (race not winning)
      (18:06:01 panic, 18:06:29 next boot, banner correctly reports "mode: staged")

  (The `zero writes so far` in that pasted tail is the pre-BUG.5 engine wording,
  kept verbatim here because it is device output. It meant no KERNEL writes - the
  same run pegs a core and dirties ~1 GB of file-backed memory, which is what
  BUG.5 is about. The engine logs `no kernel writes so far` from 0.13 on.)

  Panic: `panic-full-2026-09-11-180601.0002.ips`, identical signature to SG.8 -
  `zone bound checks: buffer 0xffffffe0d1f26550 of length 32 overflows object
  0xffffffe0d1f26500 of size 96 in zone [data.kalloc.96] @zalloc.c:1322`,
  `Panicked task ... pid 586: W0lfTerm`.

  Reading: stage 1/2 (the layout check) passes, then the **write probe**
  (`[STAGED] ... corrupting single socket` -> `physical_oob_write_mo` of the
  corrupted PCB page) runs, and the very next lines are the read-back that
  feeds the restore failing (race not winning, 50+ retries). So the corruption
  was left in a LIVE inpcb whose icmp6 filter pointer the kernel then
  dereferenced/freed. The 32-byte writer is `early_kwrite32bytes` (via
  `kwrite_zone_element`'s shifted RMW), and the object it overran is a
  kalloc.96 - the probe's own restore path (`early_kwrite64` of the saved filt
  pointer) is what walks off the object when the saved offsets do not describe
  the real allocation on this iOS.

  Remediation, in order:
  1. **The restore must be unconditional.** Today the saved values are written
     back only after a successful OOB read-back; when the race loses (exactly
     what the log shows) the corruption stays. Restore on every path, bounded
     retries, and log the outcome either way.
  2. **Never probe with a pointer the kernel dereferences concurrently.** The
     filt pointer is read by the kernel on the next packet/socket operation.
     Probe a field that is inert until WE touch it (`so_usecount`,
     `inp_depend6_chksum` - the full path already writes those) or a scratch
     object we allocated ourselves.
  3. **A kalloc size probe before any write near an object's tail**, or clamp
     `kwrite_zone_element` to refuse a write whose 32-byte block is not provably
     inside the target object (read the zone element header when the address is
     kalloc-backed).
  4. Keep `readonly` the only mode offered on unproven device/iOS pairs; all
     three panics so far (SG.7, SG.8, SG.9) came from a write-capable ladder.

- [ ] `SG.10` 🔴 — **DEVICE EVIDENCE 2026-09-11 (evening): the guards work, and
  the earlier hang has a named cause.** Three separate results from the SE
  (iPhone12,8 / 18.4.1 / A13):

  1. The 18:14 hang ended in a **watchdog panic**, not memory corruption.
     `panic-full-2026-09-11-182740.0002.ips`:
     `userspace watchdog timeout: no successful checkins from SpringBoard
     (2 induced crashes) in 180 seconds` / `Panicked task ... pid 59: watchdogd`.
     Reading: the app's CPU/socket pressure crashed SpringBoard twice, SpringBoard
     stopped checking in, watchdogd panicked the kernel. That is why the side
     button did nothing (it was a panic path, and the phone only came back on a
     forced restart). So SG.8/SG.9's zone-bound panic and SG.10's watchdog panic
     are two DIFFERENT failures: one corrupts memory, the other exhausts resources.
  2. The 19:10 **staged** run ended cleanly on the new budget. App log:
     `[race] stopping the read race (stop requested or 120s budget reached)` ->
     `[scan] stop requested (or 120s budget) at offset 0x1cc4000 - aborting the walk`
     -> `[-] scan stopped on request (cancel or 120s budget)` ->
     `[boot] cancelled - the scan stopped where it was; nothing was left half-done`.
     No panic, no hang, no resource kill; the walk aborted at the offset it had
     reached instead of visiting the rest (the exact reviewer finding fixed in
     0.11). It also never hit ENFILE this time (spray stopped at 26,624 sockets).
  3. New resource axis: `W0lfTerm.diskwrites_resource-2026-09-11-191238.ips`
     (bug_type 145) — `1073.75 MB of file backed memory dirtied over 1083 seconds
     (991.58 KB per second average), exceeding limit of 12.43 KB per second over
     86400 seconds`, action taken: none. i.e. one run used the entire 1 GB/day
     write budget. Contributors: the exploit's own memory pressure (compressor /
     swap of the large sprays and mappings) and the per-line log fsync added for
     panic forensics.
     Fix shipped: the fsync is rate limited to one per 200 ms (a panic loses at
     most 200 ms of lines). Remaining lever: reduce memory pressure — release the
     search mapping and drop the socket spray as soon as the scan ends, and keep
     the 120 s budget as the hard stop.

    T12 closing pass (task 12/12, host only, no device command): that rate limit
    is now a compiled, counted gate instead of a comment. The decision left the
    ObjC-only block of `utils/tweak_log.h` for `utils/tweak_log_policy.c`, which
    the engine archive AND the tweak build both compile - so the file the host
    test drives is the file the device ships - and the sink holds ONE
    process-wide gate (`TweakLog()` is a static function in a header, so a gate
    per translation unit would have multiplied the rate limit by the number of
    files that log). Counter report: `bash
    scripts/run_tweak_log_throttle_host_test.sh` -> `checks=30 failures=0` /
    `TWEAK_LOG_THROTTLE_HOST_TEST PASS` (exit 0). It drives a simulated clock:
    510 ms of lines -> 3 fsyncs at 10, 100, 450 and 5000 line/s alike (the bound
    is the WINDOW, not the line rate); 10,000 lines 1 ms apart -> 50 fsyncs
    against 10,000 for the pre-fix one-fsync-per-line policy (200x fewer); a
    600 s run -> 3000 grants, inside the advertised 3001 (600 s / 200 ms + the
    first line); a backwards clock step grants nothing; the first line always
    flushes; and the pre-fix policy is asserted to VIOLATE the bound, so the
    check is not vacuous. Structural half: `python3
    scripts/check_scan_budget_cancel_writes.py` -> `25 check(s) passed, 0 failed`
    with four new BUG.6 checks (the sink's fsync sits inside the gate's own
    condition, one gate and not one per TU, the policy is in both build lists
    and in the host test, and no OTHER ungated fsync exists in the code the app
    compiles - the archive's sources plus their local headers plus the app's own
    sources, ~100 files), `--selftest` -> `selftest: all mutations caught`
    (21/21; the five new mutations are: the gate dropped from the sink, the gate
    moved into the per-TU header, the policy dropped out of the archive, the
    window set to 0 ms, an ungated fsync added to the app).
    NOT device-verified, and the arithmetic limit stated plainly: the gate bounds
    the fsync CALLS (<= 1 per 200 ms per process); how many bytes one fsync
    flushes is the file's own dirty pages, so the byte half of this report stays
    a device measurement - `idevicecrashreport -e <dir>` diskwrites / CPU /
    wakeup reports for a run with the throttle in place, against the 1073.75 MB
    in 1083 s measured below. The other pressure source this item names (the
    scan dirtying every page of every search mapping, ~30 MB per pass) is
    untouched and is tracked under 0.12 `BUG.2`.
    Note for any future resource work: three resource axes are now known to kill
    this app on device — CPU (90 s/180 s), wakeups (45k/300 s) and disk writes
    (1 GB/day) — and `idevicecrashreport -e <dir>` returns all three reports.
    T18 + landing pass (2026-09-15, host only, no device command): the CPU axis
    has its half now. `free_thread`'s first wait already yielded; the other two
    (`goSync` and the inner `raceSync` spin) were bare `;` hot spins, which is the
    shape this item's own text names, and the userspace watchdog kill is what
    starving SpringBoard looks like from the kernel side. Both now end in
    `pthread_yield_np();` - a yield, not a sleep, so the thread stays runnable and
    the race window's latency is unchanged; what goes away is the wasted cycle on
    a core the main thread needs. Evidence: `THEOS=$HOME/theos make libengine` ->
    `OK: .theos/libengine/libw0lfengine.a` (804K), the host suite green,
    `docs/WORKLOG.md` "T18 + landing pass". NOT device-verified: the CPU (90/180 s)
    and wakeup (45k/300 s) reports for a run with the yields in place are the
    device half, exactly like the fsync throttle's byte half under BUG.6.
    The same pass re-took the six pinned hashes the edit invalidated (the pinned
    suite reported `15 ok, 6 drift`; two of the six were real defects - a
    selftest mutation that had stopped applying since the edit, and a harness
    whose redirected stdout was fully buffered so a `df` child interleaved into
    its own result lines run to run). Both are fixed, not excused: the mutation
    drops the stop-flag half of the first wait (selftest `all mutations caught`,
    19/19) and `tests/trm_shell_host_test.c` line-buffers stdout (canon hash
    identical over three runs). The other four had one cause - the artifact
    hashes of an engine whose code size changed - and are re-pinned with that
    reason written down in `scripts/check_host_verification.sh`, in
    `t17/verify_bug_claims.py` and in the WORKLOG table. Re-captured:
    `WITH_BUILDS=1 bash docs/verification/2026-09-11-0.12/t17/capture.sh` (4/4
    rc=0), suite `16 ok, 0 drift` plain and `21 ok, 0 drift` with builds,
    `claim check: 64 ok, 0 bad`. The HISTORICAL counts (41/65/95) were not
    touched - they reproduce from `replay_revisions.sh`.

## 0.12 — Open bug list (from the 2026-09-11 device day)

> Everything found broken on device, in one place, with the evidence. Fix order
> is the list order. Resource metrics and the failure modes are in `SG.10`.

- [x] `BUG.1` 🔴 — **the staged write probe panics the device.** A 32-byte write
  from `early_kwrite32bytes` (via `kwrite_zone_element`'s backward-shifted RMW)
  lands past the end of a kalloc.96 object → `zalloc.c:1322` zone bound check →
  panic. Twice confirmed (SG.8, SG.9), both times with `Panicked task: W0lfTerm`.
  Fix: (1) restore the saved values unconditionally on every path, not only after
  a successful read-back; (2) probe a field with no concurrent reader
  (`so_usecount` / `inp_depend6_chksum`) or a scratch object we own, never the
  icmp6 filter pointer the kernel dereferences on the next packet; (3) clamp the
  writer so a 32-byte block that is not provably inside the target object is
  refused. Until this lands: readonly is the only mode for any device.
  All three steps are in (steps 2 and 3 below, then step 3b which closes the two
  gaps they left: an undeclared exact-0x20 write - the SE write itself - was still
  emitted, and the probe's/restore's put-back bypassed the clamp entirely).
  Host-verified only; the device run that would confirm it on the SE is the next
  device day, and readonly stays the only mode offered on unproven device/iOS
  pairs until then.

  Step 2 of the fix shipped (engine `kexploit/kexploit_opa334.m`): the staged
  write probe no longer targets `inp_depend6.inp6_icmp6filt`. It probes
  `inp_depend6.inp6_chksum` (`filt+8`, `off_inpcb_inp_depend6_inp6_chksum`) in two
  places: first as a plain page write verified by the OOB read-back, before any
  pointer is written into a live inpcb, then as an end-to-end round trip through
  the krw primitive (`early_kwrite64` / `early_kread64` on the chksum qword the
  alias addresses). `so_usecount` was rejected as the probe field: this tree
  already treats it as a refcount (`offsets.m` names it, and the chain's own
  `krw_sockets_leak_forever` bumps it by `0x0000100100001001`), and a refcount is
  not a free-to-write scalar - its value decides whether the socket goes away.
  `inp6_chksum` is data by this tree's own evidence: the stage-1/2 fingerprint
  (device-confirmed, SG.9) requires the live qword at `filt+8` to be
  `0x0000ffffffffffff` (in6p_cksum -1 + in6p_hops 0xffff), which is not a kernel
  VA at all (`VM_MIN_KERNEL_ADDRESS` = 0xFFFFFFDC00000000), there is no
  `send()`/`recv()` anywhere in `kexploit/`, `terminal/` or `utils/` to consume
  the number, and the full chain already writes that field. The promotion verdict
  is now that round trip plus a value check -
  the alias must read back the stock chksum/hops qword `0x0000ffffffffffff` - and
  not `getsockopt(controlSocket, ICMP6_FILTER) != -1`: that 32-byte read went
  through the freshly written pointer, which is what made a wrong value fatal
  instead of detectable, and "!= -1" accepted a stale pointer too.
  `GETSOCKOPT_READ_LEN` / `getsockoptReadData` are gone with it. The step-1
  save/restore funnel is unchanged and now covers the new exits (probe never
  landed, alias write unconfirmed, krw fds not live, chksum expectation mismatch,
  round-trip failure); the probe also restores its own marker through the
  primitive and reads it back. The icmp6filt write itself stays: it IS the krw
  primitive (see the comment above `find_and_corrupt_socket_probe`), so the probe
  is what had to move off a pointer field. NOT device-verified; step 3 (clamp the
  writer) is still open and the fixed 32-byte block width is the residual risk
  this step does not remove.

  Step 3 of the fix shipped (same day, engine `kexploit/krw_zone_write.c` +
  `kexploit/krw_zone_write.h`, called by `kwrite_zone_element`): the 32-byte block
  writer now decides before it writes anything. With an object declared the whole
  requested range must fit it (`dst + len <= base + size`) - that is the check
  that catches THIS panic, whose block was `0x50..0x70` of a `0x60` object; a
  shifted tail block with NO object declared is refused instead of written; and a
  refusal emits no block at all, so it can never leave a half-applied write in a
  live kernel object. The declaration: `kwrite_zone_element_declared(dst, src,
  len, base, size)` (by value - nothing global is left behind for a later,
  unrelated write) or `kwrite_zone_element_set_object` / `_clear_object` for
  callers that prefer the process-wide window. The one caller that needs the
  shift path is `VM.m`'s `struct vm_map_entry` write (`sizeof` = 0x50, pinned by
  a `_Static_assert` on the tree's own struct - the iOS SDK ships no
  `struct vm_map_entry`, the size comes from the engine toolchain's record
  layout, `[sizeof=80, align=8]`, and `0x50 % 0x20 = 0x10`); it
  now declares its object, so the RemoteCall shmem mapping still patches its
  entry instead of being refused. Verification that actually ran:
  `bash scripts/run_krw_zone_write_host_test.sh` compiles this writer - the same
  file the engine builds - against a fake kernel window and records every block
  emitted. The count that belongs to THIS tree is `checks=116 failures=0` /
  `KRW_ZONE_WRITE_HOST_TEST PASS`, exit 0, captured at
  `docs/verification/2026-09-11-0.12/t17/krw_zone_write.log` (sha256
  `1386b0b6...`; the harness grew with steps 1 and 3b). The `41 checks, 0
  failures` below is HISTORICAL: it is the count of the clamp-only revision of
  the harness as COMMITTED at `HEAD`, not of the working tree, and it is
  reproduced by replaying that revision
  (`t17/revisions/krw_head/build_and_run.log` and the second capture
  `t17/head_replay/build_and_run.log`, both with their sparse source trees
  in-repo). Reading 41 as the current count was the stale-prose error T17
  corrected; the re-run of this pass prints 116, and the 116 include the SE
  write replayed
  (32 bytes at +0x50 of a 0x60 object) and refused with zero blocks emitted, a
  stale declaration that cannot authorise a foreign write, a 4753-combination sweep
  where not one block left the object, and the refusal log line. `make libengine`
  and the W0lfTerm ipa build both pass. NOT device-verified. Remaining risks this
  step does not remove: an exact multiple of 0x20 with no object declared is
  still emitted unproven (refusing those would stop every existing caller, so the
  guard sits where the task put it), and the sibling writers `kwritebuf` /
  `early_kwrite64` (8-byte calls that still emit a whole 32-byte block at the
  address they are given) are outside this guard entirely - if the next device
  panic names a kalloc object again, that is the first place to look.

  Step 1 completed (same day, engine `kexploit/kexploit_opa334.m` plus the new
  `kexploit/probe_restore_policy.c` / `.h`): "every exit funnels through the
  restore helper" was necessary but not sufficient - the helper could not always
  WRITE. It re-opened its fds from the spray tracking array, and pe_v1's release
  funnel (the BUG.2 audit above, same day) empties that array via
  `sockets_release()` before the caller's own restore runs, so the staged -5 exit
  (kernel-base scan exhausted) hit `controlSocketIdx out of range (0 sockets)` ->
  `[STAGED] probe restore FAILED after 0 tries: krw socket not live` and returned
  with the corrupted inpcb still live and NOT ONE saved byte written back: BUG.1,
  one exit later. Both halves of the contract are now a policy the host test
  compiles and drives (probe_restore_policy.c is in the engine archive and in the
  test binary):

    * `probe_exit_action_for(rc)` hands the socket over ONLY for the promotion
      (`KERN_SUCCESS`); every other return - including a code added later -
      restores. The wrapper used to enumerate `rc != KERN_SUCCESS`; the default is
      now the safe direction, so a future exit cannot silently walk away from a
      corrupted object.
    * `probe_restore_fd_source(...)` picks the fds the put-back writes through:
      the spray tracking array when it still holds the pair, else the fds the
      PROMOTION opened for THIS corruption (stamped with the save generation and
      the socket index - `probe_fds_are_live_for()` requires both, so a pair left
      over from an earlier save can never be used to write through a foreign
      socket), else UNREACHABLE, which the helper logs loudly as a failure instead
      of reporting a restore it did not perform.
    * `open_probe_socket_fds()` opens into locals and commits the pair only when
      both opens succeeded, and the promotion verdict uses the same stamp check
      instead of "the globals are non-zero" - zeroing the globals first is what
      made the -5 restore impossible (a pair that was still the right one, gone)
      and a stale pair usable, at the same time.
    * pe_v1 clears `g_test_mo` where it releases that memory object (the restore's
      OOB verify reads through the same right), so the -5 put-back reports "put
      back, unverified: no OOB mapping" after ONE write pair instead of five
      dead-port read races that can never land.

  Verification that actually ran (host, no device, no device command):
  `bash scripts/run_krw_zone_write_host_test.sh` -> `checks=116 failures=0` /
  `KRW_ZONE_WRITE_HOST_TEST PASS`. That is the T17 re-run of 2026-09-11: raw log
  `docs/verification/2026-09-11-0.12/t17/krw_zone_write.log`, sha256
  `1386b0b6e393b4923dc3ad9cd69547b8e9471e78f2c904688b5a09cc3b0ea5be`. The
  intermediate `checks=65 failures=0` this prose used to quote is WITHDRAWN - no
  captured log and no committed revision of the harness produces it; the
  reproducible comparison is 41 (the clamp-only revision at `HEAD`, replayed in
  `t17/head_replay/`) against 116 here, and the delta is this step's 24
  restore-policy checks plus step 3b's 51. Those 24 are
  the restore policy - the promotion is the only hand-off, an exit code the policy
  has never seen still restores, the staged -5 sequence still reaches the pair
  after the array is gone, a generation-stale pair is refused - plus the boundary
  case "a block ending exactly at the object end is allowed, one byte more is
  refused" and the documented BUG.7 residual "an undeclared exact multiple of 0x20
  is still emitted" pinned as the SE overrun it was. `python3
  scripts/check_bug2_release_paths.py` -> `56 check(s) passed, 0 failed`, exit 0
  (`docs/verification/2026-09-11-0.12/t17/suite_logs/w0lf_host_verification/bug2_release_paths.log`;
  the `43` this
  block used to quote has no captured log and is WITHDRAWN. Nine of the checks
  read `probe_restore_policy.c` too). `python3
  scripts/check_bug2_release_paths.py --selftest` mutates TEMP COPIES thirteen ways
  (six of them new, two on the policy file) and requires the lint to fail on each
  -> `selftest: all mutations caught`, exit 0. `THEOS=$HOME/theos make libengine`
  -> `OK: .theos/libengine/libw0lfengine.a (792K, 50 objects)` with a 0-byte
  build log (zero warnings, zero errors; the archive defines
  `_probe_exit_action_for` and `_probe_restore_fd_source`, and
  `kexploit_opa334.o` references them). `clang -fsyntax-only
  kexploit/kexploit_opa334.m` is clean (exit 0, no errors) under both `-DDEBUG`
  and `-DNDEBUG` - and so are `krw.m`, `krw_zone_write.c`, the policy file,
  `VM.m` and `sandbox.m` (same flags, no diagnostics). Both host commands are now
  part of the standing suite: `scripts/regression.sh` gained a "BUG.1 host tests"
  section (host-only, no device command) that runs the writer+restore host test
  and the release-path lint and reports their check counts - verified through all
  three of its paths (in-repo: 2 ok, 65 and 43 checks; scripts absent: 2 skip
  notes; stubbed failing scripts: 2 bad, exit 1). NOT device-verified, and one residual this step does not remove:
  the restore's own put-back still goes through `early_kwrite64`, which is NOT
  routed through the `kwrite_zone_element` clamp - that is BUG.7 (0.13 section),
  and the staged -5 exit is now one more exit that issues those two writes.

  Step 3b (same day, later pass: the residual steps 3 and 1 left): the clamp now COVERS the
  probe, and nothing in the tree writes without a declaration. Three changes:

    * default deny in the writer (`kexploit/krw_zone_write.c`): a call with no
      declared object - or with one that does not contain the target - is refused
      (`KRW_ZONE_REFUSE_UNDECLARED`) and no block is emitted, whatever its length.
      Step 3 only refused the SHIFTED tail block, and the SE write was an exact
      multiple of 0x20 (one full block at +0x50 of a 0x60 object), so the check
      that was supposed to catch it never saw it. Every block of the range is now
      checked before the first byte goes out, and the emit loop re-checks each
      block so a later edit to the loop cannot silently emit an out-of-object one;
    * `krw_zone_write_qword()` / `kwrite_zone_element_qword()` - the qword write
      the probe needs (what `early_kwrite64` does, with the bound check it never
      had), clamped identically. It read-patches-writes the 0x20-ALIGNED block
      containing the qword instead of 32 bytes starting at it, so the block cannot
      straddle two aligned units - which is also why the SE address (+0x50 of a
      0x60 object) is now a legal, in-object write (its block is +0x40..+0x60);
    * the staged writing probe uses it for everything it touches: the promotion
      round trip's marker write and its put-back, the restore's two put-back
      writes (via `probe_kwrite_inpcb_qword`), and the escape path's other inpcb
      write in `krw_sockets_leak_forever`. A refused put-back is reported as the
      failure it is instead of writing through an address nothing verified. The
      window those writes declare is DERIVED from the field offsets, not guessed:
      the runtime `filt` offset + 8 (the qword the probe preserves), rounded up to
      a whole block by `krw_zone_window_for_field_end()` - 0x160 for both layouts
      this tree knows (0x148+8 -> 0x158, and 0x150+8 -> 0x160), and the filt and
      chksum qwords share the aligned block 0x140..0x160 that window covers. It is
      the inpcb's own field span, NOT the kalloc bucket size: reading that needs a
      zone elem_size offset through `inpcbinfo.ipi_zone` (0.13 BUG.7), and
      inventing one is the class of guess that panicked the SE. Address trust
      therefore stays where it already was - the 0.13 canonical-pointer guard plus
      the live-inpcb value check in the round trip; the clamp's job is only that
      no block is ever emitted unproven.

  The one other caller, `kexploit/sandbox.m`'s class-node write, now declares the
  object it knows (`sizeof(struct extension_class_node)` == 0x20 == one block, the
  same structural declaration `VM.m` makes for its `struct vm_map_entry`) and
  skips the bucket if the writer refuses. The two `so_usecount` writes in
  `krw_sockets_leak_forever` deliberately stay on `early_kwrite64`: their object is
  a `struct socket`, and this tree has no field table for it that could state a
  window honestly.

  Verification that actually ran (host, no device, no device command):
  `bash scripts/run_krw_zone_write_host_test.sh` -> `checks=116 failures=0` /
  `KRW_ZONE_WRITE_HOST_TEST PASS`, exit 0 (T17 re-run: raw log
  `docs/verification/2026-09-11-0.12/t17/krw_zone_write.log`; the clamp-only
  revision at `HEAD` is the 41-check one - `t17/head_replay/` - so this step's 51
  new ones sit on top of step 1's 24 restore-policy checks. The intermediate `65`
  this prose used to quote is WITHDRAWN, uncaptured and unreproducible). The 51
  are the default-deny shapes - the SE write itself among them, each asserting no
  block, no RMW read and no changed kernel byte - the undeclared sweep (768
  shapes, not one block), the qword clamp (the SE address allowed with its object
  declared, and refused when the window is undeclared, foreign, or cuts the
  aligned block) and the window arithmetic for both inpcb layouts). `python3
  scripts/check_bug2_release_paths.py` -> `56 check(s) passed, 0 failed`, exit 0
  (`docs/verification/2026-09-11-0.12/t17/suite_logs/w0lf_host_verification/bug2_release_paths.log`;
  the `43 before`
  this block used to quote is WITHDRAWN - uncaptured. The 13 new ones read
  `krw_zone_write.c` and `sandbox.m` too and
  assert the deny branch, the aligned qword RMW, that the probe and the restore
  hold NO `early_kwrite64`/`early_kwrite32bytes` call at all, that both declare
  their window from the field offsets, and that no bare undeclared
  `kwrite_zone_element(` caller is left). `python3
  scripts/check_bug2_release_paths.py --selftest` mutates TEMP COPIES nineteen
  ways (six new: the restore back on `early_kwrite64`, the marker round trip back
  on it, the writer's two deny branches removed, the qword RMW un-aligned,
  sandbox.m back on the undeclared call) and requires the lint to fail on each
  -> `selftest: all mutations caught`, exit 0. `THEOS=$HOME/theos make libengine`
  -> `OK: .theos/libengine/libw0lfengine.a (796K, 50 objects)`, exit 0, 0-byte
  build log (zero warnings, zero errors), and `llvm-nm` shows the archive defines
  `_krw_zone_write_qword`, `_krw_zone_block_align_down`,
  `_krw_zone_window_for_field_end`, `_kwrite_zone_element_qword` with
  `kexploit_opa334.o` referencing them (U) - i.e. the engine really links the new
  path, not just compiles it. `clang -fsyntax-only` (theos SDK, tweak flags) is
  clean (exit 0, no diagnostics) for `krw.m`, `krw_zone_write.c`,
  `kexploit_opa334.m`, `sandbox.m` and `VM.m` under both `-DDEBUG` and
  `-DNDEBUG`. `python3 scripts/test_offsets.py` -> PASS (exit 0), `bash
  scripts/test_chain_select.sh` -> `26 passed, 0 failed` (exit 0), `./W0lfSword
  audit` -> `AUDIT PASSED` (exit 0: shellcheck clean, 178 defs/0 dead, 49 files
  parse). The full `scripts/regression.sh` was NOT run: its "Live device smoke"
  section ssh's to whatever `.w0lfsword/active_device` names, and this task runs
  no device command; the two commands its BUG.1 section wraps were run directly
  (above).
  NOT device-verified, and the limits this step does not remove: the clamp
  verifies a block against the window it is GIVEN, so a caller that declares a
  window derived from an address it never verified still gets a self-consistent
  answer (that is the address-trust half, held by the canonical-pointer guard and
  the value check); the declared window is the field span, not the bucket; and
  BUG.7's other half (a true kalloc size probe, and the `so_usecount` writes)
  stays open in the 0.13 section. The SE's 2026-09-11 write class is closed on the
  host: the exact call (a 0x20 block at +0x50 of a 0x60 object, undeclared) now
  emits nothing.

  T12 closing pass (task 12/12, host only, no device command): all three steps
  re-run on the tree as it stands, plus the whole pinned suite.
  `bash scripts/run_krw_zone_write_host_test.sh` -> `checks=116 failures=0` /
  `KRW_ZONE_WRITE_HOST_TEST PASS` (exit 0) - the clamp, the qword clamp and the
  restore policy in one run, including "staged -5 step 3: the restore is NOT
  unreachable after the spray array was released",
  "staged -5 step 3: it writes the saved values back through the promotion's fds"
  and "a pair opened for an earlier save is refused (no write through a foreign
  socket)". `python3 scripts/check_bug2_release_paths.py` -> `56 check(s) passed,
  0 failed` (exit 0), `--selftest` -> `selftest: all mutations caught` (19/19,
  exit 0). `bash scripts/check_host_verification.sh --with-builds` -> `17 ok,
  0 drift` (exit 0) - every hash this item's prose quotes reproduced byte-for-byte
  after the BUG.6 work changed the engine archive and the app binary; the two
  pinned hashes that legitimately moved are re-pinned with the new values
  (`engine_lib_archive` 263ae60d..., `app_binary` 2922ebb3...), not excused as
  "expected to differ". `THEOS=$HOME/theos make libengine` ->
  `OK: .theos/libengine/libw0lfengine.a (804K, 52 objects)` with a 0-byte build
  log, and `./W0lfSword audit` -> `AUDIT PASSED` (shellcheck clean, 178 defs /
  0 dead, 53 shell+python files parse). Still NOT device-verified: the SE run
  that would confirm the restore on the device is the next device day, and
  readonly stays the only mode offered on unproven device/iOS pairs.

  BUG.1 option 2 (the field choice) now has its own artifact instead of a
  sentence: `scripts/check_pressure_budget.py` asserts, over the archive's
  sources plus their local headers plus the app's sources, that (a) the probe
  body never writes the `inp6_icmp6filt` field - the pointer the kernel
  dereferences on the next packet - and (b) the probe's preserved qword is the
  one at `filtOffset + 8` (the chksum qword, i.e. the field with no concurrent
  reader), and (c) nothing in the compiled sources calls `send` / `sendto` /
  `recv` / `recvfrom` / `sendmsg` / `recvmsg` at all, so no kernel path in this
  process consumes the number the probe writes. Evidence: `python3
  scripts/check_pressure_budget.py` -> `ok BUG.1 probe field: nothing in the
  shipped code consumes the probed qword`, `ok BUG.1 probe field: the probe body
  does not touch the icmp6 filter pointer`, `7 check(s) passed, 0 failed`
  (exit 0); `--selftest` mutates temp copies seven ways - the probe preserving
  the filter pointer instead of the chksum qword, a `send()` added to the
  compiled sources, and five pressure-side mutations - and reports `selftest:
  all mutations caught` (7/7, exit 0). [T17 re-run: the `7 check(s)` / `7/7`
  above are the counts of THAT pass - the checker has 8 checks now (the
  disk-budget one added at T14), and the re-run prints `8 check(s) passed,
  0 failed` with the same two `BUG.1 probe field` lines, raw log
  `t17/suite_logs/w0lf_host_verification/pressure_budget.log`.]
  "Probe a scratch object we own" stays
  unnecessary: the shipped probe never touches a live pointer field it does not
  save and restore, and the `or` in the item is satisfied by the inert-field
  half the checker pins.

  Step 3e (task 13/14, host only): the item's three steps now have an END-TO-END
  host artifact that injects the overrun and then walks the whole probe sequence,
  instead of driving the clamp and the policy one at a time. `tests/
  probe_restore_e2e_host_test.c` + `scripts/run_probe_restore_e2e_host_test.sh`
  compile the SAME two engine files and run, over a fake kernel window: (1) the
  SE overrun (0x20 at +0x50 of a 0x60 kalloc.96 object) refused with zero blocks
  emitted - with a detector check that requires the harness's own out-of-object
  counter to fire on a raw block, so the refusal is measured and not an absence
  of evidence - plus the asymmetry the fix rests on (the 32-byte shape there is
  refused, the qword shape at the same address is allowed because its
  0x20-aligned block is +0x40..+0x60); (2) the restore on the error exit (`-1`,
  write-verify exhaustion) and on the cancel/budget exit (`-7`), for BOTH inpcb
  layouts offsets.m ships, requiring the two saved qwords to be byte-identical
  again (the chksum marker gone), exactly two put-back blocks and none outside
  the declared window; (3) the cancel shape that was BUG.1 one exit later - after
  pe_v1's release funnel emptied the spray tracking array, the restore still
  reaches the pair through the promotion's fds, and with no usable pair it writes
  NOTHING and reports a FAILED restore; (4) the promotion handed over (no
  put-back at all); (5) the clamp covering the restore's own put-back (a
  declaration that is too small, or one that cuts the qword's aligned block, is
  refused with no byte written and the failure reported); (6) the field-derived
  window asserted at 0x160 for both layouts. Evidence: `bash
  scripts/run_probe_restore_e2e_host_test.sh` -> `checks=56 failures=0` /
  `PROBE_RESTORE_E2E_HOST_TEST PASS` (exit 0), sha256 of the raw output
  `62f760e7402071fcb823a7ec5191904e098ac6b520907ef13135ba6fa729cf4b`;
  `python3 scripts/probe_restore_e2e_selftest.py --selftest` -> `selftest: all
  mutations caught` (4/4, exit 0) after mutating TEMP COPIES four ways (the
  clamp's block-end refusal removed, the writer's default deny removed, the
  cancel exit handed off instead of restored, the promotion-fd fallback removed)
  and requiring the harness to fail on each; `bash
  scripts/check_host_verification.sh` -> `16 ok, 0 drift` (exit 0, the two new
  entries added, all fourteen pre-existing pins unmoved); `./W0lfSword audit` ->
  `AUDIT PASSED` (178 defs / 0 dead, 56 files parse). Both new commands are wired
  into `scripts/regression.sh`'s BUG.1 host section (five host results now); the
  section run alone through all three of its paths - in-repo `5 ok` including the
  two new ones, scripts-absent skip notes, and the two new scripts stubbed to
  `exit 1` reported `✗` - is logged in
  `docs/verification/2026-09-11-0.12/t13/regression_bug1_section.{repo,absent,failing}.log`
  (sha256 `7bf73e02...`, `95de928b...`, `f84000b8...`). Raw command lines, outputs
  and hashes are in
  `docs/WORKLOG.md` (T13) with the logs under
  `docs/verification/2026-09-11-0.12/t13/`. Still NOT device-verified: the SE run
  that would confirm the restore on the device is the next device day, and
  readonly stays the only mode offered on unproven device/iOS pairs.

  T15 closing pass (task 15/16, host only, no device command): all three steps
  re-run on the tree as it stands, with the per-case output kept this time.
  `bash docs/verification/2026-09-11-0.12/t15/capture.sh` -> 15/15 commands rc=0,
  and counted off the captured logs themselves -
  `s1_krw_zone_write_host_test: 116 ok, 0 FAIL (of 116)` plus
  `s1_probe_restore_e2e: 56 ok, 0 FAIL (of 56)`, i.e. 172 host cases, 0
  failures; every case line is in
  `docs/verification/2026-09-11-0.12/t15/BUG1-CASES.txt`, and each sub-step is
  mapped to the shipped file:line that implements it in `BUG1-EVIDENCE.txt`
  (step 1 `kexploit_opa334.m:1740` + `probe_restore_policy.c` fail-safe default;
  step 2 `kexploit_opa334.m:1580` chksum qword, pinned by
  `scripts/check_pressure_budget.py`; step 3 `krw_zone_write.c`
  `krw_zone_check_bounds` default-deny + `krw_zone_write_qword`). The SE write is
  refused in both harnesses ("SE write (0x50 into a 0x60 object) is refused",
  "injected overrun (0x20 at +0x50 of 0x60) is REFUSED"), and an INDEPENDENT
  sweep written for this pass (its own monitor, not the project harness) over
  15253 offset/length/object-size combinations around a kalloc.96 object reports
  `allowed=2460 refused=12793 violations=0` / `INDEPENDENT_CLAMP_SWEEP PASS` - so
  the pass is not a clamp that refuses everything. `THEOS=$HOME/theos make
  libengine` -> `OK: .theos/libengine/libw0lfengine.a (804K, 52 objects)`, archive
  sha256 `263ae60d...` (the value `scripts/check_host_verification.sh` pins; `16
  ok, 0 drift`), and `llvm-nm` shows `_krw_zone_write_qword`,
  `_krw_zone_window_for_field_end`, `_kwrite_zone_element_qword`,
  `_probe_exit_action_for` DEFINED with `kexploit_opa334.o` referencing (U) the
  clamped qword writer - the engine links the path, it does not merely compile
  it. Re-running the capture reproduced all seven harness logs byte-identically
  (recorded in `docs/verification/2026-09-11-0.12/t15/MANIFEST.txt`). Still NOT
  device-verified: the SE run that would confirm the restore on hardware is the
  next device day, and readonly stays the only mode offered on unproven
  device/iOS pairs. Residuals this pass does not remove, unchanged from step 3b:
  the clamp checks a block against the window it is GIVEN, so address trust stays
  with the canonical-pointer guard + the live-inpcb value check, and the
  `early_kwrite64` / `so_usecount` callers stay outside it (BUG.7, 0.13).

  T15 re-run (same day, later pass, host only): the same capture was run again
  and the two harnesses' logs came back BYTE-IDENTICAL to the run above
  (`s1_krw_zone_write_host_test.log` sha256 `1386b0b6...` and
  `s1_probe_restore_e2e.log` sha256 `62f760e7...`, each equal to the earlier
  unsuffixed log of the same command - the pairs are listed in `MANIFEST.txt`),
  so the 172/0 is reproducible and not one lucky run. `capture.sh` now prints
  every case with its own PASS/FAIL line (172 lines, 0 FAIL, full stdout kept in
  `t15/capture.out`) instead of counts plus FAIL lines only, and ends on an
  explicit `BUG.1 HOST VERDICT: PASS` whose exit code is the script's own
  (`capture rc=0`). The step-1/2/3 artifact results are unchanged from the run
  above: 15/15 commands rc=0, `host verification: 16 ok, 0 drift`, the BUG.1
  regression section `5 ok, 0 bad`, `INDEPENDENT_CLAMP_SWEEP PASS`
  (15253 shapes, 2460 allowed, 12793 refused, 0 violations), archive
  `263ae60d...` still the pinned value. Still NOT device-verified.

  T17 re-run (task 17/18, host only, no device command): every host harness for
  this item re-run against the working tree as it stands; raw output, the
  changed-file list and a hash of both are in
  `docs/verification/2026-09-11-0.12/t17/` (`capture.sh`, `replay_revisions.sh` and
  `make_manifest.sh` reproduce it, `MANIFEST.txt` hashes every capture,
  `changed_files.sha256` every changed source, `inputs.sha256` the sources the
  harnesses compile, `CLAIMS-RECONCILED.md` is the claim-by-claim table,
  `t17/revisions/krw_head/tree/` - and the same layout under `trm_routea`,
  `trm_trm2`, `trm_trm1` - holds a SPARSE copy of each old harness revision,
  only the paths that harness compiles, ~0.6 MB each instead of a 15 MB
  whole-repo export, so the capture depends on nothing outside the repo, and
  `t17/check_capture_paths.py` asserts that every path cited here exists). All
  exit 0:
  `bash scripts/run_krw_zone_write_host_test.sh` -> `checks=116 failures=0` /
  `KRW_ZONE_WRITE_HOST_TEST PASS` (steps 1 + 3 + 3b in one run, sha256
  `1386b0b6...`); `bash scripts/run_probe_restore_e2e_host_test.sh` ->
  `checks=56 failures=0` / `PROBE_RESTORE_E2E_HOST_TEST PASS` (sha256
  `62f760e7...` - the SE overrun refused, then the `-1` and `-7` exits restored
  end to end); `python3 scripts/probe_restore_e2e_selftest.py --selftest` ->
  `selftest: all mutations caught`; step 2 where it lives - `python3
  scripts/check_pressure_budget.py` -> `8 check(s) passed, 0 failed`, whose two
  `BUG.1 probe field` lines are "nothing in the shipped code consumes the probed
  qword" and "the probe body does not touch the icmp6 filter pointer";
  `python3 scripts/check_bug2_release_paths.py` -> `56 check(s) passed, 0 failed`,
  `--selftest` -> `selftest: all mutations caught`;
  `bash scripts/check_host_verification.sh --with-builds` -> `21 ok, 0 drift`
  (exit 0 - engine archive `263ae60d...`, linked app binary `2922ebb3...`, and the
  app-side symbol/strings entry, each re-pinned to this tree). Claims this pass
  corrected in the item above: `41 checks, 0 failures` is labelled HISTORICAL and
  cited to the replay of the committed `HEAD` revision
  (`t17/revisions/krw_head/build_and_run.log`, `t17/head_replay/build_and_run.log`
  - the committed harness really does print 41), while the current tree's number
  `checks=116 failures=0` is the one captured for this tree; and every `65` and
  `43` count this item used to quote is WITHDRAWN: no captured log and no
  committed revision produces them.
  Re-run after that table was written (same day, host only): the capture was
  taken again and the three anchor hashes came back byte-identical, and
  `t17/verify_bug_claims.py` re-asserts every capture-backed claim of this item
  mechanically -> `claim check: 64 ok, 0 bad` (`t17/verify_bug_claims.log`); the
  one claim it caught as mis-cited was an attribution, not a count - see
  `t17/CLAIMS-RECONCILED.md` section 7.
  Still NOT device-verified - readonly stays the only mode on unproven
  device/iOS pairs.

- [x] `BUG.2` — **memory pressure drives two of the three resource kills.**
  Fixed in `0.13`: pe_v2's cancel path returned before its cleanup and leaked the
  search mapping + memory object + socket spray; the pe_v2 release log read the
  socket count after clearing the array (always 0); the app now releases the
  spray between retry attempts instead of holding ~22k sockets through the 12 s
  settle. REMAINING (needs a technique decision, not a patch): the scan writes
  `randomMarker` into EVERY page of every search mapping (~30 MB mapped and
  dirtied per pass), and the initial spray holds ~22.5k sockets; those two are
  what the compressor swaps out, which is where the 1.07 GB/18 min disk-write
  report comes from. Options: allocate/scan/free the mappings one at a time
  instead of all up front, and/or limit the marker writes to the pages the walk
  actually reads. Measure with `W0lfTerm.diskwrites_resource-*.ips` before/after.

  [Correction, T12: "~30 MB" does not match the source. `scripts/check_pressure_budget.py`
  prints the real numbers per RAM class, and on the 3 GB SE2 class this report came
  from the pass maps `(3GB / 8) / 4096` = 98304 pages = 384 MB as 12 x 32 MB
  mappings - which is also what the engine's own comment on the allocate-failure
  path says ("up to 12 x 32MB per cycle", `kexploit/kexploit_opa334.m:2047-2049`).
  So the 1073.75 MB / 1083 s report should be read against 384 MB per cycle
  (re-dirtied on each of up to 6 spray/race cycles), not against 30 MB, and a
  "mark fewer pages" change has 384 MB per cycle as its headroom. The original
  figure is left in place so the wrong number stays traceable.]

  Release-path audit (task 8, same day, engine `kexploit/kexploit_opa334.m` only):
  every function-level exit of `pe_v1` (8) and `pe_v2` (4) was listed and traced
  BEFORE any code changed, plus the two loop-back paths (`continue` / `goto
  retry_alloc`) and the inline releases inside the walks. Five leaks found, all
  fixed (the fifth, pe_v2's `wiredAddrs` tracker object, in a second pass after
  the first lint was itself audited - see the verification note below); the
  allocation order, the mapping count, the spray size and the technique are
  untouched, and "allocate one mapping at a time" stays a documented OPTION (not
  implemented). Every release now prints one `[cleanup] ...` KPRINTF line, so a
  device log shows each item going away.

  The funnel (one call site per exit):
  `pe_v1_release_cycle()` (sockets; per-mapping surface_munlock +
  mach_vm_deallocate; the A18 wired mapping munlocked on every call, deallocated
  only on a terminal exit because that mapping is allocated once and reused
  across cycles), `release_memory_object()` (the port right, one bounded retry,
  logged either way), `wired_pages_cleanup()` (pe_v2's tracked wired pages) and
  `sockets_release()`.

  What "released exactly once" rests on (structural, not a call-site habit):
  the fileport arrays ARE the record (`sockets_release()` empties both, so a
  second call is a no-op), a search mapping / a wired page is removed from its
  tracking array BEFORE it is touched, `wired_pages_cleanup()` empties the array
  it walks, and `surface_munlock()` is a no-op unless the address is still in
  `gMlockDict` - so munlocking a mapping that was never walked cannot fail or
  double-release. pe_v1 has exactly ONE release site per resource (zero direct
  sockets_release / mach_vm_deallocate / surface_munlock calls left in its body;
  the lint enforces that).

  pe_v1 (returns int: -1 fail, -2 readonly stop, -3 writetest stop, -4 race
  rejected, -7 cancel/budget, 0 success):

  | exit | what it releases | state before the fix |
  | --- | --- | --- |
  | OOB calloc failed (src 1606) | the one buffer that allocated | leaked it |
  | race latched broken, -4 (1628) | funnel, wired mapping included | leaked the A18 wired mapping + both buffers |
  | 6 spray/race cycles exhausted, -1 (1637) | funnel, wired mapping included | same |
  | search-mapping allocate failed (1660) | funnel: this cycle's already-allocated mappings, A18 wired mapping, buffers | leaked up to 12 x 32MB of mappings |
  | spray produced 0 sockets -> continue (1696, funnel 1701) | funnel, wired mapping munlocked and KEPT for the next cycle | released the mappings, never munlocked them |
  | mach_make_memory_entry_64 failed (1733) | funnel: ~22.5k sprayed fileports, every mapping, the walked mappings' surfaces, A18 wired mapping, buffers | leaked all of it (A3.5 had covered pe_v2 only) |
  | memory-object release failed (1834) | port retried once + logged (1825); funnel for the rest | leaked the port AND the whole cycle |
  | end of cycle, -2/-3/-7 (1845 -> 1850) | funnel, wired mapping deallocated (terminal exit) | mappings deallocated, their surfaces never munlocked |
  | success, 0 (1860) | the same funnel + buffers | one leaked IOSurface per mapping walked, buffers leaked |
  | each walked search mapping | its memory object, by `release_memory_object()` (1825) inside the walk | bare mach_port_deallocate whose failure aborted the attempt |
  | each search mapping the walk read (mlock 1735) | surface_munlock() in the funnel (600) | `surface_mlock()` had no munlock anywhere in pe_v1: one leaked IOSurface per mapping per cycle |

  pe_v2 (void; 0.13 had already removed the cancel path's early return):

  | exit | what it releases | state before the fix |
  | --- | --- | --- |
  | OOB calloc failed (1873, exit 1878) | the one buffer that allocated | leaked it |
  | all four sizes failed (1893, exit 1899) | the two buffers | leaked them |
  | wired-page allocate failed (1915) | wired_pages_cleanup() (1945) + smaller size | already correct (A3.5) |
  | search-mapping allocate failed (1972, exit 1977) | wired_pages_cleanup() + wiredAddrs tracker + buffers | buffers AND the tracker leaked |
  | memory-entry make failed (1988, exit 1994) | mapping munlock (1989) + wired_pages_cleanup() (1990) + wiredAddrs tracker + buffers | buffers AND the tracker leaked |
  | found a wired page (2031) | that page munlocked + deallocated inline (2051/2052) | the page was removed from `wiredAddrs` BEFORE the deallocate, so wired_pages_cleanup() never saw it: leaked mlock + IOSurface on the success path |
  | socket limit reached (2081) | sockets_release() (2077) + fresh arrays | correct, now logged |
  | cancel/budget -7, aborted (2012) | memory object (2097), sockets (2101), search mapping munlock + deallocate (2108/2109), then wired_pages_cleanup() (2118) + tracker + buffers | 0.13 stopped the early return, but the mapping's mlock was never released |
  | success | the same chain | same missing munlock |
  | allocFailed -> smaller size (1943 -> goto 1892) | wired_pages_cleanup() (1945) + wiredAddrs tracker | the tracker (up to 4MB of backing store for the 2GB attempt) was leaked, and re-leaked per retry |

  The two pe_v2 exits marked "allocFailed"/"all four sizes failed" are the pattern
  the fifth leak lived in: the array is created with `initWithCapacity:` (524288
  entries at 2GB/4096 = ~4MB of backing store) BEFORE the first wired page is
  attempted, so it is held even when the allocation that made it necessary fails -
  i.e. the leak is largest exactly under the memory pressure this bug is about.

  Release log lines, all KPRINTF so they land in the pullable device log:
  `[cleanup] sockets_release: N sprayed socket fileports released`,
  `[cleanup] wired_pages_cleanup: N wired page(s) munlocked + deallocated`,
  `[cleanup] pe_v1: memory object 0x... released (kr=...)`,
  `[cleanup] pe_v1: search mapping 0x... munlocked + deallocated (kr=...)`,
  `[cleanup] pe_v1: wired mapping 0x... munlocked + deallocated (kr=...)` (or
  `... munlocked (kept for the next cycle)`),
  `[cleanup] pe_v2: search mapping 0x... munlocked + deallocated (kr=...)`,
  `[cleanup] pe_v2: found wired page 0x... munlocked + deallocated (kr=...)`.

  Round 3 (same day, after the reviewer refused the first pass): the three leaks
  the audit FOUND are now FIXED, not documented. The task said "fix any path that
  leaks", and all three are release paths (the fourth resource this item names -
  the socket spray, the search mappings, the memory object, the wired pages - are
  untouched by this round; nothing about the technique or the allocation ORDER
  changed, and "allocate one mapping at a time" is still only a documented option):

  | path | what was leaked | what is released now | evidence |
  | --- | --- | --- | --- |
  | `pe_init()` on attempt 2+ / HUD RERUN (src 618) | a SECOND free thread started on top of the live one, racing the same `FIXED\|OVERWRITE` window | `if (g_freeThreadLive) return;` - the live thread is reused; a new one is created only after the teardown joined the old one | lint check "pe_init: the free thread is created only when none is live"; `KPRINTF("[cleanup] pe_init: free thread already live — reusing it...")` |
  | `initialize_physical_read_write()` on attempt 2+ (src 709) | the previous attempt's OOB mapping (2 pages) + its port right, orphaned by overwriting `pcObject`/`pcAddress` | `release_physical_mapping()` runs FIRST: `mach_port_deallocate(pcObject)` + `mach_vm_deallocate(pcAddress, pcSize)`, both globals cleared | lint check "initialize_physical_read_write: the previous OOB mapping is released first"; 2 `[cleanup] physical mapping ...` log lines |
  | `kexploit_opa334()` early returns -2/-3/-4/-7/-1 (src 2428-2450) | the free thread kept spinning on `raceSync == 0` (hot spin, no yield -> CPU axis) + `readFd`/`writeFd` stayed open | `kexploit_attempt_teardown()` on every one of them: stop flag, `raceSync = 1`, `goSync = 0`, `pthread_join`, `close(readFd/writeFd)`, `g_freeThreadLive = false` | lint check "every exit after pe_init() runs the attempt teardown" (traces all 10 exits; the 2 pre-init ones must NOT call it, and are checked); `[cleanup] kexploit: free thread stopped + joined`, `[cleanup] kexploit: target fds closed` |
  | `kexploit_opa334()` tail (was 4 inline lines, src 2229-2233) | - (was correct) | the same helper, so the success path and the early returns cannot drift apart again | lint check above; the tail's 4 lines are gone |
  | pe_v1 `socketPorts`/`socketPcbIds` (per cycle, src 1667) | the previous cycle's pair: up to 6 pairs of ~22.5k NSNumbers each, alive for the whole attempt | `tracker_arrays_reset()` at the same point in the allocation order; the FUNNEL also calls `tracker_arrays_release()` on every exit | lint checks "the funnel releases the spray-tracking pair", "only created inside tracker_arrays_reset()"; `[cleanup] spray tracking arrays released` |
  | pe_v2 `socketPorts`/`socketPcbIds` (per mapping + the socket-limit reset, src 1997/2243) | the same, per iteration | `tracker_arrays_reset()` at both re-creation sites; `tracker_arrays_release()` at the calloc/all-sizes/search-mapping/memory-entry exits and the tail | lint check "pe_v2: every exit releases the spray-tracking pair" (4 exits) |
  | pe_v1 `searchMappings` (per cycle) | the per-cycle owned array (capacity buffer included) | `[searchMappings release]` in the funnel, after the loop drained it | lint check "pe_v1 funnel empties the mapping array before releasing" + `[cleanup] pe_v1: searchMappings tracker released` |
  | pe_v1/pe_v2 `targetInpGencntList` (per call) | the third owned object, held for the whole call | `release_gencnt_tracker()` at every terminal exit (7 in pe_v1, 3 in pe_v2) - NOT on the pe_v1 cycles that loop back, because the list is shared across cycles on purpose | lint check "every terminal exit releases the gencnt tracker" (7 + 2 exits traced, the pre-creation exits named as exempt) |
  | pe_v2 `wiredAddrs` (the 2GB/4096 = ~4MB tracker) | already fixed in the first pass | 4 release sites (retry, both FAILURE exits, tail) | lint check "released on all four exit shapes" |

  A NEW hazard found while fixing item 2 (worth knowing, it is why the stop flag
  exists): a plain `pthread_join` in the teardown can HANG. `free_thread`'s first
  wait is `while (goSync == 0);`, and the pe_v1 OOB-calloc failure exit returns
  before `initialize_physical_read_write()` ever sets `goSync = 1` - joining that
  thread blocks the exploit thread forever. `g_freeThreadStop` is checked by all
  four waits plus the post-wait break, so the join always terminates; the thread
  also leaves WITHOUT mapping if it is stopped between waits.

  Residual risk inside the audited paths themselves: a `mach_port_deallocate` on
  the memory object that fails twice still leaves that one right held - it is
  logged with its kr now instead of silently aborting the attempt. And the two
  pressure sources this item named are UNCHANGED by the audit: the scan still
  writes `randomMarker` into every page of every search mapping and the initial
  spray still holds ~22.5k sockets, so an A13 pass should still be measured
  against `W0lfTerm.diskwrites_resource-*.ips` (plus the CPU/wakeup axes) before
  the technique question is called closed.

  Separate observation from this round, NOT a release path and NOT fixed here
  (pre-existing, unchanged by the audit): after pe_v1 returns, the socket arrays
  have been emptied by `sockets_release()`, so `restore_corrupted_socket()` -
  which re-opens its fds from `socketPorts[g_probe_control_idx]` - cannot re-open
  them on the staged -5 path (`kexploit_opa334`, kbase-scan exhausted) when the
  in-walk restore was never confirmed. Same in HEAD. That is a BUG.1 restore
  question (keep the corrupted pair addressable past pe_v1), not a leak, so it
  stays out of this patch and is recorded here so it is not re-discovered.
  FIXED in the same device-day pass - BUG.1 step 1 below (the promotion's fds are
  now the fallback, stamped with the save generation, and the restore reports its
  own outcome on that exit instead of writing nothing).

  Verification that actually ran (host, no device, no device commands):
  `python3 scripts/check_bug2_release_paths.py` -> `34 check(s) passed, 0 failed`,
  exit 0 - 43 checks and thirteen mutations after the BUG.1 step-1 checks below
  [T17 note on those three numbers: the `34`, the `43` and the `thirteen` are the
  counts of THAT pass. This lint is untracked - no revision of it exists in git -
  and no log of that run was kept, so none of the three is reproducible. What IS
  captured on the current tree is `56 check(s) passed, 0 failed` plus 19 selftest
  mutations and their baseline
  (`t17/suite_logs/w0lf_host_verification/bug2_release_paths.log`,
  `.../bug2_release_paths_self.log`).]

  extended the same lint with the restore contract (it traces every
  function-level exit of both functions and prints the funnel
  call found for each; requires the funnel - not just "some release" - before every
  exit, with the two exits that legitimately hold nothing named explicitly by their
  branch log line; asserts no release site bypasses `release_memory_object()`;
  enforces pe_v1's one-release-site rule; accounts for every `surface_mlock()`
  against a documented munlock path; requires every `[cleanup]` log line and all
  four `wiredAddrs` release sites; and, from round 3, walks every exit of
  `kexploit_opa334()` through the block scopes of its own path - so an exit covered
  only by a SIBLING branch's teardown fails - checks that the teardown never fires
  before `pe_init()`, that no bare `[NSMutableArray new]` re-created the spray
  trackers outside `tracker_arrays_reset()`, that the previous OOB mapping is
  released before a new one replaces it, and that every gencnt/tracker exit is
  covered). The first version of this lint was itself audited and had two checks
  that could not fail (a lookback that accepted a bare `free(readBuffer)` as "the
  resource was released", and a `^(?!...)` lookahead that matched any line NOT
  containing the forbidden call); a third was found in round 3 (the block scanner
  filtered brace depths with a slice-relative index, so two exits got empty scope
  windows). All three are real now, and
  `python3 scripts/check_bug2_release_paths.py --selftest` mutates a TEMP COPY of
  the source SEVEN ways (drops pe_v1's -4 funnel, drops pe_v1's -4 teardown,
  restores a bare `[NSMutableArray new]` tracker pair, drops the previous-mapping
  release, removes one `g_freeThreadStop` wait, bypasses
  `release_memory_object`, drops the pe_v2 tail tracker release) and requires the
  lint to fail on each -> `selftest: all mutations caught`, exit 0. `THEOS=$HOME/theos
  make libengine` -> `OK: .theos/libengine/libw0lfengine.a (788K, 49 objects)` with
  a 0-byte `.theos/libengine/build.log` (zero warnings, zero errors); W0lfTerm
  `THEOS=$HOME/theos REBUILD_ENGINE=1 bash scripts/build_ipa.sh sideload 0.19` ->
  `OK: dist/W0lfTerm-0.19-sideload.ipa` (153264 bytes; the rebuilt engine library
  still links into the app). NOT device-verified: the next device run - plus a
  `W0lfTerm.diskwrites_resource-*.ips` / CPU / wakeup comparison - is what proves
  the freed resources are actually gone.

  T12 closing pass (task 12/12, host only, no device command) - the LEAK half of
  this item is what the 2026-09-11 device day could act on, and it is closed with
  per-exit evidence, not with the word "fixed":
  `python3 scripts/check_bug2_release_paths.py` -> `56 check(s) passed, 0 failed`
  (exit 0) traces EVERY function-level exit of `pe_v1` (8) and `pe_v2` (4),
  prints the funnel call it found for each, requires the funnel - not "some
  release" - before every one, with the two exits that legitimately hold nothing
  named by their own branch log line, and `--selftest` -> `selftest: all
  mutations caught` (19/19, exit 0) shows those checks bite (dropping pe_v1's -4
  funnel, its -4 teardown, the previous-mapping release, a `g_freeThreadStop`
  wait, `release_memory_object`, the pe_v2 tail tracker release, or re-adding a
  bare `[NSMutableArray new]` tracker pair each fail the lint). The cancel half
  is asserted in the same run's other lint: `python3
  scripts/check_scan_budget_cancel_writes.py` -> `25 check(s) passed, 0 failed`
  including "BUG.4 engine pe_v2: the aborted (-7) path frees the mapping, the
  object and the spray", "BUG.4 engine pe_v1: the -7 cancel exit releases the
  spray AND the mappings" and "every -7 exit goes through the funnel (no cancel
  exit leaks)". No leaked search mapping and no leaked socket spray on the cancel
  path, as far as static + host evidence can show.
  OPEN and deliberately NOT patched - so this checkbox is not read as more than
  it is: the two pressure sources named above (the scan dirtying every page of
  every search mapping, ~30 MB per pass, and the up-front spray holding ~22.5k
  sockets) are unchanged, and "allocate/scan/free the mappings one at a time"
  remains a documented OPTION. It is a technique change to the proven kernel path
  and no host test can decide it, so it is recorded rather than attempted. Its
  evidence is the measurement this item asks for: `idevicecrashreport -e <dir>`
  -> `W0lfTerm.diskwrites_resource-*.ips` / CPU / wakeup reports, before and
  after. The one part of that budget that COULD be bounded without a device - the
  per-line log fsync - is throttled and counted now; see the closing note under
  `SG.10` and W0lfTerm 0.6 `BUG.3`.

  The remaining half now has a regression guard instead of only a note:
  `scripts/check_pressure_budget.py` parses the real constants out of
  `kexploit/kexploit_opa334.m` and pins them, and fails if any of them grows -
  the page count and the RAM scaling, the mapping size and therefore the mapping
  count, the per-page marker loops (a mutation that marks one page instead of
  every page is caught), the `OPEN_MAX * 3 - 4096 * 2` spray bound (22528
  sockets), and the per-cycle release funnel that keeps the PEAK at one cycle's
  worth rather than six. Evidence: `python3 scripts/check_pressure_budget.py` ->
  `8 check(s) passed, 0 failed` (exit 0) with a printed table (T17 re-run, raw
  log `t17/suite_logs/w0lf_host_verification/pressure_budget.log`); `--selftest`
  -> `selftest: all mutations caught` (exit 0). The `7 check(s) passed` /
  `7/7` this note used to carry is a T12-dated count from before the disk-budget
  check (the 8th) was added, with no retained log of that run. That table also
  CORRECTS this item's own figure: see the 384 MB note below.

- [x] `BUG.3` — **the 120 s budget is shorter than a full walk on this device.**
  The 19:10 run aborted at offset `0x1cc4000` of the mapping after exactly 120 s,
  i.e. roughly a quarter of the walk, so a full walk needs on the order of 8.5
  minutes. Consequence: a budget-run will almost always report
  "cancelled" instead of reaching the target. Decide: raise the budget (and
  accept the resource axes), make it a persisted setting (e.g. 120 / 300 / 600 s),
  or speed up the walk (fewer retries per offset, bigger stride) so a full pass
  fits inside 120 s.
  Fix shipped (0.13): `kexploit_set_scan_budget(int)` / `kexploit_scan_budget()`
  (`kexploit/kexploit_opa334.m`), clamped to 30..1800 s, read by all three scan
  loops (pe_v1, pe_v2, the read race) and by the `-7` message through one relaxed
  atomic; the default is still `EXPLOIT_SCAN_BUDGET_SEC` = 120 s, so an untouched
  run behaves exactly as before. W0lfTerm persists the choice (default 120 s;
  `SET > Terminal > Scan budget` = 120s / 300s / 600s), pushes it into the engine
  at load, and the boot banner prints the active budget. NOT yet verified on
  device: the 600 s option is what a full A13 walk needs, and longer runs sit
  deeper in the CPU/wakeup/disk-write budgets (0.10, BUG.2), so a device run with
  600 s should be measured against all three resource axes before it is called
  done.

  Default raised to 600 s (task 10, same day - the "settable" half was not the
  bug, the default was): `EXPLOIT_SCAN_BUDGET_SEC` is 600 and the app's
  `g_scanBudget` default is 600 (the top of the same 120/300/600 menu), so an
  untouched run gets the budget the measured ~8.5 min walk actually needs - the
  old 120 s default aborted at a quarter of the walk every time. One stale
  `#define EXPLOIT_SCAN_BUDGET_SEC 120` was still in the file under the new one;
  it is gone (it also warned `-Wmacro-redefined` in the engine build log, which
  is how the duplicate surfaced). Evidence: `THEOS=$HOME/theos make libengine` ->
  `OK: .theos/libengine/libw0lfengine.a (804K, 51 objects)` with a 0-byte build
  log, and `python3 scripts/check_scan_budget_cancel_writes.py` ->
  `20 check(s) passed, 0 failed` (it fails if either default is not 600, if the
  app stops pushing the row into the engine, or if the banner stops reading the
  value back from the engine). NOT device-verified.

  Round 4 (task 10, the verification pass): the same lint now reports
  `21 check(s) passed, 0 failed` and `--selftest` -> `selftest: all mutations
  caught` (16/16) - it gained one structural check, written up under `BUG.4`
  below. What this round adds for BUG.3 specifically is the link-level half: the
  SET row really reaches the engine in the BUILT app, not just in the source.
  `THEOS=$HOME/theos make libengine` -> `OK: .theos/libengine/libw0lfengine.a
  (804K, 51 objects)` (exit 0), `bash scripts/build_ipa.sh sideload 0.20` ->
  `OK: dist/W0lfTerm-0.20-sideload.ipa` (exit 0), and in the linked binary
  `llvm-nm` shows `T _kexploit_set_scan_budget` / `T _kexploit_scan_budget`
  defined while `llvm-objdump` shows `+[TermSettings setScanBudget:]` ending in
  `bl _kexploit_set_scan_budget` - i.e. the UI's setter and the engine's setter
  are the same call, in the artifact the device would install. NOT
  device-verified.

  T12 closing pass (task 12/12, host only, no device command):
  `python3 scripts/check_scan_budget_cancel_writes.py` -> `25 check(s) passed,
  0 failed` (exit 0) - 21 at the last pass, the four new ones are BUG.6's throttle
  checks - including "BUG.3 engine: the default budget is the one that fits the
  walk (600 s)", "BUG.3 engine: the budget is settable and clamped, and every
  scan/spray loop reads it", "BUG.3 engine: the cancel/budget check sits INSIDE
  each walk, not after it", "BUG.3 app: the default budget matches the engine
  default and is pushed in at load", "BUG.3 app: a SET row exists, persists, and
  pushes every change into the engine" and "BUG.3 app: the boot banner reads the
  budget back from the ENGINE". `--selftest` -> `selftest: all mutations caught`
  (21/21, exit 0; the budget default back to 120 s on either side is one of them,
  and so is the app dropping the `kexploit_set_scan_budget` push). The artifact
  half: `THEOS=$HOME/theos make libengine` -> `OK:
  .theos/libengine/libw0lfengine.a (804K, 52 objects)` (exit 0, 0-byte build
  log) and `bash scripts/build_ipa.sh sideload 0.20` -> `OK:
  dist/W0lfTerm-0.20-sideload.ipa` (exit 0); in the linked binary (sha256
  `2922ebb3c8138e6dcbd2efb95101afdceb26e409b83f8129d28bdb351eaf14c8`) `llvm-nm`
  still defines `T _kexploit_set_scan_budget` / `T _kexploit_scan_budget` and
  `llvm-objdump` still shows `+[TermSettings setScanBudget:] -> bl
  _kexploit_set_scan_budget`. NOT device-verified (the banner reading 600 back on
  the SE is a device-day check).

  T16 closing pass (task 16/16, host only, no device command): re-run, not
  re-quoted. `python3 scripts/check_scan_budget_cancel_writes.py` -> `25 check(s)
  passed, 0 failed` (exit 0), incl. "BUG.3 engine: the default budget is the one
  that fits the walk (600 s)" and "BUG.3 app: the boot banner reads the budget back
  from the ENGINE"; `--selftest` -> `selftest: all mutations caught` (21/21, exit
  0 - either default back to 120 s fails the lint on the mutated copy).
  `python3 scripts/check_pressure_budget.py` -> `8 check(s) passed, 0 failed`,
  `--selftest` 9/9. Two checkers written for this pass then read the two trees AND
  the built artifact independently of the lint (a lint that drifts from the tree
  has to pass twice): `docs/verification/2026-09-11-0.12/t16/rerun/
  invariant_check.py` -> `27 ok, 0 failed` (engine default 600 == app default 600,
  clamp 30..1800 with both bounds applied in the setter, 13 `SCAN_BUDGET_SEC()`
  reads across the spray/race/pe_v1/pe_v2 guards) and `rerun/callgraph_check.py` ->
  `6 ok, 0 failed` (`+[TermSettings setScanBudget:]` -> `bl
  _kexploit_set_scan_budget` in the freshly linked binary, next to the BUG.4/BUG.5
  call edges). Both artifacts were rebuilt in this pass by `bash
  scripts/check_host_verification.sh --with-builds` -> `21 ok, 0 drift` (exit 0):
  archive `sha256 263ae60d49fd0c15...`, linked binary
  `sha256 2922ebb3c8138e6d...`. Raw output: `t16/rerun/{VERIFY.md,rerun.sh,RC.txt,
  *.log}`. NOT device-verified - the banner reading 600 back on the SE is the
  device-day check.

  T17 re-run (task 17/18, host only, no device command, raw logs in
  `docs/verification/2026-09-11-0.12/t17/suite_logs/w0lf_host_verification/`,
  one per suite entry, written by `check_host_verification.sh` itself): `python3
  scripts/check_scan_budget_cancel_writes.py` -> `25 check(s) passed, 0 failed`
  (exit 0) with the six BUG.3 checks green and `--selftest` -> `selftest: all
  mutations caught`; `python3 scripts/check_pressure_budget.py` -> `8 check(s)
  passed, 0 failed`; `bash scripts/check_host_verification.sh --with-builds` ->
  `21 ok, 0 drift` (exit 0), which rebuilt `libw0lfengine.a` (`804K, 52 objects`,
  sha256 `263ae60d...`) and the ipa, and re-read `_kexploit_set_scan_budget` /
  `_kexploit_scan_budget` out of the linked binary. Count corrections: the
  `20 check(s) passed` this item quotes from the task-10 pass is a dated count
  with no retained log - history, not a reproducible number; the reproducible ones
  are `21` (`docs/verification/2026-09-11-0.12/scan_budget_cancel.log`, the first
  capture of this lint) and `25` (this pass, re-run in `t12` and `t16` too,
  `4dc5246d...`). NOT device-verified: the banner reading 600 back on the SE is
  the device-day check.

- [x] `BUG.4` — **no visible CANCEL in the app.** `cancel` / `abort` / `stop` work
  from the terminal, and the engine honours the flag at all three loop levels
  now, but there is no button. Add one that appears while a run is in flight
  (the run-state dot in the input bar is the natural place to hang it) so a
  spinning run can be stopped without typing into a busy UI.
  Fixed (W0lfTerm 0.14, app side - this repo has no UI, so nothing changed here):
  the run-state dot in the input bar is a 36 pt `UIControl`
  (`TerminalViewController.m`, `dotTapped:`), added next to the 8 pt core so the
  colour/pulse behaviour is untouched (grey idle, pulsing accent running, green
  escaped, red failed, pulse gated on Reduce Motion). It calls
  `term_bridge_cancel()` (`term_bridge.m`), which checks the app's own
  `g_exploitRunning` and then either sets the engine stop flag
  (`kexploit_request_stop()`, an atomic store -> safe from any thread, no
  main-queue dependency) plus the log line `[w0lf] cancel requested - the scan
  will stop at its next check`, or logs `[w0lf] nothing is running` and does
  nothing. Click sound (`TermClick`) + a LIGHT `UIImpactFeedbackGenerator`
  (`termHapticLight`, the key bar keeps medium). The engine checks
  `kexploit_stop_requested()` at the top of the spray, `pe_v1`, `pe_v2` and the
  read race, so "next check" is literal. The `cancel` command goes through the
  same bridge function, so the button and the terminal cannot disagree. Host
  evidence: `make libengine` -> `OK: .theos/libengine/libw0lfengine.a`, W0lfTerm
  `bash scripts/build_ipa.sh sideload 0.17` -> `OK: dist/...ipa`. (Corrected in
  the 2026-09-11 verification pass: this line used to say "the app builds with
  `-Werror`". There is no `-Werror` in the app's Makefile - `W0lfTerm_CFLAGS` is
  the `-Wno-*` set plus `-DDEBUG`. What is true is that a full
  `THEOS=$HOME/theos make W0LF_SRC=...` on this tree exits 0 with 0 compiler
  warnings and 0 errors; the only two diagnostics in the log are ld64.lld's
  `-ios_version_min` and `-multiply_defined` notes from the Theos link line.)
  NOT device-verified.

  Round 2 (task 10, same day): the control is now VISIBLE and the cancel path is
  verified against the leaks. Two changes, both sides:
  * W0lfTerm (`TerminalViewController.m`): the tap target grows from a bare
    36 pt dot to a 96 pt control that carries the word `cancel` (9 pt monospaced,
    right-aligned, accent-coloured) beside the dot. The word is on exactly while
    the run state is 1 - a dead control that promises a cancel is worse than a
    dot - and the frames never move (the label fades in/out, the field width is
    the same in both states), so nothing jumps when a run starts. The geometry is
    an enum plus `_Static_assert(TERM_CANCEL_CONTROL_W == 96)`, and the control
    finally has an accessible name (`cancel` / hint "stop the running kernel
    scan") instead of a colour only.
  * Engine (`kexploit/kexploit_opa334.m`): the CANCEL was honoured by the walks
    but NOT by the socket spray, which is the longest thing a cancelled run still
    paid for - the up-front spray opens up to ~28k sockets (a wakeup/CPU-budget
    contributor, SG.10) and ran to the end of the file table after a cancel. The
    stop flag (or the budget) is now checked at the top of pe_v1's spray/race
    cycle (terminal `-7` exit through the release funnel), inside the up-front
    spray loop, inside the mid-scan batch loop and inside pe_v2's batch loop.
  * The release half of the cancel contract is asserted, not assumed:
    `python3 scripts/check_scan_budget_cancel_writes.py` ->
    `20 check(s) passed, 0 failed`, including "pe_v1's `-7` exit releases the
    spray AND the mappings" (the funnel munlocks and deallocates every search
    mapping, then `sockets_release()`), "pe_v2's aborted path frees the mapping,
    the memory object and the spray" (munlock -> deallocate -> release, all
    before `if (aborted) break;`), and "the spray honours a cancel".
    `--selftest` mutates TEMP COPIES fourteen ways (budget default back to 120 on
    either side, the funnel call dropped, `sockets_release` dropped from the
    funnel, pe_v2's munlock dropped, the app retrying on `-7`, the spray check
    dropped, ...) and requires the lint to fail on each ->
    `selftest: all mutations caught`. `bash scripts/build_ipa.sh sideload 0.20`
    -> `OK: dist/W0lfTerm-0.20-sideload.ipa` (the built binary contains the
    `cancel` label string). NOT device-verified: the device half - tap the word
    mid-run, watch `[cleanup]` lines for the mapping and the spray - is the next
    device day.

  Round 3 (same day, in the verification pass for this task): the sentence "both
  cancel paths reach the app as -7" was not true of `pe_v2`. `pe_v2()` is void and
  its `FAILURE` exits return bare, so a CANCEL stopped pe_v2's walk and the run
  then fell through into the krw tail (the `controlSocketPcb` reads and the
  kernel-base scan) with the app still showing "running" - the A18 branch never saw
  a `-7`. The old check could not catch that: it only looked for the string
  `aborted` anywhere in the file. `pe_v2` now records the stop in
  `g_peV2Aborted` (reset per call) and the A18 branch of `kexploit_opa334()` maps it
  to the same terminal exit pe_v1 uses (`[cleanup]` teardown + `return -7`), so the
  app reports "cancelled" and stops instead of continuing. The check now requires
  the whole propagation (`pe_v2();` -> `if (g_peV2Aborted)` -> teardown ->
  `return -7`), and the selftest carries a fifteenth mutation for it. The check was
  also replayed against the pre-fix engine in temp copies (the flag write and the
  A18 read removed) and fails exactly that one check, so it is known to bite:
  `checks failing on the pre-fix engine: ['BUG.4 engine: both cancel paths reach
  the app as -7 (cancelled, not failed)']`. Verified host-side, no device: lint
  `20 check(s) passed, 0 failed`; `--selftest` -> `selftest: all mutations caught`
  (15/15); `make libengine` -> `OK: .theos/libengine/libw0lfengine.a (804K, 51
  objects)`; `bash ../W0lfTerm/scripts/build_ipa.sh sideload 0.20` ->
  `OK: dist/W0lfTerm-0.20-sideload.ipa` with `pe_v2 scan stopped on request
  (cancel or %ds budget)`, `[cleanup] pe_v2: search mapping ... munlocked +
  deallocated` and `(cancelled: mapping + object freed too)` inside the built
  binary.

  Round 4 (task 10, the verification pass for this task): the release half of the
  cancel contract was checked per call site in round 2; it is now checked
  structurally, because a NEW cancel exit that skips the funnel is exactly how
  this bug comes back. The lint reads `int pe_v1(void)`'s body, finds every
  `return -7;` in it (one today: the pre-spray exit at the top of the spray/race
  cycle) and requires the funnel call plus its `release_gencnt_tracker` release in
  the preceding 300 characters, that the walk's cancel is the `break`
  (`testResult = -7; break;` at the loop level) that flows into the terminal
  funnel call, and that that call deallocates the wired mapping for a `-7`
  (`(testResult != 0) || success`). The selftest gained a sixteenth mutation for
  it: that exit's funnel + two `free()`s + tracker release are replaced by a bare
  `return -7;` and the lint fails the new check on the mutated copy
  (`pe_v1 return -7 sites=1 unguarded=1`), so the leak shape BUG.4 describes is a
  lint failure now, not a code review.

  Evidence (host, no device, no device command):
  `python3 scripts/check_scan_budget_cancel_writes.py` -> `21 check(s) passed,
  0 failed` (exit 0), `--selftest` -> `selftest: all mutations caught` (16/16,
  exit 0, every mutation applied and caught), `bash
  scripts/run_kwrite_counter_host_test.sh` -> `checks=53 failures=0` /
  `KWRITE_COUNTER_HOST_TEST PASS` (exit 0). The app half of the plumbing is
  proven at link time rather than by strings: `THEOS=$HOME/theos make libengine`
  -> `OK: .theos/libengine/libw0lfengine.a (804K, 51 objects)`, `bash
  scripts/build_ipa.sh sideload 0.20` -> `OK: dist/W0lfTerm-0.20-sideload.ipa`,
  and in the linked app binary (`dist/Payload/W0lfTerm.app/W0lfTerm`, Mach-O
  arm64) `llvm-nm` lists `T _kexploit_request_stop`, `T _kexploit_stop_requested`,
  `T _kexploit_clear_stop`, `T _kexploit_set_scan_budget`, `T _kexploit_scan_budget`,
  `T _kexploit_scan_writes`, `T _kexploit_scan_write_bytes`,
  `T _kexploit_scan_write_failures` and the `kwrite_*` counter functions as
  DEFINED symbols, while `llvm-objdump` shows the call sites:
  `-[TerminalViewController dotTapped:]` -> `bl _term_bridge_cancel`, and
  `_term_bridge_cancel` -> `bl _kexploit_request_stop`.  A string in a binary says
  the code was compiled; a `bl` to the engine's symbol says it is called. NOT
  device-verified: the device half - tap the word mid-run, watch the `[cleanup]`
  lines for the mapping and the spray - is still the next device day.

  T12 closing pass (task 12/12, host only, no device command):
  `python3 scripts/check_scan_budget_cancel_writes.py` -> `25 check(s) passed,
  0 failed` (exit 0), and the cancel-specific checks are the ones this round
  re-read: "BUG.4 app: a visible CANCEL control that is on only while a run is in
  flight", "BUG.4 app: the tap reaches the engine stop flag through the one
  bridge", "BUG.4 app: the run loop treats -7 as cancelled and STOPS (no retry)",
  "BUG.4 engine: the socket spray honours a CANCEL (it is the longest pre-walk
  cost)", "BUG.4 engine pe_v1: every -7 exit goes through the funnel (no cancel
  exit leaks)", "BUG.4 engine pe_v2: the aborted (-7) path frees the mapping, the
  object and the spray" and "BUG.4 engine: both cancel paths reach the app as -7
  (cancelled, not failed)". `--selftest` -> `selftest: all mutations caught`
  (21/21, exit 0) - the new mutations for this item (cancel word hidden, stop flag
  dropped, the app retrying on -7, the spray ignoring a cancel, the A18 caller
  ignoring pe_v2's cancel, pe_v1's -7 exit returning bare) all fail the lint on
  the mutated copy. App artifact: `bash scripts/build_ipa.sh sideload 0.20` ->
  `OK: dist/W0lfTerm-0.20-sideload.ipa` (exit 0), and in the linked app binary
  (sha256 `2922ebb3...`) `llvm-nm` lists `T _kexploit_request_stop` /
  `T _kexploit_stop_requested` as DEFINED with `-[TerminalViewController
  dotTapped:] -> bl _term_bridge_cancel -> bl _kexploit_request_stop` in the
  disassembly (the 17 ok / 0 drift suite entry `app_static_symbols`), strings
  count `cancel` 19 and `pe_v2 scan stopped on request` 1. NOT device-verified:
  the device half is unchanged.

  T16 closing pass (task 16/16, host only, no device command): the cancel chain
  re-verified end to end with both halves rebuilt in this pass.
  `python3 scripts/check_scan_budget_cancel_writes.py` -> `25 check(s) passed, 0
  failed` (exit 0) with all seven BUG.4 checks green ("a visible CANCEL control
  that is on only while a run is in flight", "the tap reaches the engine stop flag
  through the one bridge", "the run loop treats -7 as cancelled and STOPS (no
  retry)", "the socket spray honours a CANCEL", "every -7 exit goes through the
  funnel", "pe_v2's aborted (-7) path frees the mapping, the object and the spray",
  "both cancel paths reach the app as -7"), `--selftest` -> `selftest: all
  mutations caught` (21/21). In the linked binary rebuilt here
  (`sha256 2922ebb3c8138e6dcbd2efb95101afdceb26e409b83f8129d28bdb351eaf14c8`):
  `-[TerminalViewController dotTapped:]` -> `bl _term_bridge_cancel` -> `bl
  _kexploit_request_stop` -> `stlr w8, [x9]` (the atomic the walks read), read out
  with `t16/rerun/callgraph_check.py` -> `6 ok, 0 failed`, and
  `t16/rerun/invariant_check.py` counts 7 `kexploit_stop_requested()` sites plus
  the cancel-only visibility of the 96 pt control and its VoiceOver name. NOT
  device-verified: the device half is still tap-the-word-mid-run and watch the
  `[cleanup]` lines.

  T17 re-run (task 17/18, host only, no device command, raw logs in
  `docs/verification/2026-09-11-0.12/t17/`): the eight BUG.4 cancel checks are
  green inside `python3 scripts/check_scan_budget_cancel_writes.py` -> `25
  check(s) passed, 0 failed` (exit 0, sha256 `4dc5246d...`; `--selftest` ->
  `selftest: all mutations caught`, 21 mutations incl. the A18 propagation one -
  countable in the capture, which carries the 21 `ok mutation caught:` lines
  plus the baseline in
  `t17/suite_logs/w0lf_host_verification/scan_budget_cancel_self.log`).
  Quoted from that log's own lines: "the socket spray honours a CANCEL", "a
  visible CANCEL control that is on only while a run is in flight", "the tap
  reaches the engine stop flag through the one bridge", "the run loop treats -7 as
  cancelled and STOPS (no retry)", "pe_v1: the -7 cancel exit releases the spray
  AND the mappings", "pe_v1: every -7 exit goes through the funnel", "pe_v2: the
  aborted (-7) path frees the mapping, the object and the spray", "both cancel
  paths reach the app as -7" (eight lines prefixed `BUG.4`; the T16 note above
  counts "seven cancel checks" - the log has eight, the extra one being pe_v1's
  funnel check). The linked-binary half was rebuilt and re-read by `bash
  scripts/check_host_verification.sh --with-builds` -> `21 ok, 0 drift` (exit 0):
  `dist/Payload/W0lfTerm.app/W0lfTerm` sha256
  `2922ebb3c8138e6dcbd2efb95101afdceb26e409b83f8129d28bdb351eaf14c8`, defining
  `_kexploit_request_stop`, `_kexploit_stop_requested`, `_g_peV2Aborted` and the
  `kwrite_zone_*` family, carrying `cancel` x19 and "pe_v2 scan stopped on
  request" x1
  (`t17/suite_logs/w0lf_host_verification/app_static_symbols.log` is that check's own raw
  output). Count corrections: the `20 check(s) passed` counts this item quotes
  from the earlier passes are dated with no retained log; the reproducible ones are
  `21` (`docs/verification/2026-09-11-0.12/scan_budget_cancel.log`) and `25` (this
  pass). `checks=53 failures=0` for the write counter re-ran unchanged
  (`t17/kwrite_counter.log`). NOT device-verified - the device half is unchanged.

- [x] `BUG.5` — **"readonly = zero writes" is too strong a claim.** It is zero
  KERNEL writes (`wolf_test_mode == 1` returns before the corruption), but the
  scan still dirties ~1 GB of file-backed memory and pegs a core; the wording in
  the app's settings row, the boot banner and this roadmap should say "no kernel
  writes" and keep the resource caveat next to it. Users read "zero writes" as
  "safe to leave running".
  Fixed (0.13, W0lfTerm `BUG.2`). Every hit of the claim in both repos now says
  "no kernel writes" and carries the resource caveat: the W0lfTerm mode row
  subtitle (`exploitModeRowDesc:`, caveat on the same row, 4 measured lines), the
  boot banner line, the SET red line (which still warns that staged / writetest /
  full write kernel memory and can panic the phone - warning not weakened), the
  app README, `term_settings.h/.m` comments; host side: `Makefile`, `README.md`
  (safety-ladder table + FilzaArctic-Test.ipa notes), the CLI's `testipa` /
  `--test` banners, the `TweakExploit.m` comment and its status-5 log string,
  the engine's `[STAGED] stage 1/2` line and the `DEBUG_TRACKING.md` row for it.
  The one verbatim device-log tail under `SG.9` keeps the old string (it is
  pasted output) and now carries a footnote pointing at this item.

  Round 2 (task 10, same day): the wording was the visible half; the invisible
  half was that NOTHING counted the writes, so "no kernel writes" was still an
  assertion. It is now a measurement:
  * new `kexploit/kwrite_counter.c` / `.h` (in `make libengine` and in the tweak's
    file list): every kernel write this chain can issue goes out through
    `early_kwrite32bytes` (a 32-byte `setsockopt(ICMP6_FILTER)`) - `early_kwrite64`
    and `krw_zone_write_block` funnel into it - so the counter is incremented
    there on success and the refusal counter on `setsockopt != 0`. Attribution is
    a thread_local route stack (`early_kwrite32bytes` / `early_kwrite64` /
    `krw_zone_write_block`) because the scan thread and the pe_init free thread
    both write.
  * the engine resets the counters per attempt (`kexploit_opa334()` and
    `kexploit_telemetry_reset()`) and prints a measured summary on every exit that
    tears down plus the staged -5 exit: `[SCAN] kernel writes issued ...: N
    write(s), M byte(s) [measured by kwrite_counter, BUG.5]` with the per-route
    breakdown; the readonly `-2` line and the staged stage-1/2 line carry the
    number too. Exported as `kexploit_scan_writes()` / `_write_bytes()` /
    `_write_failures()`, and the app logs the same numbers (`term_log_write_count`
    -> `[w0lf] kernel writes this attempt (scan + probe): N write(s) / M byte(s)
    (engine-counted ...)`), so "readonly writes nothing" is a measured 0 in the
    run log instead of a sentence in the settings row.
  * host evidence: `bash scripts/run_kwrite_counter_host_test.sh` ->
    `checks=53 failures=0` / `KWRITE_COUNTER_HOST_TEST PASS` (counting,
    attribution, refusals counted separately from writes, per-attempt reset, and
    two threads emitting 10k writes each with no increment lost);
    `python3 scripts/check_scan_budget_cancel_writes.py` ->
    `20 check(s) passed, 0 failed` (the primitive must count both outcomes, both
    entry points must attribute their route, and no shipped log/UI string may
    claim "zero writes" any more); `--selftest` -> `all mutations caught`
    (dropping the counting call or the route push is caught).

  Residual, stated plainly: the counter measures writes that LANDED through the
  one primitive; a write the clamp refuses never reaches it (that is what the
  refusal counter and the `krw` refusal log lines are for), and the two
  `so_usecount` writes in `krw_sockets_leak_forever` are counted like any other
  `early_kwrite64` - the counter says how many writes happened, not whether they
  were a good idea. NOT device-verified.

  Round 3 (task 10, the verification pass): re-run, and the two halves separated.
  Counter: `bash scripts/run_kwrite_counter_host_test.sh` -> `checks=53
  failures=0` / `KWRITE_COUNTER_HOST_TEST PASS` (exit 0) - the test compiles
  `kexploit/kwrite_counter.c`, the same file the engine archive is built from,
  and drives counting on emit, refusals counted separately from writes, the
  route stack nesting and restoring, an out-of-range route still counted instead
  of dropped, and two threads emitting 10k writes each with no increment lost.
  Wording: the shared lint's "no shipped log/UI string claims 'zero writes' any
  more" reads every `.m/.c/.h` in both trees with comments stripped; the only
  remaining `zero writes` hits in the trees are the comments that describe the
  bug history (this file's own header, `kexploit_opa334.h`, the host test, the
  lint script) - no log line, no settings row, no README claim. Confirmed on the
  artifact too: `strings -a dist/Payload/W0lfTerm.app/W0lfTerm | grep -c` gives
  `no kernel writes` = 5 and `zero kernel writes` = 0 in the built app binary.
  The lint reports `21 check(s) passed, 0 failed`; the link-level proof that the
  app reads these numbers (not only that the strings exist) is under `BUG.4`
  above (`T _kexploit_scan_writes` / `_write_bytes` / `_write_failures` defined in
  the linked binary). NOT device-verified.

  T12 closing pass (task 12/12, host only, no device command): the claim and the
  counter re-checked on the current tree. `bash
  scripts/run_kwrite_counter_host_test.sh` -> `checks=53 failures=0` /
  `KWRITE_COUNTER_HOST_TEST PASS` (exit 0) - it compiles
  `kexploit/kwrite_counter.c`, the file the engine archive is built from, and
  drives it: an accepted write counts once for its own route and for its exact
  length, a refused `setsockopt` counts as a refusal and never as a write, the
  route stack is per-thread (two threads, 10k writes each, no increment lost,
  each route keeping its own count), and reset zeroes everything. `python3
  scripts/check_scan_budget_cancel_writes.py` -> `25 check(s) passed, 0 failed`
  (exit 0), including "BUG.5: no shipped log/UI string claims 'zero writes' any
  more" (the lint reads every .m/.c/.h in both trees with comments stripped) -
  the only remaining `zero writes` hits are the comments that describe the bug
  history. Artifact: `strings -a dist/Payload/W0lfTerm.app/W0lfTerm | grep -cF`
  gives `no kernel writes` = 5 and `zero kernel writes` = 0, and the linked
  binary defines `T _kexploit_scan_writes` / `T _kexploit_scan_write_bytes` /
  `T _kexploit_scan_write_failures`, so the app reads the engine's measured
  numbers rather than asserting a sentence (see `BUG.4`'s closing note for the
  link-level call graph). Residual, unchanged: the counter measures writes that
  LANDED through the one primitive; a write the clamp refuses never reaches it
  (that is what the refusal counter is for), and it counts writes, not whether
  they were a good idea. NOT device-verified.

  T14 closing pass (task 14/14, host only, no device command): the last clause of
  the fix ("back the claim with a write-accounting check tied to the 1 GB/day
  limit") is now a check rather than a sentence. `scripts/check_pressure_budget.py`
  gained an 8th check, "BUG.5/BUG.6 disk budget: the write accounting is pinned
  against the 1 GB/day limit", which parses the constants out of both trees
  (`TWEAK_LOG_FSYNC_MIN_INTERVAL_MS`, `EXPLOIT_SCAN_BUDGET_SEC`,
  `KEXPLOIT_SCAN_BUDGET_MAX`, the app's `while (attempt < 3 ...)` retry cap, the
  engine's `if (cycle > 6)` cycle cap, and the 3 GB class' dirtied bytes from the
  mapping arithmetic) and prints the two halves against the figure the device day
  was measured on: `scan: 384 MB per cycle x 7 cycle(s) x 3 attempt(s) = 8064 MB
  dirtied per run (7.88x the limit)` and `log: 600 s run, one fsync per 200 ms = at
  most 3001 fsync(s)`. It fails if any of those constants moves, so the ratio
  cannot drift unnoticed, and it says in its own output that the scan half is still
  over the limit - the check backs the accounting, it does not claim the budget is
  met. `python3 scripts/check_pressure_budget.py` -> `8 check(s) passed, 0 failed`
  / `PRESSURE_BUDGET LINT PASS` (exit 0), `--selftest` -> `selftest: all mutations
  caught` (9/9; the two new ones are the fsync window shrunk to 20 ms and the retry
  cap grown to 5, i.e. one mutation per half). The two expected hashes in
  `scripts/check_host_verification.sh` were re-pinned in the same pass because both
  logs moved (7 checks / 7 mutations before, 8 / 9 after).
  `bash scripts/check_host_verification.sh --with-builds` -> `21 ok, 0 drift`
  (exit 0) and `docs/WORKLOG.md` `T14` carries the commands, the raw output and the
  `docs/verification/2026-09-11-0.12/t14/MANIFEST.txt` hashes. NOT device-verified:
  how many bytes one fsync flushes stays a device measurement.

  T16 closing pass (task 16/16, host only, no device command): the claim and the
  counter re-run on this tree, and the artifact re-read. `bash
  scripts/run_kwrite_counter_host_test.sh` -> `checks=53 failures=0` /
  `KWRITE_COUNTER_HOST_TEST PASS` (exit 0); `python3
  scripts/check_scan_budget_cancel_writes.py` -> `25 check(s) passed, 0 failed`
  (exit 0) incl. "BUG.5: no shipped log/UI string claims 'zero writes' any more",
  "BUG.5 app: the run log carries the measured number, not the claim", "BUG.5
  engine: the counters reset per attempt, are exported, and are printed" and
  "BUG.5 counter: the ONE write primitive counts both outcomes". The independent
  reader written for this pass
  (`docs/verification/2026-09-11-0.12/t16/rerun/invariant_check.py`) -> `27 ok, 0
  failed`, and on the freshly linked binary `zero writes` = 0 / `zero kernel
  writes` = 0 / `no kernel writes` = 5, with `_term_log_write_count` carrying the
  CALL edges `bl _kexploit_scan_writes` / `bl _kexploit_scan_write_bytes` / `bl
  _kexploit_scan_write_failures` (a call, not a symbol name in a table). Note for
  the next reader: the first draft of that checker failed two checks, both times by
  matching a history COMMENT that quotes the old wording verbatim ("the old
  hard-coded `#define EXPLOIT_SCAN_BUDGET_SEC 120` lived here", "\"zero kernel
  writes\" read as \"safe to leave running\"") - it strips `//`-comments now, and
  the two lines are named in `t16/rerun/VERIFY.md`. NOT device-verified: the
  readonly run's counter reading 0 on the SE stays a device-day measurement.

  T17 re-run (task 17/18, host only, no device command, raw logs in
  `docs/verification/2026-09-11-0.12/t17/`): `bash
  scripts/run_kwrite_counter_host_test.sh` -> `checks=53 failures=0` /
  `KWRITE_COUNTER_HOST_TEST PASS` (exit 0; raw log `t17/kwrite_counter.log`,
  sha256 `1dc9c1d4b0e35b86e23667ff627e4b57bb7f6ec8385e622fc78c585dd6424e63`), and
  the wording half re-ran green inside `python3
  scripts/check_scan_budget_cancel_writes.py` -> `25 check(s) passed, 0 failed`
  (exit 0), whose six `BUG.5` lines include "no shipped log/UI string claims
  'zero writes' any more". The linked app binary still carries `no kernel writes`
  x5 and `zero kernel writes` x0
  (`t17/suite_logs/w0lf_host_verification/app_static_symbols.log` - the
  binary hash there is the fresh `2922ebb3...` rebuild). Count correction: the
  `20 check(s) passed` this item's host-evidence bullet quotes is a dated count
  with no retained log; the reproducible one is `25`. NOT device-verified.

- [x] `BUG.6` — **a stale host pairing blocks every log pull.** After the
  watchdog panic the host got `Invalid HostID (-21)` on lockdown (the host record
  dated Sep 2 no longer matched), which silently kills `idevicesyslog`,
  `idevicecrashreport` and the afc log pull. Recovery: unlock the phone and tap
  Trust on the "Trust This Computer?" prompt, or remove the host record
  (`sudo rm /var/lib/lockdown/<UDID>.plist`) and replug to re-prompt. Worth a
  line in `references/dead-device-usb-triage.md` and in the app README, since
  the first thing anyone does after a crash is try to pull logs.
  Documented, both places: the W0lfTerm README section "Pulling logs over USB"
  (commit 1318f7c) and a matching section "First move after any crash: restore
  the pairing, then pull" in `references/dead-device-usb-triage.md`. Both carry
  the two errors as one table (`Mux error (-8)` = wedged mux / locked device,
  `Invalid HostID (-21)` = lost pairing, the two are not the same problem), the
  recovery order (unlock the phone -> tap Trust on the "Trust This Computer?"
  prompt -> `sudo rm /var/lib/lockdown/<UDID>.plist` + replug when no prompt
  appears -> `sudo systemctl kill -s KILL usbmuxd` + `start` when the mux is
  wedged) and the two pull commands (`afcclient --container <bundle-id> get
  Documents/FilzaTweak.log`, `idevicecrashreport -e <dir>`). Documentation only - no device run, no engine change.

  T12 closing pass (task 12/12): half of this item's claim was NOT backed, and
  that is now fixed rather than re-asserted. The app-side half exists and is
  complete - `W0lfTerm/README.md` `## Pulling logs over USB` (line 219) carries the
  two-row error table (`Mux error (-8)` vs `Invalid HostID (-21)`), the recovery
  order (unlock -> Trust -> `rm /var/lib/lockdown/<UDID>.plist` -> replug ->
  `systemctl kill -s KILL usbmuxd`), the `ls -l /var/lib/lockdown/` rule for
  finding the stale record, both pull commands (`afcclient --container ... get
  Documents/FilzaTweak.log`, `idevicecrashreport -e <dir>`) and the sentence that
  `idevicecrashreport` returns the panic plus the three resource reports. The
  engine-side half did NOT: `references/dead-device-usb-triage.md` was referenced
  by this item and by W0lfTerm's `BUG.6`, and a filename search over `$HOME` plus
  a content grep found that path in NOTHING but the two ROADMAP files - no such
  file in either repo, and none in the `w0lfsword-development` skill's
  `references/` either (which is what W0lfTerm's wording claims). Created it as
  `/home/kaffein/Desktop/W0lfSword/references/dead-device-usb-triage.md` (3205
  bytes): the same table, the same recovery order, both pull commands, the
  `Action taken:` reading rule, the `1073.75 MB / 1083 s` diskwrite report as the
  concrete example, and a pointer to the app README so the two copies cannot drift
  silently. Verified on the created file: `test -f
  references/dead-device-usb-triage.md` -> present, `wc -c` -> 3205,
  `grep -c 'Invalid HostID'` -> 2 (the table row plus the recovery step, i.e. the
  `-8` vs `-21` distinction is stated twice), `grep -c 'idevicecrashreport'` -> 2,
  `grep -c '1073.75 MB'` -> 1. NOT device-verified - this item is documentation,
  and the pairing failure itself is a host/USB condition no host test can
  reproduce.

## 0.11 — Terminal with full kernel R/W (research, 2026-09-10)

> Question to answer: can the escaped Filza process run a real terminal
> (shell + pty) with the kernel R/W already proven on the 26.0.1 daily
> driver? The pieces that exist: kernel r/w (kexploit), sandbox escape
> (ext paths → "/", class rewritten), root creds (set_root_credentials
> uid=0 gid=0), and SSV writes (overwrite_system_file). Missing is the
> process/exec side — whether iOS lets this process spawn a shell, and
> which shell route survives code signing + the container layout.

- [ ] `TRM.1` ⚪ — Research exec surface: does `posix_spawn("/bin/sh")`
  work from the escaped app process on 26.0.1? Determine which
  executables are actually present and exec-capable on iOS 26
  (`/bin/sh`, `/usr/bin/*`), whether AMFI/code-signing blocks spawning
  a platform binary from a sideloaded app, and what entitlements (if
  any) the caller needs. Document the exact failure mode when it fails.
  _Instrumented 2026-09-11: `terminal/trm_probe.c` answers all of it on
  the next launch — a 16-operand `sandbox_check` matrix (process-exec,
  process-fork, file-* on /dev/ptmx, sealed paths), a per-entry exec
  inventory of /bin /usr/bin /usr/sbin /sbin /usr/libexec (exec bit +
  Mach-O magic + the profile's verdict per path), `fork()`, and a real
  `posix_spawn("/bin/sh", -c "id; uname -a; echo TRM1-SPAWN-OK")` with
  stdout/stderr captured into the container. Runs automatically in the
  post-escape path and on demand (HUD `TRM`, shell `probe`)._
- [ ] `TRM.2` ⚪ — Fallback: bundled static shell. Build a static
  arm64 shell (bash/zsh/dash or busybox-style multi-call) and exec it
  from inside the app bundle (the app's own signature covers it).
  Test whether dyld/kernel accepts exec of a bundled binary under the
  sideload signature; if not, note the signing requirement precisely.
  _Instrumented 2026-09-11: the probe's TRM.2 stand-in copies `/bin/sh`
  into the container (bytes + Apple signature intact, location changed)
  and execs the copy — that isolates "off-SSV exec" from "signing".
  A real bundle-resident helper is a build-side item: it needs a signed
  sidecar binary (Theos tool target + nested-code signing in
  re-sign_mha.sh), which is only worth doing once TRM.1's verdict says
  exec is reachable at all._
- [ ] `TRM.3` ⚪ — Fallback: in-process shell (no exec at all). Link a
  minimal C shell into the tweak dylib and implement builtins directly
  (ls/cat/cd/echo/rm/mv + kread/kwrite/dd helpers exposed as commands).
  This route has no code-signing or exec dependency and still gets full
  kernel R/W; decide if it is enough for the intended debugging use.
  _Done 2026-09-11 (route A implemented): `terminal/trm_shell.c` — 39
  commands, in-process, no exec and no pty. Filesystem (ls -l/-a, cat,
  head, stat, mkdir/rmdir/rm -r, mv, cp, touch, chmod), process/system
  (id, uname, date, uptime, df, env, sleep, ps via sysctl, kernel-side
  `proc <name>`), and kernel R/W (`krw` status, `kread` hexdump,
  `kwrite8/16/32/64`, `sbxinfo` = label/sandbox/cred addresses, plus the
  probe commands `probe`/`verdict`/`execsurf`/`spawn`/`ptytest`/`ssvw`).
  Read-only by default; kernel writes, `rm -r`, `chmod` and the SSV
  write need an explicit `unsafe 1`. UI: a text field + RUN + TRM button
  under the HUD log panel (the panel's log view is the terminal)._
- [ ] `TRM.4` ⚪ — PTY + UI: posix_openpt/grantpt/unlockpt + a
  terminal view (UITextView-backed, or a WKWebView running xterm.js)
  wired to the pty master over a background queue; keyboard/ANSI
  handling; how the pty behaves inside the app sandbox after escape.
  _Instrumented 2026-09-11: the probe runs the full pty sequence
  (sandbox verdict on /dev/ptmx, posix_openpt, grantpt, unlockpt,
  ptsname, slave open, master→slave and slave→master round trip) with
  the errno of every step. The UI half is deliberately NOT built yet —
  it is wasted work if the profile denies /dev/ptmx (expected: it is a
  device-access rule our extension rewrite does not touch). The route A
  UI (text field + log view) ships now and needs no pty._
- [ ] `TRM.5` ⚪ — Privilege model: confirm the shell inherits uid=0 +
  the patched sandbox extensions after fork/exec (they should, since
  creds/extension sets are process attributes), and decide whether the
  terminal gets SSV write helpers (overwrite_system_file) or
  read/write only outside the sealed volume by default.
  _Instrumented 2026-09-11: `id`/`sbxinfo` report BOTH the posix creds
  and the kernel-side creds (uid/gid/groups[0] read through
  proc_ro→ucred), so an inheritance question becomes a one-line
  comparison; the probe adds a sealed-volume read/write verdict on
  SystemVersion.plist. Route A decision (implemented): kernel writes,
  `chmod`, `rm -r` and the SSV write helper (`ssvw` → ssv_write) are all
  behind `unsafe 1`, read-only is the default._
- [x] `TRM.6` ⚪ — Decide scope: is this a debug console for the
  developer (HUD-adjacent, gated behind w0lf_test_mode) or a user
  feature? Security boundary note required either way (a terminal with
  kernel R/W is the most powerful surface in the app).
  _Done 2026-09-11: debug console, shipped HUD-adjacent and always
  available (it needs no escape to start), NOT gated behind
  w0lf_test_mode — a terminal that only exists in test builds is useless
  for exactly the on-device debugging it exists for. Boundary: every
  command in the shell is read-only by default; kernel writes (`kwrite*`),
  `chmod`, `rm -r` and `ssvw` (SSV overwrite via ssv_write) return a
  refusal (rc=2) until the operator types `unsafe 1`, and the refusal
  line says why. `rm -r` additionally refuses `/`, `/System`, `/var`.
  Nothing in the terminal touches the main device's kernel without that
  explicit flag, so a stray tap on RUN cannot corrupt anything._

> First-pass findings (offline, 2026-09-11 — no device attached, so
> everything below is desk research + code reading, nothing is
> device-verified yet). Related older items, now cross-linked:
> `G3.1` (NewTerm/system()+posix_spawn probe) and `G3.2` (dropbear
> SSH server) — same question, asked before the escape existed.

> **1. There is no usable shell environment on stock iOS to spawn.**
> Apple's jailed root flist is thin: `/bin` ships essentially
> `sh`/`df`/`ps` and the rest of coreutils (bash, ls, cat, grep, tar,
> chmod…) is *jailbreak-provided* (Apple Wiki /bin); `/usr/bin` on a
> jailed device is `powerlog`, `simulatecrash`, a few more. So even a
> perfectly working `posix_spawn("/bin/sh")` yields a shell with almost
> no commands. Consequence: **TRM.2 (bundled static shell) is the
> primary route, not the fallback** — a static busybox-style
> multi-call binary in the app bundle is what makes a terminal useful.

> **2. The gate is the sandbox profile, not code signing.** Platform
> binaries are Apple-signed, so AMFI is not the wall. `process-exec`
> and device access (`/dev/ptmx` for the pty) are *profile rules*,
> while our escape rewrites hash-slot **extension paths** + the class
> to `com.apple.app-sandbox.read-write`. Extensions grant file access
> — they do not grant exec or device access. Expect
> `posix_spawn("/bin/sh")` and `posix_openpt()` to fail post-escape
> with EPERM/EACCES until the sandbox itself is relaxed. (This is why
> the jailbreak world needs `exechook.c` + `__SANDBOX_EXTENSIONS` on
> the spawned child *on top of* an already-patched system sandbox —
> see roothide/Bootstrap-basebin; NewTerm just borrows a relaxed
> sandbox.) We are the ones who have to relax it.

> **3. Three real routes, in order of cost.** (A) **In-process shell**
> (`TRM.3`): commands implemented in the dylib over POSIX + kread/
> kwrite. No exec, no pty, no sandbox dependency — works the moment
> the escape is live, but cannot run Apple's binaries. (B) **Sandbox
> credential relaxation**: with krw, clear/neutralise the process
> sandbox label (or copy a permissive label from an already-escaped
> daemon) so exec + `posix_openpt` pass; this is the jailbreak-
> equivalent unsandboxed state, highest power, and irreversible for
> that process — the whole app becomes unsandboxed, not just the
> terminal. (C) **Remote spawn through a privileged proxy**: use the
> existing `kexploit/RemoteCall.m` (TaskRop) machinery to make a
> daemon that legitimately owns exec rights spawn the shell, and pass
> `__SANDBOX_EXTENSIONS` so the child inherits file access. Most
> moving parts; also the only route that gives a *detached* shell
> (relevant to `G3.2`).

> **4. What on-device verification must answer** (attach the 26.0.1
> daily driver first): exact jailed exec surface
> (`ls -l /bin /usr/bin /usr/libexec`), the errno from
> `posix_spawn("/bin/sh")` after a completed escape, and whether
> `posix_openpt`/`grantpt`/`unlockpt` succeed — those three datapoints
> decide A vs B vs C. Until then `TRM.1` stays open and the honest
> recommendation is to build A (cheap, no unknowns) and probe B/C
> behind `w0lf_test_mode`.

### Round 2 (2026-09-11) — route A built, exec/pty probes wired

> Still no device attached, so the three datapoints above are still
> unmeasured. What changed is that the measurement is now automated and
> the recommended route exists as running code.

> **1. Route A is implemented and host-verified.** `terminal/trm_shell.c`
> (+ `trm_common.c`, `trm_probe.c`) is a 39-command in-process shell
> linked into the dylib: filesystem commands over POSIX, kernel commands
> over the escape (`kread`, `kwrite8/16/32/64`, `proc`, `sbxinfo`,
> `ssvw`), and the probe commands. It uses NO exec and NO pty, so it works
> the moment the escape is live and needs nothing from the sandbox
> profile. UI is a text field + RUN + TRM button under the HUD log panel
> (the log view is the terminal screen; the shell's output goes through
> TweakLog into the ring the panel already polls).
> `bash scripts/run_trm_host_test.sh` builds the shell on the host with
> kernel/mach stubs and runs 108 assertions (parser, path resolution,
> every filesystem command, unsafe gating, kernel command routing) —
> **108 checks, 0 failures** / `TRM_SHELL_HOST_TEST PASS` (the count grew with
> TRM.2's 13 redirect checks and TRM.1's 13 completion checks; the `65/65` this
> block used to quote is the ROUTE-A REVISION's own count, not a lie - T17
> replayed commit `8e97aa7` and it really prints `checks=65 failures=0`
> (`t17/revisions/trm_routea/`, sparse tree in-repo) - but the harness on disk
> now prints 108, so the old number must not be read as current). The number for
> THIS tree, re-run at T17 by the authorized suite
> (`bash scripts/check_host_verification.sh`, exit 0) as its
> `trm_shell_host_test` entry (that entry's command is
> `bash scripts/run_trm_host_test.sh`): the count line
> `checks=108 failures=0` is in that entry's raw log
> (`docs/verification/2026-09-11-0.12/t17/trm_shell_host_test.log`, a
> copy of the suite's own
> `t17/suite_logs/w0lf_host_verification/trm_shell_host_test.log`), while the
> suite's summary line is `host verification: 21 ok, 0 drift` and its entry for
> this harness reads
> `ok   trm_shell_host_test    rc=0 42305c27487f35be...` in
> `t17/host_verification.log` (the entry's raw hash moves between runs - the
> harness prints the live `date`/`df`/`loadavg`/tempdir - but that pinned
> canonical hash `42305c27487f35be...` is the same one
> `check_host_verification.sh` recorded at T12, so it is the same run), so
> parsing/dispatch bugs are caught without a sideload.
> Verification on the device build: `make package` clean, audit PASSED,
> and the shipped dylib contains the new markers
> (`TRM][EXEC`×6, `TRM][VERDICT`, `TRM2-CONTAINER-EXEC-OK`, …).

> **2. Deliberate limits of route A.** No ANSI/xterm (plain text into a
> UITextView), no globbing, no pipes, no redirection, no variables — the
> parser handles whitespace + quotes + `#` comments only. That is a
> security decision as much as a scoping one: a terminal with kernel R/W
> should not also grow a rich interpreter (word splitting, `$()`,
> redirection into an escaped filesystem). If xterm.js is wanted later,
> it belongs in front of a pty (TRM.4), not in front of this parser.

> **3. Precedent check (why A is not a compromise).** The App Store
> terminals all avoid exec: a-Shell/LibTerm implement commands
> in-process via `ios_system` (no spawning at all), and iSH ships a
> usermode x86 emulator running Alpine — its FAQ/community consensus is
> that creating executable pages is what fails review. MTJailed
> advertises a remote shell for non-jailbroken devices for the same
> reason. So "terminal with kernel R/W" in a sideloaded app realistically
> means in-process (A) unless we relax the sandbox label itself (B) or
> borrow a privileged daemon (C) — exactly the A/B/C split above.
> Refs: github.com/holzschu/a-shell, ish.app, github.com/MTJailed/MTJailed-Native.

> **4. The probes run themselves.** `trm_probe_run_all()` is called in
> TweakExploit's post-escape path right after `probeSystemPaths()`, and
> again from the HUD `TRM` button or the shell's `probe` command. One
> launch on the 26.0.1 daily driver therefore produces the full TRM.1-5
> dataset: the `sandbox_check` matrix, the per-directory exec inventory,
> `fork()`, the real `/bin/sh` spawn (rc + errno + captured output), the
> off-SSV copy-exec test, the pty sequence, and the sealed-volume
> read/write verdict — ending in one `[TRM][VERDICT]` line that names the
> route the measurements support. Pull it with
> `afcclient --documents <bundle> cat Documents/FilzaTweak.log | grep TRM`.

> **5. What is NOT done.** The pty UI (TRM.4's second half) is
> intentionally absent until the pty probe says /dev/ptmx is reachable —
> building a terminal view for a device we cannot open is wasted work.
> A real bundle-resident helper binary (TRM.2) needs a signed sidecar
> (Theos tool target + nested signing in `re-sign_mha.sh`), also deferred
> until TRM.1 says exec is reachable at all. Route B (neutralising the
> sandbox label with krw) and route C (spawning through a privileged
> daemon via `kexploit/RemoteCall.m`) are untouched: the shell's
> `sbxinfo` prints the exact sandbox object address route B would have to
> patch, and the `sbxtest` builtin re-measures the profile afterwards.

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

- [x] `A1.6` 🟡 — `ensureSSVActive` mutex deadlock possibility with `g_patching_in_progress`  
  _Verified 2026-08-25: ensureSSVActive releases ssv_mutex() before calling patch_sandbox_ext (mutex held only for state flags), and the exploit_is_patching()/in-flight checks short-circuit re-entry — no deadlock path._
  _Prompt:_ "Analyze the call graph of ensureSSVActive() → patch_sandbox_ext() → back to ensureSSVActive(). If any code path re-enters the mutex, we deadlock. Document or add a re-entrancy guard."

- [x] `A1.7` 🟡 — Hardcoded APFS fsnode offsets → named constants in offsets.h (v_data+0x70/0x80/0x84/0x88)  
  _Prompt:_ "Move v_data+0x80 (uid), +0x84 (gid), +0x88 (mode) from hardcoded magic numbers in permission_utils.m into named constants in offsets.h. Add per-iOS-version overrides. Same for FilzaPadlockBypass.xm v_data+0x70 (UF_IMMUTABLE)."

- [x] `A1.8` 🟡 — `runSSVDiagnosticsOnce` doesn't clean up on crash  
  _Fixed as A5.4: @try/@catch around NSFileManager ops in TweakExploit.m diagnostics._

- [x] `A1.9` 🟢 — `scheduleExploitOnce` double-registers notification observers  
  _Verified: the `dispatch_once` gate prevents double registration. Observer lifecycle is handled by NSNotificationCenter._

- [x] `A1.10` 🟢 — `TweakLog` is NOT thread-safe (fopen/fclose race) → pthread_mutex_t guard  
  _Prompt:_ "The shared TweakLog() in utils/tweak_log.h can have two threads calling fopen on the same path simultaneously. Add a pthread_mutex_t guard around the entire function."

- [x] `A1.11` 🟡 — `TweakLog` mutex deadlock if signal handler calls TweakLog → use trylock with stderr fallback  
  _Prompt:_ "Add pthread_mutex_trylock() to TweakLog. If the lock fails (held by another thread during signal handling), write to stderr instead. This prevents deadlock if an exception handler thread calls TweakLog while the main thread holds the lock."

- [x] `A1.12` 🔴 — `_Atomic bool` reads/writes need `memory_order_acquire`/`memory_order_release` for cross-thread visibility  
  _Prompt:_ "Replace bare `g_exploitDone = true` with `atomic_store_explicit(&g_exploitDone, true, memory_order_release)` and `if (g_exploitDone)` with `if (atomic_load_explicit(&g_exploitDone, memory_order_acquire))`. Same for g_patching_in_progress. Include <stdatomic.h>."

- [x] `A1.13` 🟡 — Add sanity check: verify APFS fsnode `mode & 0777` is ≤ 0777 before writing ownership fields  
  _Prompt:_ "In apply_permissions_kernel() in permission_utils.m, read the current mode from v_data+off_apfs_fsnode_mode before writing. Verify it's a valid POSIX mask (0-0777). If it's garbage, the offset is wrong and we should abort instead of corrupting kernel memory."

- [x] `A1.14` 🔴 — Verify thread/machine offsets for A16/A17/A18 on iOS 26.0.1 before any writes  
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

- [x] `A2.5` 🟠 — PadlockBypass removeItemAtPath kreads before exploit_is_done guard → kernel panic
  _Verified 2026-08-25: the A2.4 rewrite replaced all kernel-reading hooks with pure UI hooks (TG/TIGI classes) — FilzaPadlockBypass.xm contains zero kread/kwrite; nothing touches kernel memory pre-exploit._
- [x] `A2.6` 🟡 — Tweak.m zip hooks: unconditional (NSString*) cast on id → crash if non-NSString
  _Verified 2026-08-25: both zip hooks guard the cast — hook_ZipFiles line ~146 and hook_unZipFile line ~181 check isKindOfClass:[NSString class] before use._
- [x] `A2.7` 🟡 — Tweak.m unzip: char filename[512] may be unterminated → add null guard
  _Verified 2026-08-25: filename[sizeof(filename)-1]='\0' is set right after p_unzGetCurrentFileInfo64 — no unterminated string._
- [x] `A2.8` 🟡 — FilzaPadlockBypass: 11 sites pass [nil UTF8String] to TweakLog %s → SIGSEGV
  _Fixed 2026-08-25: tstr() nil-safe helper in utils/tweak_log.h; all 40 `[x UTF8String]` log-arg sites in Tweak.m now use tstr() — nil path can no longer SIGSEGV._
- [x] `A2.9` 🟡 — hook_createFileAtPath/writeToFile call ensureSSVActive AFTER %orig — too late
  _Verified 2026-08-25: all SSV hooks (createDirectoryAtPath, copyItemAtPath, moveItemAtPath, createFileAtPath, writeToFile) call ensureSSVActive() BEFORE %orig._
- [ ] `A2.10` 🟢 — Zip hooks block main thread on large archives — no background dispatch

- [x] `A2.11` 🟡 — TweakInit: stale /var/mobile/.sbx_check falsely skips exploit (H2,H3)
  _Fixed 2026-08-25: a stale .sbx_check can no longer skip the exploit — the already-escaped path is taken only when check_sandbox_var_rw() confirms rw; otherwise TweakInit falls through to the exploit scheduling. Verified live on SE 18.4.1 (jailbroken path unchanged)._

---

## A5 — SSV & Sandbox Escape Stability (audit 2026-08-10)

- [x] `A5.1` 🔴 — sandbox_escape.m:114 — non-null-terminated string written to kernel memory  
  _Fixed 2026-08-13: prior state was KRW_LEN=0x21 (33) — which itself violated the early_kread primitive limit (EARLY_KRW_LENGTH=32 → FAILURE on every patch_ext/set_rw_class call). Now: KRW_LEN = EARLY_KRW_LENGTH (32), the 32 name chars are written at da+32 and the NUL terminator is supplied by the zeroed buffer written at da+64. Added `_Static_assert` that the class name is exactly 32 chars, memset hardening on all buffers, and aligned uint64 hb buffer. Verified: full Theos build passes._

- [x] `A5.2` 🔴 — SSV/SSVUtils.m:35 — patch_sandbox_ext() called with zero exploit guard  
  _Fixed 2026-08-13 (hardening; base guard existed but was incomplete): exploit_is_done() moved to the TOP of ssv_write (before temp-file work, no leaked tmp), patch_sandbox_ext() return value now checked (abort + cleanup before kernel vnode writes on failure), and the truly ungated paths got guards: ssv_chown_root, ssv_dump_fsnode, apply_permissions_kernel (permission_utils.m), research_vnode_apfs_fsnode (vnode_research.m). No more kernel-memory access without a live exploit._

- [x] `A5.3` 🟠 — TweakExploit.m attemptCount race: static int without synchronization  
  _Verified 2026-08-25: attemptCount is already `static _Atomic int` with atomic_fetch_add — no race._
  _Multiple dispatch_after blocks fire in parallel, all increment same static int. 2 blocks see attemptCount==2 → both proceed as attempt 3 → parallel sandbox_escape corrupts kernel memory._

- [x] `A5.4` 🟠 — TweakExploit.m diagnostics: NSFileManager ops lack @try/@catch → SIGABRT  
  _Verified 2026-08-25: diagnostics block already wrapped in @try/@catch (NSException) — no SIGABRT on exception._
  _dispatch_once block calls createDirectory/removeItem without exception handler. Exception in block = process kill._

- [x] `A5.5` 🟡 — utils/tweak_log.h: localtime() not thread-safe + can return NULL → crash  
  _Verified 2026-08-25: tweak_log.h uses localtime_r with stack struct tm on both log paths._
  _Switch to localtime_r with stack-allocated struct tm._

- [x] `A5.6` 🟡 — utils/tweak_log.h: no NULL check on format param → vfprintf(NULL) SIGSEGV
  _Verified 2026-08-25: TweakLog guards `if (!format) return;` at entry._

- [x] `A5.7` 🟡 — sandbox_escape.m: ucred scan does ptr_in_kernel() but not mapping-aware
  _Done 2026-08-29: ptr_in_kernel_mapped(p, anchor) added (KPTR_WINDOW 1 GiB) — range + alignment + window around a known-mapped anchor. Applied to the proc_ro ucred scan candidates (smr/pac, anchored on proc_ro), the scan's inner label/sandbox probes (anchored on the parent), and the post-scan chain (label←ucred, sandbox←label, ext_set←sandbox). Rationale: the DarkSword kread primitive dereferences the VA in kernel context, so an in-range-but-unmapped candidate (garbage struct field) = data abort = panic; zone objects referenced by a parent sit within a GiB of VA of each other. is_kaddr_valid kept for the generic API (docs/KERNEL_PRIMITIVES_API.md). make package: 0 errors._

- [x] `A5.8` 🟢 — SSV/SSVUtils.m: fd leak on rename fallback failure → ulimit exhaustion
  _Verified 2026-08-25: SSVUtils rename-fallback closes both fds on every path (unconditional closes after the copy loop)._
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

- [x] `A6.6` 🟠 — W0lfSword script: `eval` in retry() → code injection surface  
  _Fixed 2026-08-25: retry() no longer evals a command string — takes the command as separate words ("$@"), all 4 call sites converted. No shell-string injection surface._
  _Replace with array-based command execution._

- [x] `A6.7` 🟠 — kexploit_opa334.m: 15+ file-scope vars missing `static` → pollute namespace  
  _Add static to readFd, writeFd, controlSocket, rwSocket, socketPorts, etc._

- [x] `A6.8` 🟡 — kexploit_opa334.m: hardcoded `sleep(8)` for A18 — undocumented delay  
  _Document why 8 seconds is needed, or investigate if still required._

- [x] `A6.9` 🟡 — kexploit/offsets.m:631 `printf("hello from roooot!\n")` debug joke in production  
  _Remove or wrap in #ifdef DEBUG._

- [x] `A6.10` 🟡 — Tweak.m: 6+ `NSLog()` sites should be TweakLog for unified logging
  _Fixed 2026-08-25: all 7 NSLog() sites in Tweak.m converted to TweakLog/TweakNSLog — unified logging, no more untagged stderr noise._
- [x] `A6.11` 🟡 — kutils.m: proc_get_p_name static buffer not thread-safe
  _Fixed 2026-08-25: proc_name is now static __thread — proc_find loops on different threads can't clobber each other's name buffer._
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

- [x] `A3.5` 🟡 — Wired page leak in pe_v2 error path  
  _Fixed 2026-08-25: wired_pages_cleanup() helper (munlock + deallocate) now runs on ALL pe_v2 exit paths — alloc-failure fallback, search-mapping alloc failure, mach_make_memory_entry_64 failure, and the success path. No mlock'd wired page leaks in release (NDEBUG) builds where FAILURE returns._
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

- [x] `A3.12` 🟠 — kexploit_opa334.m:461, RemoteCall.m:273 — while(1){} hangs on invalid address  
  _Verified 2026-08-25: the cited while(1) sites (kexploit_opa334.m:461 race spin, RemoteCall.m:273 wait_exception) are already bounded (10M-iter spin + FAILURE, wait_exception timeout + destroy_remote_call cleanup). Extra hardening: kernel-base scan loop (kexploit_opa334.m) now bounded at 0x100000 iterations with FAILURE instead of scanning forever._
  _Use FAILURE(0) or return error instead of permanent hang._

- [x] `A3.13` 🟠 — kexploit_opa334.m:95-101 — volatile without _Atomic for cross-thread sync race  
  _Fixed 2026-08-25: goSync/raceSync/freeThreadStart/freeTarget/freeTargetSize/targetObject/targetObjectOffset now use __atomic_load_n/__atomic_store_n (ACQUIRE/RELEASE) at every cross-thread access — ARM weak memory can no longer lose the race. mach_vm_map result goes through a local then publishes atomically._
  _goSync, raceSync, targetObject etc. use volatile not _Atomic. ARM weak memory → stale reads → race lost._

- [x] `A3.14` 🟠 — RemoteCall.m:242 — unhandled exception leaves target thread suspended (H7)  
  _Verified 2026-08-25: wait_exception timeout path returns 0 with an explicit 'cleanup will handle' note; destroy_remote_call() sends EXC_CRASH replies / restores the thread — no permanently suspended thread._
  _No reply sent on timeout → thread stuck with pending EXC_GUARD forever._

- [x] `A3.15` 🟠 — vnode.m:22 — static vp_name[256] buffer race across threads (M1)  
  _Verified 2026-08-25: vnode_get_v_name already serializes with a pthread_mutex and is dead code (no callers; vnode_get_v_name_into is used instead)._
  _vnode_get_v_name returns pointer to file-scope static. Concurrent callers see corrupted names._

- [x] `A3.16` 🟡 — RemoteCall.m:368 — SHMEM cache full with no eviction after 100 pages (M2)
  _Fixed 2026-08-25: put_shmem_in_cache no longer drops the new mapping when the 100-entry cache is full — FIFO-evicts the oldest slot (releases its memory-object port + local PAGE_SIZE mapping first). remote_read/write no longer fail spuriously past 100 distinct pages._
- [x] `A3.17` 🟡 — sandbox.m:172 — unvalidated class_name kernel pointer in kreadbuf (M3)
  _Verified 2026-08-25: sandbox.m class_name read is guarded with is_kernel_ptr() before kreadbuf — invalid pointers are skipped, not dereferenced._
- [x] `A3.18` 🟡 — offsets.m — 0xdeaddead sentinel could alias valid offset (M4)
  _Fixed 2026-08-25: Thread.m kwrite64 sites guarded against the 0xdeaddead sentinel (thread_set_pac_keys jop/rop pid; inject_guard_exception guard-exc-info branch; mach_exc_info branch zero-guarded) — no more writes through sentinel offsets._
- [x] `A3.19` 🟡 — kutils.m:17 — gSelfProc/gSelfTask cached without atomic reads/writes (M5)
  _Verified 2026-08-25: gSelfProc/gSelfTask already use __atomic_load_n/__atomic_store_n (RELAXED/RELEASE)._
- [x] `A3.20` 🟢 — kexploit_opa334.m:175 — calloc result unchecked for NULL (L4)
  _Fixed 2026-08-25: init_target_file calloc results checked (FAILURE on NULL) — the two remaining unchecked calloc sites._
- [x] `A3.21` 🟢 — RemoteCall.m:549 — pthread_create_suspended_np failure unchecked (L5)
  _Verified 2026-08-25: pthread_create_suspended_np return value checked with an explicit failure path._
- [x] `A3.22` 🟢 — VM.m:186 — memoryObject mach port leaked on entry validation failure (L6)
  _Verified 2026-08-25: VM.m deallocates localAddr + mach_port_deallocate(memoryObject) on both failure paths (make-memory-entry failure, submap/kernel-object validation failure)._

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

## C4 — Framework Attack Surface: Audio & Media (campaign 2026-08-29)

> Goal: find buffer overflows and other memory-safety bugs in Apple's
> media frameworks, starting with audio decoding. Deliverables: attack
> surface map, CVE catalog, open-source audits (ALAC / CoreAudio),
> fuzz harness, BUG_BOUNTY entries. IPSW/kernelcache work via
> kernel-deltas only if a finding needs offsets.

- [x] `C4.1` ⚪ — Audio framework attack surface map: AudioToolbox
  (AudioFile, AudioFileStream, AudioConverter, ExtAudioFile, AudioQueue,
  AudioCodec), CoreAudio, CoreMedia audio paths. Formats: CAF, WAVE, AIFF,
  MP3, AAC/ADTS, ALAC, FLAC. Entry points for fuzzing.
  _Prompt:_ document in research/audio_frameworks.md
  _Done 2026-08-29: research/audio_frameworks.md._
- [x] `C4.2` ⚪ — CVE catalog for audio decoding (2015-2026): component,
  root cause class, fixed version, live-vs-patched on 18.4.1 / 26.x.
  Confirmed live bugs go to BUG_BOUNTY.md.
  _Done 2026-08-29: catalog merged into research/audio_frameworks.md +
  other_frameworks.md (audio CVEs incl. P0 CoreAudio fuzzing
  CVE-2024-54529, CVE-2025-31200 APAC HOA decoder)._
- [x] `C4.3` ⚪ — Audit open-source Apple audio code for overflows:
  apple/ALAC decoder, apple-oss-distributions/CoreAudio,
  AudioVideoBundles. Evidence per finding (file:line, trigger, impact).
  _Done 2026-08-29: CoreAudio/AudioVideoBundles absent from the org
  (verified). ALAC audit: partialFrame heap overflow + cookie OOB read ASAN-verified, harnesses in
  research/alac_poc/._
- [x] `C4.4` ⚪ — Audio fuzz harness reusing K4.2 patterns: ALAC/CAF/WAV
  seeds, structure-aware mutator, host-side (libFuzzer/AFL++ if
  feasible) then on-device probe on SE 18.4.1 (ExtAudioFile /
  AVAudioPlayer decode).
  _Done 2026-08-30 (host side): fuzz_alac.cpp libFuzzer target
  (cookie + packet input, custom mutator on partialFrame/numSamples),
  gen_seeds.cpp encoder-vended corpus (mono/stereo, 16/24/32-bit).
  Wired `./W0lfSword poclab test alac-fuzz [secs]`; 30-60s finds the
  unpc_block READ OOB (dp_dec.c:99), dyn_decomp WRITE (ag_dec.c:345,
  compressed path) and BitBufferRead OOB (ALACBitUtilities.c:48).
  On-device probe hardware-gated (no phone)._
- [x] `C4.5` ⚪ — Other framework targets: CoreMedia sample buffers,
  CoreText fonts, PDFKit, libxml2, ICU, mDNSResponder, Quick Look.
  Rank by open-source availability, parser size, CVE density.
  _Done 2026-08-29: research/other_frameworks.md — 8 targets ranked,
  top lead CVE-2025-43400 FontParser live on 18.4.1._
- [x] `C4.6` ⚪ — IPSW userspace extraction: rootfs DMG is encrypted;
  only the kernelcache is extractable via the kernel-deltas pipeline.
  Notate as blocked if keys unavailable.
  _Done 2026-08-29: confirmed blocked — userspace frameworks come from
  the on-device dyld shared cache (blacktop/ipsw), not IPSWs._
- [x] `C4.7` ⚪ — Tracker entries for confirmed findings with
  evidence (file:line, trigger, impact, bounty category).
  _Done 2026-08-29: ALAC heap overflow, ALAC cookie OOB read, FontParser OOB write logged._

---

## C5 — CVE Hunting + Attack Chains (campaign 2026-08-29, 26.1+ direction)

> Goal: find CVEs across exploit types, chain the live bugs into usable
> attack chains, wire the catalog into the CLI. Kernel gate on 26.1+ is
> still closed (DarkSword patched); userspace modules (bad_query, MCM)
> are the 26.1+ delivery. Chains documented in research/attack_chains.md,
> CVE catalog in the CLI + research docs.

- [x] `C5.1` ⚪ — Kernel CVE hunt (26.1+): xnu bugs fixed in iOS 26.1–26.6.x.
  LPE candidates that could re-open the kernel gate (K5.6) or serve as a
  chain's final stage. Include CVE-2025-46285 (K4.7, 64-bit timestamp
  integer overflow) and any P0/ZDI 2025-2026 kernel findings. Note
  reachability (local app? sandboxed? remote?) and PoC availability.
  _Done 2026-08-29: research/kernel26_cves.md. Top-10 ranked candidates;
  DirtySlide is the only public-knowledge kernel-write path; AVEVideoEncoder
  CVE-2026-64747 is the highest-impact unknown (kernel code exec)._
- [x] `C5.2` ⚪ — Userspace CVE hunt: sandbox escape + TCC bypass + SSV
  bypass, 2025-2026, iOS 17-26. Live-vs-patched on 18.4.1 (SE2) and
  26.x. Skip already-ported bugs (bad_query K4.10, MCM/mha K4.12).
  _Done 2026-08-29: research/userspace_escapes.md. bl_sbx write-escape
  + CVE-2025-43329 sandbox escape. No iOS SSV CVEs 2025-26._
- [x] `C5.3` ⚪ — Attack chain designs: chain the live bugs (bad_query
  read-escape, MCM container access, FontParser 18.4.1 OOB write, kernel
  R/W ≤26.0.1) into 3-5 concrete chains with per-version applicability,
  prerequisites, and delivery surfaces. Mine public chain writeups
  (CVE-2025-31200+31201 iMessage, Glass Cage, FORCEDENTRY) as templates.
  _Done 2026-08-29: research/attack_chains.md — 7 chains (A-G) with
  implementation %, per-version tables, CLI automation needs._
- [x] `C5.4` ⚪ — W0lfSword CLI: add `chains` (attack chain catalog +
  per-device status) and `cve` (CVE tracker: id, component, class,
  fixed-in, live-on) commands; update the `exploits` matrix with 26.1+
  userspace chains. 5-place menu wiring, bash -n + audit verification.
  _Done 2026-08-29: cmd_chains + cmd_cve wired (dispatch/menu/menu_opt n/
  help/explain); exploits matrix updated; README commands table; verified._
- [x] `C5.5` ⚪ — Documentation: research/attack_chains.md + CVE catalog
  doc; tracker entries for confirmed live findings.
  _Done 2026-08-29: research/attack_chains.md + kernel26_cves.md +
  userspace_escapes.md._

---

## C6 — PoC Lab (campaign 2026-08-29, test the found bugs)

> Goal: take the found-but-unimplemented bugs, build and run proof-of-
> concepts where the host allows, and write up why each one works or
> doesn't. The `poclab` CLI tab lists every concept with a runnable
> test or a blocker. Docs in research/poclab.md.

- [x] `C6.1` ⚪ — ALAC PoCs (partialFrame heap overflow + cookie OOB read):
  re-verify both harnesses under ASAN on this host,
  wire `poclab test alac` to build + run them against a cloned
  apple/ALAC. Expected: heap-buffer-overflow WRITE + READ. Why it works: the reference decoder never bounds the
  bitstream numSamples against the cookie-sized buffers.
  _Done 2026-08-29: scripts/poclab_test_alac.sh (clone cached in
  .w0lfsword/poclab/alac) builds both harnesses and both ASAN
  signatures reproduce: heap-buffer-overflow WRITE at
  ALACDecoder.cpp:309, stack-buffer-overflow READ at :102. Verdict
  logic fixed once (set -euo pipefail turned the expected crash exit
  into a pipeline failure; capture with || true instead)._
- [x] `C6.2` ⚪ — libxml2 fork-diff: clone apple-oss-distributions/Libxml2
  and GNOME upstream, compare versions + fix coverage. Expected result:
  list of upstream security fixes Apple's fork has not synced, or
  confirmation it is current. Wire `poclab test libxml2-diff`.
  _Done 2026-08-29: TESTED-NEGATIVE, honest. Apple's fork is 2.9.13
  (209013) vs upstream 2.15.0 (21600) but backports selectively:
  CVE-2024-25062 reader guards + modern xmlParseInternalSubset present.
  The nextCatalog dedup loop (f75abfca) is absent, but the c632489
  NULL-deref fix guards only that loop, which Apple's code does not
  have, so no exploitable divergence in the three malformed-catalog
  shapes tested (scripts/poclab_cat.c). Real side findings: fork does
  not compile on Linux without 2 patches (uri.c stdint, xpath.c Darwin
  symbol stub)._
- [x] `C6.3` ⚪ — mDNSResponder: try the Linux build (mDNSPosix), smoke
  test the daemon. If it builds: candidate for the CVE-2015-7987-class
  record-decoder fuzz later; if not, note the blocker.
  _Done 2026-08-29: BLOCKED — mDNSPosix needs mbedTLS, the clone does
  not vendor it, the mbedtls source needs its own submodules, and this
  host has no passwordless sudo for libmbedtls-dev. Dependency chain,
  not a code problem; the Makefile targets Linux explicitly. Left for
  when deps are available._
- [x] `C6.4` ⚪ — Why-not-testable analysis (host-side): DirtySlide
  (macOS-only kernel, SPTM on A17+), bl_sbx (needs AFC/USB + device),
  FontParser 43400 diff (needs dyld caches), CVE-2025-46285 (needs a
  26.1 device), APAC (patched on 18.4.1). Each gets a blocker entry in
  poclab + a short doc.
  _Done 2026-08-29: all nine concepts documented in research/poclab.md
  with status + reason + repro._
- [x] `C6.5` ⚪ — `poclab` CLI tab: list (all concepts + status),
  test <id> (runs the host-side test), status (tested / blocked /
  needs-device). 5-place menu wiring, new menu entry.
  _Done 2026-08-29: cmd_poclab + poclab_concepts wired in all 5 places
  (dispatch, menu case, menu_opt o "PoC Lab", cmd_help, explain_text +
  Available list). `poclab list` renders the table; `poclab test alac`
  and `poclab test libxml2-diff` verified through the CLI. bash -n +
  audit pass._
- [x] `C6.6` ⚪ — research/poclab.md + per-bug docs: plain language,
  why it works or doesn't, exact repro, evidence. No AI filler.
  _Done 2026-08-29: research/poclab.md (9 concepts, terse plain style),
  index row in research/README.md, README commands table rows._

---

# SECTION D: Code Quality & Architecture

## D1 — Refactoring

- [ ] `D1.1` 🟡 — Split Tweak.m into multiple files  
  _Prompt:_ "Tweak.m is 1218 lines and does too many things: hooks, exploit orchestration, SSV activation, diagnostics, logging, UI bypass. Split into: TweakHooks.m (all method swizzling), TweakExploit.m (runExploit + retry), TweakDiagnostics.m (runSSVDiagnosticsOnce), TweakUI.m (uiDebugBypass flag). Keep Tweak.m as the %ctor entry point only."

- [ ] `D1.2` 🟡 — Create a `state.h` for all global state  
  _Prompt:_ "Move g_exploitDone, g_patching_in_progress, g_ssv_active, g_ui_debug_bypass, and all static globals scattered across files into a single state.h/state.m module with getter/setter functions. This makes state transitions auditable and prevents extern spaghetti."

- [x] `D1.3` 🟡 — Replace printf()/NSLog() with TweakLog() in sandbox.m borrow + sandbox_escape.m (all 18 calls)  
  _Prompt:_ "Offsets.m, sandbox.m, vnode.m, file.m, kutils.m, krw.m all use printf() for debug output. These go to stdout which in Filza goes nowhere (the app doesn't have a TTY). Replace all with TweakLog() so debug output actually reaches the log file. Add a compile-time flag to disable verbose kernel debug in release builds."

- [x] `D1.4` 🟢 — Add error code enum for all functions  
  _Done 2026-08-25: utils/errors.h — TWEAK_OK / TWEAK_ERR_EXPLOIT_FAILED / TWEAK_ERR_SANDBOX_ESCAPE_FAILED / TWEAK_ERR_SSV_ACTIVATION_FAILED / TWEAK_ERR_KERNEL_PTR_INVALID / TWEAK_ERR_INVALID_ARG. sandbox_escape.m converted (10 return sites; all callers check ==0/!=0 so semantics unchanged). Remaining functions convert incrementally._
  _Prompt:_ "Right now functions return 0, -1, or a magic number. Create an error code enum: TWEAK_OK, TWEAK_ERR_EXPLOIT_FAILED, TWEAK_ERR_SANDBOX_ESCAPE_FAILED, TWEAK_ERR_SSV_ACTIVATION_FAILED, TWEAK_ERR_KERNEL_PTR_INVALID, etc. Use consistently."

- [x] `D1.5` 🟢 — Add `__attribute__((cleanup))` for fd/port cleanup  
  _Added utils/scoped.h with scoped_fd, scoped_port, scoped_free macros._

- [x] `D1.6` 🟡 — CLI surface: one command registry + script layout reorg (v1.5.0)  
  _Done 2026-09-10: `W0LF_COMMANDS` inside W0lfSword is the single source of truth (name|slot|shortcut|aliases|group|label|summary|tag|docs|handler, 49 rows). The menu rows, the shortcuts line, explain's "Available:" list and the new `commands (cmds)` index are generated from it; `menu_dispatch` resolves every interactive key (slot/shortcut/alias/name, case-insensitive) through it, so a key can no longer be advertised without being wired. Layout: a generated MAP at the top lists all 39 numbered section banners; the UI primitives (line/section/ok/err/warn/info/stage/hint, menu_group/menu_opt, banner, disclaimer, show_header, spinner) moved into one UI FOUNDATION section (they used to sit between kcwatch and the wolf art under a stale banner); `cmd_report` moved next to `cmd_crashlog`; `cmd_clean`/`cmd_doctor` next to `cmd_audit`; new banners for USB TEST / PANIC ANALYZER / KERNELCACHE (previously all hidden inside "GLOBAL FLAGS", now "CORE HELPERS"). Menu regrouped: usbliter8 into exploit, PoC Lab into research, row 0 renamed "Panic PoCs" (it is not the PoC lab), row `n` now shows the CVE tracker its label promised. Bugs found and fixed on the way: `sf` (safe) was advertised in the shortcuts line but had no menu case; the shortcuts line omitted n/o/sbt/ex and printed literal `\033[..` escapes (color var passed as a %s arg); the menu loop spun forever printing "Unknown" on EOF stdin (spinning loop = 1279 lines in 25s, now exits clean). Version 1.4.0 → 1.5.0 (script + control, now checked). Verified: bash -n, shellcheck clean, dead-fn scan 167 defs/0 dead, 43 repo shell+python files parse, cli_consistency 49 commands/39 sections/0 findings, audit PASSED, menu smoke test (PTY + piped keys: cmds, lab, a bogus key, x, q) and every legacy alias (cfg/t/ch/o) still resolves._

---

## D2 — Testing Infrastructure

- [x] `D2.1` 🟡 — Unit tests for offset table  
  _Done 2026-08-25: scripts/test_offsets.py — parses offsets.m threshold blocks; validates strictly-increasing thresholds, per-threshold cumulative resolution of 4 critical offsets, and XPF-verified itk_space mapping (17.x=0x300/18.x=0x318/26.x=0x310). 0xdeaddead sentinels reported as notes (writes guarded since A3.18). PASSING. Wired into regression.sh._
  _Prompt:_ "Write a test script (Python or Swift) that reads /var/mobile/Documents/kernel_offsets.json (from B4.2) and validates: all offsets are non-zero, ptr fields are within VM_MIN/VM_MAX, sizeof fields are reasonable (<4096), no duplicates. Run after each iOS version bump."

- [x] `D2.2` 🟡 — Regression test script  
  _Done 2026-08-25: scripts/regression.sh — bash -n + py_compile + test_offsets.py + audit + doctor + make package + live-device smoke (SSH, status, tweak log pull). 8/8 green on SE. Uses grep -c not grep -q (grep -q + pipefail = false failure via SIGPIPE)._
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
  _See §0.11 (TRM.1-TRM.6) — desk research says the escape alone does NOT unlock exec (extensions grant file access, not process-exec), and jailed iOS has almost no coreutils to spawn. The three candidate routes are laid out there._

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

- [x] `J2.3` 🟢 — Auto-detect profile on startup  
  _Done 2026-08-25: main() auto-loads .w0lfsword/profiles/default.json on startup when no active profile exists (skipped for profile commands and --json)._
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

- [x] `J6.4` 🟡 — Panic log analyzer: `panic analyze` classifies .ips/panic logs (kernel/SEP/MTE/userspace) and maps to known CVEs
  _Done 2026-08-24: scripts/panic_analyzer.py (pure stdlib) — rules for SEP exhaustion (0x0006fe9x/0x6fea7), AppleJPEGDriver UAF (CVE-2026-20687), DirtySlide (CVE-2026-43724), DarkSword class (CVE-2025-43520), EXR (CVE-2026-28990), MCM activity. CLI: `panic list|fetch [ip]|analyze <file>` (menu `p`)._

- [x] `J6.5` 🟢 — Kernelcache diff: offline XPF offset research (K4.1 automation) — resolve/diff kernelcaches, extract from IPSW
  _Done 2026-08-24: `kernelcache resolve|diff|extract` (menu `k`) — runs tools/xpf-cli on IMG4 kernelcaches (no device), scripts/xpf_diff.py compares resolved tables (identical/changed/one-sided), extract pulls kernelcache.release.* from an IPSW zip with auto board detection._

## J7 — Polish

- [x] `J7.1` 🟢 — Arctic wolf ASCII art + themed header  
  _Done: show_header() with ╔═╗ box, arctic palette consistent with main W0lfSword._

- [ ] `J7.2` 🟢 — Sound on exploit success (optional, macOS only)  
  _Still open: this host is Linux (the CLI must not shell out to `afplay`), so it needs a macOS-gated path before it can be written honestly._

- [x] `J7.3` 🟢 — Colored diff output comparing builds  
  _Done 2026-09-11 (with J8.6): `./W0lfSword diff [--staged|--stat|<rev>|<revA> <revB>]` runs git diff through scripts/colorize_diff.py, which colours the CODE inside the +/- lines per language (ObjC/C keywords, types, strings, comments; python and shell rules; the extensionless CLI itself maps to shell). Colour auto-detects a TTY so piped output stays plain; --color=always / --no-color / NO_COLOR override. Host tests: tests/test_colorize_diff.py (19 checks, includes the pass-through and the process-level CLI contract)._

## J8 — Beta UX (newly added 2026-08-10)

- [x] `J8.1` 🟡 — Clear screen on menu entry / re-draw support  
  _Done 2026-09-11: `screen_reset()` now backs the menu's redraw path, emitting ANSI cursor-home + clear-to-end instead of `clear`, so terminals stop scrolling the old frame out; non-TTY / TERM=dumb falls back to a newline so piped logs stay clean._

- [x] `J8.2` 🟢 — Default profile auto-load on startup  
  _Done 2026-09-11: `profile_autoload()` runs on menu entry and silently applies `.w0lfsword/profiles/default.json` (device IP, exploit method, target bundle) via the new shared `profile_apply()`; a missing default profile is a no-op, not an error._

- [x] `J8.3` 🟢 — Verbose mode remembers state across menu sessions  
  _Done 2026-09-11: `:verbose` (also `:verbose on|off`) toggles verbose inside the menu and persists it to `.w0lfsword/state/verbose`; `verbose_restore()` reads it back on menu entry. Direct commands keep the -v flag as the per-invocation override._

- [x] `J8.4` 🟢 — ASCII progress bar during Quick Exploit wait period  
  _Done 2026-09-11: `progress_bar <cur> <total> [label] [width]` renders `[▓▓▓▓▓░░░░░]  50%` in place; both wait loops (quick 3/4 and adderall 3/5) use it instead of accumulating dots. Guards non-numeric input (returns 1, no crash) and never emits colour vars as %s arguments._

- [x] `J8.5` 🟢 — Exploit profile: per-app target selection  
  _Done 2026-09-11: `profile save <name> [--target <bundle-id>] [--method <exploit>] [--retries N]`; the target is stored, shown in `profile list`, restored by load/autoload into `PROFILE_TARGET`, and seeds the quick path's `TARGET_BUNDLE` (detection on the phone still refines it). Profile fields are read through `profile_field()` with argv-passed paths, so a profile name containing a quote or space can no longer break the python one-liner._

- [x] `J8.6` 🟢 — Color-coded diff subcommand  
  _Done 2026-09-11 with J7.3 (one implementation, both items): the `diff` command (alias `df`, housekeeping group, explain docs) + scripts/colorize_diff.py. Also fixed two pre-existing bugs found while wiring it: the profile list's active marker printed literal `\033[..m` escapes, and a root-owned `.w0lfsword/active_profile` (from an earlier sudo run) aborted `profile save` with a raw shell error instead of a warning + chown hint._

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

- [x] `K1.6` 🟠 — Add kfd/PUAF fallback options as menu choices beside DarkSword  \
  _Done 2026-09-05 (CLI half; MoE round deleg_58bba46a, parent-verified): exploit_method_valid() (after select_exploit) validates a method pick against select_exploit()'s per-model mapping (puaf-* needs the A9-A11 puaf family, pe_v1 A12-A17/M1-M4, pe_v2 A18; auto always ok); Phase 6 ask_choice list extended to "auto pe_v1 pe_v2 puaf-physpuppet puaf-smith puaf-landa"; mismatch goes through confirm() (keep with warning, else fall back to auto); puaf-* deploy prints the honest "kfd puaf backend not ported (F1.x) - deploying DarkSword pe_v1/pe_v2" line (EXPLOIT_METHOD consumer audit: profile save/load + display only, no build-arg consumer); profile load warns when restoring a puaf-* method. Mock test 17/17 (real functions extracted + stubbed warn/confirm). bash -n + audit + shellcheck clean. BACKEND STAYS OPEN: the kfd kopen/kread/kwrite port is ROADMAP F1.x research - puaf-* picks are carried, never faked._

- [ ] `K1.7` 🟡 — Auto-select best exploit per device in adderall  
  _Prompt: "Enhance the DEV_MODEL case statement: A12-A17 → pe_v1, A18 → pe_v2, A10-A11 → puaf fallback, unsupported → warn and offer kernelcache-pull + XPF route."_

- [ ] `K1.8` 🟡 — Menu shows compatibility per exploit and greys out unsupported choices  
  _Prompt: "In the interactive exploit picker, dim options that don't support the connected device's iOS/SoC instead of letting the user pick a guaranteed-to-fail combo."_

- [x] `K1.9` 🟢 — Expose exploit method in `profile save/load`  
  _Done 2026-08-25: EXPLOIT_METHOD is now a global (set by cmd_adderall); profile save writes it, load restores it (global + info line), list shows it._
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

- [x] `K5.9` 🟡 — CLI: auto-select the best chain per device in the exploit menu
  _Done 2026-08-29: select_best_chain(ver, model) + `chains best [iosver] [model]` (auto-detects USB→ideviceinfo, else saved-IP SSH). Order per prompt: DarkSword offsets + A12+ → K5 A (stages: chains b); 16.x → K5 E (kfd, pending); A9–A11 → K5 D checkm8; A12/A13 on 26.x → K5 D usbliter8 (RP2350); else 26.1+ → K5 B userspace (stages: chains a). Verified: 18.4.1/A13→A, 26.1/A16→B, 26.1/A13→D-usbliter8, 26.0.1/A16→A, 16.5/A9→E, 17.2/A11→D-checkm8. bash -n + audit pass._

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
| K — Exploit Menu & Beginner-Friendly Reform (added 2026-08-13) | 54 | 29 | 25 |
| **TOTAL** | **290** | **150** | **140** |

---

*Last updated: 2026-08-14 — K4.1 closed: XPF offline diff of 26.0.1 vs 26.1 kernelcaches (tools/xpf-cli) — structs identical, offsets.m 26.0.x block applies; task.itk_space 0x310-vs-0x318 discrepancy flagged for on-device check*

---

# SECTION L: W0lfSword .ipa — Exploit Hub App (added 2026-08-25)

> **Goal:** a standalone iOS app (sideload/TrollStore installable) that is an
> exploit hub: sandbox escape testing, privilege escalation verification,
> SSV bypass, kernel-status dashboard, and log/crash views — reusing the
> W0lfSword kexploit engine instead of reimplementing anything.
>
> **Why:** the tweak today lives inside Filza. A hub app gives the same
> capability set a first-class home: tap-to-run tests, clear pass/fail
> results, and no dependency on Filza's UI. Also the natural delivery
> vehicle for B1.4/F3.1 (standalone .ipa, no jailbreak required).
>
> **Architecture decision (L2.1) drives everything below.** Reuse rule:
> kexploit/, sandbox_escape.m, SSV/, utils/ get compiled into ONE shared
> engine (static lib `libw0lfengine`), and the app is a thin UI over it.

## L1 — Concept & Scope

- [ ] `L1.1` 🟠 — Define the app: name, icon, target iOS 15.0+, arm64/arm64e universal. Name suggestion: **W0lfSword Hub**.
- [ ] `L1.2` 🟠 — Decide delivery: TrollStore .ipa (no dev account) primary; adhoc sideload secondary. Document both in README.
- [ ] `L1.3` 🟡 — Write the feature list in the app README: sandbox escape tests, privilege escalation (root creds), SSV bypass toggle, kernel status, log viewer, panic/crash viewer.
- [ ] `L1.4` 🟢 — Scope guard: v1 is a TEST HARNESS app, NOT a persistent jailbreak. No boot-time injection, no daemons. Everything runs when the app runs.

## L2 — App Shell & Packaging

- [x] `L2.1` 🔴 — **Pick the build path and prove it**: Theos application target (`iphone:clang:latest` + `application.mk`) with ObjC/UIKit UI is the only Linux-buildable option (no Swift toolchain on Linux). Spike: `pocs/hub_shell/` minimal app that launches and shows a label.
  _Done 2026-08-29: pocs/hub_shell/ builds with the repo Theos (linux toolchain, iPhoneOS sdk): arm64 Mach-O (PIE, NOUNDEFS), Resources/Info.plist copied, Theos adhoc-sign step passes. Label app shows L2.1/L2.2/L3.1 status + runtime offset resolution. `make clean` verified. Theos application path proven on Linux._
- [x] `L2.2` 🔴 — Engine extraction: makefile target that compiles `kexploit/*.m`, `sandbox_escape.m`, `SSV/*.m`, `utils/*.m`, `kpf/*.m`, `XPF/src/*.c` into `libw0lfengine.a` (no tweak-only files: Tweak.m, FilzaPadlockBypass.xm excluded). Must build standalone with the same CFLAGS as the tweak (A2/A3/A5 fixes included).
  _Done 2026-08-29: `make libengine` → scripts/build_libengine.sh — 48 objects (kexploit 18 + sandbox_escape + SSV + utils 5 + kpf + XPF/src 6 + ChOma 17), ar rcs → .theos/libengine/libw0lfengine.a (660K). Same -I flags + -DDEBUG as the tweak; Tweak.m/TweakExploit.m/FilzaPadlockBypass.xm excluded. Key symbols verified via nm: kexploit_opa334, sandbox_escape, offsets_init, bad_query_escape, mcm_bridge_available, patch_sandbox_ext, set_root_credentials._
- [x] `L2.3` 🟠 — Entitlements: base `get-task-allow` (debug) + `platform-application` only for the TrollStore build (TrollStore grants it); document why the plain sideload build omits it.
  _Done 2026-08-29: build_hub_ipa.sh generates ent-sideload.plist (get-task-allow only) vs ent-trollstore.plist (+platform-application) per mode; verified via `ldid -e` on the signed binary._
- [x] `L2.4` 🟠 — Codesign: Procursus `ldid -S` (vendored scripts/ldid) + `jbctl trustcache add` recipe from the tweak chain (skill: w0lfsword-toolkit-dev) — the dylib-in-app must be signed or dyld refuses it.
  _Done 2026-08-29: scripts/build_hub_ipa.sh signs the app binary with scripts/ldid -S<entitlements>; CodeDirectory v=20400 verified via ldid -h. The jbctl trustcache step stays on-device (adderall-style) for real installs._
- [x] `L2.5` 🟠 — `scripts/build_hub_ipa.sh`: Theos build → ldid sign → .ipa assemble (Payload/W0lfSwordHub.app) → optional version bump. Verify with `unzip -l` + `ldid -h`.
  _Done 2026-08-29: build_hub_ipa.sh [sideload|trollstore] [version] → .w0lfsword/dist/W0lfSwordHub-<ver>-<mode>.ipa. Verified: unzip -l shows Payload/W0lfSwordHub.app/{W0lfSwordHubShell, Info.plist, offsets.json}; ldid -h shows embedded CodeDirectory; ldid -e shows the mode's entitlements; python3 plistlib version bump. Both modes built._
- [ ] `L2.6` 🟡 — App icons + LaunchScreen (asset catalog or plain PNGs; no Xcode needed).

## L3 — Reuse the W0lfSword Engine

- [x] `L3.1` 🔴 — Boot path in-app: on launch, resolve offsets for the running iOS version (port the offsets.m threshold logic — reuse `scripts/test_offsets.py`'s parse output at build time to generate a compact `offsets.json`).
  _Done 2026-08-29: scripts/gen_offsets_json.py (make offsets-json) parses kexploit/offsets.m threshold blocks (test_offsets.py logic), drops 0xdeaddead sentinels, emits cumulative effective tables → pocs/hub_shell/Resources/offsets.json (8 thresholds 17.0→26.0, 72 unique offsets; itk_space 0x310 at 26.0 verified). Bundled into the app by Theos (offsets.json in the .app wrapper, verified). In-app boot path in AppDelegate.m resolveOffsetsInfo: picks highest threshold <= running iOS, reports offset count + itk_space; unsupported iOS handled._
- [ ] `L3.2` 🟠 — XPF integration: embed the XPF-verified offset table (kcwatch data; export via `kcwatch index --json` when available). If the running version has no table entry → show "unsupported iOS" and disable kernel paths.
- [x] `L3.3` 🟠 — Engine entry: `kexploit_opa334()` + `sandbox_escape()` + `patch_sandbox_ext()` callable from the app with the same error codes (utils/errors.h — TWEAK_ERR_*).
  _Done 2026-08-31: hub_shell links libw0lfengine.a (Makefile LDFLAGS + CFLAGS include paths + IOSurface/z/sandbox); kexploit_opa334/kread64/sandbox_escape_read_posix_creds symbols verified in the app binary via llvm-nm. engine_stubs.m supplies no-op tweak_exploit_* UI callbacks (excluded from the engine by L2.2)._
- [ ] `L3.4` 🟡 — Keep the crash-safety from the tweak: port the A3.1 crash counter + auto-disable flag + success flag into the engine (app-scoped paths: Library/Application Support/ instead of /var/mobile/Documents).
- [ ] `L3.5` 🟡 — Log plumbing: route TweakLog (utils/tweak_log.h) to BOTH the app log store and (optionally) a file export. `tstr()` + mutex already in place.

## L4 — Sandbox Escape Testing

- [ ] `L4.1` 🔴 — Test suite (the hub's core): the same probes the tweak/readiness use, as in-app tests with per-test result rows:
  - write/read/delete in `/var/tmp` (sandbox-free baseline)
  - write/read/delete in app Documents (sandboxed — should already work)
  - write to `/System/Library/.w0lf_probe` (SSV-protected — fails without bypass)
  - read `/etc/master.passwd` / system container paths (permission probe)
  - `check_sandbox_var_rw()` summary (kernel-level R+W)
- [ ] `L4.2` 🟠 — Test runner: run tests in a worker thread, one at a time, with a per-test timeout; attribute each result to the probe (no whole-app hang on a stuck test).
- [ ] `L4.3` 🟠 — Safe mode: in-app toggle that writes the safe-mode flag (tweak semantics) and re-runs the suite with kernel paths disabled — proves the UI-hooks vs kernel boundary.
- [ ] `L4.4` 🟡 — Result export: share sheet / file export of the test report (JSON + human-readable) — feeds back into host-side campaign logs.

## L5 — Privilege Escalation

- [x] `L5.1` 🔴 — Root credentials check: after a successful escape, read back uid/gid/groups[0] (the set_root_credentials read-back path) and show "root:wheel active" in the UI.
  _Done 2026-08-31: sandbox_escape_read_posix_creds() exported from sandbox_escape.m (find_ucred_in_proc_ro helper extracted from the sandbox_escape() scan; read-only, gated on exploit_is_done()). Hub AppDelegate shows credentials row: "root:wheel active" / user creds / "not acquired (exploit not run)"._
- [x] `L5.2` 🔴 — Kernel R/W status: `kread64` smoke test on a known-safe address (own proc chain) → show "kernel r/w: live" or "not acquired".
  _Done 2026-08-31: kernelRWStatus() in AppDelegate.m — exploit_is_done() gate, proc_self() → kread64(p + off_proc_p_pid) == getpid() → "live". Verified linked: llvm-nm shows _kread64/_proc_self/_sandbox_escape_read_posix_creds in W0lfSwordHubShell. Both probes run on a background queue; results publish on main._
- [ ] `L5.3` 🟠 — SSV bypass panel: run `patch_sandbox_ext()` + `check_sandbox_var_rw()`; show SSV-protected-write test result before/after.
- [ ] `L5.4` 🟠 — Privilege escalation test suite: ucred patch verify, container access via MCM bridge (`container_access.m`) and bad_query traversal (`bad_query_escape.m`) — port the probes from safe mode.
- [ ] `L5.5` 🟡 — Escalation report: one-screen summary (sandbox: escaped/failed, creds: root/user, kernel: r/w or none, SSV: on/off) with the raw log behind it.

## L6 — Exploit Hub Features

- [ ] `L6.1` 🟠 — Exploit runner UI: Run/Stop DarkSword pe_v1/pe_v2 with the retry ladder (A3.2) + live status ("spraying…", "racing…", "escaped").
- [ ] `L6.2` 🟡 — Kernel info panel: slide/base/version string after resolution (KPRINTF-gated values are debug-only — show only in debug builds, matching A6.2).
- [ ] `L6.3` 🟡 — Log viewer: scrollable TweakLog stream with severity colors; export button.
- [ ] `L6.4` 🟢 — Crash/panic viewer: parse `.ips` from the app's own crash dir (host-side panic_analyzer.py logic ported or a "send to host" export).

## L7 — Safety & Persistence

- [ ] `L7.1` 🔴 — Non-persistent by default: nothing auto-runs at boot; exploit state lives only while the app is foreground. Document in-app.
- [x] `L7.2` 🔴 — Panic guard: crash counter + auto-disable after 3 crashes without success (port A3.1 exactly) — app-scoped flag files.
  _Done 2026-09-05: pocs/hub_shell/hub_guard.{h,c} (pure C) — app-scoped flags under Library/Application Support (hub_last_success / hub_crash_count / hub_disable, limit 3), A3.1 semantics verbatim (increment only when no success flag and not disabled; disable at >=3; mark_success writes success + resets counter; disable removed manually). AppDelegate: dir resolve/create, register_launch at boot, 'panic guard' label line, probes report 'disabled (panic guard)' when guard blocks, success marked when exploit_is_done() (placeholder until L6.1 runner). Build: libengine + hub make 0 errors; hub_guard_* symbols nm-verified in the app binary. Device run pending; L3.4 (engine-side guard for the tweak) stays open._
- [ ] `L7.3` 🟠 — Confirm gates: every destructive action (run exploit, SSV patch, escalate) requires an in-app confirm dialog with plain-English explanation (mirror the CLI's disclaimer pattern).
- [ ] `L7.4` 🟡 — "What could go wrong" screen: worst case = kernel panic → reboot; nothing persists (mirror the CLI disclaimer text).

## L8 — Testing & Release

- [ ] `L8.1` 🟠 — Test matrix: SE2/A13 18.4.1 (jailbroken — escape path skipped, SSV + hub UI verified), any 26.x device when available (full kernel path), plus iOS 17.x if reachable.
- [ ] `L8.2` 🟡 — Wire the engine build into `scripts/regression.sh` (build libw0lfengine + hub app as a check step).
- [ ] `L8.3` 🟢 — Release build: FINALPACKAGE=1-equivalent (NDEBUG, KPRINTF stripped — A6.2/V1.3 pattern), version bump, `build_hub_ipa.sh` produces the final .ipa.
- [ ] `L8.4` 🟢 — README for the app: install (TrollStore), screenshots, feature list, "what it can't do" (no persistence, no boot injection).

## L9 — Stretch (post-v1)

- [ ] `L9.1` ⚪ — Non-jailbroken path (B1.4): the hub app carries the full exploit chain and escapes from a plain sideload — requires the 26.1-era kernel bug to be reachable from an app context; hardware-gated research.
- [ ] `L9.2` ⚪ — Host pairing: hub app talks to the host CLI over USB/SSH (share results, trigger runs from `./W0lfSword`).
- [ ] `L9.3` ⚪ — ShareSheet/extension: run a single sandbox test on a shared file from any app.

---

# SECTION A: AUDIT (full-audit log, added 2026-08-29)

> ShellCheck 0.11.0 + bash -n + py_compile + manual review of the W0lfSword
> script and scripts/. Fixed this session = the criticals below. The rest
> is queued here for later; each item says exactly what and where.

## Fixed this session (for the record)

- `cd "$PROJECT_DIR"` had no failure handler (wrong dir = wrong deploys) → `|| exit 1` added (line ~21)
- SC2155 local+command-substitution masking x4 (deploy paths 882/2072/2296/3118) → declare/assign separated
- SC2015 fragile `&& ||` chain in cmd_audit's brace check → rewritten if/else (~1015)
- `run_menu` referenced "$@" but was called bare → `run_menu "$@"` (~4009)
- dead code removed: `progress_bar`, `hline` (called a nonexistent `line 58`), unused color vars `D`, `C_MOON`
- SoC map wrong: `iPhone17,x` was labeled A17 (it is A18 → pe_v2), `iPhone18,x` was pe_v2 (it is A19/MTE → now `mte` and refused), `iPad1[1-9],x` claimed all iPads (iPad17,x = M5 → `mte`). MTE/puaf refusal gates added to cmd_adderall and cmd_tweak_install.
- Device model detection used `HardwareModel` (returns board IDs like D79AP that never match `iPhoneN,x` patterns) → `ProductType` first, HardwareModel fallback, in adderall + tweak install
- adderall Phase 1 env checks extended: make, curl, unzip, zip, scp

## Queued for later (non-critical)

- [x] `AUD.1` — `apt install -y $to_install` unquoted (word-splitting is intentional for multi-package lists, but an array would be stricter). Lines ~2797/2802 area + cmd_setup equivalent. Low risk (package names never contain spaces).
  _Done 2026-09-01: all three sites converted to `local -a to_install=()` + `to_install+=(pkg)` appends, `"${to_install[@]}"` installs (adderall ~3790, nojailbreak ~4417, setup ~4883). SC2086 exclusion dropped from cmd_audit's shellcheck invocation (0 SC2086 hits remain). While verifying, found the audit's shellcheck counter was dead: it grepped `^W0lfSword:` but the default output format prints `In W0lfSword line N:` headers, so findings never counted toward the verdict. Fixed the pattern and the 4 pre-existing findings it had been hiding (SC2181 x2: mha re-sign `$?` checks → `if ! bash ... || [ ! -f ]`; SC2001 x2: `echo "$installed" | sed 's/^/    /'` → `${installed//$'\n'/$'\n    '}`, byte-identical). shellcheck now genuinely clean under SC2059/SC2012 exclusions only._
- [x] `AUD.2` — `ls -t | head` filename parsing in cmd_panic (~493), cmd_extract (~609), find_deb (~789), tweak deploy (~2072). Use find -print0 style if weird filenames ever matter. Low.
  _Done 2026-09-05: all four local picks now go through the new `newest_file <dir> <glob>` helper (find -print0 + `file_mtime`, GNU/BSD stat dual — newline-safe, spaces fine, mtime-sorted) — find_deb body, tweak-deploy DEB pick, kernelcache-extract `got` pick; cmd_panic `list` rebuilt as a find → date|name → sort -r → head -20 pipeline (identical output, space-name verified, 20-row cap verified on 26 files). SC2012 dropped from cmd_audit's shellcheck exclusions (comment updated) — audit now shellcheck-clean under SC2059 only. Remote ssh picks (panic fetch, mg plist probe) stay ls-based by design: shellcheck can't see inside ssh command strings and remote names are Apple-generated. bash -n OK, shellcheck 0 findings, audit PASSED._
- `AUD.3` — SC2059 "variable in printf format" hits are BY DESIGN (color escape vars must live in the format string to be interpreted — the repo-wide convention). Do not "fix" without understanding that.
- `AUD.4` — CVE catalog lives in two places: cmd_cve tables + research/attack_chains.md + kernel26_cves.md. One source of truth (a TSV data file) would stop drift. Medium.
- [x] `AUD.5` — shellcheck is not wired into `./W0lfSword audit`; the audit runs brace/paren checks only. Add `shellcheck -s bash W0lfSword` as an optional step when installed. Medium.
  _Done 2026-08-31: cmd_audit now runs `shellcheck -s bash -e SC2059,SC2012,SC2086 W0lfSword` (exclusions = the AUD.3/AUD.2/AUD.1 categories, documented in-code; drop each when its ticket lands). Skipped with a hint when shellcheck is absent; findings count toward the verdict, and `audit --json` gained a `shellcheck` key (installed/warnings/ok, folded into issues/passed). Fixed the 13 non-excluded findings: SC2155 error_report_collect, SC2181 gh issue-create check, SC2178/SC2128 array-name collisions (spinner frames→spinframes, reveal_lines lines→rlines), SC2015 x8 (trustcache add, doctor tool checks, THEOS install fallback), SC2086 interactive dispatch → read -r -a. Script shellcheck-clean under exclusions; audit, audit --json, doctor, help, menu PTY all verified._
- [x] `AUD.6` — `exploit_matrix` rows and `select_best_chain` partially duplicate each other; the selector could be generated from the matrix. Low (both verified correct today).
  _Done 2026-09-11: `select_best_chain` is now ordering only - every iOS range, SoC pattern, name, status and note comes from `exploit_matrix()` through two new helpers (`matrix_row <id>` returns a single row, `chain_candidate <letter> <id> <ios> <model> [method]` decides applicability + builds the why-text), so the "17.0–26.0.1" literals no longer exist in two places. `ios_in_range` runs the range test through version_sort_first, which also killed a real bug: a junk version used to print `[: abc: integer expression expected` x3 to stderr and still claim a chain - it now answers `|unknown||unparseable iOS version 'abc'`. The status field stopped carrying the row's note (an A9-A11 device printed `[usbliter8-fun2]` as its status, in green): statuses are now the row's real ones (implemented/pending/research) and `chains best` tints by them, and the name matches the compat table row ("DarkSword kernel R/W (pe_v1)" instead of "DarkSword kernel R/W"). "no chain" answers explain themselves now instead of one fixed hint line: closed kernel gate (26.1+ A12+, the row's own note), MTE (A19/M5), the nearest same-major row's range ("kfd PUAF fallback covers 16.0–16.9 only - not iOS 16.9.1"), or no row for the pair. Behaviour deltas, all matrix-driven and all outside real device/version pairs: 26.0.2+ no longer claims DarkSword, A12/A13 below 17.0 get the usbliter8 row (the matrix always said any iOS), and a closed kernel gate no longer claims bad_query past 26.6.1. Guards: `scripts/cli_consistency.py` gained a fourth check - matrix row shape (7 fields, known status, unique non-empty id) and every row id the selector references must exist (a dangling id makes the selector answer "no chain" for every device); proven with 4 injected breakages (dangling id, 6-field row, unknown status, duplicate id), all flagged. Behaviour lock: `scripts/test_chain_select.sh` (26-case golden grid, wired into regression.sh) asserts chain + status and that the printed name is the matrix row's own name - negative-tested (a renamed row + a narrowed range = 3 failures). Verified: bash -n, shellcheck clean, dead-fn scan 170 defs/0 dead, 44 repo files parse, cli_consistency 10 matrix rows/6 selector refs/0 findings, audit PASSED, `chains best` smoke (26.0.1→A, 26.1→B, 26.7→no chain, 15.6 A9→D, junk→unparseable)._
  _Follow-up: the matrix's `A10+` pattern also matches `iPhone8,*` (A9) - that is what the compat table has always claimed, so the selector now inherits it for A9 devices on 16.0-16.9; verify kfd's real A9 support before changing the row._
- [x] `AUD.7` — cmd_experimental's device dump has no WiFi path (USB only). Add saved-device SSH fallback like the other probes. Low.
  _Done 2026-09-03: `experimental device` now falls back to the saved-device WiFi route when no USB device is present - saved IP (device add), ping, then the same ssh probes as `device info` (echo-ok reachability check, then one simple command per field: hostname / hw.machine-or-uname -m / sw_vers x2). New device_wifi_dump() + device_compat_block() helpers (the USB path was refactored onto the same compat tail so both transports print identical exploit/chain/compatibility output; row order/format unchanged, added a link: row). BatchMode throughout: a missing key fails with a hint instead of prompting mid-dump. Offline / no-key / no-saved-device cases each print err + hint. Verified: bash -n, shellcheck clean under the SC2059/SC2012 exclusions, audit PASSED, mock-ssh end-to-end (online dump with iPhone14,6/18.4.1 rows, ssh-fail branch, no-saved-device branch)._
- [x] `AUD.8` — `ios_recommendations` and `exploit_compat_check` overlap; consider merging the gray hint lines into the compat table output. Cosmetic.
  _Done 2026-09-09: gray hint lines merged into the compat table output wherever the table is rendered - device_compat_block (the `experimental device` USB + WiFi dump tail, `exploit:`/`chain:`/`compatibility:` block) now prints ios_recommendations under the table, matching the pairing adderall and the status device list already used. The compat rows say which exploits apply; the hints say what that means and what to try next - and they finally explain the empty-table cases (e.g. an A9 on 15.5 dumped an unexplained blank table; it now gets "below the offset table (min 17.0) / try usbliter8"). adderall keeps its up-top hint placement on purpose: those hints sit ABOVE the mte/unknown/puaf refusal gates, so refused runs still see the version context, and status keeps hints-only (compact list, no table). No logic touched, purely additive rendering at the one shared call site.
- [x] `AUD.10` — audit: repo-wide script syntax + CLI consistency (registry vs dispatch vs menu vs help vs MAP vs version)
  _Done 2026-09-10 (v1.5.0): two new audit steps alongside shellcheck/dead-fn. (1) **repo script syntax** - the audit checked the ObjC sources and shellchecked the main script but nothing verified that the other shell/python files parse; now `find` (tracked + untracked, vendored trees pruned) runs `bash -n` on every *.sh and `ast.parse` on every *.py - 43 files, all parse. (2) **CLI consistency** - vendored `scripts/cli_consistency.py` (same pattern as AUD.9's dead_fn_scan) proves the six surfaces still agree: 49 registry rows, 104 keys with no collisions, every registry name/alias has a dispatch case and every dispatch alternative is a registry row, every menu handler is a defined function, docs=1 <-> explain_text has a case, plus the section MAP and the control-file version. Prints `findings: N` (audit parses it), exit 1 on any drift, `audit --json` gained `script_syntax` (checked/failed/ok) and `cli_consistency` (registry_rows/findings/ok) keys, shellcheck findings now count 0. Proven with negative tests: a dispatch case removed from the registry, a colliding key, a dead handler, a docs=0 row that has an explain case, a renamed section - each flagged. Also caught a real bug on the first run: a comment beginning with `# ... shellcheck ...` is parsed by shellcheck as a directive (SC1073) and an unused `local item` (SC2034)._

- [x] `AUD.9` — hline/progress_bar removal verified dead by call-graph; re-run the dead-function scan after every big feature round (cadence now automatic — see _Done note). Vendored 2026-09-06 as `scripts/dead_fn_scan.py` — one command: `python3 scripts/dead_fn_scan.py W0lfSword` (extract `^name()` defs, quote-aware comment stripping, def line excluded, exit 1 on dead defs).
  _Done 2026-09-08: dead-fn scan wired into cmd_audit (mirrors the AUD.5 shellcheck step) - runs `python3 scripts/dead_fn_scan.py W0lfSword` whenever the vendored script is present, dead defs count toward the verdict, clean runs print "W0lfSword (dead-fn scan: N defs, 0 dead)", missing file skips with a hint; `audit --json` gained a `dead_fn` key (scan/defs/dead/ok, folded into issues/passed). The standing manual "re-run after every big feature round" is now automatic - every audit re-checks. Verified: clean run 149 defs / 0 dead PASSED (human + --json), a deliberately appended dead function failed the audit with exactly 1 issue (then removed), bash -n OK, shellcheck clean._

*Last updated: 2026-09-11 — AUD.6 done (see its _Done note): the K5.9 chain selector is now generated from `exploit_matrix()` (new `matrix_row` / `ios_in_range` / `chain_candidate` helpers) instead of keeping its own copy of the ranges, so the compat table and the selector share one source of truth. Along the way: junk iOS versions no longer hit the shell's integer comparison, the status field prints the row's real status (A9-A11 used to print the note `usbliter8-fun2` as its status), `chains best` tints by status, and "no chain" answers explain the reason (kernel gate / MTE / nearest row's range). New audit-side check in `scripts/cli_consistency.py` (matrix row shape + dangling row references) and a 26-case golden grid in `scripts/test_chain_select.sh`, both negative-tested. Verified: audit PASSED (shellcheck clean, 170 defs/0 dead, 44 files parse, 10 matrix rows/0 findings), bash -n, grid 26/26. 2026-09-10 — v1.5.0 CLI surface round: D1.6 (command registry `W0LF_COMMANDS` drives menu rows + shortcuts + explain fallback + `commands` index via `menu_dispatch`; script reorganized into 39 numbered sections with a generated MAP; UI primitives consolidated) and AUD.10 (audit now parses every shell/python file in the repo and runs `scripts/cli_consistency.py` to prove registry = dispatch = menu = help = MAP = control version). Real bugs fixed: `sf` advertised but unwired in the menu, four menu keys missing from the shortcuts line, literal `\033[..` escapes printed in the shortcuts line, infinite "Unknown" spin on EOF stdin, `extract` misdescribed in help. Verified: audit PASSED (shellcheck clean, 167 defs/0 dead, 43 files parse, 49 commands/39 sections/0 findings), bash -n, menu smoke tests (piped keys + legacy aliases). Version 1.4.0 → 1.5.0. 2026-09-09 — AUD.8 done (see its _Done note): the gray hint lines are now merged into the compat table output everywhere the table renders - device_compat_block (the `experimental device` USB + WiFi dump tail) gained an ios_recommendations footer under the table, so e.g. an A9 on 15.5 gets "below the offset table / try usbliter8" instead of an unexplained blank `compatibility:` block, and supported/capped dumps get the same verdict + next-step hints the menu and adderall already show. adderall's up-top hints stay put (they sit above the mte/unknown/puaf refusal gates on purpose). Additive rendering only, one shared call site. Verified: bash -n, shellcheck clean, dead-fn scan 149/0, audit PASSED. 2026-09-08 — AUD.9 done (see its _Done note): the dead-fn scan is now wired into cmd_audit — every `./W0lfSword audit` re-runs `python3 scripts/dead_fn_scan.py W0lfSword` and counts dead defs toward the verdict, so the standing manual re-run cadence is automatic; `audit --json` gained a `dead_fn` key (scan/defs/dead/ok). Clean: 149 defs, 0 dead. Failure path proven with a deliberately appended dead function (audit failed with 1 issue, then removed). 2026-09-07 — explain `chains` help realigned with the C5.3 catalog: it still said "Five chains" (a-e only), omitting F GestaltForge + G FontStrike and the `best` selector — now lists all seven and `chains <a|b|c|d|e|f|g|best>`, matching cmd_chains' table and usage line (help-text only, no logic touched). 2026-09-06 — AUD.9 re-run + vendored: scripts/dead_fn_scan.py (quote-aware comment stripping, def line excluded, exit 1 on dead defs) makes the recurring dead-function scan one command. Result: 149 function defs (was 146 at the mobilegestalt/fs re-run; +2 from AUD.2's newest_file/file_mtime, +1 from the K1.6 adderall exploit-method picks), 0 dead. 2026-09-05 — AUD.2 done (see its _Done note): newest_file/file_mtime helpers, four local `ls -t | head` picks converted, cmd_panic list rebuilt on find -print0; SC2012 exclusion dropped, audit shellcheck-clean under SC2059 only. AUD.9 re-run after the mobilegestalt/fs feature rounds: 146 function defs (was 131 on 2026-09-02), 0 dead — every def has at least one non-comment word-boundary reference. 2026-09-03 — AUD.7 done: `experimental device` gained a saved-device WiFi/ssh fallback (device_wifi_dump, mirrors `device info` probes; USB path refactored onto the shared device_compat_block tail). Verified with mock-ssh shims - online dump, ssh-fail, and no-saved-device branches all correct. 2026-09-02 — AUD.9-style consistency scan: soc_family() realigned with the canonical map in select_exploit()/soc_match() (AUD.4 follow-up — iPhone16=A17, iPhone17=A18, iPhone18=A19, iPad17=M5, iPad8/11=A12-family); verdict family_set gained A19/M5 keys so every emitted label resolves; previously iPhone17/A18 devices displayed "A17" and were checked against the wrong chip set (passed only because the catalog happens to list A17). Same scan: 0 dead functions (131 defs, all referenced). Audit gate repaired: the 2 pre-existing shellcheck findings (SC2030/SC2031, PATH exported inside the `experimental testipa` subshell) fixed by converting the subshell export to a per-command `PATH=... make` prefix — audit back to PASSED. 2026-09-01 — AUD.1 done: to_install arrays in adderall/nojailbreak/setup, SC2086 exclusion dropped, audit's shellcheck counter fixed (was matching a format the tool never prints), 4 hidden findings fixed. 2026-08-31 — AUD.5 done: shellcheck wired into `./W0lfSword audit` (13 findings fixed, exclusions documented). 2026-08-29 — full audit done (0 shellcheck warnings); adderall hardened (compat matrix, MTE/puaf gates, env checks); experimental section added; criticals fixed, rest queued in AUD.*

## 0.13 - findings from the 2026-09-11 night runs (SE, staged)

Two staged runs reached the write probe and both refused to promote. What they
proved, in order of importance:

- the physical write lands: `write probe (inp6_chksum)` verified through the
  OOB read-back, and `alias write (icmp6filt)` verified, in both runs, with no
  panic. The inert-field probe (BUG.1 step 2) is the reason that is now
  survivable.
- the alias never reached a live inpcb slot. Root cause: the probe read the
  list link at a hardcoded 0x28 (`inp_list.le_prev`) and subtracted 0x20, so
  `rwSocketPcb` was not the next inpcb at all. The two other list walks in the
  file use `off_inpcb_inp_list_le_next` (0x20 for 18.0-18.7). Fixed, with a
  canonical-pointer guard before anything is corrupted. This is what the old
  `getsockopt(...) != -1` verdict hid for so long: a garbage pointer passed it.
  (2b) the restore wrote through that same bogus address - an unclamped 32-byte
  RMW at an address nothing had verified. That is the same write class that
  panicked the device; it only failed to panic because the address happened to
  be mapped.
- BUG.7, restore half CLOSED (0.12 BUG.1 step 3b, same day): the restore used to
  call `early_kwrite64`, which goes straight to `early_kwrite32bytes` - unclamped,
  twice per attempt, up to ten times per run, at a pcb nothing had verified. The
  restore, the probe's promotion round trip and `krw_sockets_leak_forever`'s inpcb
  write now all go through the clamped qword writer
  (`kwrite_zone_element_qword` / `krw_zone_write_qword`), which refuses a block
  that is not provably inside the window it is given; a refused put-back is logged
  and reported as a failure. The window is the inpcb's own field span
  (`krw_zone_window_for_field_end(filt offset + 8)` = 0x160 on both layouts), so a
  field table that disagrees gets a refusal instead of a write.
  STILL OPEN, the other half: the clamp verifies a block against the window it is
  GIVEN, so a window derived from an address that was never verified is
  self-consistent (that half is the canonical-pointer guard + the live-inpcb value
  check, not the clamp). A true kalloc size probe - the zone's `elem_size` through
  `inpcbinfo.ipi_zone` (`off_inpcbinfo_ipi_zone` = 0x68), which would let a caller
  declare the BUCKET rather than the field span - needs a `struct zone` offset this
  tree does not have; deriving one is its own task (kernelcache-verified, per the
  offsets.m convention). The two `so_usecount` writes in
  `krw_sockets_leak_forever` also stay on `early_kwrite64`: their object is a
  `struct socket`, with no field table here that could state a window honestly.
  CLOSED 2026-09-18 (BUG.7, the kalloc-bucket half): the missing offset was read
  off the kernelcaches instead of guessed. XNU's own zone bound check - the
  message that panicked the SE three times - PRINTS the element size it compares
  against ("... overflows object %p of size %zd in zone %p[%s%s]"), so
  `scripts/kc_zone_fields.py` finds that routine, finds the zone register and
  reads off every field it touches: z_name +0x10, z_quo_magic +0x28,
  `z_elem_size +0x34`, z_elem_offs +0x36, flags +0x3c. All eight kernelcaches on
  hand agree (17.0 + 18.4.1 t8030, 26.1/26.2 t8110, 26.6/26.6.1 on both boards),
  and `offsets.m` carries `off_zone_elem_size = 0x34` in all three version blocks.
  The chain `pcb -> inpcbinfo.ipi_zone -> z_elem_size` and the window decision
  built on it live in `kexploit/krw_zone_size.c` (a new engine-archive member,
  also in the tweak build) and are delegated to from
  `probe_zone_bucket_size()`; the DECISION is: an element size that is a kalloc
  class and >= the field span becomes the declaration (the widening the task
  asked for), an unreadable/implausible one keeps the field span exactly as
  before, and a PLAUSIBLE bucket SMALLER than the field span is a refusal with a
  window of 0 - two kernel-derived statements contradicting each other is the
  object the SE overran, and every write through it is now refused and logged
  (`[STAGED] zone window: pcb ... REFUSED`). The probe additionally logs the
  bucket it will declare (`[TEST] WRITETEST zone bucket: ...`), so the next device
  log shows whether the zone read works before any write is attempted.
  Host evidence: `bash scripts/run_krw_zone_size_host_test.sh` ->
  `checks=57 failures=0` / `KRW_ZONE_SIZE_HOST_TEST PASS` (compiles the shipped
  decision file against a fake kernel window; the SE's own shape - bucket 0x60
  against the 0x160 field span - is refused end to end),
  `python3 scripts/check_bug2_release_paths.py` -> `61 check(s) passed, 0 failed`
  with six new zone-window checks, `--selftest` -> `selftest: all mutations
  caught` (23/23, four of them new: the bucket read dropped, the chain read
  inline, the PAC-stripping reader wrapper, the refused-window branch removed),
  `bash scripts/check_host_verification.sh --with-builds` -> `22 ok, 0 drift`
  (the new harness is entry `krw_zone_size`; the engine archive, the linked app
  binary and its symbol table are re-pinned to this tree, and `llvm-nm` shows
  `_krw_zone_bucket_for_pcb` defined in the archive AND in the W0lfTerm app, so
  the chain is linked, not merely compiled), `THEOS=$HOME/theos make package` ->
  the tweak dylib ships the new log strings, `./W0lfSword audit` -> `AUDIT
  PASSED`. NOT device-verified: the next SE run is what proves the zone read
  returns a real bucket on hardware, and readonly stays the only mode offered on
  unproven device/iOS pairs until then. What this does NOT close: the
  `so_usecount` writes (still `early_kwrite64`, no field table for `struct
  socket`) and address trust itself - a caller that derives a window from an
  address nothing verified still gets a self-consistent answer; that half stays
  with the canonical-pointer guard plus the live-inpcb value check.
- the run budget is the only thing ending these runs: both stopped at ~29.5 MB
  walked in 120 s with the socket table full (27.4k-27.5k sockets, errno 23),
  1 GB dirtied per pass, 98% CPU. A full walk on this device needs ~8.5 min, so
  the 600 s setting is the next thing worth a run.
