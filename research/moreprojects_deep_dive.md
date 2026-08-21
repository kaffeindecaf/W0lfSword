# referenceforAI/moreprojects — Deep Dive (2026-08-21)

> **Scope:** The 5 new repositories in `referenceforAI/moreprojects/` (added 2026-08-21).
> Each entry: what it is, the bug, the trigger, tested hardware, and why it matters
> for W0lfSword (roadmap cross-refs in `ROADMAP.md` / `referenceforAI/SandboxEscape.md`).
> **Bottom line up front:** three of the five are live kernel/ImageIO bugs relevant to
> the iOS 26.1+ goal — CVE-2026-20687 (kernel UAF, A19/MTE era), DirtySlide
> (CVE-2026-43724, dyld slide OOB → potential kernel R/W), CVE-2026-28990
> (EXR ImageIO heap overflow, alive ≤26.4.2). One is a duplicate of an already-indexed
> repo. One is a deterministic SEP DoS.

---

## 1. CVE-2026-20687 — AppleJPEGDriver startDecoder() Timeout UAF

**Repo:** `referenceforAI/moreprojects/CVE-2026-20687-AppleJPEGDriver-UAF/`
**Author:** Johnny Franks (@zeroxjf)
**Component:** Kernel — AppleJPEGDriver IOKit user client (not the userspace ImageIO lib)
**Apple wording:** "An app may be able to cause unexpected system termination or write
kernel memory. A use after free issue was addressed with improved memory management."
(iOS 26.4 / iPadOS 26.4 security content, support.apple.com/en-us/126792)
**Tested:** iOS 26.3 (23D125), iPhone18,2 (iPhone 17 Pro Max, **A19 Pro**) — i.e. MTE hardware.

### The bug
`JpegRequest` is a 0x440-byte (1088) pool/zone-allocated object. Two independent flaws:

1. **Timeout UAF (the panic):** `startDecoder_sync` → `queue_io_gated()` pushes
   `req+0x78` (embedded queue-link node) into the per-codec vector at driver `self+192`,
   then waits 10s → **TIMEOUT** → `pool_free(req)` **without dequeuing** `req+0x78`.
   A later hardware-completion walk (`finish_io_gated` → `fullSpeedRequestExist`)
   reads the stale vector slot: `node_ptr = vector[i]` (== freed `req+0x78`),
   `req2 = *(node_ptr+0x8)` (reads `req+0x80`, the self-pointer) → **MTE tag check
   fault → kernel panic**. Confirmed by FEEDFACE poison in registers (x5=x6=0xfeedfacefeedfad3),
   PC inside AppleJPEGDriver.

2. **Retain leak:** client closes (`IOServiceClose`) with async jobs in flight →
   `terminatePhase1` sets `isInactive()` via the **arbitration lock, not command-gated**;
   `finish_io_gated` sees `isInactive=true` → skips `taggedRelease` → one leaked retain
   per in-flight job. Wired memory grows; measurable via `vm_statistics64`.

### Object layout (useful if this gets exploited)
```
+0x00  task_t            ← vtable-like deref: *(*(req+0)+40)() = PC control
+0x08  IOUserClient*
+0x78  queue link node   (enqueued at driver self+192)
+0x80  self-pointer      ← FIRST UAF read  (node_ptr+0x8)
+0x310 flags byte        ← SECOND UAF read (bit0 = progressive)
```

### User client surface (reverse-engineered in the PoC)
`IOUserClient2022`, 10 selectors: 0 getTarget, 1 decode (structIn/Out 0x58), 2 query,
3 encode, 4/5 (0x1000 structs), 6/7 async decode/encode (0xDA0, allowAsync), 8/9 privileged.
`AppleJPEGDriverIOStruct` = 88 bytes packed (sourceID, sizes, width/height, subsampling,
asyncToken, codecID, outW/H). `asyncToken != 0` → driver-internal async.
`input+0x00→req+684`, `+0x08→req+688` (IOSurface IDs), `+0x14→req+808` (width), etc.

### PoC stages
- `probeDriver` — selector enumeration, zeroed/sync/async decode tests
- `singleLeakTest` — N async requests on one conn, close immediately, measure wired delta
- `uafCharacterize` — Phase 1: 100 sequential victim→reclaim cycles (5 reqs victim, 3 conns × 3 reqs reclaim); Phase 2: 3-thread race (victim / same-pool reclaimer / OOL `mach_msg` spray of kalloc(0x440), NULL self-ptr at +128)
- `sprayLeak` — 8 threads × N iters × 10 async reqs (contention on command gate)
- Trigger recipe: tap Panic (primes driver) → open **Camera** app (sync JPEG decode + timeout) → deferred panic

### Relevance to W0lfSword
- **This is a kernel bug on iOS 26.3 / A19 Pro — the MTE era.** Roadmap K5.6 says:
  "when a new kernel primitive lands on 26.1+/26.4.1, FIRST re-verify offsets (K4.1),
  THEN run the existing ext-set escape". This UAF is a *candidate* for a 26.x kernel
  primitive — the PoC is panic-only today, but the object layout shows PC control
  (`*(*(req+0)+40)()`) if the freed slot is reclaimed with controlled data
  (the OOL spray + victim/reclaim phases are exactly that work in progress).
- Panic signature doubles as an MTE-era reference for the crash-monitor
  (`TweakExploit.m` sentinel logic in W0lfSword).
- Not menu-deployable as-is: Xcode project, needs `xcodebuild` on macOS + device.

---

## 2. DirtySlide — CVE-2026-43724 (dyld shared-cache slide OOB → LPE)

**Repo:** `referenceforAI/moreprojects/DirtySlide/`
**Writeup:** https://gracecondition.github.io/posts/dirtyslide/
**Bug class:** unprivileged → root LPE. 8-byte OOB read/write into kernel memory adjacent
to a dyld shared-cache page, from a **missing in-page bounds check in the v5 slide walk**
(`vm_shared_region_slide_page_v5`), reachable via **syscall 536** (`posix_spawn` with
`_POSIX_SPAWN_RESLIDE` = 0x0800).
**Patched:** macOS 26.5.2 (`25F84`, `xnu-12377.121.10`). Vulnerable through 26.5 betas
(`xnu-12377.120.72`). iOS status not stated in the repo — the iOS app build panics the
kernel ("Crash in dsc region" button).
**Tested:** macOS 26.5 arm64 under Apple Virtualization (VMAPPLE). Physical scan panics
~50% of runs; rerun after reboot.

### Architecture (3 moving parts + shims)
1. **`launcher.c`** — opens the real dyld shared cache (`/System/Volumes/Preboot/Cryptexes/OS/.../dyld_shared_cache_arm64e`), spawns the child with `POSIX_SPAWN_SETEXEC | _POSIX_SPAWN_RESLIDE`, dup2's the cache fd onto fd 3. Optional parent-procname marker via `sysctl(KERN_PROCNAME)` and pipe-spray oracle scaffolding (compile-time `PIPE_SPRAY_COUNT`).
2. **`t_reslide_zf.c`** (2468 lines) — the exploit: static, no dyld binary (patched by
   `patch-static-child-dyld.py` which adds `LC_LOAD_DYLINKER` + `LC_MAIN`, sets PIE flags,
   converts `LC_UNIXTHREAD` → ignored). The slide walker uses a **PTE oracle** (write an
   alias, verify which physical page it landed on), scans physical memory for the cred
   struct, patches uid/gid/groups → 0, then arms a setuid helper
   (`suidwrap.c` staged at `/tmp/lpe_suidwrap`, `chown 0` + `chmod 4755`).
3. **fake dylibs** — `fake_libdyld.cpp` + `fake_libsystem.c` with `__DATA_CONST`/`__AUTH_CONST`
   segment flag 0x10 set (`set-segment-flag.py`), `add-load-dylib.py` injects
   `LC_LOAD_DYLIB /usr/lib/system/libdyld.dylib`. The child is launched with
   `DYLD_SHARED_CACHE_DIR=/tmp/does-not-exist DYLD_LIBRARY_PATH=<dist>/fakelib` so dyld
   loads the fakes — this forces the shared cache to be re-slid in a fresh region the
   exploit controls.
4. **`run.sh`** (`run-on-guest.sh`) — portable: copies `suidwrap` to /tmp, fires the
   launcher, polls up to 220s for the setuid wrapper, then drops an interactive root
   shell. Detects "536 ret=0x16" (region already mapped → reboot needed).

### Key geometry (Makefile)
`PAGES=1024`, `TARGET_MAPS=2`, `SR_MAL_MAP=0x180000000 + 1024*0x4000*2`,
`TARGET_SIZE=1024*0x4000`, stack at `0x160000000`. The Makefile is a config surface —
every oracle/PTE-scan behavior is a `-D` flag (ORACLE_PTE_PHYS_CRED_PATCH,
ORACLE_STOP_AFTER_ROOT_HIT, SUID_HANDOFF, SURVIVE_LOOP, WIPE_ARGV_STRINGS...).

### iOS angle
The Xcode app (`DirtySlide.xcodeproj`) runs `main.m` → `CVE_2026_dyld()` (opens the iOS
shared cache at `/System/Cryptexes/OS/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64e`,
calls `cmain`), or `minimal_CVE_2026_43724()` on `--run`. Launch recipe
(`xcrun devicectl` / pymobiledevice3): `DYLD_SHARED_CACHE_DIR=/a _SafeMode=1` → kernel
panic. `_SafeMode` switch exists so it also reproduces on a jailbroken device (it swaps
between in-cache dylibs and the fakes, which breaks tweak-library linking).

### Relevance to W0lfSword
- **Potential kernel OOB R/W on iOS 26.x via dyld slide.** macOS-patched (26.5.2) but
  iOS status unverified — if alive on 26.1–26.4.x it's a Chain-G kernel primitive
  candidate (ROADMAP K5.6 / Section 0.2). Even panic-only, it's a valid 26.x kernel
  crash repro for the crash-monitor and for K4.7-style "alive on 26.1" verification.
- The PTE-oracle + physical-cred-patch technique is a reusable post-primitive pattern —
  directly comparable to W0lfSword's own `physical_oob_*` machinery in
  `kexploit/kexploit_opa334.m`.
- Not menu-deployable as-is on iOS: the LPE path is macOS; the iOS app is Xcode +
  devicectl/pymobiledevice3, not Theos.

---

## 3. exr-imageio-poc — CVE-2026-28990 (EXR ImageIO heap overflow)

**Repo:** `referenceforAI/moreprojects/exr-imageio-poc/`
**Authors:** Jiri Ha & Arni Hardarson (@arnihardarson) — zygosec.com
**Bug class:** integer overflow in `EXRReadPlugin::decodeBlockAppleEXR` (ImageIO)
when calculating a buffer size: supplied `width × height` **wraps to 0** →
`malloc_type_malloc` with a tiny size → file containing excess pixel data →
**heap overflow** → crash.
**Patched:** iOS/macOS **26.5**. Alive on ≤ 26.4.2 — **including 26.1**.
**Crash:** `EXC_GUARD (code=1, subcode=0x4141414141414151)` in
`libdispatch`'s `_dispatch_root_queue_drain` (the 0x41 fill pattern is visible in the
subcode). Writeup: zygosec.com/blog; video: youtube.com/watch?v=nPuU_9Kbb5o.

### PoC files
- `gen_exr_trigger.py` — builds the crafted EXR: magic 0x01312F76, version 2, chlist of
  4 HALF channels (A/B/G/R, pixel type 2), `dataWindow = box2i(0,0,16383,65535)` (the
  buggy size calc uses **dataWindow**, not displayWindow), `displayWindow` small,
  one legit scanline (`y=0`, size = 16384×4×4), **every scanline offset entry points at
  that one scanline** → reader believes 65536 scanlines exist, 65535 of them "read"
  past the real data. Run: `generate_exr_overflow_trigger("zygosec_poc.exr", 16384, 65536)`.
- `zygosec_poc.exr` — pre-generated trigger (~1MB).
- `exr_parser.m` — minimal Objective-C harness that opens the EXR via ImageIO
  (`CGImageSourceCreateWithURL` / `CGImageSourceCreateImageAtIndex`) on a background queue
  — this is the crash host (works as a macOS CLI or iOS app; the crash above was captured
  in a macOS build).

### Relevance to W0lfSword — HIGH (this is the K4-family target class)
- **A live ImageIO memory-corruption bug on iOS 26.1.** Roadmap K4.8 / K5.4 want exactly
  this: an ImageIO bug valid on 26.1/26.4.x to feed Chain B (ImageIO userspace entry →
  parser process → file access). CVE-2026-28990 is such a bug, alive on 26.1–26.4.2.
  The crash is in the *decoding process* — on iOS that's the QuickLook/Files/BlastDoor
  thumbnail path, i.e. the SandboxEscape.md Stage-2 surface (MessagesBlastDoorService /
  UserNotificationsServer decode images automatically).
- `gen_exr_trigger.py` is a **ready-made first artifact for the K4.2 fuzzing harness**
  (currently unimplemented): mutate width/height/channel-count/offset-table, batch-
  generate EXRs, push to the phone, open via Filza viewer / QuickLook, collect
  `/tmp/FilzaTweak.log` + panic signatures.
- Pure Python + one .m file → trivially runnable on the Linux host; no Xcode needed to
  generate corpus.

---

## 4. Glass-Cage-iOS18-CVE-2025-24085-CVE-2025-24201 — DUPLICATE

**Repo:** `referenceforAI/moreprojects/Glass-Cage-iOS18-CVE-2025-24085-CVE-2025-24201/`
**Status:** byte-identical duplicate of `referenceforAI/projects/Glass-Cage-...`
(verified with `diff -rq`: only `.git` metadata differs).

Chain summary (already indexed in `RESEARCH.md`): zero-click iMessage PNG →
`MessagesBlastDoorService` auto-thumbnail → CVE-2025-43300 (ImageIO OOB write in
ATXEncoder HEIF→ASTC decode) → CVE-2025-24201 (WebKit RCE) → Core Media
CVE-2025-24085 (kernel privesc) → keychain exfiltration, wifid hijack, IORegistry
bricking (`IOAccessoryPowerSourceItemBrickLimit=0`). Tested iPhone 14 Pro Max iOS 18.2.1;
patched Feb–Mar 2025; CNVD-2025-06744 / CNVD-2025-07885 certified.

**Extras in the moreprojects copy:** the full "Glass Cage Report.md" (the submission
document with log evidence) and the two CNVD certificate files. The `projects/` copy has
the git history.

**Action:** no code value beyond what's indexed — keep as reference; dedupe candidate.
If kept, prefer the `projects/` copy (has git) and note the report/certs live in
`moreprojects/`.

---

## 5. SEP-Exhaustion-Kernel-Panic — deterministic SEP DoS

**Repo:** `referenceforAI/moreprojects/SEP-Exhaustion-Kernel-Panic/`
**Author:** zeroxjf
**Bug class:** SEP (Secure Enclave Processor) firmware resource exhaustion.
`AppleKeyStore` selector 2 with open type `0x2022` → deterministic SEP panic after
**~41 consecutive calls** (1ms apart). SEP's SKS (`SEPKeyStore`) task crashes at
`0x0006fea7` — 100% consistent (no ASLR in SEP firmware), identical backtrace,
~41 threshold suggests counter overflow / resource-pool exhaustion.
Connection close/reopen resets the state; input scalars don't matter (call count only).
**Tested:** iOS 26.1–26.2, macOS 26.1–26.2 — iPhone 11 Pro Max, iPhone 17 Pro Max,
MacBook Pro M2 Max / M4 Max.

### Trigger
```c
IOServiceOpen(AppleKeyStore, ..., 0x2022, &conn);
for (i < 50) IOConnectCallMethod(conn, 2, {1,0,0,0x10,0,0}, 6, NULL, 0, out, &outCnt, NULL, NULL);
usleep(1000);
```

### Files
- `sep_panic_poc.c` — standalone C (builds on macOS: `clang -framework IOKit -framework CoreFoundation`; the header comment also claims iOS 18.1/A17+ testing)
- `SEPTest/` — iOS app (button-triggered)
- `panic-full-2026-01-13-140458.0002.ips` — sample SEP panic log (useful crash-monitor fixture)

### Relevance to W0lfSword
- **SEP attack-surface datapoint** for ROADMAP C2.2 ("Secure Enclave / SEP attack surface,
  up to $250K bounty"). A deterministic SEP firmware crash at a fixed address from a
  sandboxed-ish call is a real finding-class datapoint; the fixed crash address means the
  SEP image layout is stable — useful if SEP research deepens.
- DoS-only (reboot), no data loss. Could serve as a **panic-capture test fixture** for
  the W0lfSword crash-monitor (`A3.1` sentinel logic): fire the SEP loop on a test device,
  verify the monitor detects the reboot and re-arms correctly.
- Tiny C file — the easiest of the four to cross-compile (Theos can build it; IOKit +
  CoreFoundation frameworks are already in the W0lfSword Makefile's framework list).

---

## Menu-integration assessment (W0lfSword exploit menu script)

### What the script has today
- `cmd_targets()` (menu 8 / `targets`) — app targets only (Filza + planned apps);
  **no exploit-technique table**.
- `select_exploit()` — device → `pe_v1` / `pe_v2` / `puaf` / `unknown` (A12-A16→pe_v1,
  iPhone17→pe_v1, iPhone18→pe_v2, A9-A11→puaf).
- Menu 9 → usbliter8-arctic TUI.
- ROADMAP **K1.5 is still unchecked**: "Add an `exploits` subcommand listing available
  techniques + support matrix". K5.5 (`imagetrigger` mode) and K4.2 (ImageIO fuzz
  harness) also open.

### Recommended additions (ranked)

1. **Extend `cmd_targets()` with a "Research Exploits (referenceforAI)" table** — the
   four new technique entries with iOS range + status (implemented / panic PoC / LPE /
   crash PoC / DoS). Zero-risk doc change; makes the menu reflect the KB. **[implemented
   in this session]**

2. **Implement K1.5 `exploits` subcommand** — the content now exists to fill the matrix:
   DarkSword pe_v1/pe_v2 (implemented, 17.0–26.0.1), kfd PUAF (planned, 16.x),
   checkm8/usbliter8 (menu 9, A11-), AppleJPEGDriver UAF CVE-2026-20687 (panic PoC,
   26.3 A19), dyld-slide CVE-2026-43724 (LPE/panic, 26.x unverified), EXR ImageIO
   CVE-2026-28990 (crash PoC, ≤26.4.2), SEP exhaustion (DoS, 26.1–26.2). Medium effort,
   already roadmap-planned. **DONE 2026-08-21 (K1.5 + K1.5b + K4.2 + K4.8a + K4.10 + K4.12).**

3. **K4.2 harness first artifact: copy `gen_exr_trigger.py` into `scripts/` (or
   `research/`) and add a `fuzz-exr` helper** that batch-generates mutated EXRs
   (width/height/channel count/offset table), scp's them to the phone, opens them via
   Filza's viewer, and greps `/tmp/FilzaTweak.log` for panics. Unblocks the oldest open
   Section-0 item with real code. **DONE 2026-08-21 (K4.2 — full harness; EXR generator
   lives in pocs/exr/gen_exr_trigger.py, stdlib-only, byte-identical to the original).**

4. **Panic-PoC deploy commands (`poc applejpeg` / `poc sep-panic` / `poc dirtyslide`)**
   — plausible for a research toolkit (crash-monitor armed, explicit warnings) but they
   reboot the device by design; needs user sign-off before wiring into the menu. SEP PoC
   is the easiest to build (Theos). **DONE 2026-08-21 (K1.5b — `poc sep-panic` + `poc exr`
   fully automated; applejpeg/dirtyslide print the macOS+Xcode manual flow).**

### Not menu-material
- Glass-Cage duplicate: no code to add; dedupe note only.
- DirtySlide LPE path is macOS/VMAPPLE — stays a research reference on the host, not a
  phone-menu item (the iOS app is Xcode/devicectl-driven).

---

*Written 2026-08-21 by Hermes (session with kaffeindecaf) after full read of
`referenceforAI/` + `referenceforAI/moreprojects/`. Sources: repo READMEs, PoC sources
(ViewController.m 1357 lines, t_reslide_zf.c 2468 lines, launcher.c, Makefile,
gen_exr_trigger.py, sep_panic_poc.c), Glass Cage Report.md, diff vs projects/ copy.*
