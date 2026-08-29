# Other framework targets (C4.4 survey)
### Survey for ROADMAP C4.4 (beyond ImageIO + audio). Compiled 2026-08-29.
**Context:** SE2/A13 (arm64e), jailbroken iOS 18.4.1, kernel gate closed on 26.1+. Host: Linux.
**Goal:** rank userspace attack surfaces by (open-source availability, parser complexity, historical CVE density, attacker reachability from Messages/Safari/Mail/Quick Look), with concrete bug-hunting approaches.

**Legend:** [ok] = verified by direct source this survey (URL/CVE checked); [?] = plausible but NOT fully verified; [no] = confirmed absent/false.

**Verified open-source inventory (2026-08-29, `git ls-remote` ground truth):**
`apple-oss-distributions` contains exactly these media/parser-relevant repos: **Libxml2, ICU, mDNSResponder, Libiconv** (plus the WebKit suite: WebKit/WebCore/JavaScriptCore, and Libc/Libsystem - outside this survey's scope). Everything else below - CoreMedia, CoreText/FontParser, PDFKit, CoreGraphics, Quick Look, ModelIO, ImageIO, CoreAudio, AudioToolbox - **does not exist** in the org and is a **closed-source reverse-engineering target on the jailbroken SE (18.4.1)**. `opensource.apple.com` is dead (302/404). For audio specifically: **`github.com/apple/ALAC` exists and is cloneable - the ONLY auditable Apple audio code** (all other audio is closed).

---

## TL;DR - Ranked targets

| # | Target | Open source | CVE density | Reachability | Verdict |
|---|--------|-------------|-------------|--------------|---------|
| 1 | **CoreText / FontParser** (`libFontParser.dylib`, `libType1Scaler.dylib`) | [no] closed | 🔥🔥🔥 (incl. **CVE-2025-43400, live on 18.4.1**) | Safari (web fonts), Mail, Messages, any text render | **HUNT NOW** - diff 18.4.1 vs 18.7.1 to find the fix, then siblings |
| 2 | **CoreMedia** (sample buffers, HLS, MP4/MOV demux) | [no] closed | 🔥🔥🔥 (2025–26 cluster incl. actively-exploited UAF) | Messages (video attachments), Safari `<video>`, Quick Look, Mail | **HUNT** - on-device AVPlayer probe harness |
| 3 | **PDFKit / CoreGraphics PDF** (CGPDFDocument, JBIG2/JPX) | [no] closed | 🔥🔥 (FORCEDENTRY = proven 0-click) | iMessage 0-click proven, Mail, Safari, Quick Look | **HUNT** - FORCEDENTRY bug class as template |
| 4 | **libxml2** | [ok] `apple-oss-distributions/Libxml2` | 🔥🔥 (iOS 9.3.2 family; CVE-2024-25062 in iOS 17.4) | WebKit (DOMParser/XMLHttpRequest), Mail, iWork | **HUNT (cheap)** - fork-vs-upstream diff + OSS-Fuzz port |
| 5 | **mDNSResponder** (Bonjour) | [ok] `apple-oss-distributions/mDNSResponder` | 🔥 (RCE-class 2015 bugs; 26.5 fixes) | LAN attacker, **no user interaction** | **HUNT (medium)** - buildable on Linux, fuzz mDNSCore |
| 6 | **ICU** | [ok] `apple-oss-distributions/ICU` | 🔥 (CVE-2020-10531 etc.) | Everywhere via Foundation/WebKit, but indirect | Watchlist - port upstream fuzzers |
| 7 | **Quick Look / ModelIO** | [no] closed (ModelIO: 404) | 🔥 (CVE-2026-43818, CVE-2021-1753) | Messages USDZ, Quick Look 3D, ARKit | Mostly ImageIO-backed (already covered) - ModelIO is the new bit |
| 8 | **CoreImage (CIFormat)** | [no] closed | low (usually filed under ImageIO) | Indirect (downstream of ImageIO) | Deprioritize |

---

## 1. CoreMedia - 🟥 HIGH VALUE

**Verdict: worth hunting.** Closed source, but the single most attacker-relevant media framework and it keeps bleeding bugs (2025–2026 cluster). Delivered-content parsers (MP4/MOV demux, sample buffers, closed captions, HLS) run on any video the user receives.

**Where to research**
- **Open source:** [no] None. `apple-oss-distributions/CoreMedia` → 404 (verified; no `CoreAudio`, `AudioVideoBundles`, or `sqlite` in the org either). Must reverse the dylib from the shared cache (see §8); on-device binary: `/System/Library/Frameworks/CoreMedia.framework/CoreMedia` (carved from the cache).
- **Fuzz entry points:** `AVURLAsset`/`AVPlayer` (movie file), `CMSampleBuffer`-based custom demux, `CMFormatDescription` metadata, closed-caption/CDT parsing, HLS playlist parsing (HLS is text/plist - also pulls in libxml2 paths).
- **Template CVEs (all verified [ok]):**
  - **CVE-2025-24085** - CoreMedia use-after-free; "Apple is aware of a report that this issue may have been actively exploited against versions of iOS before iOS 17.2"; fixed iOS 18.4 / iPadOS 17.7.6 (devicebase listing of Apple release notes; also the "Glass Cage" chain used it for kernel exec - [?] chain write-up is self-published/disputed, CVE itself is real and Apple-confirmed).
  - **CVE-2025-24190 / CVE-2025-24211** - CoreMedia, "Processing a maliciously crafted video file may lead to unexpected app termination or corrupt process memory", both credited to Hossein Lotfi (@hosselot) of ZDI (Apple release notes via devicebase) [ok].
  - **CVE-2026-28956** - "Media File" memory corruption (CWE-125/787), fixed iOS 26.5 [ok] (component attribution [?]).
  - iOS 26.0 (2025-09-15) patched **both CoreAudio and CoreMedia** media-file memory corruption (GBHackers summary of Apple 26.0 notes) [ok].

**Bug-hunting approach**
1. Pull `CoreMedia` + `FigCore`/`CoreMediaIO` dylibs from the 18.4.1 shared cache; map the demux/parser entry points (symbols survive in the cache; `ipsw dyld objc class` helps).
2. Reuse the K4.2/K4.13 pipeline: structure-aware mutation of MP4/MOV/CMF + closed-caption (CEA-608/708, TTML) seeds; on-device probe via a Theos tool driving `AVURLAsset`/`AVPlayer` (mirror `pocs/imgio_probe`).
3. Study CVE-2025-24085's fix (diff 18.3.1 vs 18.4 `CoreMedia` dylib) - UAF in media pipeline state is a rich sibling-hunt area.
4. Note: since the 26.5/26.6 "media file" fixes keep landing, the bug class is *still being found* upstream - good sign for effort payoff.

---

## 2. CoreText / FontParser - 🟥 HIGH VALUE (top pick)

**Verdict: worth hunting - the most bang-per-effort target.** Closed (`libFontParser.dylib`, `libType1Scaler.dylib`), dense CVE history, **and a fresh OOB-write fix (CVE-2025-43400) landed AFTER 18.4.1 - so a known-vulnerable parser sits on the test device right now.**

**Where to research**
- **Open source:** [no] None (`apple-oss-distributions/CoreText` → 404 [ok]). FreeType is *not* what Apple runs - Apple ships its own parser; use FreeType/otfcc only as reference for format semantics (TrueType/OpenType/CFF, COLRv0/v1, SBIX, CBDT/CBLC, SVG-in-OpenType).
- **Fuzz entry points:** `CTFontCreateWithData`/`CTFontManagerCreateFontDescriptorsFromData` (font file → CTFont), `CTLineCreateWithAttributedString` (shaping), `CoreText` text layout on any UIWebView/WKWebView content, PDFKit (fonts inside PDFs!), Quick Look (font files).
- **Template CVEs (all verified [ok]):**
  - **CVE-2025-43400** - FontParser out-of-bounds **write**; "Processing a maliciously crafted font may lead to unexpected app termination or corrupt process memory"; fixed iOS 18.7.1 / 26.0.1 (2025-09). **18.4.1 is vulnerable to it** (SANS ISC + Malwarebytes). Apple-internal discovery → no public PoC; find it by diffing.
  - **CVE-2020-27930** - Safari RCE in Type 1 fonts, `libType1Scaler.dylib`, stack OOB (P0 0-days-in-the-wild RCA, Mateusz Jurczyk & Sergei Glazunov). Variant family: **CVE-2020-27943** (heap OOB write, Counter Control hints), **CVE-2020-27944** (heap OOB write, STOREWV integer overflow), **CVE-2020-27946** (memory disclosure), **CVE-2020-29624** (stack corruption, `/BlendDesignPositions`) [ok].
  - **CVE-2015-0091/0092/0093** - P0's "One font vulnerability to rule them all" (BLEND operator / STOREWV / Counter Control Hints) - the canonical study of FontParser interpreter bugs [ok] (projectzero.google blog).
  - **CVE-2021-1758** - CoreText OOB read in `GetResourcePtrCommon` (STAR Labs, has ASan repro) [ok].

**Bug-hunting approach**
1. **Diff 18.4.1 vs 18.7.1 `libFontParser.dylib`** (shared-cache extraction, §8) → locate the CVE-2025-43400 fix → hunt adjacent code paths for siblings. Best single action in this whole survey.
2. Host-side: CoreText on macOS shares the parser; fuzz with `CTFontCreateWithData` + libFuzzer/AFL++ harness, corpus from Google Fonts + malformed-font corpora (P0's fonts corpus). Font files reach the parser from Safari (web fonts), Mail, Messages, PDFs - huge blast radius.
3. On-device: extend `imgio_probe`-style Theos tool to call CTFont APIs on a font corpus; 18.4.1 is the *vulnerable* baseline, so crashes = live findings.

---

## 3. PDFKit / CoreGraphics PDF - 🟥 HIGH VALUE

**Verdict: worth hunting.** The only userspace target with a *publicly proven zero-click iMessage exploit* (FORCEDENTRY). Closed source; JBIG2/JPX decoders live inside CoreGraphics.

**Where to research**
- **Open source:** [no] None - `apple-oss-distributions/PDFKit` → 404, no `libjbig2`/`jasper`/`openjpeg` in the org (checked [ok]). Apple's JBIG2/JPX decoders are proprietary (reference: Artifex `libjbig2` is AGPL - not what Apple ships).
- **Fuzz entry points:** `CGPDFDocument` (CoreGraphics), PDFKit's `PDFDocument` (higher level, also parses forms/annotations), `QLPreviewController` on PDFs, Safari/Mail PDF viewers, `NSAttributedString` from PDF? (no). JBIG2 and JPEG2000 streams *inside* PDFs are the historically-exploited bits.
- **Template CVEs (verified [ok]):**
  - **CVE-2021-30860 (FORCEDENTRY)** - integer overflow in CoreGraphics PDF/PDF-XRef processing with JBIG2-encoded stream; 0-click via iMessage using the **"fake .gif" trick** (ImageIO sniffs the real format and hands the PDF to CoreGraphics, bypassing BlastDoor extension checks); in the wild since ≥ Feb 2021; fixed iOS 14.8. Citizen Lab captured the payloads (748-byte PSD + 4 JBIG2 PDFs); Project Zero's "A deep dive into an NSO zero-click iMessage exploit: Remote Code Execution" (2021-12-15) is the definitive technical write-up [ok][ok].
  - **CVE-2020-9897** - PDF out-of-bounds **write** → RCE, fixed iOS 14.2 [ok] (cvefeed).
  - **CVE-2019-8544** - PDFKit heap corruption, "Processing maliciously crafted web content may lead to arbitrary code execution", fixed iOS 12.2 (Safari-reachable) [ok].
  - CVE-2026-64765/64766 - "Processing a maliciously crafted file" integer overflows fixed in iOS 26.6 [?] (component attribution not confirmed).

**Bug-hunting approach**
1. Study the P0 FORCEDENTRY deep-dive: the bug class is integer overflow in allocation math from PDF object values (size fields in XRef/stream dicts) → undersized buffer → JBIG2 symbol-table write. Recreate the class: fuzz PDF streams with mutated /Length, /W, JBIG2 segment headers, JPX tile sizes.
2. Corpus: pdf.js test corpus + mutated FORCEDENTRY payload shape (JBIG2 streams are small and dense - perfect for structure-aware mutation).
3. On-device harness: `CGPDFDocumentCreateWithURL` / `PDFDocument initWithURL` in a Theos probe; also drive Quick Look (PDFs thumbnailed automatically in Messages/Mail = the exact FORCEDENTRY delivery path).
4. Note: `QLThumbnailGenerationRequest` on a PDF triggers CGPDF **without** user opening the file - same as FORCEDENTRY.

---

## 4. libxml2 - 🟧 MEDIUM-HIGH (cheapest wins)

**Verdict: worth hunting - it's open source, Apple *must* sync upstream fixes, and WebKit keeps the HTML/XML parser reachable from remote content.**

**Where to research**
- **Open source:** [ok] `https://github.com/apple-oss-distributions/Libxml2` (exists, default branch `main`, pushed 2026-03) + upstream `https://gitlab.gnome.org/GNOME/libxml2` (CVE-2024-25062 links to issue #604).
- **Fuzz entry points:** WebKit's XML/HTML paths (DOMParser, XMLHttpRequest responseXML, SVG-in-HTML), Mail (HTML), iWork, `NSXMLParser`/`NSXMLDocument` in apps, XPath/XPointer (Safari CSS/JS), HLS playlists (plist/XML), profile plists (containermanagerd/MobileAsset - interesting for the existing sandbox-escape work).
- **Template CVEs (verified [ok]):**
  - **CVE-2024-25062** - `xmlValidatePopElement` use-after-free (XML Reader + DTD validation + XInclude); libxml2 < 2.11.7/2.12.5; **patched by Apple in iOS 17.4/macOS 14.4 with credit to "OSS-Fuzz, and Ned Williamson of Google Project Zero"** [ok] (Apple release notes + NVD). High-confidence mapping of the Apple entry to this CVE [?] (credit matches exactly).
  - **CVE-2016-1833…CVE-2016-1850 family** (~18 CVEs) - shipped in iOS 9.3.2: heap overflow `xmlFAParsePosCharGroup` (CVE-2016-1840, RCE), `xmlStrncat` heap overflow (CVE-2016-1834), UAF `htmlParsePubidLiteral` (CVE-2016-1837), UAF `xmlDictComputeFastKey` (CVE-2016-1836), etc. Proves remote HTML/XML → RCE through Apple's libxml2 [ok].
  - **CVE-2016-5131** - UAF via XPointer `range-to` (reachable from browsers) [ok].
  - **CVE-2026-6653** - fresh upstream UAF in `xmlParseInternalSubset` (2.9.11–2.11.0) [?] (single secondary source) - check whether Apple's fork already syncs it.

**Bug-hunting approach**
1. **Diff Apple's fork against upstream GNOME libxml2** - every upstream CVE fix Apple hasn't merged is a free finding (this is how CVE-2024-25062-class bugs keep getting re-discovered in Apple builds).
2. Port OSS-Fuzz's libxml2 harnesses (HTML/XML/XPath) to libFuzzer on the host - upstream bug density is still high, and Apple's fork lags.
3. Focus areas: HTML parser push mode (`htmlParser` used by WebKit's old HTML path), XPath/XPointer (CVE-2016-5131 class), DTD/XInclude validation state machines.

---

## 5. ICU - 🟧 MEDIUM

**Verdict: watchlist.** Open source, but reachability on iOS is mostly *indirect* (through Foundation string APIs, WebKit Intl, text layout) and Apple has historically shipped ICU fixes late - a fork-diff yields findings, but exploitation paths are fuzzier.

**Where to research**
- **Open source:** [ok] `https://github.com/apple-oss-distributions/ICU` (exists, pushed 2026-06) + upstream `unicode-org/icu`.
- **Fuzz entry points:** `NSString`/`NSAttributedString` conversions (via Foundation → ICU converters), WebKit Intl (JS `Intl.*` - remote-reachable!), `usearch`/`ubrk` text breaking, regex (`uregex`) from JS, `unorm2` normalization, collation.
- **Template CVEs (verified [ok]):**
  - **CVE-2020-10531** - integer overflow in `UnicodeString::doAppend` (`unistr.cpp`): oldLength+srcLength wraps 32-bit → undersized buffer → heap corruption on string concat; reachable from untrusted Unicode text [ok] (SentinelOne write-up).
  - **CVE-2015-5874 / CVE-2015-5761** - ICU memory corruption fixed in iTunes 12.3 via "updating ICU to version 55" [ok] (Apple release notes).
  - **CVE-2014-8146 / CVE-2017-14952 / CVE-2017-17484** - historical ICU bugs [ok] (IBM/OpenCVE).
  - macOS 14.4+ advisory acknowledges ICU researchers again (entry added Feb 2025, specific CVE not surfaced in this survey) [?].

**Bug-hunting approach**
1. Fork-diff Apple's ICU vs upstream; port upstream's oss-fuzz ICU harnesses (icu4c has an active fuzzing corpus).
2. Highest-value entry: **JavaScriptCore's Intl** (remote JS) and converter paths (`ucnv`) - converters are where Apple's iOS-specific patches diverge.
3. Bonus sibling: **Libiconv** (`apple-oss-distributions/Libiconv`, open source) - Foundation's character-set conversion layer; same fork-diff playbook, tiny surface, historically under-audited.

---

## 6. mDNSResponder - 🟧 MEDIUM (network-reachable, no interaction)

**Verdict: worth hunting - the only target where a *remote, interaction-free* attacker reaches the code, and it's fully open source and buildable on Linux for host fuzzing.**

**Where to research**
- **Open source:** [ok] `https://github.com/apple-oss-distributions/mDNSResponder` (397★, active 2026-06; dirs: `mDNSCore/`, `mDNSPosix/`, `mDNSShared/`). Builds on Linux/BSD (`mDNSPosix`).
- **Fuzz entry points:** mDNS packet parsing (`mDNSCore/mDNS.c`, DNS record decoders), DNS-SD service registration (`handle_regservice_request`), NSEC3/TSIG/RFC3110 (DNSSEC) record handling, duplicate-record handling.
- **Template CVEs (verified [ok]):**
  - **CVE-2015-7987** - **multiple buffer overflows** in `GetValueForIPv4Addr`, `GetValueForMACAddr`, `rfc3110_import`, `CopyNSEC3ResourceRecord` → remote code execution / OOB R/W; fixed in mDNSResponder 625.41.2 (Apple security update HT103626 for iOS < 9.1) [ok][ok].
  - **CVE-2015-7988** - NULL deref in `handle_regservice_request` → remote DoS/RCE [?](RCE claim per OpenCVE text) [ok](bug itself real).
  - **VU#221876** - classic 2007 mDNSResponder buffer overflow (CERT-KB) [ok].
  - iOS 26.5 (2026) release notes list multiple mDNSResponder fixes: LAN DoS, unexpected system termination, memory corruption (AppleMagazine summary of Apple notes; **individual CVEs not surfaced - [?] unverified**) [ok](fixes exist).
  - **"bombdrop"** (Barrett Lyon, 2025-12): unauthenticated LAN-wide mDNS DoS; Apple closed the report as "addressed" without bounty - [?] status disputed/unpatched per researcher.

**Bug-hunting approach**
1. Host: build `mDNSCore` on Linux; write a structure-aware mDNS packet mutator (or use AFL++ with a UDP harness on `mDNSResponder`'s parse loop).
2. On-device (jailbroken 18.4.1): craft packets with Scapy against the real daemon; watch for crash/reboot; capture the crash log for symbolication via the shared cache.
3. Best template: the CVE-2015-7987 record-decoder overflows - record-type dispatch on attacker-controlled rdata is still a live area (DNSSEC records, NSEC3).
4. Caveat: Apple's shipped mDNSResponder is *heavily patched* vs the OSS repo - diff the OSS code against the pulled device binary to see what Apple changed.

---

## 7. Quick Look thumbnailing / CoreImage / ModelIO - 🟨 MEDIUM

**Verdict: Quick Look is a *delivery surface* (auto-thumbnailing = zero-interaction parsing, proven by FORCEDENTRY and the 2025 chains) but its decoders are ImageIO/CoreGraphics - already the repo's home turf. The genuinely new bit is ModelIO (USDZ/OBJ/STL/PLY/DAE parsing). CoreImage: deprioritize (bugs usually filed under ImageIO).**

**Where to research**
- **Open source:** [no] `apple-oss-distributions/QuickLook` → 404, `apple-oss-distributions/ModelIO` → 404 [ok]. (ModelIO's USD handling is Apple's own; Pixar's `usd-core` is a reference for format semantics only.)
- **Fuzz entry points:** ModelIO: `MDLAsset initWithURL:` (also triggered by Quick Look 3D preview of USDZ - Messages/Safari/AirDrop delivery); Quick Look: `QLThumbnailGenerationRequest` (runs in `com.apple.quicklook.ThumbnailsAgent`, sandboxed - the 2025 "Glass Cage" chain treated the thumbnailer as a sandbox-escape stage [?] chain unverified); CoreImage: `CIContext` render of crafted `CIImage` (downstream of ImageIO, skip).
- **Template CVEs (verified [ok]):**
  - **CVE-2026-43818** - image integer overflow → RCE fixed iOS 26.6; crash processes include `QuickLookThumbnailing`, `imagent`, `MediaLibraryService` (SentinelOne). This is the libAppleEXR `CreateDecompressedLocations` heap overflow (hxr1.ghost.io write-up) - **same family as the repo's CVE-2026-28990 EXR work** [ok].
  - **CVE-2021-1753** - ModelIO USD parsing out-of-bounds read → info disclosure (ZDI-21-139) [ok].
  - **CVE-2019-8731** - Quick Look default-permission issue (minor) [ok].

**Bug-hunting approach**
1. ModelIO: extend the `imgio_probe` pattern → `mdl_probe` Theos tool calling `MDLAsset` on a USDZ/OBJ/STL corpus (grab free USDZ samples + mutate with the K4.2 mutator); template = ZDI-21-139 OOB-read style (USD array offsets).
2. Quick Look: treat as the *delivery* testbed for the ImageIO/CoreMedia/PDF findings (thumbnail generation auto-parses received files) - fuzz once per codec family via `QLThumbnailGenerationRequest` in a probe app.

---

## 8. DYLD shared cache & private-framework reverse engineering (enabling workflow for all of the above)

**Verdict: this is the *prerequisite* for every closed target above. On the jailbroken SE (18.4.1) everything is one scp away.**

**What to pull off-device (18.4.1, arm64e):**
- `/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64e` (+ `.1`, `.2` … sub-caches) - the whole userspace in one file. Also extractable from an IPSW without a device.
- Priority binaries (canonical on-device paths; carve from the cache):
  - CoreText: `/usr/lib/libFontParser.dylib`, `/usr/lib/libType1Scaler.dylib`
  - Media: `/System/Library/Frameworks/CoreMedia.framework/CoreMedia`, `FigCore`, `CoreMediaIO`
  - Audio: `/System/Library/Frameworks/AudioToolbox.framework/AudioToolbox`, CoreAudio
  - PDF/Graphics: `/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics` (CGPDF/JBIG2/JPX), `/System/Library/Frameworks/PDFKit.framework/PDFKit`
  - Quick Look: QuickLook.framework + QuickLookUIFramework (ThumbnailsAgent runs QL's thumbnail path)
  - Network: `/usr/sbin/mDNSResponder`; Text: `libicucore.A.dylib`, `libxml2.2.dylib`; 3D: `ModelIO.framework/ModelIO`

**Tools (verified [ok]):**
- **blacktop/ipsw** (`https://github.com/blacktop/ipsw`) - `ipsw extract --dyld <IPSW>` pulls the cache straight from an IPSW (s11research demonstrates 15.5 extraction); `ipsw dyld extract <dsc> --dylib FontParser`, `ipsw dyld info`, `ipsw dyld objc class --class NSString`, `ipsw dyld disass/xref/dump`, symbolication, and an AI-assisted decompiler for dsc functions.
- **kennytm dyld_decache** (`https://github.com/kennytm/Miscellaneous`, `dyld_decache.cpp`) - classic; arm64 caches need Apple's **dsc_extractor** (in dyld source tarballs) per theapplewiki/iosre notes.
- **DyldExtractor** - the engine behind BinaryNinja's `bn-dyldsharecache` plugin (best dylib reconstruction; theapplewiki).
- **Ghidra** (with dyldcache loader) / **IDA 7.5+ DSCU** / **radare2/rizin** for the actual analysis; **Frida** on the jailbroken device for runtime tracing of parser entry points.
- `opensource.apple.com` now redirects (302) - the GitHub org `apple-oss-distributions` is the current source of truth. [?] Correction for ROADMAP C4.2: `apple-oss-distributions/CoreAudio` does **not** exist, and the only auditable Apple audio code is **`github.com/apple/ALAC`** (Apple Lossless reference codec - exists, cloneable; earlier "404" reports were GitHub blocking bare curl without a browser UA). Point C4.2's audit at ALAC; AudioToolbox/CoreAudio internals are closed and must be RE'd from the shared cache instead.

**Workflow:** scp cache → `ipsw dyld extract` → Ghidra/ipsw analysis of the target parser → identify export stubs (e.g. `CTFontCreateWithData`, `CGPDFDocumentCreateWithURL`) → write host-side harness (macOS binaries share these parsers) → on-device Theos probe for confirmation on the *vulnerable* 18.4.1 baseline.

---

## Note on JavaScriptCore/WebKit
Skipped per scope (covered by another repo). CVE density is the highest of any component (multiple 2024–2026 zero-days: CVE-2025-24201 used in the "Glass Cage" chain [?], CVE-2024-54534/54543, CVE-2025-24209… all [ok] from Apple notes) - but it's a mature, heavily-researched target; the frameworks above are where a small team has better odds.

---

## Ranking rationale (score 1–5 each)

| Target | Open src | Parser complexity | CVE density | Reachability | Total |
|--------|:---:|:---:|:---:|:---:|:---:|
| CoreText/FontParser | 1 | 5 (font interpreters = exotic) | 5 | 5 (fonts everywhere) | **16** |
| CoreMedia | 1 | 5 (media pipeline) | 5 | 5 (Messages/Safari/QL) | **16** |
| PDFKit/CGPDF | 1 | 5 (PDF+JBIG2+JPX) | 4 | 5 (proven 0-click) | **15** |
| libxml2 | 5 | 3 | 4 | 4 (WebKit) | **16*** (*cheapest: fork-diff = near-free findings) |
| mDNSResponder | 5 | 3 | 3 | 4 (LAN, no interaction) | **15** |
| ICU | 5 | 3 | 3 | 3 (indirect) | **14** |
| Quick Look/ModelIO | 1 | 4 | 3 | 4 | **12** |
| CoreImage | 1 | 3 | 2 | 2 | **8** |

## Top 5 recommended targets (action order)
1. **CoreText/FontParser** - CVE-2025-43400 is *live on the 18.4.1 test device*; diff 18.4.1 ↔ 18.7.1 `libFontParser.dylib` to recover the fix, then hunt siblings. Template: P0's BLEND/STOREWV family (CVE-2015-0091-93, CVE-2020-27930/43/44/46/29624).
2. **CoreMedia** - actively-exploited UAF (CVE-2025-24085) + steady 2025–26 fix stream; build AVPlayer/AVURLAsset on-device probe harness.
3. **PDFKit/CoreGraphics PDF** - FORCEDENTRY (CVE-2021-30860) is the best-documented 0-click template in existence; recreate the integer-overflow-in-JBIG2-stream class.
4. **libxml2** - cheapest: diff Apple's fork vs upstream, port OSS-Fuzz harnesses; every unsynced upstream fix is a free bug report (CVE-2024-25062 precedent).
5. **mDNSResponder** - only interaction-free remote target; builds on Linux for host fuzzing; CVE-2015-7987 record-decoder overflows are the template.

---

## Sources
- Repo existence: `git ls-remote` on candidate `apple-oss-distributions` repos (verified 2026-08-29: media-relevant org inventory = Libxml2, ICU, mDNSResponder, Libiconv; CoreMedia/CoreText/PDFKit/QuickLook/ModelIO/ImageIO/CoreAudio/AudioToolbox/sqlite absent) + GitHub API spot-checks ([?] API calls were rate-limited; 404s cross-checked against git ls-remote). `github.com/apple/ALAC` exists (cloned successfully).
- Apple release notes: support.apple.com (iOS 17.4 = 120893, macOS 14.4 = 120895, iOS 15.4 = 102850, mDNSResponder update = 103626); devicebase.net Apple update listing; GBHackers iOS 26 summary.
- Citizen Lab: "FORCEDENTRY: NSO Group iMessage Zero-Click Exploit" (citizenlab.ca/2021/09/…).
- Project Zero: "A deep dive into an NSO zero-click iMessage exploit: Remote Code Execution" (googleprojectzero.blogspot.com/2021/12/…); "One font vulnerability to rule them all" (2015); 0-days-in-the-wild RCA CVE-2020-27930.
- NVD/cvefeed/OpenCVE: CVE-2024-25062, CVE-2020-10531, CVE-2016-1833–1850, CVE-2016-4447/4448, CVE-2015-7987/7988, CVE-2021-1753 (ZDI-21-139), CVE-2021-1758 (STAR Labs), CVE-2020-9897, CVE-2019-8544, CVE-2019-8731, CVE-2026-28956, CVE-2026-43818, CVE-2026-64765/66, CVE-2026-6653.
- hxr1.ghost.io "Heap Overflow in Apple's EXR Decoder"; Malwarebytes/SANS on CVE-2025-43400; SentinelOne CVE-2020-10531 & CVE-2026-43818; AppleMagazine mDNSResponder 26.5 summary; cert.org VU#221876; theapplewiki Dev:dyld_shared_cache; s11research.com iOS RE write-up; blacktop.github.io/ipsw docs.
