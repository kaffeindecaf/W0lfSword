# PoC Lab (C6) — proof of concepts for found-but-unimplemented bugs

Every bug this repo found or tracked that is not yet a shipped exploit
stage, with a status: does a host-side PoC exist, does it run, and if
not, why not. The `poclab` command in the W0lfSword CLI shows the same
table and runs the testable ones (`./W0lfSword poclab list`, `test
alac`, `test libxml2-diff`).

Statuses: TESTED-WORKING (reproduced), TESTED-NEGATIVE (tried, no bug),
BLOCKED (host limitation), NEEDS-DEVICE, NEEDS-CACHE, PATCHED.

## alac — ALAC decoder overflow (BB-038 + BB-039) — TESTED-WORKING

Repro: `./W0lfSword poclab test alac`. Clones apple/ALAC once into
.w0lfsword/poclab/alac, builds the two harnesses from research/alac_poc/
with -fsanitize=address,undefined, runs them.

Why it works, in plain terms: the ALAC bitstream has a 1-bit
"partialFrame" flag. When it is set, the decoder throws away the sample
count the caller gave it and reads a fresh 32-bit count straight out of
the compressed data (ALACDecoder.cpp:250-254). Nothing ever checks that
count against frameLength, which is the only number that sizes the
internal buffers (calloc at ALACDecoder.cpp:135-139). A count of
0x100000 with a frameLength-1 cookie writes 4 megabytes of int32s into a
4-byte buffer. The cookie bug is simpler: Init() looks for 'frma' and
'alac' atoms by reading cookie[4..7] before checking how big the cookie
actually is (ALACDecoder.cpp:101-113), and the -=12 underflow for small
cookies makes the size check pass on garbage.

Evidence: ASAN heap-buffer-overflow WRITE at ALACDecoder.cpp:309
(uncompressed path) and ag_dec.c:321 (compressed path), plus
stack-buffer-overflow READ at ALACDecoder.cpp:102 for the cookie. Full
traces in research/audio_frameworks.md.

Caveat: this is the open-source reference decoder. Apple ships this
code lineage in CoreAudio, but the production binary in the dyld cache
has not been disassembly-confirmed. Do that before reporting anything
to Apple. The harnesses only prove the reference code is broken.

## libxml2-diff — Apple libxml2 fork vs upstream — TESTED-NEGATIVE

Repro: `./W0lfSword poclab test libxml2-diff`. Clones
apple-oss-distributions/Libxml2 and GNOME/libxml2, builds both with
cmake, runs a crafted-catalog harness (scripts/poclab_cat.c) across
malformed nextCatalog shapes.

What was tested: Apple's fork reports libxml 209013 (2.9.13 base),
upstream is 21600 (2.15.0). Three catalog shapes: nextCatalog without
the catalog attribute, with an empty attribute, and a valid entry
followed by an invalid one. None crashed either fork.

Why it came back negative, honestly: the version gap is real but Apple
backports selectively. The CVE-2024-25062 reader guards and the modern
xmlParseInternalSubset rewrite are present in their tree. The one
divergence found, the missing nextCatalog dedup loop (upstream commit
f75abfca, added after 2.9.13), is not a security gap: the August 2026
NULL-deref fix (c632489) only guards that loop, and Apple's code does
not have the loop, so the vulnerable path does not exist there. The
dedup absence is behavioral (duplicate nextCatalog entries each trigger
a catalog load during resolution; a recursion guard bounds it).

Side findings that are real: Apple's fork does not compile on Linux
without two patches (uri.c is missing <stdint.h>, xpath.c calls the
Darwin-only linkedOnOrAfterFall2022OSVersions). So host-side testing of
the exact iOS-shipped libxml2 is not turnkey, and a naive
fork-vs-upstream diff overstates the risk.

Not done: schema validation, XInclude, push-parser paths. Those are
future work if this line is pursued.

## mdns — mDNSResponder record-decoder fuzz — BLOCKED

The plan was to build apple-oss-distributions/mDNSResponder (mDNSPosix)
on Linux and set up a packet fuzzer for the CVE-2015-7987-class record
decoders. The build needs mbedTLS. The clone does not vendor it, the
mbedtls source clone needs its own submodules, and this host has no
passwordless sudo for libmbedtls-dev. Blocker is a dependency chain,
not a code problem. With libmbedtls-dev installed the build is expected
to work (the Makefile targets Linux explicitly). Left in ROADMAP C6.3.

## dirtyslide — DirtySlide kernel OOB R/W (CVE-2026-43724) — NEEDS-MACOS

The only public kernel-write LPE in the 26.x window: a missing in-page
bounds check in vm_shared_region_slide_page_v5() reachable via syscall
536. The public PoC works on macOS VMs. It does not run on this Linux
host (the exploit depends on macOS kernel behavior), and on a real
iPhone the author's own writeup says it needs a sandbox bypass plus
SPTM-free silicon (A16 or older), and even then is unproven on iOS.
Nothing to test here. Full analysis in research/kernel26_cves.md.

## bl_sbx — itunesstored/bookassetd write-escape (BB-041) — NEEDS-DEVICE

Two daemons trust user-writable SQLite metadata, so a crafted
downloads.28.sqlitedb + BLDatabaseManager.sqlite + EPUB can write
arbitrary mobile-owned files after three reboots. The PoC is public
(github.com/hanakim3945/bl_sbx). Testing requires writing files under
/var/mobile/Media on a real phone over AFC/USB, which needs the device
attached. The SE2 is not connected this session. The bug is claimed
alive through 26.2b1; a fix would land in 26.3+ release notes. Details
in BUG_BOUNTY BB-041.

## fontparser — FontParser OOB write diff (CVE-2025-43400) — NEEDS-CACHE

The test device (18.4.1) is vulnerable to an OOB write with no public
PoC. The way in is to diff libFontParser between 18.4.1 and 18.7.1 to
recover the fix, then hunt siblings. That needs the dyld shared caches
for both versions. The device is not attached (cache would come off the
phone) and the IPSW rootfs is encrypted, so the caches are not
obtainable on this host right now. This is the highest-leverage open
research item. Details in research/other_frameworks.md, BB-040.

## cve-2025-46285 — kernel timestamp LPE (K4.7) — NEEDS-DEVICE

Integer overflow fixed by adopting 64-bit timestamps, app to root,
fixed in 26.2/18.7.3, so live on 26.1 and on 18.4.1. No public PoC or
writeup. The repo's own kernelcache diff (26.1 vs 26.2) shows the fix
is not in the seconds-to-ns multiply paths, which narrows it but does
not locate the bug. Trigger validation needs a 26.1 device. Nothing
testable on the host. Details in research/kernel26_cves.md.

## apac — APAC HOA remapper (CVE-2025-31200) — PATCHED

The in-the-wild audio codec bug (channel-count mismatch -> OOB in
APACChannelRemapper::Process). Fixed exactly in iOS 18.4.1, which is
what the test device runs. So it cannot be tested here, and the value
is now the pattern: config-vs-buffer size mismatches in the APAC
decoder are a live hunting ground for a sibling. Public PoCs exist.
Details in research/audio_frameworks.md.

## cve-2025-43329 — sandbox permissions escape (BB-042) — NEEDS-DEVICE

Sandbox escape fixed only in iOS 26.0, never backported to 18.x, so
live on every 18.x device including the SE2. No public writeup. The
recovery path is diffing the sandbox components between 18.7.10 and
26.0. Testing needs a stock 18.x device (the SE2 is jailbroken, which
alters the sandbox and invalidates the test). Details in BUG_BOUNTY
BB-042 and research/userspace_escapes.md.

---

How to add a concept: append a row to poclab_concepts() in the W0lfSword
script, add a test script under scripts/poclab_test_*.sh if it is host-
testable, wire it in cmd_poclab's test case, and document it here.
