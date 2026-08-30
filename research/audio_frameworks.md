# Audio Framework Research (campaign 2026-08-29)

Buffer overflows and other memory-safety bugs in Apple's audio decoding
stack. Started with the only auditable piece (ALAC), mapped the rest of
the attack surface, and got two ASAN-verified findings out of the ALAC
reference decoder. See C4 in ../ROADMAP.md.

## Attack surface map

| Framework | What parses | Entry points | Open source? |
|-----------|-------------|--------------|--------------|
| AudioToolbox | AudioFile / AudioFileStream (CAF, WAVE, AIFF, MP3, AAC/ADTS, M4A, FLAC, Opus), AudioConverter, ExtAudioFile, AudioQueue, AudioCodec | any app playing/decoding audio; Quick Look; AVAudioPlayer/AVAudioEngine | no (binary in dyld cache) |
| CoreAudio | AudioUnit, AudioHardware, HAL; hosts the codec plugins (ALAC, AAC) | audio session / unit processing | no (binary) |
| CoreMedia | audio sample buffers, HLS, MP4/MOV demux, caption parsing | AVPlayer, Safari media, Messages audio | no (binary) |
| AVFoundation | AVAudioPlayer/AVAudioEngine wrappers over AudioToolbox/CoreMedia | app-level playback | no (binary) |
| ALAC codec | the ALAC bitstream + ALACSpecificConfig magic cookie | every ALAC decode on the platform (CoreAudio loads this codec) | YES: github.com/apple/ALAC (the reference implementation Apple ships) |

Formats worth fuzzing, in order of historical bug density: CAF (container,
chunk-size driven), M4A/MP4 (stsd/alac atoms, packet tables), ADTS/AAC
(header + frame parse), ALAC packets (verified bugs below), WAVE (fmt +
fact chunks), FLAC/Opus (bundled third-party decoders).

Attack entry points on the device: `ExtAudioFileOpenURL` /
`AudioFileOpen` on a crafted file, `AudioFileStreamOpen` (streaming,
used by Safari), `AVAudioPlayer initWithContentsOfURL`, AVAudioEngine
`AVAudioPlayerNode scheduleFile`. The ImageIO-style probe pattern
(imgio_probe, K4.13) applies: a headless decode tool for audio would use
ExtAudioFile + AVAudioPlayer in one binary.

## What is auditable

Checked 2026-08-29 (git ls-remote, not API): apple-oss-distributions has
ICU, Libiconv, libxml2, mDNSResponder only. CoreAudio, AudioVideoBundles
and CoreMedia are NOT in apple-oss-distributions; opensource.apple.com is
dead. The only open-source Apple audio code is **apple/ALAC**
(github.com/apple/ALAC, Apache 2.0, the production ALAC codec
implementation). Everything else in the audio stack is binary-only:
reverse-engineering targets, not audit targets.

## Verified findings (ALAC reference decoder)

Both confirmed with ASAN harnesses in alac_poc/ (build against a clone of
apple/ALAC, see below). BUG_BOUNTY entries: BB-038, BB-039.

### F1: partialFrame numSamples heap overflow (CRIT/HIGH)

ALACDecoder.cpp:250-254 (SCE) and 401-405 (CPE): the 1-bit partialFrame
flag overrides the caller's numSamples with 32 bits straight from the
bitstream:

```cpp
if ( partialFrame != 0 )
{
    numSamples  = BitBufferRead( bits, 16 ) << 16;
    numSamples |= BitBufferRead( bits, 16 );
}
```

No bound against mConfig.frameLength (the only thing that sizes the
internal buffers). Init() allocates mMixBufferU/V and mPredictor from
the magic cookie:

```cpp
mMixBufferU = (int32_t *) calloc( mConfig.frameLength * sizeof(int32_t), 1 );
mMixBufferV = (int32_t *) calloc( mConfig.frameLength * sizeof(int32_t), 1 );
mPredictor  = (int32_t *) calloc( mConfig.frameLength * sizeof(int32_t), 1 );
```

Every decode loop iterates numSamples over those buffers:

- ALACDecoder.cpp:309 `mMixBufferU[i] = val;` (SCE uncompressed) - heap
  write overflow, ASAN-verified
- ag_dec.c:321 `*outPtr++ = del;` in dyn_decomp (SCE/CPE compressed,
  writes mPredictor) - heap write overflow, ASAN-verified
- ALACDecoder.cpp:336 / 520-524 `mShiftBuffer[i]` (shift path, CPE does
  numSamples*2) - mShiftBuffer aliases mPredictor
- matrix_dec.c unmix24/unmix32 read `shiftUV[k]` with k up to
  2*numSamples-1 - OOB read of the same buffer
- output loops write the caller's sampleBuffer with the inflated
  numSamples; *outNumSamples reports it back

ASAN trace (harness_overflow.cpp, cookie frameLength=1, stream
partialFrame numSamples=0x00100000):

```
ERROR: AddressSanitizer: heap-buffer-overflow
WRITE of size 4 at 0x502000000014
    #0 ALACDecoder::Decode codec/ALACDecoder.cpp:309
    #1 main harness_overflow.cpp:52
0x502000000014 is located 0 bytes after 4-byte region
    allocated: ALACDecoder::Init codec/ALACDecoder.cpp:135
```

Second trigger path without partialFrame: caller numSamples (e.g. 4096)
against a cookie frameLength=1 also overflows mPredictor via dyn_decomp
(ag_dec.c:321) - the decoder never checks numSamples <= frameLength,
period.

Caveat for the bounty writeup: this is the open-source reference
implementation. The production CoreAudio ALAC codec on iOS/macOS is a
binary; it is very likely the same code but that has to be verified by
disassembly (compare dyn_decomp / Decode structure against
AudioToolbox's ALAC codec plugin in the dyld shared cache) before
submitting to Apple. The magic cookie and partialFrame flag are part of
the public ALAC format (ALACMagicCookieDescription.txt), so any ALAC
file can carry the trigger.

### F2: Init() magic cookie OOB read (MED)

ALACDecoder.cpp:101-113: the decoder sniffs for 'frma'/'alac' atoms by
reading theActualCookie[4..7] BEFORE checking the size:

```cpp
if (theActualCookie[4] == 'f' && ... 'r' ... 'm' ... 'a')
{
    theActualCookie += 12;
    theCookieBytesRemaining -= 12;   // uint32 underflow for 5-12 byte cookies
}
```

A cookie smaller than 8 bytes is read OOB (ASAN-verified with a 4-byte
cookie: stack-buffer-overflow READ at ALACDecoder.cpp:102). For 5-12
byte cookies with an 'frma' prefix, the -= 12 wraps and the later
`>= sizeof(ALACSpecificConfig)` check passes, so 24 bytes are read from
a 12-byte-shifted pointer into a small buffer: heap OOB read. The magic
cookie originates from the container (CAF kuki chunk, MP4 alac atom),
i.e. file-controlled.

## How to reproduce

```bash
git clone --depth 1 https://github.com/apple/ALAC /tmp/ALAC
cp research/alac_poc/harness_overflow.cpp research/alac_poc/harness_cookie.cpp /tmp/ALAC/
cd /tmp/ALAC
g++ -fsanitize=address,undefined -g -I codec harness_overflow.cpp \
    codec/ALACDecoder.cpp codec/ag_dec.c codec/dp_dec.c codec/matrix_dec.c \
    codec/ALACBitUtilities.c codec/EndianPortable.c -o harness_overflow
./harness_overflow    # heap-buffer-overflow WRITE at ALACDecoder.cpp:309
g++ -fsanitize=address -g -I codec harness_cookie.cpp \
    codec/ALACDecoder.cpp codec/ag_dec.c codec/dp_dec.c codec/matrix_dec.c \
    codec/ALACBitUtilities.c codec/EndianPortable.c -o harness_cookie
./harness_cookie      # stack-buffer-overflow READ at ALACDecoder.cpp:102
```

Both harnesses build the trigger with the codec's own BitBufferWrite, so
no hand-assembled bitstreams. The overflow harness uses an uncompressed
(escape=1) SCE frame; flipping the escape bit to 0 reproduces the
compressed-path variant through dyn_decomp.

## Additional audit findings (independently verified 2026-08-29)

Second pass over the same codebase (ASAN+UBSAN harness, /tmp/alac_harness
T1/T2/T5/T6) confirmed three more manifestations, all the same root family
(unvalidated bitstream/cookie fields vs frameLength-sized buffers, and no
bounds checks in the bit layer):

- **F3 (HIGH, ASAN-verified):** ag_dec.c getstreambits/read32bit
  (ag_dec.c:117-126, 135-168) read 4-5 bytes past the frame allocation;
  the only guard is the loop-top `bitPos < maxPos` (ag_dec.c:302) which
  can't cover reads inside the iteration. Truncated compressed frame →
  heap OOB read at ag_dec.c:123 (read32bit ← dyn_get_32bit ← dyn_decomp
  ← ALACDecoder.cpp:283). Also desyncs the stream pointer for later
  elements.
- **F4 (MED, ASAN-verified):** BitBufferRead/ReadSmall/Peek/ReadOne
  (ALACBitUtilities.c:48, 73, 95, 111) read 1-3 bytes past end with the
  bounds asserts commented out; the only caller-side guard is the element
  tag read (ALACDecoder.cpp:215). 1-byte frame → heap OOB read at
  ALACBitUtilities.c:73.
- **F5 (HIGH, conditional):** unpc_block warm-up loop (dp_dec.c:97-101)
  writes out[1..numactive] bounded by numactive (5-bit bitstream field,
  1..30), not by num. With a small attacker cookie frameLength (<
  numactive), e.g. frameLength=16 + numU=20: 16-byte heap OOB write past
  mMixBufferU. Static analysis (no harness).
- Disproved: extra SCE elements past numChannels are guarded in release
  builds (channelIndex >= numChannels → break, ALACDecoder.cpp:591).
- UTILITY-ONLY (alacconvert, NOT shipped on iOS): ReadBERInteger OOB
  read (CAFFileALAC.cpp:245-253), pakt-table fread heap overflow
  (main.cpp:591-660), channel-layout tag array OOB (main.cpp:631/732).
  Not bounty items.
- UB (LOW): denshift=0 → `1<<(denshift-1)` (dp_dec.c:64); mixbits >= 32
  → UB shift (matrix_dec.c); kMaxBitDepth=32 never enforced (Init
  accepts any bitDepth).

Repo note: the canonical reference repo answers on both
github.com/apple/ALAC and github.com/macosforge/alac (same code, 2011
CoreAudio release; last reference-repo push 2016-05, commit c38887c).

## Verified audio CVE catalog (2026-08-29, NVD/P0/Apple release notes)

| CVE | Component | Root cause class | Fixed in | Live on 18.4.1? |
|-----|-----------|------------------|----------|-----------------|
| CVE-2024-54529 | CoreAudio coreaudiod, com.apple.audio.audiohald Mach service | type confusion on HALS_Object (no type check before vtable call) → RCE as coreaudiod (Apple rated kernel-priv) | macOS 15.2 / 14.7.2 (Dec 2024) | n/a (macOS daemon; same service exists on iOS) |
| CVE-2025-31235 | CoreAudio coreaudiod | double-free, found by same P0 fuzzing campaign | macOS 15.4.1 | n/a |
| CVE-2025-31200 | CoreAudio APAC (Apple Positional Audio Codec) HOA decoder | mRemappingArray sized from low 2 bytes of mChannelLayoutTag; global 4ch vs remap 64ch mismatch → 16x OOB access in APACChannelRemapper::Process; actively exploited in the wild | **iOS 18.4.1** / macOS 15.4.1 (Apr 2025) | **PATCHED** (SE2 runs 18.4.1). Public PoCs exist (zhuowei, hunters-sec); the mismatch pattern is the sibling-hunt template |
| CVE-2026-43744 | audio (NVD) | **OOB write**, "Processing a maliciously crafted audio file" | iOS 26.6 | unverified |
| CVE-2021-30963 | AudioToolbox (audio file parsing) | buffer overflow parsing crafted audio file | macOS 11.6.2 / Catalina 2021-008 | patched long ago |
| CVE-2021-30742 | audio file parsing | memory consumption (resource exhaustion) | iOS 14.7/15 | patched |
| CVE-2015-7003 | coreaudiod | uninitialized data structure → code exec | macOS 10.11.1 | patched |

The recurring class: **container-parser memory corruption (CAF/WAVE/AIFF/MP3-ID3/ADTS)
has produced CVEs every year 2015→2026** (CVE-2020-9884/9889 OOB write, CVE-2021-30957
buffer overflow, CVE-2025-43277, CVE-2026-43744 OOB write...). Apple fixes them
piecemeal; each fix is a local bounds check and adjacent bugs keep landing. This is
the #1 live hunt area, reachable in-app via AVFoundation/AudioFileStream (Safari
audio previews, Messages media).

Key research to mine (both verified): Project Zero "Breaking the Sound Barrier" I+II
(Dillon Franke, 2025-05 + 2026-01) fuzzed coreaudiod's HALB Mach service with
Jackalope/TinyInst and open-sourced the harness at
github.com/googleprojectzero/p0tools/tree/master/CoreAudioFuzz. The same
com.apple.audio.audiohald service and CoreAudio framework exist on iOS:
Mach-message fuzzing of iOS coreaudiod is an unexplored variant of this work.
CVE-2025-31200 shows Apple's APAC/HOA decoder (spatial audio, iOS 18+)
is a live bug family: channel-count mismatch → OOB. APAC cookies are
file-controlled via M4A/MP4; the mismatch pattern deserves a structure-aware
fuzzer even though the specific CVE is patched on 18.4.1. The 2025 in-the-wild
exploit (CVE-2025-31200 + CVE-2025-31201 RPAC bypass + SEP misuse, zero-click
iMessage chain per CISA vulnrichment issue 200) proves the audio decode path is
a viable chain entry.

Bonus reverse-engineering path: on macOS the AudioCodecs private framework
(AppleAAC/MP3/FLAC/AMR/Opus/APAC decoders) is NOT part of the dyld shared
cache, so it diffs cleanly with radiff2 (demonstrated publicly for
CVE-2025-31200, blog.noahhw.dev). An apac.ksy Kaitai definition exists in
zhuowei's PoC repo for structure-aware APAC fuzzing. Misattribution watchlist
(not audio): CVE-2015-7054=zlib, CVE-2019-8644=WebKit, CVE-2023-42897=Siri,
CVE-2025-43429=WebKit.

## Next steps

- [x] Host-side ALAC fuzzing: wrap ALACDecoder in a libFuzzer target
  (cookie + packet bytes as input), seeds from the convert-utility
  corpus. The format is small; structure-aware mutation of the
  partialFrame/numSamples fields is the highest-yield recipe.
  _Done 2026-08-30: research/alac_poc/fuzz_alac.cpp + gen_seeds.cpp,
  wired as `./W0lfSword poclab test alac-fuzz [secs]`. Custom mutator
  keeps the cookie valid and edits the partialFrame/escapeFlag header +
  numSamples field. Finds in 30-60s: unpc_block READ OOB (dp_dec.c:99),
  dyn_decomp WRITE (ag_dec.c:345, BB-038 compressed path), BitBufferRead
  OOB (ALACBitUtilities.c:48). Crashes to research/alac_poc/crashes/._
- [ ] On-device probe (SE 18.4.1): imgio_probe-style binary using
  ExtAudioFile/AVAudioPlayer to decode a mutated corpus; needs the
  phone attached (iproxy 2222). Hardware-gated for now.
- [ ] Disassemble AudioToolbox's ALAC codec plugin in the 18.4.1 dyld
  shared cache and confirm the partialFrame check is absent there too
  (or present: then F1 is a fix-only-in-binary finding and the
  open-source repo should be updated).
- [ ] CAF container fuzz (chunk sizes, packet tables) once a probe
  exists; CoreAudio's AudioFile CAF parser is closed, so this is
  black-box.
- [ ] AAC/ADTS + FLAC/Opus decoders: closed-source, fuzz-only.
