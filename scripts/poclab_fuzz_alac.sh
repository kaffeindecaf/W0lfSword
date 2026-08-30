#!/usr/bin/env bash
# C4.4 - host-side ALAC libFuzzer run.
#
# Builds fuzz_alac (clang + libFuzzer + ASAN/UBSAN) against the cached
# apple/ALAC codec, generates a fresh seed corpus with gen_seeds, and runs
# a bounded fuzz campaign. Every crash is copied to
# research/alac_poc/crashes/ and summarized by ASAN site.
#
# Run: ./W0lfSword poclab test alac-fuzz [seconds]   (default 60)
set -euo pipefail
cd "$(dirname "$0")/.."

DUR="${1:-60}"
CACHE=".w0lfsword/poclab/alac"
SRC="research/alac_poc"
WORK=".w0lfsword/poclab/alac-fuzz"
CORPUS="$SRC/corpus"
CRASH_DIR="$SRC/crashes"
ROOT="$(pwd)"

mkdir -p "$WORK" "$CRASH_DIR"

if [ ! -d "$CACHE/codec" ]; then
    echo "  cloning apple/ALAC (cached in $CACHE) ..."
    git clone --depth 1 https://github.com/apple/ALAC "$CACHE" 2>/dev/null \
        || git clone --depth 1 https://github.com/macosforge/alac "$CACHE"
fi

command -v clang++ >/dev/null || { echo "  clang++ missing - run ./W0lfSword setup"; exit 1; }

echo "  building fuzz_alac (libFuzzer + ASAN/UBSAN) ..."
clang++ -std=gnu++14 -fsanitize=fuzzer,address,undefined -g -O1 \
    -I "$CACHE/codec" \
    "$SRC/fuzz_alac.cpp" \
    "$CACHE/codec/ALACDecoder.cpp" \
    "$CACHE/codec/ag_dec.c" \
    "$CACHE/codec/dp_dec.c" \
    "$CACHE/codec/matrix_dec.c" \
    "$CACHE/codec/ALACBitUtilities.c" \
    "$CACHE/codec/EndianPortable.c" \
    -o "$WORK/fuzz_alac" 2>"$WORK/build.log" || {
        echo "  build failed - see $WORK/build.log"; exit 1
    }

echo "  building seed generator + generating corpus ..."
g++ -I "$CACHE/codec" "$SRC/gen_seeds.cpp" \
    "$CACHE/codec/ALACEncoder.cpp" \
    "$CACHE/codec/ag_enc.c" \
    "$CACHE/codec/dp_enc.c" \
    "$CACHE/codec/matrix_enc.c" \
    "$CACHE/codec/ALACBitUtilities.c" \
    "$CACHE/codec/EndianPortable.c" \
    "$CACHE/codec/ag_dec.c" \
    -o "$WORK/gen_seeds" 2>/dev/null || {
        echo "  gen_seeds build failed"; exit 1
    }
rm -rf "$WORK/corpus"
mkdir -p "$WORK/corpus"
"$WORK/gen_seeds" "$WORK/corpus" 1 16 44100 2 >/dev/null
"$WORK/gen_seeds" "$WORK/corpus" 2 16 44100 2 >/dev/null
"$WORK/gen_seeds" "$WORK/corpus" 1 24 48000 2 >/dev/null
"$WORK/gen_seeds" "$WORK/corpus" 1 32 44100 2 >/dev/null
"$WORK/gen_seeds" "$WORK/corpus" 2 24 44100 2 >/dev/null
# keep the checked-in corpus as fallback seeds too
cp "$CORPUS"/*.bin "$WORK/corpus/" 2>/dev/null || true

echo "  fuzzing for ${DUR}s ..."
echo ""
cd "$WORK"
ASAN_OPTIONS=abort_on_error=1:detect_leaks=0 \
UBSAN_OPTIONS=halt_on_error=0 \
./fuzz_alac -max_total_time="$DUR" -artifact_prefix="$ROOT/$CRASH_DIR/" corpus/ \
    > fuzz.log 2>&1 || true

echo ""
echo "  == results =="
crash_count=$(ls "$ROOT/$CRASH_DIR"/crash-* 2>/dev/null | wc -l | tr -d ' ')
if [ "$crash_count" -gt 0 ]; then
    echo "  crashes found: $crash_count (saved in $CRASH_DIR/)"
    grep -h "ERROR: AddressSanitizer\|SUMMARY: AddressSanitizer" fuzz.log \
        | sort -u | sed 's/^/    /'
    echo ""
    echo "  top ASAN sites:"
    grep -oP "(?<=in )[A-Za-z_][A-Za-z0-9_]*" fuzz.log \
        | sort | uniq -c | sort -rn | head -5 | sed 's/^/    /'
else
    echo "  no crashes in ${DUR}s (check fuzz.log for coverage stats)"
fi
echo ""
echo "  corpus: $(ls corpus | wc -l | tr -d ' ') seeds, coverage log: $WORK/fuzz.log"
