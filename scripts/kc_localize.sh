#!/usr/bin/env bash
# kc_localize.sh - localize the code delta between two kernelcache Mach-Os.
#
# No device, no symbols, no source: this drives the kernelcache patch-diff
# toolchain over one build pair and writes a reproducible bundle. Use it to
# answer "what code changed in this release, and in which functions".
#
#   scripts/kc_localize.sh OLD NEW [OUTDIR]
#
#   OLD/NEW  XPF-decoded kernelcache Mach-Os (tools/xpf-cli; a .img4 must be
#            decompressed first - see scripts/fetch_kernelcache.py)
#   OUTDIR   default: docs/verification/$(date +%F)-kc-localize
#
# Bundle:
#   funcdiff_kernel.log    changed functions inside one fileset image (default
#                          com.apple.kernel __TEXT_EXEC = the xnu kernel text)
#   funcdiff_all_text.log  changed functions across the whole kernelcache text
#                          (the root __TEXT_EXEC container: kernel + every kext)
#   pairs_kernel.txt       per-function instruction diff of the changed bodies,
#                          smallest diff first (a fix is a few instructions)
#   funcs_kernel.json      machine-readable changed-body list
#   SHA256SUMS             input + artifact hashes
#
# The method: a positional diff is meaningless here (each build lays functions
# out in a different order, ~20% of bytes differ even for a point release), so
# kc_funcdiff matches functions by canonical content instead of by address. See
# scripts/kc_funcdiff.py for the canonicalization rules and its --selftest.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
    echo "usage: scripts/kc_localize.sh <old-macho> <new-macho> [outdir] [image-name]"
    echo "   e.g. scripts/kc_localize.sh .w0lfsword/kernelcaches/macho_18.7.2 \\"
    echo "                              .w0lfsword/kernelcaches/macho_18.7.3"
    exit 2
}

OLD="${1:-}"; NEW="${2:-}"
OUT="${3:-$HERE/docs/verification/$(date +%F)-kc-localize}"
IMAGE="${4:-com.apple.kernel}"
[ -n "$OLD" ] && [ -n "$NEW" ] || usage
for f in "$OLD" "$NEW"; do
    [ -f "$f" ] || { echo "no such file: $f" >&2; exit 1; }
done

mkdir -p "$OUT"
OLD="$(cd "$(dirname "$OLD")" && pwd)/$(basename "$OLD")"
NEW="$(cd "$(dirname "$NEW")" && pwd)/$(basename "$NEW")"
echo "kc_localize: $OLD -> $NEW"
echo "  image=$IMAGE  outdir=$OUT"

echo "  [1/3] function-level delta, $IMAGE"
python3 "$HERE/scripts/kc_funcdiff.py" "$OLD" "$NEW" \
    --owner "$IMAGE" --region __TEXT_EXEC \
    --json "$OUT/funcs_kernel.json" > "$OUT/funcdiff_kernel.log"
cat "$OUT/funcdiff_kernel.log"

echo "  [2/3] function-level delta, whole kernelcache text"
python3 "$HERE/scripts/kc_funcdiff.py" "$OLD" "$NEW" \
    --region __TEXT_EXEC --json "$OUT/funcs_all_text.json" > "$OUT/funcdiff_all_text.log"
tail -4 "$OUT/funcdiff_all_text.log"

echo "  [3/3] per-function instruction diffs of the changed bodies"
python3 "$HERE/scripts/kc_pairs.py" "$OLD" "$NEW" --owner "$IMAGE" \
    --max 40 > "$OUT/pairs_kernel.log"
head -1 "$OUT/pairs_kernel.log"
echo "     (full pair list: scripts/kc_pairs.py --json <path>)"

( cd "$OUT" && sha256sum "$(basename "$OLD")" 2>/dev/null || true
  sha256sum "$OLD" "$NEW" 2>/dev/null | sed "s#$HERE/##"
  sha256sum funcs_kernel.json funcdiff_kernel.log funcdiff_all_text.log pairs_kernel.log ) \
    > "$OUT/SHA256SUMS"
echo "  wrote $OUT/SHA256SUMS"
