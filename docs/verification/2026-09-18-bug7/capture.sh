#!/usr/bin/env bash
# Capture the host evidence for BUG.7's closing pass (ROADMAP 0.13): the kalloc
# BUCKET size read out of the zone, and the window decision built on it.
#
# Host only - no device command, no exploit run. Every command here either
# compiles C with the host cc, runs a Python source lint, or runs the Theos
# cross-build; the raw output of each is written next to this script (the
# *.log extension is gitignored on purpose - logs stay local, MANIFEST.txt is
# committed) and sha256'd into MANIFEST.txt.
#
#   bash docs/verification/2026-09-18-bug7/capture.sh
set -uo pipefail

cd "$(dirname "$0")/../../.."

OUT="docs/verification/2026-09-18-bug7"
mkdir -p "$OUT"

run() {
    local name="$1" cmd="$2"
    ( eval "$cmd" ) >"$OUT/$name.log" 2>&1
    local rc=$?
    printf '%-26s rc=%s  sha256=%s\n' "$name" "$rc" "$(sha256sum <"$OUT/$name.log" | cut -d' ' -f1)"
    return $rc
}

run krw_zone_size_host_test   'bash scripts/run_krw_zone_size_host_test.sh'
run bug2_release_paths        'python3 scripts/check_bug2_release_paths.py'
run bug2_release_paths_self   'python3 scripts/check_bug2_release_paths.py --selftest'
run krw_zone_write_host_test  'bash scripts/run_krw_zone_write_host_test.sh'
run probe_restore_e2e         'bash scripts/run_probe_restore_e2e_host_test.sh'
run host_verification         'bash scripts/check_host_verification.sh'
run host_verification_builds  'bash scripts/check_host_verification.sh --with-builds'
run test_offsets              'python3 scripts/test_offsets.py'
run audit                     './W0lfSword audit'
run engine_build              'THEOS=${THEOS:-$HOME/theos} make libengine'
run tweak_package             'THEOS=${THEOS:-$HOME/theos} make package DEBUG=0'

{
    echo "BUG.7 capture - $(date -Iseconds)"
    echo "host: $(uname -srm)"
    echo
    for f in "$OUT"/*.log; do
        printf '%s  %s\n' "$(sha256sum <"$f" | cut -d' ' -f1)" "$(basename "$f")"
    done
    printf '%s  %s\n' "$(sha256sum .theos/libengine/libw0lfengine.a | cut -d' ' -f1)" "engine archive"
} >"$OUT/MANIFEST.txt"

echo
echo "manifest: $OUT/MANIFEST.txt"
