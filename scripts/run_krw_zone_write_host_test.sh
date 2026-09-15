#!/usr/bin/env bash
# Host test for BUG.1 (2026-09-11 SE panic): the clamp on the 32-byte block
# writer (kexploit/krw_zone_write.c) and the staged write probe's restore
# contract (kexploit/probe_restore_policy.c).
#
# The block writer is the code that panicked the SE (a 32-byte write at +0x50 of
# a 96-byte kalloc.96 object, zalloc.c:1322); the restore policy is the code that
# decides whether a corrupted live inpcb is put back on EVERY exit of the write
# probe - including the staged -5 exit, where the spray tracking array has
# already been emptied. Both files are compiled as the ENGINE compiles them
# (same sources, no stubs), so these checks cannot drift from what ships.
#
#   bash scripts/run_krw_zone_write_host_test.sh
set -euo pipefail

cd "$(dirname "$0")/.."

CC="${CC:-cc}"
OUT="${TMPDIR:-/tmp}/krw_zone_write_host_test"

# shellcheck disable=SC2086
"$CC" -std=gnu99 -Wall -Wextra -Wno-unused-parameter \
    -I. \
    -o "$OUT" \
    tests/krw_zone_write_host_test.c kexploit/krw_zone_write.c kexploit/probe_restore_policy.c

exec "$OUT"
