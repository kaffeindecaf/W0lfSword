#!/usr/bin/env bash
# Host test for the BUG.1 step 3 zone writer (kexploit/krw_zone_write.c).
#
# The block writer is the code that panicked the SE on 2026-09-11 (a 32-byte
# write at +0x50 of a 96-byte kalloc.96 object, zalloc.c:1322). This compiles
# the REAL writer - the same file the engine builds - against a fake kernel
# window and records every emitted block, so the guard, the block sequencing and
# the refusal log lines are verified on this machine, not by hoping a sideload
# does not reboot the phone.
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
    tests/krw_zone_write_host_test.c kexploit/krw_zone_write.c

exec "$OUT"
