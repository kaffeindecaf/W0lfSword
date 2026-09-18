#!/usr/bin/env bash
# Host test for BUG.7 (ROADMAP 0.13): the kalloc BUCKET size read out of the
# zone (kexploit/krw_zone_size.c) and the window decision built on it.
#
# BUG.1 step 3b made every 32-byte write prove itself against an object it could
# only DESCRIBE (the inpcb's field span, 0x160). BUG.7 asked the kernel instead:
# pcb -> inpcbinfo.ipi_zone -> struct zone's z_elem_size is the size the object
# was actually allocated with, which is the extent the clamp should be given. The
# decision file is compiled here exactly as the engine compiles it (same source,
# no stubs), so the window the device uses is the window these checks cover.
#
#   bash scripts/run_krw_zone_size_host_test.sh
set -euo pipefail

cd "$(dirname "$0")/.."

CC="${CC:-cc}"
OUT="${TMPDIR:-/tmp}/krw_zone_size_host_test"

# shellcheck disable=SC2086
"$CC" -std=gnu99 -Wall -Wextra -Wno-unused-parameter \
    -I. \
    -o "$OUT" \
    tests/krw_zone_size_host_test.c kexploit/krw_zone_size.c kexploit/krw_zone_write.c

exec "$OUT"
