#!/usr/bin/env bash
# Host test for BUG.5 (2026-09-11 device day): the engine used to CLAIM the
# readonly scan does "zero kernel writes". Nothing counted them, so nothing
# could contradict the sentence - and a reader takes it as "safe to leave
# running" (the scan still pegs a core and dirties ~1 GB of file-backed memory).
#
# kexploit/kwrite_counter.c is the file the engine links for that measurement:
# every kernel write this chain can issue goes out through
# `early_kwrite32bytes` (a 32-byte setsockopt), and both that primitive and the
# clamped block writer feed this counter. This test compiles the same source and
# drives it directly, so the arithmetic the summary line prints cannot drift from
# what the engine counts.
#
#   bash scripts/run_kwrite_counter_host_test.sh
set -euo pipefail

cd "$(dirname "$0")/.."

CC="${CC:-cc}"
OUT="${TMPDIR:-/tmp}/kwrite_counter_host_test"

# shellcheck disable=SC2086
"$CC" -std=gnu11 -Wall -Wextra -Wno-unused-parameter \
    -pthread \
    -I. \
    -o "$OUT" \
    tests/kwrite_counter_host_test.c kexploit/kwrite_counter.c

exec "$OUT"
