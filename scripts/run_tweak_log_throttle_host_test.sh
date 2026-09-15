#!/usr/bin/env bash
# Host test for BUG.6 (2026-09-11 device day): the disk-write budget.
#
# The fsync that makes the app log survive a kernel panic used to be paid on
# EVERY line; on the SE that dirtied ~1.07 GB of file-backed memory in 18 minutes
# against the 1 GB/day disk-write limit iOS reports (W0lfTerm.diskwrites_
# resource-*.ips). The fix is a rate gate - at most one fsync per 200 ms, one
# gate for the whole process - and utils/tweak_log_policy.c is the file both the
# engine archive and the tweak build compile for it. This test compiles that same
# source and counts the grants for simulated bursts, so "the throttle bounds the
# fsyncs" is a counter report instead of a sentence.
#
#   bash scripts/run_tweak_log_throttle_host_test.sh
set -euo pipefail

cd "$(dirname "$0")/.."

CC="${CC:-cc}"
OUT="${TMPDIR:-/tmp}/tweak_log_throttle_host_test"

# shellcheck disable=SC2086
"$CC" -std=gnu11 -Wall -Wextra -Wno-unused-parameter \
    -I. \
    -o "$OUT" \
    tests/tweak_log_throttle_host_test.c utils/tweak_log_policy.c

exec "$OUT"
