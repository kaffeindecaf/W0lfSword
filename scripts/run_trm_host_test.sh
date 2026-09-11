#!/usr/bin/env bash
# Host test for the route-A in-process shell (terminal/trm_shell.c).
#
# Compiles the shell core with the kernel/mach dependencies stubbed
# (tests/trm_shell_host_test.c) so parsing, the POSIX commands and the unsafe
# gating are verified on this machine, before any device round trip costs a
# sideload. Not part of the tweak build.
#
#   bash scripts/run_trm_host_test.sh
set -euo pipefail

cd "$(dirname "$0")/.."

CC="${CC:-cc}"
OUT="${TMPDIR:-/tmp}/trm_shell_host_test"

# shellcheck disable=SC2086
"$CC" -std=gnu99 -Wall -Wno-unused-parameter -Wno-unused-function -Wno-sign-compare \
    -I. -Itests/hostshim \
    -o "$OUT" \
    tests/trm_shell_host_test.c terminal/trm_shell.c terminal/trm_common.c \
    -lpthread

exec "$OUT"
