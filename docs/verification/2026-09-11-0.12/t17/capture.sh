#!/usr/bin/env bash
# Task 17 (re-run) - re-run the no-device host harnesses for ROADMAP 0.12
# (W0lfSword) / 0.6 (W0lfTerm) against the CURRENT working tree and capture raw
# output. No device command is issued anywhere in this file, and nothing is
# committed.
#
#   bash docs/verification/2026-09-11-0.12/t17/capture.sh
#   WITH_BUILDS=1 bash docs/verification/2026-09-11-0.12/t17/capture.sh
#
# Authorized run set (exactly the three the task names):
#   scripts/run_krw_zone_write_host_test.sh   -> BUG.1 (writer clamp + restore)
#   scripts/run_kwrite_counter_host_test.sh   -> BUG.5 (measured writes)
#   scripts/check_host_verification.sh        -> BUG.1/3/4/5/6 suite
# scripts/check_host_verification.sh runs nine further host harnesses itself
# (probe_restore_e2e, trm_shell, tweak_log_throttle, scan_budget_cancel,
# bug2_release_paths, pressure_budget, test_offsets, test_chain_select,
# py_compile, bash_syntax); their raw output is captured here because it is the
# output of an authorized command, and they are NOT run as separate entries.
#
# TMPDIR is pinned to a directory inside this capture so the per-entry raw logs
# the suite writes are stored in the repo instead of /tmp - the capture has to
# stay readable after /tmp is cleared.
#
# Writes, next to this script:
#   <name>.log          raw stdout+stderr of each command
#   RC.txt              "<name> <rc>" per command
#   COMMANDS.txt        the exact command line per entry, with TMPDIR
#   suite_logs/         per-entry raw logs of the --with-builds suite run
#   suite_logs_plain/   per-entry raw logs of the plain suite run
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SW="$(cd "$HERE/../../../.." && pwd)"          # W0lfSword repo root
TERM_SRC="${W0LF_TERM:-$HOME/Desktop/W0lfTerm}"

mkdir -p "$HERE/suite_logs" "$HERE/suite_logs_plain"

: >"$HERE/RC.txt"
: >"$HERE/COMMANDS.txt"

run() {  # run <name> <tmpdir> <cwd> <command...>
    local name="$1" tmp="$2" dir="$3"; shift 3
    printf '%s\t%s\tTMPDIR=%s\t%s\n' "$name" "$dir" "$tmp" "$*" >>"$HERE/COMMANDS.txt"
    ( cd "$dir" && TMPDIR="$tmp" eval "$@" ) >"$HERE/$name.log" 2>&1
    local rc=$?
    printf '%s %s\n' "$name" "$rc" >>"$HERE/RC.txt"
    printf '%-32s rc=%s (%s bytes)\n' "$name" "$rc" "$(wc -c <"$HERE/$name.log")"
}

run krw_zone_write      "$HERE/suite_logs"       "$SW" 'bash scripts/run_krw_zone_write_host_test.sh'
run kwrite_counter      "$HERE/suite_logs"       "$SW" 'bash scripts/run_kwrite_counter_host_test.sh'
run host_verification   "$HERE/suite_logs_plain" "$SW" 'bash scripts/check_host_verification.sh'

# --with-builds adds the Theos cross-builds (host only, no device): the engine
# archive, the W0lfTerm ipa and the static check on the linked binary.
if [ "${WITH_BUILDS:-0}" = 1 ]; then
    run host_verification_builds "$HERE/suite_logs" "$SW" \
        "W0LF_TERM=$TERM_SRC bash scripts/check_host_verification.sh --with-builds"
fi

echo
echo "raw logs: $HERE"
echo "per-entry suite logs: $HERE/suite_logs (builds) / $HERE/suite_logs_plain (plain)"

# Two of the suite's raw logs are cited by path from the README and from both
# roadmaps; copy them up to the capture root so those citations do not depend on
# the suite's own output-directory name. Both are the raw output of the
# authorized suite run, byte-identical to the file they are copied from.
for n in probe_restore_e2e trm_shell_host_test; do
    cp "$HERE/suite_logs/w0lf_host_verification/$n.log" "$HERE/$n.log"
    printf 'copied %-24s -> %s.log (sha256 %s)\n' "$n" "$n" \
        "$(sha256sum "$HERE/$n.log" | cut -c1-16)"
done
