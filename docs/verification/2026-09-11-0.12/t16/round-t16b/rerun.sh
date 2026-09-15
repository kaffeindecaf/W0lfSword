#!/usr/bin/env bash
# T16 (round 2) - BUG.3 / BUG.4 / BUG.5 verification, reproduced from scratch.
#
# Why a second bundle: the first pass (../rerun/) is the recorded evidence for
# this item. This script re-runs the same host-only checks into THIS directory so
# the numbers can be reproduced without overwriting that record, and so a reader
# can see the same result twice from two independent runs of two different
# scripts.
#
# Host only: Python source lints, host C harnesses, the Theos cross-build and a
# read of the linked Mach-O. No device command, no exploit run, no git command,
# nothing deleted.
#
#   bash rerun.sh                 # everything incl. both cross-builds (~2.5 min)
#   SKIP_BUILDS=1 bash rerun.sh   # host checks only (~40 s)
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT=/home/kaffein/Desktop/W0lfSword
APP=/home/kaffein/Desktop/W0lfTerm
BIN="$APP/dist/Payload/W0lfTerm.app/W0lfTerm"
SKIP_BUILDS="${SKIP_BUILDS:-0}"
RC=0

run() {                    # run <logfile> <cwd> <command...>
    local log="$HERE/$1"; shift
    local dir="$1"; shift
    ( cd "$dir" && "$@" ) >"$log" 2>&1
    local r=$?
    printf 'rc=%-3s %-34s %s\n' "$r" "$1" "$(tail -1 "$log" 2>/dev/null)"
    [ "$r" = 0 ] || RC=1
    return 0
}

echo "== the two checkers the task names, plus the shared suites =="
run check_scan_budget_cancel_writes.log      "$ROOT" python3 scripts/check_scan_budget_cancel_writes.py
run check_scan_budget_cancel_selftest.log    "$ROOT" python3 scripts/check_scan_budget_cancel_writes.py --selftest
run check_pressure_budget.log                "$ROOT" python3 scripts/check_pressure_budget.py
run check_pressure_budget_selftest.log       "$ROOT" python3 scripts/check_pressure_budget.py --selftest
run kwrite_counter_host_test.log             "$ROOT" bash scripts/run_kwrite_counter_host_test.sh
run tweak_log_throttle_host_test.log         "$ROOT" bash scripts/run_tweak_log_throttle_host_test.sh

if [ "$SKIP_BUILDS" = 1 ]; then
    echo
    echo "(SKIP_BUILDS=1: the cross-builds and the artifact checks were not run)"
else
    echo
    echo "== fresh builds, then the artifact a device would install =="
    run host_verification.log "$ROOT" env W0LF_TERM="$APP" bash scripts/check_host_verification.sh --with-builds
    { sha256sum "$ROOT/.theos/libengine/libw0lfengine.a"
      sha256sum "$BIN"; } > "$HERE/binary_hash.log" 2>&1
    run linked_binary_symbols.log "$APP" bash -c \
        "llvm-nm-19 '$BIN' | grep -E ' _kexploit_| _kwrite_count| _g_peV2Aborted| _tweak_log_fsync_due| _term_bridge_cancel'"
    run linked_binary_marker_counts.log "$APP" bash -c \
        'for m in cancel "pe_v2 scan stopped on request" "no kernel writes" "zero kernel writes" "zero writes" "measured by kwrite_counter" "engine-counted"; do printf "  %-34s %s\n" "$m" "$(strings -a '"$BIN"' | grep -cF "$m")"; done'
    ( cd "$APP" && llvm-objdump-19 -d --macho --no-show-raw-insn "$BIN" ) > "$HERE/linked_binary.dis" 2>&1
    run callgraph_check.log "$HERE" python3 "$ROOT/docs/verification/2026-09-11-0.12/t16/rerun/callgraph_check.py" "$HERE/linked_binary.dis" "$BIN"
    run invariant_check.log "$HERE" python3 "$ROOT/docs/verification/2026-09-11-0.12/t16/rerun/invariant_check.py" "$ROOT" "$APP" "$BIN"
fi

echo
printf 'rerun.sh: %s\n' "$([ "$RC" = 0 ] && echo 'all commands rc=0' || echo 'AT LEAST ONE COMMAND FAILED - see the logs above')"
printf '%s\n' "$RC" > "$HERE/RC.txt"
exit "$RC"
