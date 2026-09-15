#!/usr/bin/env bash
# T16 (task 16/16) - verification capture for W0lfSword 0.12 BUG.3 / BUG.4 / BUG.5
# (W0lfTerm 0.6 BUG.3 / BUG.1 / BUG.2).
#
# Host only. This script compiles C with the host cc, runs the two Python source
# lints, runs the Theos cross-build of the engine archive and of the app, and
# reads the linked Mach-O. It issues NO device command and does NOT run the
# exploit: the "Live device smoke" section of scripts/regression.sh (which ssh's
# to .w0lfsword/active_device) is deliberately not part of this capture.
#
#   bash docs/verification/2026-09-11-0.12/t16/capture.sh
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SW="$(cd "$HERE/../../../.." && pwd)"
TERM="${W0LF_TERM:-$HOME/Desktop/W0lfTerm}"
BIN="$TERM/dist/Payload/W0lfTerm.app/W0lfTerm"
RC=0

run() {   # run <logname> <cmd...>
    local name="$1"; shift
    "$@" >"$HERE/$name.log" 2>&1
    local rc=$?
    printf '%-34s rc=%s\n' "$name" "$rc"
    [ "$rc" = 0 ] || RC=1
}

cd "$SW" || exit 1

# --- the two checkers named by the task -------------------------------------
run check_scan_budget_cancel_writes        python3 scripts/check_scan_budget_cancel_writes.py
run check_scan_budget_cancel_writes_selftest python3 scripts/check_scan_budget_cancel_writes.py --selftest
run check_pressure_budget                  python3 scripts/check_pressure_budget.py
run check_pressure_budget_selftest         python3 scripts/check_pressure_budget.py --selftest

# --- the host harnesses the two lints stand on ------------------------------
run kwrite_counter_host_test               bash scripts/run_kwrite_counter_host_test.sh
run tweak_log_throttle_host_test           bash scripts/run_tweak_log_throttle_host_test.sh
run probe_restore_e2e_host_test            bash scripts/run_probe_restore_e2e_host_test.sh

# --- the whole host verification suite, with the two cross-builds -----------
# Rebuilds .theos/libengine/libw0lfengine.a and dist/W0lfTerm-0.20-sideload.ipa
# from THIS working tree and compares every run against the hash pinned in
# scripts/check_host_verification.sh: a drift is a real code change, not a flake.
W0LF_TERM="$TERM" bash scripts/check_host_verification.sh --with-builds >"$HERE/host_verification.log" 2>&1
hv_rc=$?
printf '%-34s rc=%s\n' "host_verification --with-builds" "$hv_rc"
[ "$hv_rc" = 0 ] || RC=1
tail -1 "$HERE/host_verification.log"

# --- the linked binary: symbols, UI link edges, marker counts ---------------
if [ -f "$BIN" ]; then
    {
        echo "binary: $BIN"
        echo "sha256: $(sha256sum "$BIN" | cut -d' ' -f1)"
        echo
        echo "== engine API symbols (llvm-nm-19), T = defined =="
        llvm-nm-19 "$BIN" | grep -E " _kexploit_scan_budget| _kexploit_set_scan_budget| _kexploit_scan_writes| _kexploit_scan_write_bytes| _kexploit_scan_write_failures| _kwrite_count_emit| _kwrite_count_reset| _kexploit_request_stop| _kexploit_stop_requested| _kexploit_clear_stop"
        echo
        echo "== engine symbols still UNDEFINED (empty = the app has its own copies) =="
        llvm-nm-19 -u "$BIN" | grep -E "_kexploit|_kwrite" || echo "(none)"
    } >"$HERE/linked_binary_symbols.log" 2>&1

    llvm-objdump-19 --disassemble --no-show-raw-insn "$BIN" >"$HERE/linked_binary.dis" 2>/dev/null
    {
        echo "== -[TermSettings setScanBudget:] (the SET row -> engine: g_scanBudget store + the engine call) =="
        grep -F -A 70 -- "+[TermSettings setScanBudget:]>:" "$HERE/linked_binary.dis" | grep -E "str[[:space:]]+w8, \[x9, #0xd38\]|bl[[:space:]]+0x[0-9a-f]+ <_kexploit_set_scan_budget>"
        echo
        echo "== -[TerminalViewController dotTapped:] (the CANCEL tap) =="
        grep -F -A 24 -- "-[TerminalViewController dotTapped:]>:" "$HERE/linked_binary.dis" | grep -E "bl[[:space:]]+0x[0-9a-f]+ <_term_bridge_cancel>"
        echo
        echo "== _term_bridge_cancel -> _kexploit_request_stop -> atomic store =="
        grep -F -A 24 -- "<_term_bridge_cancel>:" "$HERE/linked_binary.dis" | grep -E "bl[[:space:]]+0x[0-9a-f]+ <(_kexploit_request_stop|_TweakLog)>"
        echo
        echo "== _kexploit_request_stop (stlr = the atomic stop flag the walks read) =="
        grep -F -A 10 -- "<_kexploit_request_stop>:" "$HERE/linked_binary.dis" | grep -E "stlr[[:space:]]+w[0-9]"
    } >"$HERE/ui_link_edges.log" 2>&1

    {
        echo "== shipped-string marker counts in the linked binary =="
        for m in "cancel" "pe_v2 scan stopped on request" "no kernel writes" "zero kernel writes" "zero writes" "measured by kwrite_counter"; do
            printf '  %-34s %s\n' "$m" "$(strings -a "$BIN" | grep -cF "$m")"
        done
        echo
        echo "== the measured-write format strings =="
        strings -a "$BIN" | grep -E "kernel writes|measured by kwrite_counter|kwrite_counter, BUG.5"
    } >"$HERE/linked_binary_marker_counts.log" 2>&1
else
    echo "BAD  app binary not found at $BIN" | tee "$HERE/linked_binary_symbols.log"
    RC=1
fi

echo "$RC" >"$HERE/RC.txt"
echo
echo "capture rc=$RC (0 = every command above exited 0)"
exit "$RC"
