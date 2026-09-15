#!/usr/bin/env bash
# T14c - capture every T14 host command and its full output into this directory.
# Host only: compiles C with the host cc, runs Python source lints, runs the
# Theos cross-builds. No device command, no exploit, no git write command.
set -u
cd "$(dirname "$0")/../../../.." || exit 1
ROOT="$PWD"
D="$ROOT/docs/verification/2026-09-11-0.12/t14c"
TERM_SRC="${W0LF_TERM:-$HOME/Desktop/W0lfTerm}"
mkdir -p "$D"

: > "$D/COMMANDS.txt"
: > "$D/RC.txt"

capture() {           # capture <name> <cwd> <command...>
    local name="$1" dir="$2"; shift 2
    local log="$D/$name.log"
    echo "$name :: cwd=$dir :: $*" >> "$D/COMMANDS.txt"
    ( cd "$dir" && "$@" ) > "$log" 2>&1
    local rc=$?
    printf '%s rc=%s\n' "$name" "$rc" | tee -a "$D/RC.txt"
}

# --- KRW host suites (W0lfSword engine) ---
capture e1_krw_zone_write            "$ROOT" bash scripts/run_krw_zone_write_host_test.sh
capture e2_kwrite_counter            "$ROOT" bash scripts/run_kwrite_counter_host_test.sh
capture e3_probe_restore_e2e         "$ROOT" bash scripts/run_probe_restore_e2e_host_test.sh
capture e3b_probe_restore_selftest   "$ROOT" python3 scripts/probe_restore_e2e_selftest.py --selftest
capture e7_tweak_log_throttle        "$ROOT" bash scripts/run_tweak_log_throttle_host_test.sh
# --- TRM host suite (route-A in-process shell) ---
capture e8_trm_shell                 "$ROOT" bash scripts/run_trm_host_test.sh
# --- the BUG.3/4/5/6 end-to-end source lint + its mutation selftest ---
capture e5_scan_budget_cancel        "$ROOT" python3 scripts/check_scan_budget_cancel_writes.py
capture e5b_scan_budget_cancel_self  "$ROOT" python3 scripts/check_scan_budget_cancel_writes.py --selftest
# --- BUG.1/BUG.2 pressure + disk-budget lint ---
capture e6_pressure_budget           "$ROOT" python3 scripts/check_pressure_budget.py
capture e6b_pressure_budget_selftest "$ROOT" python3 scripts/check_pressure_budget.py --selftest
capture e4_bug2_release_paths        "$ROOT" python3 scripts/check_bug2_release_paths.py
capture e4b_bug2_release_paths_self  "$ROOT" python3 scripts/check_bug2_release_paths.py --selftest
# --- syntax gates ---
capture py_compile                   "$ROOT" python3 -m py_compile scripts/check_scan_budget_cancel_writes.py scripts/check_bug2_release_paths.py scripts/check_pressure_budget.py scripts/probe_restore_e2e_selftest.py
capture bash_syntax                  "$ROOT" bash -n scripts/run_krw_zone_write_host_test.sh scripts/run_probe_restore_e2e_host_test.sh scripts/run_kwrite_counter_host_test.sh scripts/run_tweak_log_throttle_host_test.sh scripts/build_libengine.sh scripts/regression.sh
# --- the W0lfTerm app build (engine archive + ipa), from THIS tree ---
capture e9_engine_lib_build          "$ROOT" make THEOS="$HOME/theos" libengine
capture e9b_engine_lib_archive_hash  "$ROOT" sha256sum .theos/libengine/libw0lfengine.a
capture e9c_app_ipa_build            "$TERM_SRC" bash scripts/build_ipa.sh sideload 0.20
capture e9d_app_binary_hash          "$TERM_SRC" sha256sum dist/Payload/W0lfTerm.app/W0lfTerm
capture e9e_app_ipa_hash             "$TERM_SRC" sha256sum dist/W0lfTerm-0.20-sideload.ipa

echo "--- capture complete ---"
cat "$D/RC.txt"
