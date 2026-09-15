#!/usr/bin/env bash
# T15 - BUG.1 (zone-bound write fix) closing verification, ONE host-only capture.
#
# Re-runs every command that proves the three BUG.1 sub-steps fixed in ROADMAP
# 0.12, writes one log per command into this directory, and prints the per-case
# result of the two harnesses that drive the real sources (the boundary clamp in
# kexploit/krw_zone_write.c and the restore path in
# kexploit/probe_restore_policy.c + kexploit/kexploit_opa334.m).
#
# Host only: host `cc`, `clang`/`make` (Theos cross-build), `python3`, `bash`.
# No device command, no exploit run, no git write command.
#
#   bash docs/verification/2026-09-11-0.12/t15/capture.sh
set -u
cd "$(dirname "$0")/../../../.." || exit 1
ROOT="$PWD"
D="$ROOT/docs/verification/2026-09-11-0.12/t15"
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

# --- sub-step 1: the restore runs on EVERY exit (policy + funnel) ------------
capture s1_krw_zone_write_host_test   "$ROOT" bash scripts/run_krw_zone_write_host_test.sh
capture s1_probe_restore_e2e          "$ROOT" bash scripts/run_probe_restore_e2e_host_test.sh
capture s1_probe_restore_e2e_selftest "$ROOT" python3 scripts/probe_restore_e2e_selftest.py --selftest
capture s1_bug2_release_paths         "$ROOT" python3 scripts/check_bug2_release_paths.py
capture s1_bug2_release_paths_selftest "$ROOT" python3 scripts/check_bug2_release_paths.py --selftest

# --- sub-step 2: the probed field has no concurrent reader -------------------
capture s2_pressure_budget            "$ROOT" python3 scripts/check_pressure_budget.py
capture s2_pressure_budget_selftest   "$ROOT" python3 scripts/check_pressure_budget.py --selftest

# --- sub-step 3: the writer is clamped (source shape + shipped archive) ------
capture s3_engine_lib_build           "$ROOT" make THEOS="$HOME/theos" libengine
capture s3_engine_archive_hash        "$ROOT" sha256sum .theos/libengine/libw0lfengine.a
capture s3_engine_archive_symbols     "$ROOT" bash -c 'llvm-nm-19 .theos/libengine/libw0lfengine.a | grep -E "krw_zone_write_qword|krw_zone_block_align_down|krw_zone_window_for_field_end|kwrite_zone_element_qword|probe_exit_action_for|probe_restore_fd_source" | sort -u'
capture s3_portable_syntax            "$ROOT" cc -std=gnu99 -Wall -Wextra -Wno-unused-parameter -fsyntax-only -I. kexploit/krw_zone_write.c kexploit/probe_restore_policy.c
# An INDEPENDENT check written for this pass: the shipped clamp against a monitor
# this file owns (not the project harness), sweeping every offset/length shape
# around a kalloc.96-sized object. A clean sweep is evidence the clamp is not
# just passing its own tests.
capture s3b_independent_clamp_sweep   "$ROOT" bash -c 'cc -std=gnu99 -Wall -Wextra -Wno-unused-parameter -I. -o "${TMPDIR:-/tmp}/indep_clamp" docs/verification/2026-09-11-0.12/t15/independent_clamp_sweep.c kexploit/krw_zone_write.c && "${TMPDIR:-/tmp}/indep_clamp"'

# --- the standing suite that pins the two harnesses' outputs -----------------
capture suite_host_verification       "$ROOT" bash scripts/check_host_verification.sh

# --- the same section regression.sh runs, alone (never the whole file: its
#     last section ssh's to whatever .w0lfsword/active_device names) ---------
{
    echo '#!/usr/bin/env bash'
    echo 'set -uo pipefail'
    echo "cd $ROOT || exit 1"
    sed -n '12,28p' "$ROOT/scripts/regression.sh"
    sed -n '41,101p' "$ROOT/scripts/regression.sh"
    echo 'printf "\nBUG.1 section (regression.sh lines 41-101): %d ok, %d bad\n" "$PASS" "$FAIL"'
    echo '[ "$FAIL" = 0 ] || exit 1'
} > "$D/regression_bug1_section.sh"
capture suite_regression_bug1_section "$ROOT" bash "$D/regression_bug1_section.sh"

capture suite_audit                   "$ROOT" ./W0lfSword audit

echo
echo "--- BUG.1 host cases, pass/fail PER CASE (the two harnesses that drive the real sources) ---"
python3 - "$D" <<'PY'
import os, re, sys
d = sys.argv[1]
total_ok = total_fail = 0
for log in ("s1_krw_zone_write_host_test", "s1_probe_restore_e2e"):
    text = open(os.path.join(d, log + ".log")).read()
    cases = re.findall(r"^  (ok|FAIL) +(.*)$", text, re.M)
    ok = sum(1 for r, _ in cases if r == "ok")
    bad = sum(1 for r, _ in cases if r == "FAIL")
    total_ok += ok
    total_fail += bad
    print(f"[{log}] {ok} ok, {bad} FAIL (of {len(cases)} cases)")
    for r, what in cases:
        print(f"  {'PASS' if r == 'ok' else 'FAIL'}  {what}")
print(f"BUG.1 host cases: {total_ok} pass, {total_fail} fail")
verdict = "PASS" if (total_ok > 0 and total_fail == 0) else "FAIL"
print(f"BUG.1 HOST VERDICT: {verdict}")
print("(same logs rendered as a file by extract_cases.py -> BUG1-CASES.txt)")
sys.exit(0 if verdict == "PASS" else 1)
PY
per_case_rc=$?
echo "--- capture complete (rc per command in RC.txt; per-case verdict rc=$per_case_rc) ---"
sed -n '1,200p' "$D/RC.txt"
exit "$per_case_rc"
