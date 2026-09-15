#!/usr/bin/env bash
set -uo pipefail
cd /home/kaffein/Desktop/W0lfSword || exit 1
PASS=0
FAIL=0
SKIP_BUILD=false
DEV_IP=""
for a in "$@"; do
    case "$a" in
        --skip-build) SKIP_BUILD=true;;
        --ip) shift; DEV_IP="${1:-}";;
    esac
done

note()  { printf '  \033[0;36m%s\033[0m\n' "$*"; }
ok()    { printf '  \033[0;32m✓\033[0m %s\n' "$*"; PASS=$((PASS+1)); }
bad()   { printf '  \033[0;31m✗\033[0m %s\n' "$*"; FAIL=$((FAIL+1)); }

section() { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }

section "BUG.1 host tests (zone-writer clamp + probe restore policy)"
# BUG.1 (2026-09-11 SE panic) is a 32-byte block written past the end of a
# kalloc.96 object and a corrupted live inpcb left behind on a probe exit. Both
# fixes are host-testable: the writer (kexploit/krw_zone_write.c) and the
# restore policy (kexploit/probe_restore_policy.c) compile as the engine
# compiles them, so these two host-only commands are what keeps the clamp and
# the unconditional restore from silently regressing. No device is involved.
if [ -f scripts/run_krw_zone_write_host_test.sh ]; then
    if bash scripts/run_krw_zone_write_host_test.sh >/tmp/regression_krw_host.log 2>&1; then
        ok "krw_zone_write_host_test ($(grep -c '^  ok ' /tmp/regression_krw_host.log) checks)"
    else
        bad "run_krw_zone_write_host_test.sh — see /tmp/regression_krw_host.log"
    fi
else
    note "run_krw_zone_write_host_test.sh missing — skipping"
fi
# The end-to-end half of the same item: the 32-byte overrun injected, then the
# probe's save -> corrupt -> exit -> put-back sequence on the -1 (write-verify)
# and -7 (cancel/budget) exits, including the shape where pe_v1's release funnel
# has already emptied the spray tracking array. Host-only, like the rest.
if [ -f scripts/run_probe_restore_e2e_host_test.sh ]; then
    if bash scripts/run_probe_restore_e2e_host_test.sh >/tmp/regression_probe_restore.log 2>&1; then
        ok "probe_restore_e2e_host_test ($(grep -c '^  ok ' /tmp/regression_probe_restore.log) checks)"
    else
        bad "run_probe_restore_e2e_host_test.sh — see /tmp/regression_probe_restore.log"
    fi
else
    note "run_probe_restore_e2e_host_test.sh missing — skipping"
fi
if [ -f scripts/probe_restore_e2e_selftest.py ]; then
    if python3 scripts/probe_restore_e2e_selftest.py --selftest >/tmp/regression_probe_restore_self.log 2>&1; then
        ok "probe_restore_e2e_selftest.py ($(grep -c 'harness rejects' /tmp/regression_probe_restore_self.log) mutations rejected)"
    else
        bad "probe_restore_e2e_selftest.py — see /tmp/regression_probe_restore_self.log"
    fi
else
    note "probe_restore_e2e_selftest.py missing — skipping"
fi
if [ -f scripts/check_bug2_release_paths.py ]; then
    if python3 scripts/check_bug2_release_paths.py >/tmp/regression_bug2_lint.log 2>&1; then
        ok "check_bug2_release_paths.py ($(grep -c '^PASS' /tmp/regression_bug2_lint.log) checks)"
    else
        bad "check_bug2_release_paths.py — see /tmp/regression_bug2_lint.log"
    fi
else
    note "check_bug2_release_paths.py missing — skipping"
fi
# BUG.1's field choice and BUG.2's remaining pressure sources: both halves are
# properties of the shipped sources rather than of one line (nothing sends on the
# probed socket; every page of every mapping is marked; the mapping/spray sizes are
# pinned). Host-only, like the rest.
if [ -f scripts/check_pressure_budget.py ]; then
    if python3 scripts/check_pressure_budget.py >/tmp/regression_pressure_budget.log 2>&1; then
        ok "check_pressure_budget.py ($(grep -c '^  ok ' /tmp/regression_pressure_budget.log) checks)"
    else
        bad "check_pressure_budget.py — see /tmp/regression_pressure_budget.log"
    fi
else
    note "check_pressure_budget.py missing — skipping"
fi

printf "\nBUG.1 section (regression.sh lines 41-101): %d ok, %d bad\n" "$PASS" "$FAIL"
[ "$FAIL" = 0 ] || exit 1
