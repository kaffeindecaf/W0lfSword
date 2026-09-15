#!/usr/bin/env bash
# D2.2 — W0lfSword regression suite.
#
# Runs the full static + build + audit checks, then an optional live-device
# smoke test when a device is reachable (via saved IP or --ip). Safe to run
# any time; nothing here touches the kernel exploit path.
#
# Usage: scripts/regression.sh [--ip <device-ip>] [--skip-build]
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

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

section "Shell syntax"
if bash -n W0lfSword research/*.sh scripts/*.sh 2>/dev/null; then ok "bash -n on all scripts"; else bad "bash -n"; fi

section "Python syntax"
if python3 -m py_compile research/*.py scripts/*.py 2>/dev/null; then ok "py_compile on all .py"; else bad "py_compile"; fi

section "Offset table tests (D2.1)"
if python3 scripts/test_offsets.py >/dev/null 2>&1; then ok "test_offsets.py"; else bad "test_offsets.py"; fi

section "Chain selector golden grid (AUD.6)"
if bash scripts/test_chain_select.sh >/dev/null 2>&1; then ok "test_chain_select.sh"; else bad "test_chain_select.sh"; fi

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

section "BUG.3 + BUG.5 + BUG.4 + BUG.6 host tests (scan budget, measured writes, CANCEL, disk-write throttle)"
# BUG.3: the scan budget has to be settable AND default to a value the walk fits
# into; BUG.5: "no kernel writes" has to be a measured counter, not a sentence;
# BUG.4: a CANCEL has to be reachable from the UI and its path has to release the
# search mappings and the socket spray; BUG.6: the log sink's fsync (added for
# panic forensics) has to be rate limited - one per 200 ms through one
# process-wide gate - because fsync-per-line dirtied ~1.07 GB in 18 minutes on
# the SE against the 1 GB/day disk-write budget. All four span both trees, so the
# lint reads the W0lfSword engine and the W0lfTerm app sources together. Host
# only - no device command, no exploit run.
if [ -f scripts/run_kwrite_counter_host_test.sh ]; then
    if bash scripts/run_kwrite_counter_host_test.sh >/tmp/regression_kwrite_counter.log 2>&1; then
        ok "kwrite_counter_host_test ($(grep -c '^  ok ' /tmp/regression_kwrite_counter.log) checks)"
    else
        bad "run_kwrite_counter_host_test.sh — see /tmp/regression_kwrite_counter.log"
    fi
else
    note "run_kwrite_counter_host_test.sh missing — skipping"
fi
if [ -f scripts/run_tweak_log_throttle_host_test.sh ]; then
    if bash scripts/run_tweak_log_throttle_host_test.sh >/tmp/regression_tweak_log_throttle.log 2>&1; then
        ok "tweak_log_throttle_host_test ($(grep -c '^  ok ' /tmp/regression_tweak_log_throttle.log) checks)"
    else
        bad "run_tweak_log_throttle_host_test.sh — see /tmp/regression_tweak_log_throttle.log"
    fi
else
    note "run_tweak_log_throttle_host_test.sh missing — skipping"
fi
if [ -f scripts/check_scan_budget_cancel_writes.py ]; then
    if python3 scripts/check_scan_budget_cancel_writes.py >/tmp/regression_bug345_lint.log 2>&1; then
        ok "check_scan_budget_cancel_writes.py ($(grep -c '^  ok ' /tmp/regression_bug345_lint.log) checks)"
    else
        bad "check_scan_budget_cancel_writes.py — see /tmp/regression_bug345_lint.log"
    fi
else
    note "check_scan_budget_cancel_writes.py missing — skipping"
fi

section "Audit"
if [ "$(./W0lfSword audit 2>&1 | grep -c 'AUDIT PASSED')" -gt 0 ]; then ok "audit"; else bad "audit"; fi

section "Doctor"
if [ "$(./W0lfSword doctor 2>&1 | grep -cE 'All tools ready|All.*present')" -gt 0 ]; then ok "doctor"; else bad "doctor"; fi

section "Build"
if $SKIP_BUILD; then
    note "skipped (--skip-build)"
else
    export THEOS="${THEOS:-$HOME/theos}"
    if make package >/tmp/regression_build.log 2>&1; then
        ok "make package ($(ls -t packages/*.deb | head -1 | xargs basename 2>/dev/null))"
    else
        bad "make package — see /tmp/regression_build.log"
    fi
fi

section "Live device smoke"
if [ -z "$DEV_IP" ]; then
    DEV_IP=$(cat .w0lfsword/active_device 2>/dev/null || echo "")
fi
if [ -n "$DEV_IP" ] && ssh -o ConnectTimeout=5 -o BatchMode=yes "root@$DEV_IP" 'echo ok' >/dev/null 2>&1; then
    ok "SSH reachable: $DEV_IP"
    if [ "$(./W0lfSword status 2>&1 | grep -c 'online')" -gt 0 ]; then ok "status: device online"; else bad "status"; fi
    if [ "$(./W0lfSword log 3 2>&1 | grep -c 'FilzaTweak')" -gt 0 ]; then ok "tweak log pull"; else note "no tweak log yet (fresh device?)"; fi
else
    note "no device reachable — smoke test skipped (pass --ip <ip> to run it)"
fi

printf '\n\033[1mRegression: %d passed, %d failed\033[0m\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
