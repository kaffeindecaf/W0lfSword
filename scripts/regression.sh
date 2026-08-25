#!/usr/bin/env bash
# D2.2 — W0lfSword regression suite.
#
# Runs the full static + build + audit checks, then an optional live-device
# smoke test when a device is reachable (via saved IP or --ip). Safe to run
# any time; nothing here touches the kernel exploit path.
#
# Usage: scripts/regression.sh [--ip <device-ip>] [--skip-build]
set -uo pipefail
cd "$(dirname "$0")/.."

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
