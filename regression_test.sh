#!/bin/bash
# regression_test.sh — W0lfSword post-exploit validation
# Run this on the device via SSH after a successful exploit.
#
# Usage: scp regression_test.sh root@<ip>:/tmp/ && ssh root@<ip> "bash /tmp/regression_test.sh"

set -euo pipefail
PASS=0
FAIL=0
LOG="/tmp/w0lfsword_regression_test.log"

log() { echo "[$(date '+%H:%M:%S')] $*" | tee -a "$LOG"; }
pass() { log "PASS: $1"; ((PASS++)); }
fail() { log "FAIL: $1 (errno=$2: $3)"; ((FAIL++)); }

# ── Test 1: Write to unsealed location ────────────────────────
log "=== Test 1: Unsealed Write ==="
TEST_FILE="/private/var/tmp/w0lfsword_test_$$"
if echo "test" > "$TEST_FILE" 2>/dev/null; then
    pass "write to /private/var/tmp"
    rm -f "$TEST_FILE"
else
    fail "write to /private/var/tmp" "$?" "cannot write to unsealed path"
fi

# ── Test 2: Write to sealed /System/ ──────────────────────────
log "=== Test 2: SSV Write ==="
TEST_FILE="/System/Library/.w0lfsword_test_$$"
if echo "test" > "$TEST_FILE" 2>/dev/null; then
    pass "write to /System/Library/"
    rm -f "$TEST_FILE"
else
    fail "write to /System/Library/" "$?" "SSV bypass may not be active"
fi

# ── Test 3: Write to /usr/lib/ ────────────────────────────────
log "=== Test 3: /usr/lib/ Write ==="
TEST_FILE="/usr/lib/.w0lfsword_test_$$"
if echo "test" > "$TEST_FILE" 2>/dev/null; then
    pass "write to /usr/lib/"
    rm -f "$TEST_FILE"
else
    fail "write to /usr/lib/" "$?" "SSV bypass may not be active"
fi

# ── Test 4: Create directory in sealed path ───────────────────
log "=== Test 4: SSV Directory Creation ==="
TEST_DIR="/System/Library/.w0lfsword_testdir_$$"
if mkdir "$TEST_DIR" 2>/dev/null; then
    pass "mkdir in /System/Library/"
    rmdir "$TEST_DIR"
else
    fail "mkdir in /System/Library/" "$?" "directory creation failed"
fi

# ── Test 5: chmod on sealed file ──────────────────────────────
log "=== Test 5: chmod on sealed file ==="
TEST_FILE="/private/var/tmp/w0lfsword_chmod_$$"
echo "test" > "$TEST_FILE"
if chmod 0644 "$TEST_FILE" 2>/dev/null; then
    pass "chmod on unsealed file"
else
    fail "chmod" "$?" "chmod failed"
fi
rm -f "$TEST_FILE"

# ── Test 6: Sandbox check via syscall ─────────────────────────
log "=== Test 6: Sandbox State ==="
if [ -f /tmp/FilzaTweak.log ]; then
    if grep -q "SANDBOX ESCAPED" /tmp/FilzaTweak.log 2>/dev/null; then
        pass "Sandbox escape confirmed in log"
    else
        fail "sandbox check" "0" "no 'SANDBOX ESCAPED' in log"
    fi
else
    fail "log file" "0" "/tmp/FilzaTweak.log not found — tweak may not be loaded"
fi

# ── Results ───────────────────────────────────────────────────
log ""
log "=================================="
log "Results: $PASS passed, $FAIL failed"
log "=================================="

if [ "$FAIL" -eq 0 ]; then
    log "ALL TESTS PASSED"
    exit 0
else
    log "SOME TESTS FAILED"
    exit 1
fi
