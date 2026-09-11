#!/usr/bin/env bash
# D2.5 / AUD.6  -  golden test for the K5.9 chain selector.
#
# `select_best_chain()` no longer keeps its own copy of the exploit ranges: it
# looks rows up in `exploit_matrix()` (the same table the compat lines render),
# so a range edit can no longer change one surface and not the other. This test
# locks the resulting device x iOS -> chain mapping and proves the coupling is
# real: for every case that resolves to a chain, the name the selector prints
# must be the matrix row's own name (parsed independently here).
#
# Goes through the CLI (`chains best <ios> <model>`), so it also covers the
# cmd_chains wiring and the selector's fallback text.
#
# Usage: scripts/test_chain_select.sh
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT" || exit 1

PASS=0
FAIL=0
ok()  { printf '  \033[0;32m✓\033[0m %s\n' "$*"; PASS=$((PASS + 1)); }
bad() { printf '  \033[0;31m✗\033[0m %s\n' "$*"; FAIL=$((FAIL + 1)); }

# independent reader for the matrix name field (id -> name, field 4 -> 5)
matrix_name() {
    sed -n "/^exploit_matrix() {/,/^EOF$/p" W0lfSword \
        | awk -F'|' -v id="$1" '$4 == id { print $5; exit }'
}

# <ios>|<model>|<chain>|<status>|<matrix row id>  ("-" = no chain expected)
CASES=(
    # K5 A - DarkSword kernel R/W (pe_v1 / pe_v2 split picks the row)
    "26.0.1|iPhone14,7|A|implemented|darksword"
    "26.0|iPhone14,7|A|implemented|darksword"
    "17.0|iPhone11,2|A|implemented|darksword"
    "18.4.1|iPad13,1|A|implemented|darksword"
    "26.0.1|iPhone17,1|A|implemented|darksword-v2"
    "25.0|iPhone17,1|A|implemented|darksword-v2"
    # K5 B - userspace escape, the 26.x route (also for MTE devices)
    "26.1|iPhone14,7|B|implemented|bad_query"
    "26.6.1|iPhone14,7|B|implemented|bad_query"
    "26.2|iPhone16,1|B|implemented|bad_query"
    "26.2|iPhone18,1|B|implemented|bad_query"
    "26.5|iPad17,1|B|implemented|bad_query"
    # K5 D - bootchain: checkm8 (A9-A11) outranks usbliter8 (A12/A13)
    "15.6|iPhone8,1|D|research|checkm8"
    "27.0|iPhone8,1|D|research|checkm8"
    "26.1|iPhone12,8|D|implemented|usbliter8"
    "15.6|iPhone12,8|D|implemented|usbliter8"
    # K5 E - kfd PUAF fallback (16.x, port still pending)
    "16.0|iPhone8,1|E|pending|kfd"
    "16.6.1|iPhone14,7|E|pending|kfd"
    # no chain - one row per fallback reason
    "26.7|iPhone14,7|-|-|-"      # kernel gate closed past the bad_query range
    "16.9.1|iPhone14,7|-|-|-"    # outside kfd's 16.x range
    "15.6|iPhone14,7|-|-|-"      # below the DarkSword range
    "17.1|iPhone18,1|-|-|-"      # MTE device, no kernel R/W at all
    "17.1|iPad17,1|-|-|-"        # M5, same
    "17.1|Bogus9,9|-|-|-"        # unknown model
    "26.2|Bogus9,9|B|implemented|bad_query"  # the * rows still apply
)

echo "== chain selector golden grid (AUD.6) =="
for case in "${CASES[@]}"; do
    IFS='|' read -r ios model want_chain want_status want_row <<<"$case"
    out=$(./W0lfSword chains best "$ios" "$model" 2>&1 | sed 's/\x1b\[[0-9;]*m//g')
    line=$(printf '%s\n' "$out" | grep -m1 'best chain (K5 matrix):' || true)
    if [ -z "$line" ]; then
        nochain=$(printf '%s\n' "$out" | grep -c 'no chain available for this device' || true)
        if [ "$want_chain" = "-" ] && [ "$nochain" -gt 0 ]; then
            why=$(printf '%s\n' "$out" | grep -A1 'no chain available' | tail -1)
            if [ -n "${why// /}" ]; then
                ok "$ios $model: no chain (${why## })"
            else
                bad "$ios $model: no chain verdict without a reason"
            fi
        else
            bad "$ios $model: expected chain $want_chain, got no chain at all"
        fi
        continue
    fi
    got_chain=$(printf '%s' "$line" | sed -E 's/.*matrix\): *([A-Z]) .*/\1/')
    got_name=$(printf '%s' "$line" | sed -E 's/.*matrix\): *[A-Z] +- +//; s/ *\[[a-z]+\]$//')
    got_status=$(printf '%s' "$line" | sed -E 's/.*\[([a-z]+)\]$/\1/')
    if [ "$want_chain" = "-" ]; then
        bad "$ios $model: expected no chain, got $got_chain ($got_name)"
        continue
    fi
    want_name=$(matrix_name "$want_row")
    if [ -z "$want_name" ]; then
        bad "$ios $model: test row id '$want_row' is not in exploit_matrix()"
        continue
    fi
    if [ "$got_chain" = "$want_chain" ] && [ "$got_status" = "$want_status" ] \
       && [ "$got_name" = "$want_name" ]; then
        ok "$ios $model: $want_chain $got_name [$got_status]"
    else
        bad "$ios $model: expected $want_chain/$want_name/$want_status, got $got_chain/$got_name/$got_status"
    fi
done

# Regressions that used to be silent: an unparseable version made the old
# selector print `[: abc: integer expression expected` to stderr while still
# claiming a chain, and a note could land in the status field.
echo "== selector robustness =="
out=$(./W0lfSword chains best abc iPhone14,7 2>&1)
if printf '%s' "$out" | grep -q 'integer expression expected'; then
    bad "junk version still reaches the shell's integer comparison"
else
    ok "junk version: no shell comparison error"
fi
if printf '%s' "$out" | grep -q 'unparseable iOS version'; then
    ok "junk version: reported as unparseable"
else
    bad "junk version: no unparseable-version reason"
fi

printf '\n\033[1mchain selector: %d passed, %d failed\033[0m\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
