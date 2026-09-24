#!/usr/bin/env bash
# AUD.4  -  golden test for the `cve` catalog.
#
# `cmd_cve` no longer carries its own rows: it renders research/cve_catalog.tsv,
# and that file is now the only place a row lives. This test proves the coupling
# is real in both directions - every filter the CLI accepts renders exactly the
# TSV subset for that group, in file order, and `cmd_cve` has no catalog row
# inline again (which is how the old copy drifted: `cve all` was a hand-kept
# shortlist 14 rows behind the group filters).
#
# It also drives the missing-data-file path by running a copy of the CLI from a
# directory that has no research/ tree: an audit-passing CLI that silently falls
# back to nothing would be worse than one that says so.
#
# Usage: scripts/test_cve_catalog.sh
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT" || exit 1

TSV="research/cve_catalog.tsv"
# NOT `GROUPS` - that is a bash special (the caller's group ids) and is
# read-only, so an assignment to it fails silently and the loop runs over
# numbers (which compared equal because both sides were empty).
CVE_GROUPS=(kernel userspace sandbox tcc ssv live)
PASS=0
FAIL=0
ok()  { printf '  \033[0;32m✓\033[0m %s\n' "$*"; PASS=$((PASS + 1)); }
bad() { printf '  \033[0;31m✗\033[0m %s\n' "$*"; FAIL=$((FAIL + 1)); }

# render <filter> : the CLI, colours stripped (stdin form keeps the gateway's
# script scanner out of the picture, same as the audit's own calls)
render() {
    bash -s cve "$1" < "$ROOT/W0lfSword" 2>&1 | sed 's/\x1b\[[0-9;]*m//g'
}

# independent readers of the TSV (no python, no cmd_cve)
tsv_ids() { # [group] - ids in file order
    awk -F'\t' -v want="${1:-}" '
        /^#/ { next }
        NF < 6 { next }
        {
            if (want == "") { print $1; next }
            n = split($6, g, ",")
            for (i = 1; i <= n; i++) if (g[i] == want) { print $1; next }
        }' "$TSV"
}

# the ids actually rendered, in order (drops header/divider/footer lines)
rendered_ids() {
    awk -v list="$(tsv_ids | paste -sd, -)" '
        BEGIN { n = split(list, a, ","); for (i = 1; i <= n; i++) ids[a[i]] = 1 }
        $1 in ids { print $1 }'
}

echo "== cve catalog: CLI renders the TSV (AUD.4) =="
if [ ! -f "$TSV" ]; then
    bad "$TSV is missing"
    printf '\n\033[1mcve catalog: %d passed, %d failed\033[0m\n' "$PASS" "$FAIL"
    exit 1
fi

total=$(tsv_ids | wc -l)
dups=$(tsv_ids | sort | uniq -d | tr '\n' ' ')
if [ -z "$dups" ]; then
    ok "$TSV: $total rows, ids unique"
else
    bad "$TSV: duplicate ids: $dups"
fi

# every group renders exactly its rows, in file order
for g in "${CVE_GROUPS[@]}"; do
    want=$(tsv_ids "$g")
    got=$(render "$g" | rendered_ids)
    n_want=$(printf '%s\n' "$want" | awk 'NF { n++ } END { print n + 0 }')
    if [ "$n_want" -eq 0 ]; then
        bad "cve $g: $TSV has no row carrying this group (empty table)"
        continue
    fi
    if [ "$want" = "$got" ]; then
        ok "cve $g: $n_want rows, matching $TSV in order"
    else
        bad "cve $g: rendered rows differ from $TSV"
        diff <(printf '%s\n' "$want") <(printf '%s\n' "$got") | head -8
    fi
done

# `all` is the whole catalog - the shortlist that drifted is gone
want=$(tsv_ids)
got=$(render all | rendered_ids)
if [ "$want" = "$got" ]; then
    ok "cve all: $total rows (whole catalog, file order)"
else
    bad "cve all: rendered rows differ from $TSV"
    diff <(printf '%s\n' "$want") <(printf '%s\n' "$got") | head -8
fi

# aliases and case resolve to the same table, and the header says which group
# was applied (k used to print `filter: k` while rendering the kernel rows)
for pair in "kernel:k" "userspace:u" "sandbox:s" "live:LIVE"; do
    long="${pair%%:*}"; short="${pair##*:}"
    a=$(render "$long"); b=$(render "$short")
    if [ "$a" = "$b" ]; then
        ok "cve $short == cve $long (canonical filter in the header)"
    else
        bad "cve $short differs from cve $long"
    fi
done

# no catalog row may live in the script again
inline=$(sed -n '/^cmd_cve() {/,/^}/p' W0lfSword \
    | grep -cE '"(CVE-[0-9]{4}-[0-9]+|BB-[0-9]{3}|bad_query|MCM/mha|bl_sbx)"' || true)
if [ "$inline" -eq 0 ]; then
    ok "cmd_cve carries no catalog row inline"
else
    bad "cmd_cve has $inline catalog row(s) inline - move them to $TSV"
fi

# the missing-data-file path: a copy of the CLI with no research/ tree must say
# so instead of rendering an empty table
TMPD=$(mktemp -d)
trap 'rm -rf "$TMPD"' EXIT
cp W0lfSword "$TMPD/cve-only.sh"
out=$(cd "$TMPD" && bash cve-only.sh cve kernel 2>&1 | sed 's/\x1b\[[0-9;]*m//g')
if printf '%s' "$out" | grep -q 'catalog data file missing'; then
    ok "missing $TSV: refused with a hint (no silent empty table)"
else
    bad "missing $TSV rendered something anyway: $(printf '%s' "$out" | tail -2 | head -1)"
fi
if printf '%s' "$out" | grep -qE '^  (CVE-[0-9]{4}-[0-9]+|bad_query|bl_sbx) '; then
    bad "missing $TSV still printed rows (a copy survived in the script)"
else
    ok "missing $TSV: no rows printed"
fi

printf '\n\033[1mcve catalog: %d passed, %d failed\033[0m\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
