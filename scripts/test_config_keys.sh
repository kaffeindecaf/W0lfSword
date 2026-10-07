#!/usr/bin/env bash
# AUD.13  -  every config key must survive a load.
#
# The config lives in four parallel tables inside W0lfSword: config_schema (the
# declared keys + defaults), config_defaults, config_get, config_valid and
# load_config's case. Adding a key to three of them is silent - that is exactly
# what happened to `report_errors`: it was in the schema, in config_defaults, in
# config_get and in config_valid, but load_config had no arm for it, so a
# `report_errors=off` line in the config file (or `config set report_errors
# off`, which re-loads through the same function) was ignored and the CLI kept
# prompting. Nothing failed; the setting just never applied.
#
# This test has two halves so neither can drift again:
#   1. structural  - every key config_schema declares is a case arm of all four
#      functions, read out of the source independently of the runtime.
#   2. behavioural - through the CLI, in a throwaway project dir: a missing file
#      yields the schema defaults, a file of valid values is applied in full, a
#      file of invalid values is ignored in full, and `config set` round-trips.
#
# Usage: scripts/test_config_keys.sh
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT" || exit 1
SRC="W0lfSword"

PASS=0
FAIL=0
ok()  { printf '  \033[0;32m✓\033[0m %s\n' "$*"; PASS=$((PASS + 1)); }
bad() { printf '  \033[0;31m✗\033[0m %s\n' "$*"; FAIL=$((FAIL + 1)); }

# ── key table ────────────────────────────────────────────────────────────────
# key|schema default|a valid non-default value ("-" = every non-empty value is
# valid, so the invalid-value check uses an empty one)
KEYS=(
    "animations|on|off"
    "anim_speed|normal|fast"
    "show_wolf|menu|never"
    "menu_compact|off|on"
    "device_scan|on|off"
    "color|on|off"
    "confirm_risky|on|off"
    "prompt_symbol|W0lfSword|wolf>"
    "loading_time|1.2|3.5"
    "report_errors|ask|off"
)

# schema itself, read from the source (key|default|help)
schema_rows() {
    awk '/^config_schema\(\) \{/,/^EOF$/ { if (index($0, "|") > 0) print }' "$SRC"
}

schema_keys() { schema_rows | awk -F'|' '{ print $1 }' | grep -E '^[a-z_]+$'; }

schema_default() {
    schema_rows | awk -F'|' -v k="$1" '$1 == k { print $2; exit }'
}

# function body from the source: from "<name>() {" to the next column-0 "}"
fn_body() {
    awk -v fn="$1() {" 'index($0, fn) == 1 { f = 1 } f { print } f && /^\}/ { exit }' "$SRC"
}

# is <key> a case arm in this body? (start of line, or an | alternative -
# config_valid groups the booleans as `animations|menu_compact|...)`, so an arm
# can be terminated by `|` as well as by `)`)
has_arm() {
    grep -Eq "(^[[:space:]]*|\|)${1}([[:space:]]*\)|[[:space:]]*\|)" "$2"
}

echo "== config keys: structural (the four tables) =="
BASE="$(mktemp -d "${TMPDIR:-/tmp}/w0lfcfg.XXXXXX")"
trap 'rm -rf "$BASE"' EXIT
# every function that must know every key
FNS="config_defaults config_get config_valid load_config"
for fn in $FNS; do
    fn_body "$fn" > "$BASE/$fn.body"
    if [ ! -s "$BASE/$fn.body" ]; then
        bad "could not extract $fn() from $SRC"
    fi
done
while IFS='|' read -r key _def _val; do
    for fn in $FNS; do
        if [ -s "$BASE/$fn.body" ] && ! has_arm "$key" "$BASE/$fn.body"; then
            bad "$key is not a case arm of $fn()"
        fi
    done
done < <(schema_rows)
if [ "$FAIL" -eq 0 ]; then
    ok "all $(schema_keys | wc -l | tr -d ' ') keys are wired into $FNS"
fi

# the declared keys are the keys we test - a new schema row must be added above
declared=$(schema_keys | sort | tr '\n' ' ')
tested=$(printf '%s\n' "${KEYS[@]}" | cut -d'|' -f1 | sort | tr '\n' ' ')
if [ "$declared" = "$tested" ]; then
    ok "the test table covers every schema key"
else
    bad "test table is out of step with config_schema"
    bad "  schema: $declared"
    bad "  test:   $tested"
fi

# the defaults this test assumes are the schema's own defaults
while IFS='|' read -r key def _val; do
    real=$(schema_default "$key")
    if [ -n "$real" ] && [ "${real%% *}" != "$def" ]; then
        bad "$key: test expects default '$def', config_schema declares '$real'"
    fi
done < <(printf '%s\n' "${KEYS[@]}")

# ── behavioural: through the CLI in a throwaway project dir ──────────────────
# The CLI derives PROJECT_DIR from $0, so a copy under a temp dir gets a temp
# .w0lfsword/ - the developer's real config is never touched.
PROJ="$BASE/proj"
mkdir -p "$PROJ/.w0lfsword"
cp "$SRC" "$PROJ/wolf.sh"
CONF="$PROJ/.w0lfsword/config"

# run `config show` in the throwaway project, strip ANSI, print the rows
show() {
    (cd "$PROJ" && bash wolf.sh config show </dev/null 2>/dev/null) \
        | sed 's/\x1b\[[0-9;]*m//g'
}

# value the CLI reports for <key>, taken from the rendered table row
reported() {
    awk -v k="$1" '{ for (i = 1; i <= NF; i++) if ($i == k) { print $(i + 1); exit } }'
}

echo "== config keys: behavioural (through the CLI) =="

# 1. no config file at all -> every schema default
rm -f "$CONF"
out=$(show)
while IFS='|' read -r key def _val; do
    got=$(printf '%s\n' "$out" | reported "$key")
    if [ "$got" = "$def" ]; then
        ok "no config file: $key=$def (schema default)"
    else
        bad "no config file: $key shows '$got', expected the default '$def'"
    fi
done < <(printf '%s\n' "${KEYS[@]}")

# 2. a config file of valid values -> every value is applied
: > "$CONF"
while IFS='|' read -r key _def val; do echo "$key=$val" >> "$CONF"; done < <(printf '%s\n' "${KEYS[@]}")
out=$(show)
while IFS='|' read -r key _def val; do
    got=$(printf '%s\n' "$out" | reported "$key")
    if [ "$got" = "$val" ]; then
        ok "loaded from file: $key=$val"
    else
        bad "loaded from file: $key shows '$got', expected '$val' (value silently dropped)"
    fi
done < <(printf '%s\n' "${KEYS[@]}")

# 3. a config file of invalid values -> every one is ignored (defaults win)
: > "$CONF"
while IFS='|' read -r key _def _val; do echo "$key=bogus" >> "$CONF"; done < <(printf '%s\n' "${KEYS[@]}")
# prompt_symbol accepts any non-empty string, so its invalid value is an empty one
grep -v '^prompt_symbol=' "$CONF" > "$CONF.tmp" && mv "$CONF.tmp" "$CONF"
echo "prompt_symbol=" >> "$CONF"
out=$(show)
while IFS='|' read -r key def _val; do
    got=$(printf '%s\n' "$out" | reported "$key")
    if [ "$got" = "$def" ]; then
        ok "invalid value ignored: $key falls back to $def"
    else
        bad "invalid value accepted: $key shows '$got', expected the default '$def'"
    fi
done < <(printf '%s\n' "${KEYS[@]}")

# 4. `config set` writes the file AND applies it in the same session
rm -f "$CONF"
for pair in "report_errors=off" "anim_speed=slow" "loading_time=4.5"; do
    key="${pair%%=*}"; val="${pair#*=}"
    (cd "$PROJ" && bash wolf.sh config set "$key" "$val" </dev/null >/dev/null 2>&1)
    got=$(show | reported "$key")
    if [ "$got" = "$val" ]; then
        ok "config set $key=$val applied ($(grep -c "^$key=$val\$" "$CONF") file line)"
    else
        bad "config set $key=$val: CLI reports '$got' and the file holds '$(grep "^$key=" "$CONF")'"
    fi
done
# an invalid value must be refused AND must not touch the file
before=$(cat "$CONF")
(cd "$PROJ" && bash wolf.sh config set anim_speed=bogus "bogus" </dev/null >/dev/null 2>&1)
if [ "$(cat "$CONF")" = "$before" ] && [ "$(show | reported anim_speed)" = "slow" ]; then
    ok "config set with an invalid value is refused, file unchanged"
else
    bad "config set accepted an invalid value"
fi

printf '\n\033[1mconfig keys: %d passed, %d failed\033[0m\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
