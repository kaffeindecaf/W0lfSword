#!/usr/bin/env bash
# Host test for BUG.1 (2026-09-11 SE panic), end to end: the 32-byte block clamp
# (kexploit/krw_zone_write.c) and the staged write probe's restore path
# (kexploit/probe_restore_policy.c) driven through the save -> corrupt -> exit ->
# put-back sequence the engine runs.
#
# Sibling of scripts/run_krw_zone_write_host_test.sh, which tests the clamp and
# the restore policy one at a time. This one injects the 32-byte overrun the SE
# died on and then takes the probe's ERROR (-1, write-verify exhaustion) and
# CANCEL (-7) exits - including the shape where pe_v1's release funnel has
# already emptied the spray tracking array - and requires the saved values to be
# back in the object afterwards, or the failure to be reported as a failure.
#
# Both sources are compiled as the ENGINE compiles them (same files, no stubs),
# so these checks cannot drift from what ships. No device is involved: this is
# the host `cc` and a fake kernel window.
#
#   bash scripts/run_probe_restore_e2e_host_test.sh
set -euo pipefail

cd "$(dirname "$0")/.."

CC="${CC:-cc}"
OUT="${TMPDIR:-/tmp}/probe_restore_e2e_host_test"

# shellcheck disable=SC2086
"$CC" -std=gnu99 -Wall -Wextra -Wno-unused-parameter \
    -I. \
    -o "$OUT" \
    tests/probe_restore_e2e_host_test.c kexploit/krw_zone_write.c kexploit/probe_restore_policy.c

exec "$OUT"
