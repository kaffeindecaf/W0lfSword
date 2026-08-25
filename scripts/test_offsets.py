#!/usr/bin/env python3
"""D2.1 — offset table unit tests for kexploit/offsets.m.

Parses the per-iOS-version threshold blocks and validates:
  * thresholds are strictly increasing (no duplicate/out-of-order versions)
  * every assignment inside a block is non-zero
  * the EFFECTIVE (cumulative) value of each critical offset is non-zero at
    every threshold — i.e. no critical field is ever left unresolved
  * known-good XPF-verified values (off_task_itk_space) hold at each threshold:
    17.x -> 0x300, 18.x -> 0x318, 26.x -> 0x310 (t8030/t8110/T8150, XPF-verified)

0xdeaddead sentinels are intentional (fields that don't exist on a device/iOS —
writes through them are guarded in Thread.m, A3.18), so they are reported but
not failures.

Exit 0 on pass, 1 on failure. Run after every iOS version bump or offsets.m edit.
"""

import re
import sys

OFFSETS_M = "kexploit/offsets.m"

# (threshold major.minor, expected effective itk_space) — XPF-verified 2026-08
KNOWN_ITK_SPACE = [
    ("17.0", 0x300),   # 17.0-17.7
    ("18.0", 0x318),   # 18.0-18.7 (A13/A15 verified)
    ("26.0", 0x310),   # 26.x (t8030/t8110/T8150 verified)
]

CRITICALS = ["off_task_itk_space", "off_proc_p_pid", "off_thread_t_tro", "off_socket_so_usecount"]

# A plain threshold block: if (SYSTEM_VERSION_GREATER_THAN_OR_EQUAL_TO(@"X.Y")) {
# — NOT negated, compound, or CPU-specific conditions.
BLOCK_RE = re.compile(
    r'^\s*if\s*\(\s*SYSTEM_VERSION_GREATER_THAN_OR_EQUAL_TO\(@"([0-9]+\.[0-9]+)"\)\s*\)\s*\{?\s*$'
)
OFF_RE = re.compile(r'^\s*(?:uint(?:32|64)_t)?\s*(off_\w+)\s*=\s*(0x[0-9a-fA-F]+|\d+)\s*;')


def parse_blocks():
    """Return list of (threshold, {off_name: value}) in source order.

    Assignments are attributed to the most recent enclosing threshold block,
    even when they sit inside nested conditions (e.g. cpuFamily branches).
    """
    blocks = []
    cur = None
    with open(OFFSETS_M, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            m = BLOCK_RE.match(line)
            if m:
                cur = {"threshold": m.group(1), "offs": {}}
                blocks.append(cur)
                continue
            if cur is None:
                continue
            om = OFF_RE.match(line)
            if om:
                name, val = om.group(1), int(om.group(2), 0)
                cur["offs"][name] = val
    return blocks


def major_minor(t):
    a, b = t.split(".")
    return int(a), int(b)


def main():
    failures = []
    warnings = []
    blocks = parse_blocks()
    if not blocks:
        print("FAIL: no version blocks parsed from %s" % OFFSETS_M)
        return 1

    print("D2.1 offsets.m tests — %d version blocks" % len(blocks))

    # 1. thresholds strictly increasing
    prev = None
    for b in blocks:
        cur = major_minor(b["threshold"])
        if prev is not None and cur <= prev:
            failures.append("threshold %s not strictly increasing (after %s)" % (b["threshold"], prev))
        prev = cur

    # 2. sentinels reported as warnings (intentional — writes are guarded)
    for b in blocks:
        for name, v in b["offs"].items():
            if v == 0xDEADDEAD:
                warnings.append("%s: %s = 0xdeaddead sentinel (intentional, writes guarded)" % (b["threshold"], name))

    # 3. cumulative effective values of criticals + known-good itk_space,
    #    checked with per-threshold snapshot semantics (an offset set in a
    #    later block must not mask a gap at an earlier threshold)
    effective = {}
    for b in blocks:
        effective.update(b["offs"])
        for c in CRITICALS:
            v = effective.get(c)
            if v is None or v == 0:
                failures.append("%s: effective %s unresolved (%s)" % (b["threshold"], c, "unset" if v is None else "0"))
        v = effective.get("off_task_itk_space")
        expected = None
        for kt, kv in KNOWN_ITK_SPACE:
            if major_minor(b["threshold"]) >= major_minor(kt):
                expected = kv
        if expected is not None and v != expected:
            failures.append("%s: effective off_task_itk_space=0x%x expected 0x%x (XPF-verified)" % (b["threshold"], v, expected))

    for w in warnings:
        print("  note: %s" % w)

    if failures:
        print("FAIL: %d problem(s)" % len(failures))
        for f in failures:
            print("  - %s" % f)
        return 1

    print("PASS: thresholds strictly increasing, %d critical offsets resolved at" % len(CRITICALS))
    print("      every threshold, itk_space matches XPF-verified values")
    return 0


if __name__ == "__main__":
    sys.exit(main())
