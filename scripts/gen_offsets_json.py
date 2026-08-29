#!/usr/bin/env python3
"""L3.1 — build-time offsets.json generation for the W0lfSword Hub app.

Parses kexploit/offsets.m threshold blocks (same logic as scripts/test_offsets.py,
D2.1) and emits a compact offsets.json: the EFFECTIVE (cumulative) offset table
per iOS version threshold. 0xdeaddead sentinels are dropped (writes through them
are guarded in Thread.m, A3.18 — the app never needs them).

The app picks the highest threshold <= its running iOS version and reads that
table (boot path, L3.1).

Usage: python3 scripts/gen_offsets_json.py [out.json]
Default out: pocs/hub_shell/Resources/offsets.json (bundled with the app).
"""

import json
import re
import sys

OFFSETS_M = "kexploit/offsets.m"
DEFAULT_OUT = "pocs/hub_shell/Resources/offsets.json"

BLOCK_RE = re.compile(
    r'^\s*if\s*\(\s*SYSTEM_VERSION_GREATER_THAN_OR_EQUAL_TO\(@\"([0-9]+\.[0-9]+)\"\)\s*\)\s*\{?\s*$'
)
OFF_RE = re.compile(r'^\s*(?:uint(?:32|64)_t)?\s*(off_\w+)\s*=\s*(0x[0-9a-fA-F]+|\d+)\s*;')


def parse_blocks():
    """Return list of (threshold, {off_name: value}) in source order."""
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
                if val != 0xdeaddead:
                    cur["offs"][name] = val
    return blocks


def main():
    blocks = parse_blocks()
    if not blocks:
        print("FAIL: no version blocks parsed from %s" % OFFSETS_M, file=sys.stderr)
        return 1

    effective = {}
    for b in blocks:
        effective.update(b["offs"])
        b["effective"] = dict(effective)

    out = {
        "generated_by": "scripts/gen_offsets_json.py (L3.1)",
        "source": OFFSETS_M,
        "versions": [
            {"threshold": b["threshold"], "offsets": b["effective"]}
            for b in blocks
        ],
    }

    path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_OUT
    with open(path, "w") as f:
        json.dump(out, f, indent=1)
    print("OK: %s — %d version thresholds, %d unique offsets"
          % (path, len(blocks), len(effective)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
