#!/usr/bin/env python3
"""
dead_fn_scan.py — AUD.9 dead-function scan for the W0lfSword bash CLI.

Recurring repo check (ROADMAP AUDIT section, AUD.9): after every big
feature round, verify no function is defined but never called. Previous
rounds ran this ad hoc; this is the vendored, repeatable version.

Method (matches the historical scans):
  - defs = lines matching `^name() {` (name = [A-Za-z_][A-Za-z0-9_]*, any
    whitespace before the brace — single-line defs like
    `log_script() { echo ...; }` are caught too).
  - references = word-boundary occurrences of each name in the code with
    comment tails stripped (full-line `#` comments + inline `#` outside
    quotes), definition line excluded.
  - a def with ZERO references is flagged dead.

Comment stripping is quote-aware. Heredoc bodies are not special-cased:
a name echoed only inside a heredoc/string can only produce a FALSE LIVE
reference, never a false dead flag — safe direction for this check.

Usage: dead_fn_scan.py [script]          (default: ./W0lfSword)
Exit:  0 = scan ran clean (no dead defs), 1 = dead defs found,
       2 = file missing / unreadable.
"""

import re
import sys


def strip_comment(line):
    """Remove an inline/whole-line comment tail, respecting quotes."""
    out = []
    i = 0
    n = len(line)
    while i < n:
        c = line[i]
        if c == "'":
            j = line.find("'", i + 1)
            if j == -1:  # unterminated — treat rest as literal
                out.append(line[i:])
                break
            out.append(line[i : j + 1])
            i = j + 1
            continue
        if c == '"':
            j = i + 1
            while j < n:
                if line[j] == "\\":
                    j += 2
                    continue
                if line[j] == '"':
                    break
                j += 1
            out.append(line[i : j + 1])
            i = j + 1
            continue
        if c == "#" and (i == 0 or line[i - 1] in " \t"):
            break
        out.append(c)
        i += 1
    return "".join(out)


DEF_RE = re.compile(r"^([a-zA-Z_][a-zA-Z0-9_]*)\(\)\s*\{")


def scan(path):
    try:
        lines = open(path, encoding="utf-8").read().splitlines()
    except OSError as exc:
        print(f"dead_fn_scan: cannot read {path}: {exc}", file=sys.stderr)
        return 2

    code = [strip_comment(l) for l in lines]
    defs = []
    for lineno, s in enumerate(code, start=1):
        m = DEF_RE.match(s)
        if m:
            defs.append((m.group(1), lineno))

    # blank out def lines so a def cannot count as its own reference
    corpus = "\n".join("" if DEF_RE.match(s) else s for s in code)

    dead = []
    for name, lineno in defs:
        hits = re.findall(rf"\b{re.escape(name)}\b", corpus)
        if not hits:
            dead.append((name, lineno))

    print(f"function defs: {len(defs)}")
    if dead:
        print(f"DEAD FUNCTIONS: {len(dead)}")
        for name, lineno in dead:
            print(f"  {name}  (def line {lineno})")
        print("cross-check with plain grep before deleting: the name may")
        print("appear only inside heredocs/strings, which this scan ignores")
        print("by design (false-live direction only).")
        return 1
    print("dead candidates: 0 — every def has at least one reference.")
    return 0


if __name__ == "__main__":
    sys.exit(scan(sys.argv[1] if len(sys.argv) > 1 else "W0lfSword"))
