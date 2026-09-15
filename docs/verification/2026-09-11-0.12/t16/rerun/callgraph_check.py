#!/usr/bin/env python3
"""T16 verification pass: read the call graph for BUG.3 / BUG.4 / BUG.5 straight
out of the freshly built app binary (the artifact a device would install), not
out of the source. Host only: reads one Mach-O file, touches no device.

Usage: python3 callgraph_check.py <disassembly.txt> <binary>

Expects the output of
  llvm-objdump-19 -d --macho --no-show-raw-insn <linked app binary>
where a function starts at a bare `<name>:` line and its instructions follow as
`<address>:\t<mnemonic> ...` lines.
"""
import re
import sys

DIS = sys.argv[1]
BIN = sys.argv[2]

# (function, [fragments that must appear in its body], why)
EXPECT = [
    ("-[TerminalViewController dotTapped:]", ["_term_bridge_cancel"],
     "BUG.4 app: the CANCEL tap reaches the bridge"),
    ("_term_bridge_cancel", ["_kexploit_request_stop"],
     "BUG.4 app: the bridge calls the engine's stop flag"),
    ("_kexploit_request_stop", ["stlr"],
     "BUG.4 engine: the flag is the atomic store the walks read"),
    ("+[TermSettings setScanBudget:]", ["_kexploit_set_scan_budget"],
     "BUG.3 app: the SET row pushes the budget into the engine"),
    ("-[SettingsViewController scanBudgetChanged:]", ["setScanBudget:"],
     "BUG.3 app: the segmented control's handler reaches the model setter"),
    ("_term_log_write_count",
     ["_kexploit_scan_writes", "_kexploit_scan_write_bytes",
      "_kexploit_scan_write_failures"],
     "BUG.5 app: the run log prints the engine's measured write count"),
]

lines = open(DIS, encoding="utf-8", errors="replace").read().splitlines()

# A function label: a non-indented line ending in ':'; the body runs to the next
# label line or to a blank line.
label_at = {}
for i, l in enumerate(lines):
    s = l.strip()
    if not s.endswith(":"):
        continue
    if re.match(r"^[0-9a-f]{6,}:", s):     # an instruction line, not a label
        continue
    label_at.setdefault(s[:-1], i)

def block(name):
    st = label_at.get(name)
    if st is None:
        return None
    out = []
    for l in lines[st + 1:]:
        s = l.strip()
        if not s or (s.endswith(":") and not re.match(r"^[0-9a-f]{6,}:", s)):
            break
        if re.match(r"^[0-9a-f]{6,}:", s):
            out.append(s)
    return out

ok = fail = 0
for name, want, why in EXPECT:
    b = block(name)
    if b is None:
        print("FAIL %-46s symbol not found in the disassembly  (%s)" % (name, why))
        fail += 1
        continue
    body = "\n".join(b)
    missing = [w for w in want if w not in body]
    if missing:
        print("FAIL %-46s missing %s  (%s)" % (name, ", ".join(missing), why))
        fail += 1
    else:
        hits = [" ".join(x.split()) for x in b if any(w in x for w in want)][:3]
        print("ok   %-46s %s" % (name, " | ".join(hits)))
        print("     %s" % why)
        ok += 1

print()
print("callgraph checks read out of %s: %d ok, %d failed" % (BIN, ok, fail))
sys.exit(1 if fail else 0)
