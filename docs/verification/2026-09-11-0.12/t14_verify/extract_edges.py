#!/usr/bin/env python3
"""Extract the call edges the W0lfTerm app builds into the engine from a Mach-O
disassembly (llvm-objdump -d --macho). Prints, per requested label, the `bl`
targets inside that function's body (up to the next label)."""
import sys

path = sys.argv[1]
labels = sys.argv[2:]
lines = open(path, encoding="utf-8", errors="replace").read().splitlines()

starts = []
for line in lines:
    s = line.strip()
    if s.endswith(":") and not s.endswith("::") and s and s[0] not in "0123456789abcdef \t":
        starts.append(s)

for want in labels:
    idx = None
    for i, line in enumerate(lines):
        if line.strip() == want:
            idx = i
            break
    print("=== %s" % want)
    if idx is None:
        print("    NOT FOUND in the disassembly")
        continue
    calls = []
    for line in lines[idx + 1:]:
        s = line.strip()
        if s.endswith(":") and s and s[0] not in "0123456789abcdef \t":
            break                      # the next function starts here
        if "\tbl\t" in line or "\tb\t" in line:
            calls.append(line.split("\t", 1)[1].replace("\t", " "))
    for c in calls:
        print("    %s" % c)
    if not calls:
        print("    (no direct call in this body - the callee is reached via objc_msgSend)")
    print()
