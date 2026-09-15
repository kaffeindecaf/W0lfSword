#!/usr/bin/env python3
"""Extract the cancel/budget call edges from the linked W0lfTerm binary's
disassembly (llvm-objdump-19 -d --macho --symbolize-operands). Host-only
static read of the Mach-O; the symbol names come from the comment objdump
emits after each `bl`."""
import re
import sys

path = sys.argv[1]
text = open(path, encoding="utf-8", errors="replace").read()

# function labels in this objdump output are bare symbol lines ending in ':'
# (instruction lines carry a tab and start with a hex address, and selector-ref
# comments can end in ':' too, so anchor on "no tab and not an address")
blocks = re.split(r"\n(?=[^\t\n]*[^\s:][^\t\n]*:\n)", text)
blocks = [b for b in blocks if not re.match(r"[0-9a-f]{6,}:", b)]

want = {
    "-[TerminalViewController dotTapped:]": "term_bridge_cancel",
    "+[TermSettings setScanBudget:]": "kexploit_set_scan_budget",
    "+[TermSettings load]": "kexploit_set_scan_budget",
    "_term_bridge_cancel": "kexploit_request_stop",
}

found = 0
for b in blocks:
    head = b.split("\n", 1)[0]
    if not head.endswith(":") or " " in head.strip() and not head.startswith("-["):
        pass
    name = head[:-1] if head.endswith(":") else head
    key = next((k for k in want if name == k), None)
    if not key:
        continue
    targets = sorted(set(re.findall(
        r"\bbl\s+(?:0x[0-9a-f]+\s*;\s*(?:symbol stub for:\s*)?)?(\S+)", b)))
    hit = [t for t in targets if want[key] in t]
    print("%s:" % name)
    print("    calls: %s" % (", ".join(targets) if targets else "(none)"))
    print("    -> contains %r: %s" % (want[key], "YES" if hit else "NO"))
    found += 1

print("\nfunctions inspected with a call edge: %d" % found)
