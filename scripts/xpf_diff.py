#!/usr/bin/env python3
"""xpf_diff.py — compare two xpf-cli resolution dumps.

xpf-cli prints one line per resolved item:
    0x0000000000000310 <- kernelStruct.task.itk_space
    0x0000000000000000 <- kernelStruct.thread.ast [UNRESOLVED/crash]
plus header lines starting with '#'.

Usage:
    xpf_diff.py <dumpA.txt> <dumpB.txt>
    xpf_diff.py <dumpA.txt> <dumpB.txt> --json

Prints kernel identity headers, then identical/changed/one-sided item
counts and the changed values. Pure stdlib.
"""
import json
import re
import sys

HEAD_RE = re.compile(r"^# (kernel|darwin|xnu|os): (.*)")
ITEM_RE = re.compile(r"^0x([0-9a-f]+) <- (.+)$")
UNRES_RE = re.compile(r"^0x[0-9a-f]+ <- (.+?) \[UNRESOLVED")


def parse(path):
    hdr, items = {}, {}
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\n")
            m = HEAD_RE.match(line)
            if m:
                hdr[m.group(1)] = m.group(2)
                continue
            m = UNRES_RE.match(line)
            if m:
                items[m.group(1)] = None
                continue
            m = ITEM_RE.match(line)
            if m:
                items[m.group(2)] = int(m.group(1), 16)
    return hdr, items


def main():
    if len(sys.argv) < 3:
        print("usage: xpf_diff.py <dumpA> <dumpB> [--json]", file=sys.stderr)
        return 1
    ha, ia = parse(sys.argv[1])
    hb, ib = parse(sys.argv[2])
    as_json = "--json" in sys.argv[3:]

    names = sorted(set(ia) | set(ib))
    same = [n for n in names if ia.get(n) == ib.get(n) and ia.get(n) is not None]
    changed = [n for n in names
               if ia.get(n) is not None and ib.get(n) is not None and ia.get(n) != ib.get(n)]
    only_a = [n for n in names if n not in ib]
    only_b = [n for n in names if n not in ia]

    if as_json:
        print(json.dumps({
            "kernel_a": ha.get("kernel", "?"), "kernel_b": hb.get("kernel", "?"),
            "darwin_a": ha.get("darwin", "?"), "darwin_b": hb.get("darwin", "?"),
            "xnu_a": ha.get("xnu", "?"), "xnu_b": hb.get("xnu", "?"),
            "resolved_a": sum(1 for v in ia.values() if v is not None),
            "resolved_b": sum(1 for v in ib.values() if v is not None),
            "identical": len(same), "changed": len(changed),
            "only_in_a": len(only_a), "only_in_b": len(only_b),
            "changed_items": {n: [ia[n], ib[n]] for n in changed},
            "only_in_a_items": only_a, "only_in_b_items": only_b,
        }, indent=2))
        return 0

    def hdr_line(label, h):
        return (f"{label}: kernel={h.get('kernel', '?')} darwin={h.get('darwin', '?')} "
                f"xnu={h.get('xnu', '?')}")

    print(hdr_line("A", ha))
    print(hdr_line("B", hb))
    print("")
    print(f"resolved:  A={sum(1 for v in ia.values() if v is not None)}  "
          f"B={sum(1 for v in ib.values() if v is not None)}")
    print(f"identical: {len(same)}   changed: {len(changed)}   "
          f"only-in-A: {len(only_a)}   only-in-B: {len(only_b)}")
    if changed:
        print("")
        print("CHANGED:")
        for n in changed:
            print(f"  {n}: 0x{ia[n]:016x} -> 0x{ib[n]:016x}")
    if only_a or only_b:
        print("")
        print("ONE-SIDED / UNRESOLVED:")
        for n in only_a:
            print(f"  {n}: only in A")
        for n in only_b:
            print(f"  {n}: only in B")
    return 0


if __name__ == "__main__":
    sys.exit(main())
