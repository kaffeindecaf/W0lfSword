#!/usr/bin/env python3
"""kc_pairs.py — instruction-level diff of the changed function bodies.

kc_funcdiff answers "which functions differ". This answers "how" - it pairs the
changed bodies of the two builds by address order (in a point release the layout
shift is monotonic, so the i-th changed body on one side corresponds to the i-th
on the other) and prints a unified diff of their canonical token streams.

Pairs are printed smallest-diff-first: a security fix is usually a handful of
instructions, while a data-permutation artifact touches hundreds of lines.

Usage:
    kc_pairs.py OLD NEW [--owner com.apple.kernel] [--region __TEXT_EXEC]
               [--json OUT] [--max N] [--min-changed N]
"""
import argparse
import difflib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import kc_funcdiff as K


def changed_pairs(old_path, new_path, owner=None, region="__TEXT_EXEC"):
    """[(old_func, new_func, diff_lines)] for the changed bodies, smallest first."""
    old = K.kc_macho.load(old_path)
    new = K.kc_macho.load(new_path)
    A = open(old_path, "rb").read()
    B = open(new_path, "rb").read()
    if owner:
        so, sn = K._owner_seg(old, owner, region), K._owner_seg(new, owner, region)
    else:
        so, sn = old.segment(region), new.segment(region)
    if not so or not sn:
        raise SystemExit("region/owner not found: %s/%s" % (owner, region))
    md = K._md()
    fo = K.functions_of(A, so, md)
    fn = K.functions_of(B, sn, md)
    ho = {f["hash"] for f in fo}
    hn = {f["hash"] for f in fn}
    uo = sorted((f for f in fo if f["hash"] not in hn), key=lambda f: f["va"])
    un = sorted((f for f in fn if f["hash"] not in ho), key=lambda f: f["va"])
    pairs = []
    for a, b in zip(uo, un):
        d = [l for l in difflib.unified_diff(a["key"].split("\n"), b["key"].split("\n"),
                                             lineterm="", n=1)
             if l[:1] in "+-" and not l.startswith(("+++", "---"))]
        pairs.append((a, b, d))
    pairs.sort(key=lambda p: len(p[2]))
    return pairs


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("old")
    ap.add_argument("new")
    ap.add_argument("--owner", default="com.apple.kernel")
    ap.add_argument("--region", default="__TEXT_EXEC")
    ap.add_argument("--json", default=None, help="also write the pair list as json")
    ap.add_argument("--max", type=int, default=-1, help="max pairs to print")
    ap.add_argument("--min-changed", type=int, default=1, help="skip pairs with fewer")
    a = ap.parse_args()

    pairs = changed_pairs(a.old, a.new, a.owner, a.region)
    print("changed pairs: %d  (%s: %s -> %s)" % (len(pairs), a.region, a.old, a.new))
    shown = 0
    for i, (o, n, d) in enumerate(pairs):
        if len(d) < a.min_changed:
            continue
        if a.max >= 0 and shown >= a.max:
            break
        shown += 1
        print("\n########## pair %d  old_va=0x%x size=%d | new_va=0x%x size=%d | changed_lines=%d"
              % (i, o["va"], o["size"], n["va"], n["size"], len(d)))
        for l in d:
            print("   " + l)
    if a.json:
        with open(a.json, "w") as fh:
            json.dump([{"old_va": o["va"], "old_size": o["size"],
                        "new_va": n["va"], "new_size": n["size"],
                        "changed_lines": len(d), "diff": d} for o, n, d in pairs],
                      fh, indent=2)
        print("\nwrote %s" % a.json)
    return 0


if __name__ == "__main__":
    sys.exit(main())
