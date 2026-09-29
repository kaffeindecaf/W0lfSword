#!/usr/bin/env python3
"""kc_datainsert.py - locate bytes INSERTED between two builds of one segment.

Function-level diffing (kc_funcdiff) finds changed code. A release can also fix
something by changing DATA only: a rule table, a compiled profile, a const blob.
When that happens the segment is not rewritten in place - the blob grows and
everything after it shifts - so a byte-for-byte compare reports a huge
difference while the real edit is a few dozen bytes.

This finds that edit: given one segment from each build, it locates the single
insertion point by binary search (everything before it is byte-identical,
everything from it matches the other build shifted by N), then prints the
inserted bytes and their context. Works on strings, profile blobs, tables.

Usage:
    kc_datainsert.py OLD NEW --owner com.apple.security.sandbox --seg __TEXT
    kc_datainsert.py OLD NEW --owner com.apple.kernel --seg __TEXT --context 64
    kc_datainsert.py --selftest
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import kc_macho


def segment_bytes(path, owner, seg_name):
    img = kc_macho.load(path)
    data = open(path, "rb").read()
    for own, seg in kc_macho.all_segments(img):
        if (owner is None or owner in own) and seg.name == seg_name:
            return data[seg.fileoff:seg.fileoff + seg.filesize], seg
    raise SystemExit("no segment %s for owner %s in %s" % (seg_name, owner, path))


def find_insertion(A, B, d=None):
    """(point, n) with A[:point] == B[:point] and A[point:] == B[point+n:].

    point is None when the difference is not a single insertion (a rewrite, or
    a difference that starts at byte 0 - e.g. a Mach-O header field).
    """
    if d is None:
        d = len(B) - len(A)
    if d == 0:
        return None, 0
    if len(A) != len(B) - d or d < 0:
        return None, d

    def shifted(i):
        return A[i:] == B[i + d:]

    lo, hi = 0, len(A)
    if shifted(0):                       # pure insertion at the very start
        return 0, d
    if not shifted(len(A)):
        return None, d
    while lo + 1 < hi:                   # first index where the shift holds
        mid = (lo + hi) // 2
        if shifted(mid):
            hi = mid
        else:
            lo = mid
    return hi, d


def printable(b):
    return "".join(chr(c) if 32 <= c < 127 else "." for c in b)


def selftest():
    ok = fails = 0

    def check(name, cond):
        nonlocal ok, fails
        if cond:
            ok += 1
        else:
            fails += 1
            print("FAIL %s" % name)

    A = bytes(range(256)) * 4
    ins = b"NEW-RULES"
    B = A[:100] + ins + A[100:]
    p, n = find_insertion(A, B)
    check("locate mid-insertion", (p, n) == (100, len(ins)))
    assert p is not None
    check("inserted bytes", B[p:p + n] == ins)
    B2 = ins + A
    check("insertion at start", find_insertion(A, B2) == (0, len(ins)))
    B3 = A + ins
    check("insertion at end", find_insertion(A, B3) == (len(A), len(ins)))
    B4 = bytearray(A)
    B4[7] ^= 0xFF                        # in-place rewrite, no insertion
    check("rewrite rejected", find_insertion(A, bytes(B4))[0] is None)
    check("equal rejected", find_insertion(A, A)[0] is None)
    B5 = A[:50] + ins + A[50:]
    p, n = find_insertion(A, B5)
    assert p is not None
    check("insertion over 1 byte value", B5[p:p + n] == ins)
    print("checks=%d failures=%d" % (ok, fails))
    print("KC_DATAINSERT_SELFTEST %s" % ("PASS" if fails == 0 else "FAIL"))
    return 1 if fails else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("old", nargs="?")
    ap.add_argument("new", nargs="?")
    ap.add_argument("--owner", default=None, help="image name substring (default: any)")
    ap.add_argument("--seg", default="__TEXT", help="segment name (default __TEXT)")
    ap.add_argument("--context", type=lambda x: int(x, 0), default=48)
    ap.add_argument("--hex", action="store_true", help="also dump the inserted bytes as hex")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        return selftest()
    if not a.old or not a.new:
        ap.error("OLD and NEW are required (or --selftest)")

    A, sa = segment_bytes(a.old, a.owner, a.seg)
    B, sb = segment_bytes(a.new, a.owner, a.seg)
    print("%s %s: %d bytes" % (a.old, a.seg, len(A)))
    print("%s %s: %d bytes" % (a.new, a.seg, len(B)))
    d = len(B) - len(A)
    print("size delta: %+d bytes" % d)
    if d == 0:
        i = 0
        while i < min(len(A), len(B)) and A[i] == B[i]:
            i += 1
        print("same size; first differing byte at +0x%x" % i)
        return 0
    point, n = find_insertion(A, B)
    if point is None:
        print("not a single insertion (rewrite, or the difference starts at byte 0)")
        return 1
    va = sb.vmaddr + point
    print("insertion point: %s+0x%x (VA 0x%x)" % (a.seg, point, va))
    print("  identical prefix: 0x%x bytes; shifted tail: 0x%x bytes" % (point, len(A) - point))
    print("  context before : %s" % printable(A[max(0, point - a.context):point]))
    print("  inserted bytes : %s" % printable(B[point:point + n]))
    print("  context after  : %s" % printable(B[point + n:point + n + a.context]))
    if a.hex:
        print("  inserted hex   : %s" % B[point:point + n].hex())
    return 0


if __name__ == "__main__":
    sys.exit(main())
