#!/usr/bin/env python3
"""kc_patchdiff.py — shift-tolerant patch-diff localizer for iOS kernelcaches.

Comparing two kernelcaches of the same built product (a point release, e.g.
18.7.2 -> 18.7.3) with a byte diff is useless: ~20% of the bytes differ even
when almost no source changed, because every literal pointer, branch
displacement and shifted function moves. This tool answers the question a
security review actually asks: *which code regions changed, and where are the
insertions/deletions?*

Method (per segment):
  1. hash every 32-byte window of B (stride 8) -> offset, dropping ambiguous
     hashes;
  2. the same over A, keeping only windows that hit B UNIQUELY and byte-equal;
  3. walk those anchor pairs in address order with a locality bound, so a
     shifted copy of a function still chains to itself;
  4. consecutive anchors with a constant (iA - iB) delta are an IDENTICAL run;
     the bytes between two runs are a DELTA region, classified by the length
     difference: equal sizes = in-place modification, B shorter = code removed
     in B, B longer = code INSERTED in B (that is where a fix lives).

Every reported identical run is byte-verified, and the region is covered
exactly once (identical runs + delta regions tile it), so the totals are
checkable - `--selftest` asserts both against synthetic pairs with known
edits.

Usage:
    kc_patchdiff.py OLD NEW [--segment NAME] [--json] [--top N] [--quiet]
    kc_patchdiff.py --selftest
"""
import argparse
import json
import sys
import zlib

import kc_macho

WH = 32            # anchor window (bytes)
STRIDE = 8         # anchor stride (bytes)
LOCALITY = 0x8000  # max local drift between anchors (bytes)


# ── alignment ─────────────────────────────────────────────────────────
def _index(buf, wh=WH, stride=STRIDE):
    """crc32(window) -> offset, ambiguous hashes marked -1."""
    idx = {}
    for i in range(0, len(buf) - wh + 1, stride):
        h = zlib.crc32(buf[i:i + wh])
        if h in idx:
            idx[h] = -1
        else:
            idx[h] = i
    return idx


def align(a, b, wh=WH, stride=STRIDE, locality=LOCALITY):
    """Return (runs, deltas).

    runs   = [(a_off, b_off, length), ...]   byte-identical stretches
    deltas = [(a_off, b_off, a_len, b_len), ...]  everything in between

    Anchors are chained with a locality bound (a shifted copy of a function
    still chains to itself) and a run is kept only while the (i - j) delta is
    constant, i.e. no code was inserted or removed inside it.
    """
    b_idx = _index(b, wh, stride)
    pairs = []
    for i in range(0, len(a) - wh + 1, stride):
        j = b_idx.get(zlib.crc32(a[i:i + wh]))
        if j is None or j < 0:
            continue
        if a[i:i + wh] == b[j:j + wh]:
            pairs.append((i, j))
    pairs.sort()

    chain = []
    pi = pj = None
    for (i, j) in pairs:
        if pi is not None:
            if i <= pi or j <= pj:
                continue                                    # not monotone
            if abs(j - (pj + (i - pi))) > locality:
                continue                                    # not local
        chain.append((i, j))
        pi, pj = i, j

    runs = []                                               # (a0, b0, a_end)
    for (i, j) in chain:
        if runs:
            a0, b0, a_end = runs[-1]
            b_end = b0 + (a_end - a0)
            # extend only while the delta is constant AND the span the anchors
            # do not cover is byte-equal - otherwise the gap is a delta region
            if (i - j) == (a0 - b0) and (i <= a_end or a[a_end:i] == b[b_end:j]):
                runs[-1] = (a0, b0, i + wh)
                continue
        runs.append((i, j, i + wh))
    runs = [(a0, b0, a_end - a0) for (a0, b0, a_end) in runs]

    runs = _merge_runs(a, b, runs)
    # everything the runs do not cover is a delta region
    deltas = []
    pa = pb = 0
    for (a0, b0, ln) in runs:
        if a0 > pa or b0 > pb:
            deltas.append((pa, pb, a0 - pa, b0 - pb))
        pa, pb = a0 + ln, b0 + ln
    if pa < len(a) or pb < len(b):
        deltas.append((pa, pb, len(a) - pa, len(b) - pb))
    return runs, deltas


def _merge_runs(a, b, runs):
    """Merge runs that are separated by equal bytes in both files (a gap the
    ambiguous-hash filter dropped), verifying the merged range."""
    out = []
    for r in runs:
        if out:
            p = out[-1]
            g = r[0] - (p[0] + p[2])
            gb = r[1] - (p[1] + p[2])
            if 0 < g == gb and a[p[0] + p[2]:r[0]] == b[p[1] + p[2]:r[1]] \
                    and a[p[0]:r[0] + r[2]] == b[p[1]:r[1] + r[2]]:
                out[-1] = (p[0], p[1], (r[0] + r[2]) - p[0])
                continue
        out.append(r)
    return out


def classify(a_len, b_len):
    if a_len == b_len:
        return "modify"          # same size, different bytes
    if b_len > a_len:
        return "insert"          # code added in NEW
    return "delete"              # code removed in NEW


# ── reporting ─────────────────────────────────────────────────────────
def compare(old_path, new_path, segments=None, top=None):
    old = kc_macho.load(old_path)
    new = kc_macho.load(new_path)
    with open(old_path, "rb") as fh:
        A = fh.read()
    with open(new_path, "rb") as fh:
        B = fh.read()

    report = {"old": old_path, "new": new_path,
              "old_uuid": old.uuid.hex() if old.uuid else None,
              "new_uuid": new.uuid.hex() if new.uuid else None,
              "segments": [], "totals": {}}
    tot_id = tot_delta = tot_bytes = 0
    for s in new.segments:
        if not s.filesize or s.name in ("__LINKEDIT",):
            continue
        if segments and s.name not in segments:
            continue
        os_ = old.segment(s.name)
        if os_ is None or os_.filesize != s.filesize:
            report["segments"].append({"segment": s.name, "skipped": "size mismatch"})
            continue
        a = A[s.fileoff:s.fileoff + s.filesize]
        b = B[s.fileoff:s.fileoff + s.filesize]
        runs, deltas = align(a, b)
        deltas = [d for d in deltas if d[2] or d[3]]
        deltas.sort(key=lambda d: -(d[2] + d[3]))
        ident = sum(r[2] for r in runs)
        dbytes = sum(d[2] + d[3] for d in deltas)
        tot_id += ident
        tot_delta += dbytes
        tot_bytes += max(len(a), len(b))
        entry = {
            "segment": s.name,
            "vmsize": s.vmsize,
            "identical_bytes": ident,
            "identical_pct": round(100.0 * ident / max(len(a), 1), 2),
            "delta_regions": len(deltas),
            "delta_bytes": dbytes,
            "kinds": {},
            "deltas": [],
        }
        for (ao, bo, al, bl) in deltas:
            k = classify(al, bl)
            entry["kinds"][k] = entry["kinds"].get(k, 0) + 1
        for (ao, bo, al, bl) in (deltas[:top] if top else deltas):
            entry["deltas"].append({
                "kind": classify(al, bl),
                "old_file_off": ao, "new_file_off": bo,
                "old_va": s.vmaddr + ao, "new_va": s.vmaddr + bo,
                "old_len": al, "new_len": bl,
            })
        report["segments"].append(entry)
    report["totals"] = {
        "identical_bytes": tot_id,
        "delta_bytes": tot_delta,
        "compared_bytes": tot_bytes,
        "identical_pct": round(100.0 * tot_id / max(tot_bytes, 1), 2),
        "naive_byte_diff_pct": None,
    }
    # the number this tool exists to replace: an unaligned byte diff
    n = min(len(A), len(B))
    try:
        import numpy as np
        aa = np.frombuffer(A[:min(len(A), len(B))], dtype=np.uint8)
        bb = np.frombuffer(B[:min(len(A), len(B))], dtype=np.uint8)
        d = int((aa != bb).sum())
    except ImportError:                                   # pragma: no cover
        d = sum(1 for x, y in zip(A[:min(len(A), len(B))], B[:min(len(A), len(B))]) if x != y)
    report["totals"]["naive_byte_diff_pct"] = round(100.0 * d / max(n, 1), 2)
    return report


def render(report, quiet=False):
    out = []
    t = report["totals"]
    out.append("old uuid %s" % report["old_uuid"])
    out.append("new uuid %s" % report["new_uuid"])
    out.append("")
    out.append("%-16s %9s %9s %8s %7s  %s" % (
        "segment", "identB", "deltaB", "ident%", "regions", "kinds"))
    for e in report["segments"]:
        if "skipped" in e:
            out.append("%-16s SKIPPED (%s)" % (e["segment"], e["skipped"]))
            continue
        k = ",".join("%s=%d" % (a, b) for a, b in sorted(e["kinds"].items()))
        out.append("%-16s %9d %9d %7.2f%% %7d  %s" % (
            e["segment"], e["identical_bytes"], e["delta_bytes"],
            e["identical_pct"], e["delta_regions"], k))
    out.append("")
    out.append("aligned identical: %d/%d bytes = %.2f%%" % (
        t["identical_bytes"], t["compared_bytes"], t["identical_pct"]))
    out.append("delta bytes: %d" % t["delta_bytes"])
    out.append("unaligned byte diff (what this replaces): %.2f%%" % t["naive_byte_diff_pct"])
    if not quiet:
        out.append("")
        for e in report["segments"]:
            if "skipped" in e or not e["deltas"]:
                continue
            out.append("== %s: %d delta region(s), largest first" % (
                e["segment"], e["delta_regions"]))
            for d in e["deltas"]:
                out.append("   %-6s old 0x%011x+%-5d new 0x%011x+%-5d  (file 0x%08x/0x%08x)" % (
                    d["kind"], d["old_va"], d["old_len"],
                    d["new_va"], d["new_len"],
                    d["old_file_off"], d["new_file_off"]))
    return "\n".join(out)


# ── selftest ──────────────────────────────────────────────────────────
def selftest():
    import random
    random.seed(1234)
    checks = fails = 0

    def check(cond, what):
        nonlocal checks, fails
        checks += 1
        if not cond:
            fails += 1
            print("FAIL %s" % what)

    # synthetic pair: identical filler + 3 known deltas
    def mk(n):
        return bytearray(random.randrange(256) for _ in range(n))

    body = mk(0x4000)
    a = bytearray(body)
    # (1) insert 16 bytes at 0x1000   (2) modify 8 bytes at 0x2000
    # (3) delete 12 bytes at 0x3000
    b = bytearray(a[:0x1000]) + bytearray(random.randrange(256) for _ in range(16)) + \
        bytearray(a[0x1000:0x2000]) + bytearray(b"\xaa" * 8) + \
        bytearray(a[0x2008:0x3000]) + bytearray(a[0x300c:])
    runs, deltas = align(bytes(a), bytes(b))
    deltas = [d for d in deltas if d[2] or d[3]]
    kinds = sorted(classify(d[2], d[3]) for d in deltas)
    check(kinds == ["delete", "insert", "modify"],
          "3 synthetic edits classified (got %s)" % kinds)
    # every identical run is byte-identical by construction - verify
    for (ao, bo, ln) in runs:
        check(bytes(a[ao:ao + ln]) == bytes(b[bo:bo + ln]), "identical run really identical")
    # tiling: identical runs + deltas cover both files exactly once
    cov_a = sum(r[2] for r in runs) + sum(d[2] for d in deltas)
    cov_b = sum(r[2] for r in runs) + sum(d[3] for d in deltas)
    check(cov_a == len(a) and cov_b == len(b),
          "regions tile both files (a %d/%d, b %d/%d)" % (cov_a, len(a), cov_b, len(b)))
    # a pure shift must NOT be reported as a delta
    c = bytearray(random.randrange(256) for _ in range(0x100)) + bytearray(a)
    runs2, deltas2 = align(bytes(a), bytes(c))
    d2 = [d for d in deltas2 if d[2] or d[3]]
    check(sum(d[2] + d[3] for d in d2) <= 0x100 + 4 * STRIDE,
          "a pure copy-shift is not reported as change (delta %d bytes)" %
          sum(d[2] + d[3] for d in d2))
    # identical files -> zero delta
    runs3, deltas3 = align(bytes(a), bytes(a))
    d3 = [d for d in deltas3 if d[2] or d[3]]
    check(sum(d[2] + d[3] for d in d3) == 0 and not d3, "identical files report nothing")
    print("checks=%d failures=%d" % (checks, fails))
    print("KC_PATCHDIFF_SELFTEST %s" % ("PASS" if fails == 0 else "FAIL"))
    return 0 if fails == 0 else 1


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("old", nargs="?")
    ap.add_argument("new", nargs="?")
    ap.add_argument("--segment", action="append", default=None,
                    help="limit to these segments (repeatable)")
    ap.add_argument("--top", type=int, default=20, help="delta regions printed per segment")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    if not args.old or not args.new:
        ap.print_help()
        return 2
    rep = compare(args.old, args.new, args.segment, args.top)
    if args.json:
        print(json.dumps(rep, indent=2))
    else:
        print(render(rep, args.quiet))
    return 0


if __name__ == "__main__":
    sys.exit(main())
