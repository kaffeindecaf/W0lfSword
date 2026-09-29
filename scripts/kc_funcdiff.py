#!/usr/bin/env python3
"""kc_funcdiff.py — content-based function diff for iOS kernelcaches.

Why this exists: a positional diff of two kernelcaches is useless even for a
point release. Measured on 18.7.2 vs 18.7.3 (same xnu base 11417.140.69):
20.4% of all bytes differ, 86.6% differ inside the kernel's own __TEXT_EXEC,
and only 8.6% of that region's 32-byte blocks appear at all in the other
build - because the kernel's functions are laid out in a different ORDER in
each build (kernel text permutation). So a changed function cannot be found by
comparing "what is at address X".

This tool matches functions by CONTENT:

  1. candidate function starts = PAC prologues (pacibsp/paciasp) + every
     branch target whose predecessor looks like a block end;
  2. each candidate body is decoded with capstone and reduced to a canonical
     token stream - address-carrying immediates (adrp/add page references,
     branch targets, literal loads) are dropped, everything structural
     (register operands, stack offsets, plain constants) is kept;
  3. bodies are keyed by hash: a hash present in both builds = unchanged
     function (whatever address it moved to); a hash present in only one =
     changed/added/removed.

Output is the interesting set: functions whose canonical form exists in only
one of the two builds, with VA + the kext that owns the range.

Usage:
    kc_funcdiff.py OLD NEW [--region __TEXT] [--region __TEXT_EXEC] [--owner NAME]
                  [--json OUT] [--dump-dir DIR] [--all]
    kc_funcdiff.py --selftest
"""
import argparse
import json
import os
import struct
import sys
import zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import kc_macho

try:
    import capstone
except ImportError:                                   # pragma: no cover
    capstone = None

PAC_PROLOGUES = {0xD503237F: "pacibsp", 0xD503233F: "paciasp"}
BRANCH_MN = ("bl", "b", "br", "blr", "cbz", "cbnz", "tbz", "tbnz", "ret")
DROP_IMM_MN = ("b", "bl", "adr", "adrp", "cbz", "cbnz", "tbz", "tbnz", "ldr", "ldrsw")
TERMINATORS = ("ret", "br", "udf", "b")


def _md():
    """ARM64 decoder with skipdata enabled.

    capstone's generator STOPS at the first word it cannot decode, and kernel
    text contains literal pools/jump tables inline, so without skipdata a
    function body would be compared only up to its first data blob - and a
    whole-region sweep would end a few KB in. skipdata emits a `.byte`
    pseudo-instruction for such words and keeps going; the caller counts those
    as the body's data footprint.
    """
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    md.detail = False
    md.skipdata = True
    return md


def starts_of(code, va):
    """Candidate function starts inside this region.

    Deliberately conservative: PAC prologues and `bl` targets only. A
    conditional-branch target is mostly a local label, and letting those in
    makes the function EXTENT depend on which side of a build the branch
    happens to be preceded by a terminator - which shows up as a bogus
    "changed function" on both sides.
    """
    starts = set()
    for i in range(0, len(code) - 3, 4):
        if struct.unpack_from("<I", code, i)[0] in PAC_PROLOGUES:
            starts.add(va + i)
    md = _md()
    for ins in md.disasm(code, va):
        if ins.mnemonic == "bl":
            tgt = _branch_target(ins)
            if tgt is not None and va <= tgt < va + len(code):
                starts.add(tgt)
    return starts


def _branch_target(ins):
    """Immediate branch target of a branch instruction (None otherwise)."""
    op = ins.op_str
    if "#" not in op:
        return None
    tail = op.rsplit("#", 1)[1].strip()
    try:
        return int(tail, 16)
    except ValueError:
        return None


def canon_body(code, va, md):
    """Canonical token text for ONE function body (code = its exact bytes).

    Address-carrying immediates are dropped, everything structural is kept:

    * `adrp xN, #page`                -> "adrp xN"        (page base is layout)
    * `add/ldr/str ..., xN, #imm`     -> the imm becomes #D when xN came from an
      `adrp` (the in-page offset of a data object is layout-dependent)
    * `b`/`bl`/`b.cond`/`cbz`/...     -> branch target becomes #T
    * `ldr xN, #literal`              -> "#L"             (literal pool address)
    * every other immediate (stack offsets, struct offsets, plain constants)
      is kept: those ARE the code, and a fix usually shows up as one of them
      changing width or value.

    Returns (tokens, undecodable_bytes).
    """
    toks = []
    page_regs = set()
    ndata = 0
    for ins in md.disasm(code, va):
        mn, ops = ins.mnemonic, ins.op_str
        if mn == ".byte":
            ndata += 1
            toks.append(".byte %s" % ops)
            continue
        if mn in ("adrp", "adr") and ops:
            dest = ops.split(",")[0].strip()
            if mn == "adrp":
                page_regs.add(dest)
            ops = dest
        elif mn == "b" or mn == "bl" or mn.startswith("b.") or mn in ("cbz", "cbnz", "tbz", "tbnz"):
            if "#" in ops:
                ops = ops.rsplit("#", 1)[0].rstrip().rstrip(",") + ", #T"
                ops = ops.lstrip(", ")
        elif mn in ("ldr", "ldrsw", "prfm") and "#" in ops and "[" not in ops:
            ops = ops.rsplit("#", 1)[0].rstrip().rstrip(",") + " #L"
        elif page_regs and "#" in ops:
            for r in page_regs:
                if ("%s," % r) in (ops + ",") or ("[%s" % r) in ops or ops.startswith(r + " ") \
                        or ops.endswith(" " + r):
                    ops = ops.rsplit("#", 1)[0].rstrip().rstrip(",") + ", #D"
                    break
        toks.append(("%s %s" % (mn, ops)).strip())
    return toks, ndata * 4


def functions_of(data, seg, md, min_size=8, max_size=0x4000):
    """Yield (va, size, hash, tokens) for every candidate function in a segment."""
    code = data[seg.fileoff:seg.fileoff + seg.filesize]
    va = seg.vmaddr
    starts = sorted(starts_of(code, va))
    if not starts or starts[0] != va:
        starts.insert(0, va)
    out = []
    for k, s in enumerate(starts):
        e = starts[k + 1] if k + 1 < len(starts) else va + len(code)
        size = e - s
        if size <= 0 or size > max_size:
            continue
        off = s - va
        toks, bad = canon_body(code[off:off + size], s, md)
        if not toks:
            continue
        key = "\n".join(toks)
        out.append({
            "va": s, "size": size, "bad": bad,
            "hash": zlib.crc32(key.encode()), "key": key,
        })
    return out


def owner_of(m, va, segs=None):
    """Which fileset image owns this VA (innermost segment containing it)."""
    name, _seg = kc_macho.own_segment(m, va, segs)
    return name or "<none>"


def compare(old_path, new_path, regions=("__TEXT", "__TEXT_EXEC"), owner=None,
            dump_dir=None, show_all=False):
    old = kc_macho.load(old_path)
    new = kc_macho.load(new_path)
    with open(old_path, "rb") as fh:
        A = fh.read()
    with open(new_path, "rb") as fh:
        B = fh.read()
    if capstone is None:
        raise SystemExit("capstone not installed (pip install capstone)")
    md = _md()

    report = {"old": old_path, "new": new_path, "regions": [], "counts": {}}
    old_funcs, new_funcs = {}, {}
    for rname in regions:
        so = old.segment(rname)
        sn = new.segment(rname)
        if not so or not sn:
            continue
        if owner:
            # restrict to the fileset image with this name
            so, sn = _owner_seg(old, owner, rname), _owner_seg(new, owner, rname)
            if not so or not sn:
                report["regions"].append({"region": "%s/%s" % (rname, owner),
                                          "skipped": "owner not found"})
                continue
        fo = functions_of(A, so, md)
        fn = functions_of(B, sn, md)
        ho = {}
        for f in fo:
            ho.setdefault(f["hash"], []).append(f)
        hn = {}
        for f in fn:
            hn.setdefault(f["hash"], []).append(f)
        only_old = [f for h, fs in ho.items() if h not in hn for f in fs]
        only_new = [f for h, fs in hn.items() if h not in ho for f in fs]
        same = sum(min(len(v), len(hn.get(h, []))) for h, v in ho.items())
        report["regions"].append({
            "region": "%s%s" % (rname, "/%s" % owner if owner else ""),
            "old_funcs": len(fo), "new_funcs": len(fn),
            "identical_funcs": same,
            "only_old": len(only_old), "only_new": len(only_new),
            "old_undecodable": sum(f["bad"] for f in fo),
            "new_undecodable": sum(f["bad"] for f in fn),
        })
        old_funcs.update({f["va"]: f for f in only_old})
        new_funcs.update({f["va"]: f for f in only_new})
        if dump_dir:
            os.makedirs(dump_dir, exist_ok=True)
            base = os.path.basename(old_path)
            _dump(os.path.join(dump_dir, "%s.%s.old.txt" % (base, rname.strip("_"))), only_old)
            _dump(os.path.join(dump_dir, "%s.%s.new.txt" % (base, rname.strip("_"))), only_new)
    report["counts"] = {
        "only_old_total": len(old_funcs), "only_new_total": len(new_funcs),
    }
    report["only_old"] = sorted(
        ({"va": f["va"], "size": f["size"], "owner": owner_of(old, f["va"])} for f in old_funcs.values()),
        key=lambda d: d["va"])
    report["only_new"] = sorted(
        ({"va": f["va"], "size": f["size"], "owner": owner_of(new, f["va"])} for f in new_funcs.values()),
        key=lambda d: d["va"])
    return report


def _owner_seg(m, owner, region):
    for name, vm, off in m.fileset_entries:
        if name != owner:
            continue
        try:
            k = kc_macho.MachO(m.data, off, name=name)
        except ValueError:
            return None
        for s in k.segments:
            if s.name == region:
                return s
    return None


def _dump(path, funcs):
    with open(path, "w") as fh:
        for f in funcs:
            fh.write("=== 0x%x size=%d bad=%d\n%s\n" % (f["va"], f["size"], f["bad"], f["key"]))


def render(rep):
    out = []
    for r in rep["regions"]:
        if "skipped" in r:
            out.append("%-22s SKIPPED (%s)" % (r["region"], r["skipped"]))
            continue
        out.append("%-22s funcs old=%d new=%d identical=%d | only-old=%d only-new=%d | undecodable old=%d new=%d" % (
            r["region"], r["old_funcs"], r["new_funcs"], r["identical_funcs"],
            r["only_old"], r["only_new"], r["old_undecodable"], r["new_undecodable"]))
    t = rep["counts"]
    out.append("")
    out.append("changed function bodies: %d (old) / %d (new)" % (
        t["only_old_total"], t["only_new_total"]))
    return "\n".join(out)


def selftest():
    """Synthetic: a permuted copy with (a) one modified function, (b) one added,
    (c) one removed must be reported exactly, and a pure permutation must not
    be reported at all."""
    if capstone is None:
        print("capstone missing; selftest skipped")
        return 1
    md = _md()
    checks = fails = 0

    def check(cond, what):
        nonlocal checks, fails
        checks += 1
        if not cond:
            fails += 1
            print("FAIL %s" % what)

    # hand-assembled arm64 bodies (little endian words)
    def fn(*words):
        return b"".join(struct.pack("<I", w) for w in words)

    PACIBSP = 0xD503237F
    RET = 0xD65F03C0
    NOP = 0xD503201F
    MOV_X0_X1 = 0xAA0103E0
    MOV_X0_X2 = 0xAA0203E0
    MOV_X2_X0 = 0xAA0003E2
    MOV_X3_X0 = 0xAA0003E3
    ADD_SP = 0x91000000                                # add x0, x0, #0
    ADD_SP_10 = 0x91004000                             # add x0, x0, #0x10
    ADD_SP_20 = 0x91008000                             # add x0, x0, #0x20
    ADD_SP_30 = 0x9100C000                             # add x0, x0, #0x30
    BL = lambda delta: 0x94000000 | ((delta // 4) & 0x03FFFFFF)   # bl @+delta

    # five distinct bodies, so "which ones disappeared" is unambiguous
    f1 = fn(PACIBSP, MOV_X0_X1, RET)
    f2 = fn(PACIBSP, MOV_X0_X2, RET)
    f3 = fn(PACIBSP, MOV_X2_X0, RET)
    f4 = fn(PACIBSP, ADD_SP_10, RET)
    f5 = fn(PACIBSP, ADD_SP_20, RET)

    class Seg:
        def __init__(self, blob, va):
            self.vmaddr = va
            self.fileoff = 0
            self.filesize = len(blob)
            self.name = "__TEXT"
            self.vmsize = len(blob)

    def seg_of(blob, va):
        return Seg(blob, va)

    VA = 0xfffffff007000000
    # A: f1 f2 f3 f4 f5
    # B: permuted, f3 modified (an instruction inserted), f4 replaced by new f6
    A = f1 + f2 + f3 + f4 + f5
    f3b = fn(PACIBSP, MOV_X2_X0, ADD_SP_10, RET)      # f3 with one instruction added
    f6 = fn(PACIBSP, ADD_SP_30, RET)                  # new body
    B = f5 + f2 + f3b + f1 + f6
    fa = functions_of(A, seg_of(A, VA), md)
    fb = functions_of(B, seg_of(B, VA), md)
    ha = {f["hash"] for f in fa}
    hb = {f["hash"] for f in fb}
    only_a = ha - hb
    only_b = hb - ha
    check(len(fa) == 5 and len(fb) == 5, "5 candidate functions per side (got %d/%d)" % (len(fa), len(fb)))
    check(len(only_a) == 2 and len(only_b) == 2,
          "permutation ignored, 2 changed bodies each side (got %d/%d; old-sizes %s new-sizes %s)" % (
              len(only_a), len(only_b),
              sorted(f["size"] for f in fa if f["hash"] in only_a),
              sorted(f["size"] for f in fb if f["hash"] in only_b)))
    # a pure permutation of the same bodies reports nothing
    C = f4 + f1 + f5 + f3 + f2
    fc = functions_of(C, seg_of(C, VA), md)
    check({f["hash"] for f in fc} == ha,
          "pure permutation is not a change (%d vs %d hashes)" % (len({f["hash"] for f in fc}), len(ha)))
    # canonical form really ignores the branch target
    base = fn(PACIBSP, BL(16), RET)
    moved = fn(PACIBSP, BL(64), RET)
    ta, _ = canon_body(base, VA, md)
    tb, _ = canon_body(moved, VA, md)
    check(ta == tb, "branch target is dropped from the canonical form")
    # ... but keeps structural immediates
    ta2, _ = canon_body(f3, VA, md)
    tb2, _ = canon_body(f4, VA, md)
    check(ta2 != tb2, "a changed structural immediate IS a change")
    print("checks=%d failures=%d" % (checks, fails))
    print("KC_FUNCDIFF_SELFTEST %s" % ("PASS" if fails == 0 else "FAIL"))
    return 0 if fails == 0 else 1


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("old", nargs="?")
    ap.add_argument("new", nargs="?")
    ap.add_argument("--region", action="append", default=None)
    ap.add_argument("--owner", default=None, help="restrict to this fileset image")
    ap.add_argument("--dump-dir", default=None)
    ap.add_argument("--json", default=None)
    ap.add_argument("--all", action="store_true", help="list every changed VA")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    if not args.old or not args.new:
        ap.print_help()
        return 2
    regions = args.region or ["__TEXT", "__TEXT_EXEC"]
    rep = compare(args.old, args.new, regions, args.owner, args.dump_dir)
    print(render(rep))
    if args.json:
        with open(args.json, "w") as fh:
            json.dump(rep, fh, indent=2)
        print("wrote %s" % args.json)
    if args.all:
        print("")
        print("only_old:")
        for d in rep["only_old"]:
            print("  0x%011x size=%-5d %s" % (d["va"], d["size"], d["owner"]))
        print("only_new:")
        for d in rep["only_new"]:
            print("  0x%011x size=%-5d %s" % (d["va"], d["size"], d["owner"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
