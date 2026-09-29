#!/usr/bin/env python3
"""kc_xref.py — resolve what a function refers to (strings, data, other text).

A kernelcache has no symbol table, so the cheapest way to NAME a function is to
read the data it points at: `adrp x8, #page ; add x8, x8, #off ; bl _strlcpy` is a
string reference, and in XNU that string is usually `__func__`, a panic message,
a sysctl name or a format string. This tool walks the adrp/add (and adrp/ldr)
pairs of a function, computes the target VA, and reads it back.

  kc_xref.py <macho> --at 0xfffffff007f11dc8 --size 644
  kc_xref.py <macho> --json /tmp/changed.json --max 12

Output per function: address, size, and one line per reference:
  +0x1c  str   0xfffffff00a123456  "vnode: iocount overflows"
  +0x40  text  0xfffffff007e12345  (call/data into __TEXT_EXEC)
  +0x58  data  0xfffffff007a12345  (__DATA_CONST+0x12345)
"""
import argparse
import json
import re
import struct
import sys

import capstone

sys.path.insert(0, __file__.rsplit("/", 1)[0])
import kc_macho  # noqa: E402

PRINTABLE = re.compile(rb"^[ -~]{4,}$")
M64 = (1 << 64) - 1          # capstone hands back signed 64-bit values


def _md():
    """ARM64 decoder with skipdata ON.

    Without skipdata, capstone's generator STOPS at the first word it cannot
    decode - and a kernel text segment has literal pools and jump tables in it,
    so a whole-segment sweep would silently end a few KB in and report "no
    reference found" for everything after. With skipdata the sweep emits a
    `.byte` pseudo-instruction for those words and continues.
    """
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    md.detail = True
    md.skipdata = True
    return md


class Image:
    """A kernelcache with VA-accurate reads."""

    def __init__(self, path):
        self.path = path
        self.data = open(path, "rb").read()
        self.root = kc_macho.load(path)
        # The root Mach-O only holds a stub __TEXT; every kernel VA lives in a
        # fileset sub-image segment, so the read map must be the union.
        self.segs = kc_macho.all_segments(self.root)
        self.segments = [s for _n, s in self.segs]

    def read_va(self, va, n=256):
        name, s = kc_macho.own_segment(self.root, va, self.segs)
        if s is None:
            return b"", None
        off = s.fileoff + (va - s.vmaddr)
        return self.data[off:off + n], s

    def describe(self, va):
        name, s = kc_macho.own_segment(self.root, va, self.segs)
        if s is None:
            return "?"
        return "%s:%s+0x%x" % (name, s.name, va - s.vmaddr)

    def cstring_at(self, va, maxlen=200):
        blob, sec = self.read_va(va, maxlen)
        if not blob:
            return None
        end = blob.find(b"\x00")
        if end < 0:
            return None
        s = blob[:end]
        if len(s) < 4 or not PRINTABLE.match(s):
            return None
        try:
            return s.decode("ascii")
        except UnicodeDecodeError:
            return None


def refs_of(code, va, img, max_bytes=None):
    """Resolve adrp/add|ldr pairs into target virtual addresses.

    Register tracking rules that matter for correctness: an `adrp` INVALIDATES
    the derived value of its destination (a stale derived entry from a previous
    adrp/add pair in the same function silently produced wrong targets), and a
    load into a register makes that register a value, not an address.
    """
    md = _md()
    page = {}          # reg -> page VA   (from adrp)
    derived = {}       # reg -> VA        (from add reg, pagereg, #imm)
    out = []
    code = code if max_bytes is None else code[:max_bytes]
    for ins in md.disasm(code, va):
        mn = ins.mnemonic
        if mn == ".byte" or ins.id == 0:
            continue                     # skipdata placeholder: no operands
        try:
            ops = ins.operands
        except capstone.CsError:         # CS_ERR_SKIPDATA
            continue
        if mn == "adrp" and len(ops) >= 2 and ops[0].type == capstone.arm64.ARM64_OP_REG:
            dst = ins.reg_name(ops[0].reg)
            page[dst] = ops[1].imm & M64
            derived.pop(dst, None)
            continue
        if mn in ("add", "sub") and len(ops) >= 3 and ops[0].type == capstone.arm64.ARM64_OP_REG:
            dst = ins.reg_name(ops[0].reg)
            if ops[1].type == capstone.arm64.ARM64_OP_REG and ops[2].type == capstone.arm64.ARM64_OP_IMM:
                src = ins.reg_name(ops[1].reg)
                base = derived.get(src, page.get(src))
                if base is not None:
                    derived[dst] = (base + ops[2].imm) & M64
                    out.append((ins.address - va, "adrp+add", derived[dst]))
            else:
                derived.pop(dst, None)          # reg+reg: value unknown
            continue
        if mn in ("ldr", "ldrb", "ldrh", "adr", "prfm", "str", "strb") and ops:
            # literal form: ldr x0, #imm
            if len(ops) == 2 and ops[1].type == capstone.arm64.ARM64_OP_IMM and ops[0].type == capstone.arm64.ARM64_OP_REG:
                out.append((ins.address - va, "adr/lit", ops[1].imm & M64))
                continue
            if len(ops) >= 2 and ops[1].type == capstone.arm64.ARM64_OP_MEM:
                mem = ops[1].mem
                base = None
                if mem.base != 0:
                    b = ins.reg_name(mem.base)
                    base = derived.get(b, page.get(b))
                if base is not None:
                    out.append((ins.address - va, mn, (base + mem.disp) & M64))
                if mn in ("ldr", "ldrb", "ldrh") and ops[0].type == capstone.arm64.ARM64_OP_REG:
                    dst = ins.reg_name(ops[0].reg)
                    derived.pop(dst, None)      # loaded value, not an address
                    page.pop(dst, None)
    return out


def label(img, va):
    s = img.cstring_at(va)
    if s:
        return "str", '"%s"' % s
    txt, sec = img.read_va(va, 16)
    if sec is not None and sec.name in ("__TEXT_EXEC", "__PPLTEXT", "__PPLTRAMP"):
        return "text", "(code)"
    return "data", img.describe(va)


def find_string_va(img, text):
    """All VAs whose bytes are exactly `text\0`."""
    needle = text.encode() + b"\0"
    out = []
    start = 0
    while True:
        i = img.data.find(needle, start)
        if i < 0:
            break
        start = i + 1
        for name, s in img.segs:                      # file offset -> VA
            if s.fileoff <= i < s.fileoff + s.filesize:
                out.append((s.vmaddr + (i - s.fileoff), name))
                break
    return out


def find_refs(img, target_va, limit=40, only_image=None):
    """Scan executable segments for adrp/add pairs that build target_va.

    `only_image` restricts the scan to one fileset image (e.g. "com.apple.kernel"):
    the kernelcache root declares a __TEXT_EXEC container that covers every
    kext's text, so an unfiltered scan hits the same reference several times and
    takes minutes instead of seconds.
    """
    hits = []
    for name, s in img.segs:
        if not (s.maxprot & 0x4) or not s.filesize:
            continue
        if only_image and name != only_image:
            continue
        blob = img.data[s.fileoff:s.fileoff + s.filesize]
        for off, kind, tgt in refs_of(blob, s.vmaddr, img):
            if tgt == target_va:
                hits.append((s.vmaddr + off, name, kind))
                if len(hits) >= limit:
                    return hits
    return hits


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("macho")
    ap.add_argument("--at", help="hex VA of a function")
    ap.add_argument("--size", type=lambda x: int(x, 0), help="function size in bytes")
    ap.add_argument("--json", help="changed-functions json: print refs for every entry")
    ap.add_argument("--side", default="only_old", choices=["only_old", "only_new"])
    ap.add_argument("--max", type=int, default=-1, help="max functions from --json")
    ap.add_argument("--strings-only", action="store_true")
    ap.add_argument("--find-string", help="locate this C string and print code refs to it")
    ap.add_argument("--window", type=int, default=0x60, help="bytes of disasm around each ref")
    ap.add_argument("--mark-va", help="annotate a disasm window at this hex VA")
    ap.add_argument("--seg", help="restrict scans to this fileset image name")
    ap.add_argument("--disasm", action="store_true",
                    help="print the disassembly of --at/--size with data labels")
    a = ap.parse_args()
    img = Image(a.macho)

    if a.find_string:
        vas = find_string_va(img, a.find_string)
        print("string %r -> %d location(s)" % (a.find_string, len(vas)))
        for va, name in vas:
            print("\n  VA 0x%x  in %s" % (va, name))
            refs = find_refs(img, va, only_image=a.seg)
            if not refs:
                print("    (no adrp+add reference in executable segments)")
                continue
            for radr, rname, kind in refs:
                lo, hi = radr - a.window, radr + a.window
                print("    ref at 0x%x (%s, %s), window:" % (radr, rname, kind))
                start = max(s_.vmaddr for _n, s_ in img.segs
                            if s_.vmaddr <= lo < s_.vmaddr + s_.filesize)
                blob, _s = img.read_va(start, hi - start)
                md2 = _md()
                for ins in md2.disasm(blob, start):
                    if lo <= ins.address <= hi:
                        mark = "  <<<" if ins.address == radr else ("  ***" if ins.address == int(a.mark_va, 16) else "") if a.mark_va else ""
                        print("      0x%x  %-8s %s%s" % (ins.address, ins.mnemonic, ins.op_str, mark))
        return

    if a.disasm:
        va = int(a.at, 16)
        blob, _s = img.read_va(va, a.size or 0x400)
        labels = {}
        for off, _kind, tgt in refs_of(blob, va, img):
            labels.setdefault(va + off, []).append(tgt)
        md2 = _md()
        print("=== disasm 0x%x size=%d  %s" % (va, len(blob), img.describe(va)))
        for ins in md2.disasm(blob, va):
            note = ""
            for tgt in labels.get(ins.address, []):
                k, text = label(img, tgt)
                note += "   ; 0x%x %s" % (tgt, text)
            print("  0x%011x  %-10s %-34s%s" % (ins.address, ins.mnemonic, ins.op_str, note))
        return

    jobs = []
    if a.json:
        d = json.load(open(a.json))
        for e in d.get(a.side, [])[:a.max if a.max >= 0 else None]:
            jobs.append((e["va"], e.get("size", 0x400)))
    else:
        jobs.append((int(a.at, 16), a.size or 0x400))

    for va, size in jobs:
        blob, sec = img.read_va(va, size)
        print("\n=== 0x%x  size=%d  %s" % (va, size, img.describe(va)))
        seen = set()
        for off, kind, tgt in refs_of(blob, va, img):
            if tgt in seen:
                continue
            seen.add(tgt)
            k, text = label(img, tgt)
            if a.strings_only and k != "str":
                continue
            print("   +0x%-6x %-8s 0x%011x  %s" % (off, kind, tgt, text))


if __name__ == "__main__":
    main()
