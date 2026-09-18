#!/usr/bin/env python3
"""kc_zone_fields.py - read the `struct zone` field offsets off a kernelcache.

Why: BUG.7 (ROADMAP 0.13) wants the kalloc BUCKET size of an object instead of
the field span this tree can derive from its own offsets table, i.e. the zone's
`z_elem_size` reached through inpcbinfo.ipi_zone. That needs one more offset this
tree did not have (offsetof(struct zone, z_elem_size)), and offsets.m's rule is
that a new offset is *kernelcache-verified* or it does not ship - inventing one
is the class of guess that panicked the SE (SG.8/SG.9).

How: XNU's own zone bound check prints the violation, and the value it prints as
the object's size IS z_elem_size:

    zone bound checks: buffer %p of length %zd overflows object %p of size %zd
    in zone %p[%s%s] @%s:%d

So the function that builds that message reads the field. This tool finds that
function in a kernelcache, finds the zone pointer register, and reports every
zone-relative load in the window - the field offsets fall out of it:

    +0x10  64-bit   z_name         (the [%s] argument; also offsets.m's
                                    off_kalloc_type_view_kt_zv_zv_name = 0x10)
    +0x28  32-bit   z_quo_magic    (the multiply magic of Z_FAST_MOD)
    +0x34  16-bit   z_elem_size    <- the value printed as "of size %zd"
    +0x36  16-bit   z_elem_offs
    +0x3c   8-bit   flags, bit 6 = z_percpu ("is a per-cpu allocation")

Cross-checked against XNU source (osfmk/kern/zalloc_internal.h, `struct zone`)
from two public tags that bracket the builds: xnu-12377.41.6 (iOS 26.1 era) and
xnu-11417.101.15 (iOS 18.x era). Both define the same layout; this tool is what
proves the shipped binaries have it too.

Usage:
    python3 scripts/kc_zone_fields.py <kernelcache-or-macho> [--json] [--quiet]

Input is either a raw Mach-O (an xpf-cli decompression output) or an IMG4
kernelcache - the latter is decompressed through tools/xpf-cli when it is
present. Host-only: reads a file, runs no device command.
"""
import json
import os
import re
import struct
import subprocess
import sys
import tempfile

try:
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
except ImportError:                                        # pragma: no cover
    print("this tool needs capstone: pip install capstone", file=sys.stderr)
    sys.exit(2)

MAGIC64 = 0xfeedfacf
LC_SEGMENT_64 = 0x19
VM_PROT_EXECUTE = 4

# The two strings the bound check emits; the big one carries the size argument.
STR_MAIN = b"zone bound checks: buffer %p of length %zd overflows object"
STR_PCPU = b"zone bound checks: address %p is a per-cpu allocation"
STR_FILE = b"zalloc.c"

# What struct zone says these fields are (see the module docstring). The tool
# asserts the binary agrees; a mismatch is a FAIL, never a silent pass.
EXPECTED = {
    "z_name": (0x10, 64),
    "z_quo_magic": (0x28, 32),
    "z_elem_size": (0x34, 16),
    "z_elem_offs": (0x36, 16),
    "z_flags": (0x3c, 8),
}


# --------------------------------------------------------------------------
# Mach-O
# --------------------------------------------------------------------------
def parse_macho(path):
    with open(path, "rb") as fh:
        d = fh.read()
    magic = struct.unpack_from("<I", d, 0)[0]
    if magic != MAGIC64:
        raise ValueError("not a 64-bit Mach-O (magic %#x)" % magic)
    ncmds = struct.unpack_from("<I", d, 16)[0]
    off = 32
    segs = []
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<2I", d, off)
        if cmd == LC_SEGMENT_64:
            name = d[off + 8:off + 24].split(b"\0")[0].decode()
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<4Q", d, off + 24)
            _maxprot, initprot, nsects, _flags = struct.unpack_from("<4I", d, off + 56)
            sects = []
            so = off + 72
            for _i in range(nsects):
                sname = d[so:so + 16].split(b"\0")[0].decode()
                addr, size = struct.unpack_from("<2Q", d, so + 32)
                offset, _align, _reloff, _nreloc, flags = struct.unpack_from("<5I", d, so + 48)
                sects.append({"name": sname, "addr": addr, "size": size,
                              "off": offset, "flags": flags})
                so += 80
            segs.append({"name": name, "vmaddr": vmaddr, "vmsize": vmsize,
                         "off": fileoff, "size": filesize, "prot": initprot,
                         "sects": sects})
        off += cmdsize
    return d, segs


def exec_ranges(segs):
    """Every byte range that can hold code, sections or not.

    iOS 26 kernelcaches put most code in a section-less __TEXT_EXEC segment, so
    a section-only walk finds a fraction of the kernel.
    """
    out = []
    for seg in segs:
        if not seg["prot"] & VM_PROT_EXECUTE:
            continue
        pure = [s for s in seg["sects"] if s["flags"] & 0x80000000]
        if pure:
            for s in pure:
                out.append((seg["name"] + "/" + s["name"], s["addr"], s["size"], s["off"]))
        else:
            out.append((seg["name"] + "/<nosect>", seg["vmaddr"], seg["size"], seg["off"]))
    return out


def find_vaddrs(d, segs, needle):
    out = []
    start = 0
    while True:
        i = d.find(needle, start)
        if i == -1:
            return out
        for seg in segs:
            if seg["off"] <= i < seg["off"] + seg["size"]:
                out.append(seg["vmaddr"] + (i - seg["off"]))
                break
        start = i + 1


def refs_to(d, ranges, target):
    """adrp+add sites whose computed address is `target`."""
    out = []
    for name, base, size, off in ranges:
        prev = None
        for i in range(size // 4):
            o = off + i * 4
            if o + 4 > len(d):
                break
            insn = struct.unpack_from("<I", d, o)[0]
            va = base + i * 4
            if (insn & 0x9f000000) == 0x90000000:            # ADRP
                immlo = (insn >> 29) & 3
                immhi = (insn >> 5) & 0x7ffff
                imm = (immhi << 2) | immlo
                if imm & (1 << 20):
                    imm -= 1 << 21
                prev = (va, insn & 0x1f, (va & ~0xfff) + (imm << 12))
                continue
            if prev is not None and (insn & 0x7f800000) == 0x11000000:
                if ((insn >> 5) & 0x1f) == prev[1]:
                    imm12 = (insn >> 10) & 0xfff
                    if (insn >> 22) & 1:
                        imm12 <<= 12
                    if prev[2] + imm12 == target:
                        out.append((prev[0], va))
            prev = None
    return out


# --------------------------------------------------------------------------
# the bound-check window
# --------------------------------------------------------------------------
def decode_ldst(insn):
    """Return (width_in_bits, is_load, rt, rn, imm) for unsigned-offset LDR/STR, else None."""
    if (insn & 0x3b000000) != 0x39000000:
        return None
    size = (insn >> 30) & 3
    v = (insn >> 26) & 1
    if v:
        return None
    width = 8 << size                                       # 8/16/32/64 bits
    load = (insn >> 22) & 1
    rt = insn & 0x1f
    rn = (insn >> 5) & 0x1f
    imm = ((insn >> 10) & 0xfff) << size
    return (width, bool(load), rt, rn, imm)


def reg_num(operand):
    """'x23' / 'w23' -> 23, else None."""
    operand = operand.strip().rstrip(",")
    if len(operand) < 2 or operand[0] not in "wx" or not operand[1:].isdigit():
        return None
    return int(operand[1:])


def score_zone_registers(md, code_bytes, base):
    """Find the zone pointer by scoring candidate base registers.

    The window holds the bound-check routine, which reads several fields of one
    struct zone. Which register holds it is not fixed from build to build (17.0
    reads the flags word through a scratch register and only later recomputes
    the zone into x21), so score every base register by how many of the five
    `struct zone` fields it reads at the expected offset and width, and take the
    best. Requiring four of five makes this identify the struct, not a
    coincidence: an unrelated pointer would have to hit four exact
    offset+width pairs.

    Returns (best_reg, hits, all_loads) where hits is {field: load}.
    """
    loads = []
    for insn in md.disasm(code_bytes, base):
        dec = decode_ldst(int.from_bytes(insn.bytes, "little"))
        if dec is None:
            continue
        width, is_load, rt, rn, imm = dec
        if not is_load:
            continue
        loads.append({"reg": rn, "off": imm, "width": width, "rt": rt,
                      "at": "0x%x" % insn.address,
                      "asm": "%s %s" % (insn.mnemonic, insn.op_str)})

    best_reg, best_hits = None, {}
    for reg in sorted({l["reg"] for l in loads}):
        hits = {}
        for field, (off, width) in EXPECTED.items():
            for l in loads:
                if l["reg"] == reg and l["off"] == off and l["width"] == width and field not in hits:
                    hits[field] = l
        if len(hits) > len(best_hits):
            best_reg, best_hits = reg, hits
    return best_reg, best_hits, loads


def find_flags_anchor(md, code_bytes, base):
    """Find the `ldrb wT, [X, #0x3c]` whose value feeds `tbnz wT, #5/#6`.

    That branch is the per-cpu path of the bound check, so the byte read at 0x3c
    IS the flags word and bit 5/6 IS z_percpu (bit 5 on the 17.0-era build, bit 6
    from 18.x on: xnu-10002.1.13 has five lifecycle bits before z_percpu, later
    XNU gained z_exhausts in front of it). The flags OFFSET is 0x3c in both eras.

    The register holding the zone here can be a scratch register that later gets
    recomputed (17.0 does exactly that), which is why this is a separate lookup
    rather than part of the per-register scoring.

    Returns (load, bit) or (None, None).
    """
    insns = list(md.disasm(code_bytes, base))
    for insn in insns:
        m = re.match(r"w(\d+), #([0-9]+)", insn.op_str)
        if insn.mnemonic != "tbnz" or not m or m.group(2) not in ("5", "6"):
            continue
        want = int(m.group(1))
        for prev in reversed(insns):
            if prev.address >= insn.address:
                continue
            mm = re.match(r"w%d, \[(x\d+)(?:, #(0x[0-9a-f]+))?\]" % want, prev.op_str)
            if not mm or prev.mnemonic != "ldrb":
                continue
            if mm.group(2) is not None and int(mm.group(2), 16) == EXPECTED["z_flags"][0]:
                return ({"reg": reg_num(mm.group(1)), "off": EXPECTED["z_flags"][0],
                         "width": 8, "at": "0x%x" % prev.address,
                         "asm": "%s %s" % (prev.mnemonic, prev.op_str)}, int(m.group(2)))
    return (None, None)


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    flags = {a for a in sys.argv[1:] if a.startswith("--")}
    if not args:
        print(__doc__)
        return 2

    path = args[0]
    workdir = None
    try:
        d, segs = parse_macho(path)
    except ValueError:
        # IMG4 kernelcache: decompress with the repo's xpf-cli
        cli = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "..", "tools", "xpf-cli", "xpf-cli")
        if not os.path.exists(cli):
            print("input is not a Mach-O and tools/xpf-cli/xpf-cli is missing", file=sys.stderr)
            return 2
        workdir = tempfile.mkdtemp(prefix="kc_zone_fields_")
        raw = os.path.join(workdir, "kernel.macho")
        subprocess.run([cli, path, raw], check=True, capture_output=True)
        d, segs = parse_macho(raw)

    ranges = exec_ranges(segs)
    main_vas = find_vaddrs(d, segs, STR_MAIN)
    pcpu_vas = find_vaddrs(d, segs, STR_PCPU)
    if not main_vas or not pcpu_vas:
        print("FAIL: the zone bound-check strings are not in this kernelcache", file=sys.stderr)
        return 1

    main_refs = [r for va in main_vas for r in refs_to(d, ranges, va)]
    pcpu_refs = [r for va in pcpu_vas for r in refs_to(d, ranges, va)]
    if not main_refs or not pcpu_refs:
        print("FAIL: no code reference to the bound-check messages", file=sys.stderr)
        return 1

    pcpu_ref = pcpu_refs[0][0]
    main_ref = main_refs[0][0]
    window_lo = min(pcpu_ref, main_ref) - 0x180
    window_hi = max(pcpu_ref, main_ref) + 0x40

    def read_at(va, size):
        for seg in segs:
            if seg["vmaddr"] <= va < seg["vmaddr"] + seg["size"]:
                o = seg["off"] + (va - seg["vmaddr"])
                return d[o:o + size]
        return None

    buf = b"".join(filter(None, [read_at(va, 4) for va in range(window_lo, window_hi, 4)]))
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    zone_reg, hits, loads = score_zone_registers(md, buf, window_lo)
    if zone_reg is None or len(hits) < 3:
        print("FAIL: no base register in the bound-check window reads the struct zone fields "
              "(best: %s, %d/5)"
              % (("x%d" % zone_reg) if zone_reg is not None else "none", len(hits)),
              file=sys.stderr)
        return 1

    size_load = hits.get("z_elem_size")
    size_arg_reg = size_load["rt"] if size_load else None

    # the size argument must reach the panic call: the register that took the
    # 16-bit load at +0x34 is stored to the stack in the same window
    passed = False
    if size_arg_reg is not None:
        for insn in md.disasm(buf, window_lo):
            if insn.mnemonic in ("stp", "str") and "[sp" in insn.op_str:
                if reg_num(insn.op_str.split(",")[0]) == size_arg_reg:
                    passed = True
                    break

    flags_load, percpu_bit = find_flags_anchor(md, buf, window_lo)
    hit_flags = hits.get("z_flags")
    if hit_flags is None and flags_load is not None:
        # the 17.0-era build reads the flags word through a scratch register; the
        # anchor is the evidence for that field either way
        hits["z_flags"] = flags_load
        hit_flags = flags_load

    zone_loads = [l for l in loads if l["reg"] == zone_reg]
    result = {
        "kernelcache": os.path.abspath(path),
        "zone_register": "x%d" % zone_reg,
        "window": ["0x%x" % window_lo, "0x%x" % window_hi],
        "loads": [{k: (hex(v) if k == "off" else v) for k, v in l.items() if k in
                   ("at", "off", "width", "asm")} for l in zone_loads],
        "fields": {},
        "checks": {},
    }
    ok = True
    for field, (off, width) in EXPECTED.items():
        hit = hits.get(field)
        good = bool(hit) and hit["width"] == width
        result["fields"]["off_zone_%s" % field[2:]] = {
            "offset": hex(off), "width": width,
            "found": "yes" if hit else "no",
            "asm": hit["asm"] if hit else None,
            "ok": good,
        }
        if not good:
            ok = False
    result["checks"]["elem_size_is_the_panic_size_argument"] = passed
    result["checks"]["z_percpu_branch_corroborates_the_flags_offset"] = flags_load is not None
    result["checks"]["zone_fields_match_struct_zone"] = ok
    result["off_zone_elem_size"] = EXPECTED["z_elem_size"][0]

    if "--json" in flags:
        print(json.dumps(result, indent=2))
    else:
        print("kernelcache: %s" % result["kernelcache"])
        print("bound-check window: %s..%s   zone pointer register: %s"
              % (result["window"][0], result["window"][1], result["zone_register"]))
        print("zone-relative loads seen (offset, width, instruction):")
        for l in zone_loads:
            print("   %-8s %2d-bit  %-44s @%s" % (hex(l["off"]), l["width"], l["asm"], l["at"]))
        print()
        print("derived fields:")
        for name, info in result["fields"].items():
            print("   %-22s %-7s %2d-bit  %s  %s" % (
                name, info["offset"], info["width"],
                "OK " if info["ok"] else "BAD", info["asm"] or "not found"))
        print("   off_zone_elem_size = %s" % hex(result["off_zone_elem_size"]))
        print()
        print("checks: elem_size reaches the panic as the size argument: %s"
              % ("yes" if passed else "NO"))
        print("        the flags byte feeds the z_percpu branch:        %s"
              % ("yes (bit %d)" % percpu_bit if flags_load else "NO"))
        print("        all five fields match struct zone:                %s"
              % ("yes" if ok else "NO"))
        print("%s: zone fields%s" % ("ZONE_FIELDS_OK" if (ok and passed) else "ZONE_FIELDS_FAIL",
                                     "" if (ok and passed) else " - do not pin this offset from here"))

    if workdir:
        try:
            os.unlink(os.path.join(workdir, "kernel.macho"))
            os.rmdir(workdir)
        except OSError:
            pass
    return 0 if (ok and passed) else 1


if __name__ == "__main__":
    sys.exit(main())
