#!/usr/bin/env python3
"""kc_macho.py — minimal Mach-O / fileset parser for kernelcache patch-diffing.

Read-only. Parses what a kernelcache Mach-O actually carries (segments,
sections, fileset entries) so a patch-diff can compare per-region bytes
instead of a whole-file byte diff (which is 20% noise on an iOS kernelcache
because every literal pointer and branch displacement is relinked).

No dependencies outside the stdlib.
"""
import struct

MH_MAGIC_64 = 0xFEEDFACF
LC_SEGMENT_64 = 0x19
LC_FILESET_ENTRY = 0x80000035
LC_UUID = 0x1B
LC_SYMTAB = 0x2


class Segment:
    __slots__ = ("name", "vmaddr", "vmsize", "fileoff", "filesize",
                 "maxprot", "initprot", "sections")

    def __repr__(self):
        return "<Seg %s vm=0x%x..0x%x file=0x%x+0x%x>" % (
            self.name, self.vmaddr, self.vmaddr + self.vmsize,
            self.fileoff, self.filesize)


class Section:
    __slots__ = ("name", "segname", "addr", "size", "offset", "align", "flags")

    def __repr__(self):
        return "<Sect %s,%s addr=0x%x size=0x%x off=0x%x>" % (
            self.segname, self.name, self.addr, self.size, self.offset)


class MachO:
    """One Mach-O image inside a (possibly fileset) kernelcache."""

    def __init__(self, data, off=0, name="<root>"):
        self.data = data
        self.off = off
        self.name = name
        self.segments = []
        self.sections = []
        self.fileset_entries = []     # (name, vmaddr, fileoff)
        self.uuid = None
        self.symtab = None
        self._parse(off)

    def _cstr(self, b):
        return b.split(b"\0", 1)[0].decode("utf-8", "replace")

    def _parse(self, off):
        magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, _res = \
            struct.unpack_from("<8I", self.data, off)
        if magic != MH_MAGIC_64:
            raise ValueError("not MH_MAGIC_64 at 0x%x (magic=0x%x)" % (off, magic))
        self.cputype = cputype
        self.filetype = filetype
        p = off + 32
        for _ in range(ncmds):
            cmd, cmdsize = struct.unpack_from("<II", self.data, p)
            if cmd == LC_SEGMENT_64:
                (sname, vmaddr, vmsize, foff, fsize, maxprot, initprot,
                 nsects, _sflags) = struct.unpack_from("<16sQQQQiiII", self.data, p + 8)
                seg = Segment()
                seg.name = self._cstr(sname)
                seg.vmaddr, seg.vmsize = vmaddr, vmsize
                seg.fileoff, seg.filesize = foff, fsize
                seg.maxprot, seg.initprot = maxprot, initprot
                seg.sections = []
                sp = p + 8 + 16 + 8 * 4 + 4 * 4
                for _i in range(nsects):
                    (sectn, segn, addr, size, soff, align, reloff, nreloc,
                     sflags, _r1, _r2, _r3) = struct.unpack_from("<16s16sQQIIIIIIII", self.data, sp)
                    sec = Section()
                    sec.name, sec.segname = self._cstr(sectn), self._cstr(segn)
                    sec.addr, sec.size, sec.offset = addr, size, soff
                    sec.align, sec.flags = align, sflags
                    seg.sections.append(sec)
                    self.sections.append(sec)
                    sp += 80
                self.segments.append(seg)
            elif cmd == LC_FILESET_ENTRY:
                # struct fileset_entry_command { cmd, cmdsize, vmaddr, fileoff,
                #                                union lc_str entry_id, reserved }
                vmaddr, foff = struct.unpack_from("<QQ", self.data, p + 8)
                eid_off = struct.unpack_from("<I", self.data, p + 24)[0]
                ename = self._cstr(self.data[p + eid_off:p + eid_off + 64])
                self.fileset_entries.append((ename, vmaddr, foff))
            elif cmd == LC_UUID:
                self.uuid = self.data[p + 8:p + 24]
            elif cmd == LC_SYMTAB:
                symoff, nsyms, stroff, strsize = struct.unpack_from("<IIII", self.data, p + 8)
                self.symtab = (symoff, nsyms, stroff, strsize)
            p += cmdsize

    # ── helpers ────────────────────────────────────────────────────
    def segment(self, name):
        for s in self.segments:
            if s.name == name:
                return s
        return None

    def code_segments(self):
        """Segments that carry executable bytes, in file order."""
        out = []
        for s in self.segments:
            if s.filesize and (s.maxprot & 0x4):          # VM_PROT_EXECUTE
                out.append(s)
        return out

    def kexts(self):
        """Parse each fileset entry into its own MachO (lazily, on demand)."""
        out = []
        for ename, vmaddr, foff in self.fileset_entries:
            try:
                out.append(MachO(self.data, foff, name=ename))
            except ValueError:
                pass                        # some entries are not Mach-O images
        return out


def load(path):
    with open(path, "rb") as fh:
        return MachO(fh.read(), 0, name=path)


def all_segments(m):
    """[(image_name, Segment)] for the root image plus every fileset entry.

    A kernelcache's root Mach-O only carries a stub __TEXT (the first page); all
    the real segments live in the fileset sub-images. Tools that map a VA to
    bytes (or name a VA's owner) need the whole set.
    """
    out = [(m.name, s) for s in m.segments]
    for ename, _vm, foff in m.fileset_entries:
        try:
            sub = MachO(m.data, foff, name=ename)
        except ValueError:
            continue
        out.extend((ename, s) for s in sub.segments)
    return out


def own_segment(m, va, segs=None):
    """Innermost segment containing va -> (image_name, Segment) or (None, None).

    "Innermost" = smallest filesize, so a kext's own segment beats the main
    image's placeholder container that covers the same VA range.
    """
    best = (None, None)
    for name, s in (segs if segs is not None else all_segments(m)):
        if s.vmaddr <= va < s.vmaddr + s.filesize:
            if best[1] is None or s.filesize < best[1].filesize:
                best = (name, s)
    return best


if __name__ == "__main__":
    import sys
    m = load(sys.argv[1])
    print("%s: cputype=0x%x filetype=0x%x uuid=%s" % (
        m.name, m.cputype, m.filetype,
        m.uuid.hex() if m.uuid else "-"))
    print("%d segments, %d sections, %d fileset entries" % (
        len(m.segments), len(m.sections), len(m.fileset_entries)))
    for s in m.segments:
        print("  %-22s vm=0x%011x size=0x%-9x file=0x%08x size=0x%-9x prot=%d/%d" % (
            s.name, s.vmaddr, s.vmsize, s.fileoff, s.filesize,
            s.initprot, s.maxprot))
