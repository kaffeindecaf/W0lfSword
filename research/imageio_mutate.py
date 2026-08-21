#!/usr/bin/env python3
"""
imageio_mutate.py — deterministic ImageIO fuzz-sample generator (K4.2 / K4.8).

Parses DNG/TIFF and JPEG structure (validated, unlike the reference analyzer
which walks garbage as IFDs) and emits a corpus of mutated samples plus a TSV
manifest so every crash is attributable to a mutation recipe.

Strategies:
  dng     — structure-aware mutations of a DNG/TIFF: SamplesPerPixel tag,
            SOF3 (JPEG Lossless) component count / dimensions / precision,
            compression tag, and the CVE-2025-43300 combined mismatch.
  jpeg    — structure-aware mutations targeting the AppleJPEG decode surface
            (CVE-2025-43539 class): SOF precision/dims/components/sampling,
            DQT precision + table ids, DHT class, SOS component/spectral
            fields, APP1 EXIF IFD tags, scan-data desync/truncation, APPn
            declared-length inflation.
  generic — byte flips at deterministic offsets + truncation variants
            (for HEIF/TIFF/anything without parseable structure).
  all     — auto-detect per seed by magic (FFD8 -> jpeg, II*/MM* -> dng).

Usage:
  imageio_mutate.py <seed> <outdir> [--count N] [--strategy dng|jpeg|generic|all]
                    [--random-seed S] [--manifest file.tsv]

Exit: 0 on success. Writes <outdir>/<stem>_m*.ext files + manifest rows:
  sha256<TAB>filename<TAB>strategy<TAB>offset<TAB>old_hex<TAB>new_hex<TAB>desc
"""

import argparse
import hashlib
import random
import struct
import sys
from pathlib import Path

# ── TIFF tags we care about ──────────────────────────────────────
TAG_SAMPLES_PER_PIXEL = 0x0115
TAG_IMAGE_WIDTH = 0x0100
TAG_IMAGE_LENGTH = 0x0101
TAG_COMPRESSION = 0x0103
TAG_SUBIFD = 0x014A

SOF3 = b"\xff\xc3"


class DNGStructure:
    """Validated, minimal DNG/TIFF structural parse."""

    def __init__(self, data: bytes):
        self.data = data
        self.endian: str = ""
        self.tiff_offset: int = 0
        self.samples_per_pixel = []   # [(abs_offset_of_value, value)]
        self.width_height = []        # [(w_offset, h_offset, w, h)]
        self.compression = []         # [(abs_offset, value)]
        self.sof3 = []                # dicts: offset, comp_off, w_off, h_off,
                                      #        prec_off, precision, w, h, components
        self.parsed = False

    def _u16(self, off):
        return struct.unpack_from(self.endian + "H", self.data, off)[0]

    def _u32(self, off):
        return struct.unpack_from(self.endian + "I", self.data, off)[0]

    def _in_bounds(self, off, size):
        return 0 <= off and off + size <= len(self.data)

    def _val_byte(self, pos, typ):
        """Absolute offset of the LOW byte of an inline tag value field
        (endian-aware — flipping the low byte gives the fine-grained delta)."""
        if self.endian == "<":
            return pos + 8
        return pos + 8 + {3: 1, 4: 3}.get(typ, 0)

    def find_tiff(self):
        for pos in (self.data.find(b"II\x2a\x00"), self.data.find(b"MM\x00\x2a")):
            if pos != -1:
                self.tiff_offset = pos
                self.endian = "<" if self.data[pos:pos + 2] == b"II" else ">"
                return True
        return False

    def walk_ifd(self, ifd_off: int):
        """Walk one IFD (and its SubIFDs). Validates everything."""
        if ifd_off is None:
            return
        abs_off = self.tiff_offset + ifd_off
        if not self._in_bounds(abs_off, 2):
            return
        count = self._u16(abs_off)
        if count == 0 or count > 1024:          # validate: sane entry count
            return
        if not self._in_bounds(abs_off + 2, count * 12 + 4):
            return
        pos = abs_off + 2
        for _ in range(count):
            tag, typ, cnt, val = struct.unpack_from(
                self.endian + "HHII", self.data, pos)
            if tag == TAG_SAMPLES_PER_PIXEL and typ == 3 and cnt == 1:
                self.samples_per_pixel.append((self._val_byte(pos, typ), val & 0xFFFF))
            elif tag == TAG_IMAGE_WIDTH and typ in (3, 4) and cnt == 1:
                self.width_height.append((self._val_byte(pos, typ), None, val & 0xFFFF, None))
            elif tag == TAG_IMAGE_LENGTH and typ in (3, 4) and cnt == 1:
                self.width_height.append((None, self._val_byte(pos, typ), None, val & 0xFFFF))
            elif tag == TAG_COMPRESSION and typ == 3 and cnt == 1:
                self.compression.append((self._val_byte(pos, typ), val & 0xFFFF))
            elif tag == TAG_SUBIFD:
                # value is an offset to an array of offsets
                sub_off = val
                if self._in_bounds(self.tiff_offset + sub_off, 4):
                    target = self._u32(self.tiff_offset + sub_off)
                    self.walk_ifd(target)
            pos += 12

    def find_sof3(self):
        pos = 0
        while True:
            pos = self.data.find(SOF3, pos)
            if pos == -1:
                break
            # Validate segment: len>=8, plausible precision/dims/components
            if pos + 10 <= len(self.data):
                seg_len = struct.unpack_from(">H", self.data, pos + 2)[0]
                precision = self.data[pos + 4]
                h = struct.unpack_from(">H", self.data, pos + 5)[0]
                w = struct.unpack_from(">H", self.data, pos + 7)[0]
                comps = self.data[pos + 9]
                if (seg_len >= 8 and 2 <= precision <= 16
                        and 0 < w < 65536 and 0 < h < 65536 and 1 <= comps <= 4):
                    self.sof3.append({
                        "offset": pos,
                        "comp_off": pos + 9,
                        "w_off": pos + 7,
                        "h_off": pos + 5,
                        "prec_off": pos + 4,
                        "precision": precision,
                        "w": w, "h": h, "components": comps,
                    })
            pos += 1

    def parse(self):
        if not self.find_tiff():
            return False
        first_ifd = self._u32(self.tiff_offset + 4)
        self.walk_ifd(first_ifd)
        self.find_sof3()
        self.parsed = True
        return True


def sha256hex(b):
    return hashlib.sha256(b).hexdigest()


class JPEGInfo:
    """Validated JPEG marker scan. Skips stuffed 0x00 and RST markers so
    entropy-coded scan data never produces false segment parses."""

    SOF_CODES = (0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF)

    def __init__(self, data: bytes):
        self.data = data
        self.markers = []    # (code_offset, code, payload_offset, payload_len)
        self.sof = []        # dicts: off, precision, h_off, w_off, h, w, ncomp, ncomp_off, comp_offsets
        self.dqt = []        # (payload_off, precision, table_id)
        self.dht = []        # payload offsets
        self.sos = []        # dicts: off, ncomp, ncomp_off, spectral_off, approx_off
        self.scan_start = None
        self.scan_end = None
        self.app1_exif = None  # (absolute_exif_base, length)

    def parse(self):
        d = self.data
        n = len(d)
        if n < 4 or d[0:2] != b"\xff\xd8":
            return False
        i = 2
        while i < n - 1:
            if d[i] != 0xFF:
                i += 1
                continue
            j = i
            while j < n and d[j] == 0xFF:
                j += 1
            if j >= n:
                break
            code = d[j]
            if code == 0x00 or 0xD0 <= code <= 0xD7:
                i = j + 1
                continue
            if code == 0xD9:  # EOI
                if self.sos and self.scan_end is None:
                    self.scan_end = j
                break
            if code == 0x01 or code == 0xD8:
                i = j + 1
                continue
            if j + 2 > n:
                break
            seg_len = struct.unpack_from(">H", d, j + 1)[0]
            if seg_len < 2 or j + 1 + seg_len > n:
                break
            payload = j + 3
            self.markers.append((j, code, payload, seg_len - 2))
            if code in self.SOF_CODES and seg_len >= 8:
                p = payload
                ncomp = d[p + 5]
                self.sof.append({
                    "off": p,
                    "precision": d[p],
                    "h_off": p + 1,
                    "w_off": p + 3,
                    "h": struct.unpack_from(">H", d, p + 1)[0],
                    "w": struct.unpack_from(">H", d, p + 3)[0],
                    "ncomp": ncomp,
                    "ncomp_off": p + 5,
                    "comp_offsets": [(p + 7 + 3 * k, p + 8 + 3 * k, p + 9 + 3 * k)
                                     for k in range(min(ncomp, 10))],
                })
            elif code == 0xDB and seg_len >= 2:  # DQT
                self.dqt.append((payload, (d[payload] >> 4) & 1, d[payload] & 0x0F))
            elif code == 0xC4 and seg_len >= 2:  # DHT
                self.dht.append(payload)
            elif code == 0xDA and seg_len >= 2:  # SOS
                ncomp = d[payload]
                self.sos.append({
                    "off": payload,
                    "ncomp": ncomp,
                    "ncomp_off": payload,
                    "spectral_off": payload + 1 + 2 * ncomp,
                    "approx_off": payload + 2 + 2 * ncomp,
                })
                self.scan_start = j + 1 + seg_len
            elif code == 0xE1 and seg_len > 8:  # APP1 EXIF
                if d[payload:payload + 6] == b"Exif\x00\x00":
                    self.app1_exif = (payload + 6, seg_len - 8)
            i = j + 1 + seg_len
        return bool(self.sof or self.dqt or self.sos or self.app1_exif)


class Mutator:
    def __init__(self, seed_path: Path, outdir: Path, rng: random.Random):
        self.seed_path = seed_path
        self.data = bytearray(seed_path.read_bytes())
        self.outdir = outdir
        self.rng = rng
        self.stem = seed_path.stem
        self.ext = seed_path.suffix or ".bin"
        self.index = 0

    def _write(self, data, strategy, off, old, new, desc):
        self.index += 1
        fname = f"{self.stem}_m{self.index:02d}_{strategy}{self.ext}"
        path = self.outdir / fname
        path.write_bytes(data)
        row = "\t".join([
            sha256hex(bytes(data)), fname, strategy,
            f"0x{off:X}" if off is not None else "-",
            f"0x{old:02X}" if old is not None else "-",
            f"0x{new:02X}" if new is not None else "-",
            desc,
        ])
        return row

    def _flip(self, data, off, new_val):
        old = data[off]
        data[off] = new_val & 0xFF
        return old

    # ── DNG structure-aware recipes ───────────────────────────────
    def mutate_dng(self, s: DNGStructure):
        rows = []
        # The CVE-2025-43300 class: metadata/stream component mismatch.
        # Prefer the *real* SPP (largest plausible value is usually the
        # full-res one; take the first 1..8 value).
        spp = next(((off, v) for off, v in s.samples_per_pixel if 1 <= v <= 8), None)

        # SamplesPerPixel mutations — independent of SOF3 presence
        if spp:
            off, v = spp
            # known trigger shape: bump metadata up
            for target in (1, 2, v + 1, v - 1):
                if target != v and 1 <= target <= 8:
                    d = bytearray(self.data)
                    old = self._flip(d, off, target)
                    rows.append(self._write(
                        d, "dng", off, old, target, f"SamplesPerPixel {v}->{target}"))

        for sof3 in s.sof3:
            if sof3["components"] < 1 or sof3["components"] > 4:
                continue

            if spp and 1 <= spp[1] <= 8 and spp[1] != sof3["components"]:
                # known trigger: bump metadata up, drop stream count
                off, v = spp
                for target in (v + 1, sof3["components"]):
                    if target != v and 1 <= target <= 8:
                        d = bytearray(self.data)
                        self._flip(d, off, target)
                        rows.append(self._write(
                            d, "dng", off, v, target,
                            f"CVE-43300 SPP {v}->{target} vs SOF3 {sof3['components']}"))

            # SOF3 component count
            c_off, c = sof3["comp_off"], sof3["components"]
            for target in (c - 1, c + 1):
                if target != c and 1 <= target <= 4:
                    d = bytearray(self.data)
                    old = self._flip(d, c_off, target)
                    rows.append(self._write(
                        d, "dng", c_off, old, target, f"SOF3 components {c}->{target}"))

            # dimensions
            for label, off, val in (("w", sof3["w_off"], sof3["w"]),
                                    ("h", sof3["h_off"], sof3["h"])):
                for target in (1, 0xFFFF):
                    if target != val:
                        d = bytearray(self.data)
                        old = self._flip(d, off, target)
                        rows.append(self._write(
                            d, "dng", off, old, target, f"SOF3 {label} {val}->{target}"))
                # swap w/h
                d = bytearray(self.data)
                self._flip(d, sof3["w_off"], sof3["h"])
                self._flip(d, sof3["h_off"], sof3["w"])
                rows.append(self._write(
                    d, "dng", sof3["w_off"], sof3["w"], sof3["h"],
                    f"SOF3 w/h swapped ({sof3['w']}x{sof3['h']})"))

            # precision
            p_off, p = sof3["prec_off"], sof3["precision"]
            for target in (8, 16):
                if target != p:
                    d = bytearray(self.data)
                    old = self._flip(d, p_off, target)
                    rows.append(self._write(
                        d, "dng", p_off, old, target, f"SOF3 precision {p}->{target}"))

        # compression tag flips
        for off, v in s.compression:
            for target in (7, 34892, 1):
                if target != v and target <= 0xFFFF:
                    d = bytearray(self.data)
                    old = self._flip(d, off, target)
                    rows.append(self._write(
                        d, "dng", off, old, target, f"compression {v}->{target}"))

        # width/height tag flips
        for w_off, h_off, w, h in s.width_height:
            if w_off is not None and w and w > 1:
                d = bytearray(self.data)
                old = self._flip(d, w_off, 1)
                rows.append(self._write(d, "dng", w_off, old, 1, "TIFF width->1"))
            if h_off is not None and h and h > 1:
                d = bytearray(self.data)
                old = self._flip(d, h_off, 1)
                rows.append(self._write(d, "dng", h_off, old, 1, "TIFF height->1"))
        return rows

    # ── JPEG structure-aware recipes (AppleJPEG decode surface) ──
    def mutate_jpeg(self, info: JPEGInfo):
        rows = []

        for sof in info.sof:
            # precision: AppleJPEG allocates per precision — 8<->16 confusions
            for t in (8, 16):
                if t != sof["precision"]:
                    d = bytearray(self.data)
                    old = self._flip(d, sof["off"], t)
                    rows.append(self._write(d, "jpeg", sof["off"], old, t,
                                            f"SOF precision {sof['precision']}->{t}"))
            # dimensions: 0/1/0xFFFF stress width*height math
            for label, off, v in (("h", sof["h_off"], sof["h"]),
                                  ("w", sof["w_off"], sof["w"])):
                for t in (0, 1, 0xFFFF):
                    if t != v:
                        d = bytearray(self.data)
                        old = self._flip(d, off, t)
                        rows.append(self._write(d, "jpeg", off, old, t,
                                                f"SOF {label} {v}->{t}"))
            # component count vs SOS/allocator assumptions
            for t in (1, 3, 4):
                if t != sof["ncomp"]:
                    d = bytearray(self.data)
                    old = self._flip(d, sof["ncomp_off"], t)
                    rows.append(self._write(d, "jpeg", sof["ncomp_off"], old, t,
                                            f"SOF components {sof['ncomp']}->{t}"))
            # per-component sampling factors + quant table selectors
            for k, (samp_off, _, q_off) in enumerate(sof["comp_offsets"]):
                for t in (0x11, 0x22, 0x21, 0x12):
                    d = bytearray(self.data)
                    old = self._flip(d, samp_off, t)
                    rows.append(self._write(d, "jpeg", samp_off, old, t,
                                            f"SOF comp{k} sampling->0x{t:02X}"))
                for t in (0, 1, 3):
                    d = bytearray(self.data)
                    old = self._flip(d, q_off, t)
                    rows.append(self._write(d, "jpeg", q_off, old, t,
                                            f"SOF comp{k} quant table->{t}"))

        for poff, prec, tid in info.dqt:
            # 8-bit vs 16-bit quant table precision (classic OOB read)
            for t in (0, 1):
                if t != prec:
                    newb = (t << 4) | tid
                    d = bytearray(self.data)
                    old = self._flip(d, poff, newb)
                    rows.append(self._write(d, "jpeg", poff, old, newb,
                                            f"DQT precision {prec}->{t}"))
            # table id swap
            newb = (prec << 4) | (tid ^ 1)
            d = bytearray(self.data)
            old = self._flip(d, poff, newb)
            rows.append(self._write(d, "jpeg", poff, old, newb, "DQT table id flip"))

        for poff in info.dht:
            newb = self.data[poff] ^ 0x10
            d = bytearray(self.data)
            old = self._flip(d, poff, newb)
            rows.append(self._write(d, "jpeg", poff, old, newb, "DHT class flip"))

        for sos in info.sos:
            for t in (1, 3, 4):
                if t != sos["ncomp"]:
                    d = bytearray(self.data)
                    old = self._flip(d, sos["ncomp_off"], t)
                    rows.append(self._write(d, "jpeg", sos["ncomp_off"], old, t,
                                            f"SOS components {sos['ncomp']}->{t}"))
            if sos["spectral_off"] + 2 <= len(self.data):
                d = bytearray(self.data)
                old = self._flip(d, sos["spectral_off"], 0x3F)
                rows.append(self._write(d, "jpeg", sos["spectral_off"], old, 0x3F,
                                        "SOS spectral selection->63"))
            if sos["approx_off"] < len(self.data):
                d = bytearray(self.data)
                old = self._flip(d, sos["approx_off"], 0)
                rows.append(self._write(d, "jpeg", sos["approx_off"], old, 0,
                                        "SOS successive approx->0"))

        # APP1 EXIF: reuse the validated TIFF parser on the EXIF payload.
        # AppleJPEG parses EXIF for orientation/thumbnails — IFD offset bugs
        # are the classic bounds-check fix site.
        if info.app1_exif:
            base, ln = info.app1_exif
            exif = DNGStructure(bytes(self.data[base:base + ln]))
            if exif.parse():
                for off, v in exif.samples_per_pixel:
                    if 1 <= v <= 8:
                        for t in (v + 1, 1, 2):
                            if t != v and 1 <= t <= 8:
                                d = bytearray(self.data)
                                old = self._flip(d, base + off, t)
                                rows.append(self._write(d, "jpeg", base + off, old, t,
                                                        f"EXIF SamplesPerPixel {v}->{t}"))
                for w_off, h_off, w, h in exif.width_height:
                    if w_off is not None and w not in (0, 1):
                        d = bytearray(self.data)
                        old = self._flip(d, base + w_off, 1)
                        rows.append(self._write(d, "jpeg", base + w_off, old, 1,
                                                "EXIF width->1"))
                    if h_off is not None and h not in (0, 1):
                        d = bytearray(self.data)
                        old = self._flip(d, base + h_off, 1)
                        rows.append(self._write(d, "jpeg", base + h_off, old, 1,
                                                "EXIF height->1"))

        # scan-data mutations (entropy-coded region between SOS and EOI)
        if info.scan_start and info.scan_end and info.scan_end > info.scan_start:
            idx = self.data.find(b"\xff\x00", info.scan_start, info.scan_end)
            if idx != -1:
                d = bytearray(self.data)
                del d[idx + 1]  # remove stuffing byte -> decoder desync
                rows.append(self._write(d, "jpeg", idx, None, None,
                                        "scan: removed stuffed 0x00 (desync)"))
            cut = (info.scan_start + info.scan_end) // 2
            if cut > info.scan_start:
                rows.append(self._write(bytes(self.data[:cut]), "jpeg", cut,
                                        None, None, f"truncate mid-scan at {cut}"))
            rows.append(self._write(bytes(self.data[:info.scan_start]), "jpeg",
                                     info.scan_start, None, None,
                                     "truncate at scan start"))
            off = info.scan_start + 10
            if off < info.scan_end:
                d = bytearray(self.data)
                old = d[off]
                d[off] = 0xFF
                rows.append(self._write(d, "jpeg", off, old, 0xFF,
                                        "scan byte->0xFF"))

        # APPn declared-length inflation -> parser reads past segment
        for coff, code, poff, plen in info.markers:
            if 0xE0 <= code <= 0xEF and plen > 0:
                # length field at code_off+1; inflate by 0x1000 (beyond EOF)
                d = bytearray(self.data)
                old_len = struct.unpack_from(">H", d, coff + 1)[0]
                new_len = old_len + 0x1000
                if new_len <= 0xFFFF:
                    struct.pack_into(">H", d, coff + 1, new_len)
                    rows.append(self._write(d, "jpeg", coff + 1, old_len,
                                            new_len, f"APPn length {old_len}->{new_len}"))
        return rows

    # ── Generic recipes (any container) ───────────────────────────
    def mutate_generic(self, count=8):
        rows = []
        n = len(self.data)
        # deterministic byte flips at structural offsets
        for i in range(min(count, 12)):
            off = min(0x10 * (i + 1), n - 1) if n > 0x10 else i % max(n, 1)
            d = bytearray(self.data)
            old = d[off]
            new = old ^ 0xFF
            d[off] = new
            rows.append(self._write(d, "generic", off, old, new, "byte flip"))

        # random flips (seeded)
        for i in range(count):
            off = self.rng.randrange(n)
            d = bytearray(self.data)
            old = d[off]
            new = self.rng.randrange(256)
            d[off] = new
            rows.append(self._write(d, "generic", off, old, new, "random byte flip"))

        # truncations
        for frac in (0.9, 0.5, 0.1):
            cut = int(n * frac)
            if cut > 64:
                d = bytes(self.data[:cut])
                rows.append(self._write(
                    d, "generic", cut, None, None, f"truncate to {cut}/{n}"))
        return rows


def detect_strategy(data: bytes):
    """Auto-pick a strategy from magic bytes."""
    if data[:2] == b"\xff\xd8":
        return "jpeg"
    if data[:4] in (b"II\x2a\x00", b"MM\x00\x2a"):
        return "dng"
    return "generic"


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("seed", type=Path)
    ap.add_argument("outdir", type=Path)
    ap.add_argument("--count", type=int, default=24,
                    help="target mutations per seed (dng/jpeg recipes fixed; generic uses this)")
    ap.add_argument("--strategy", choices=["dng", "jpeg", "generic", "all"], default="all")
    ap.add_argument("--random-seed", type=int, default=0xC0FFEE)
    ap.add_argument("--manifest", type=Path, default=None)
    args = ap.parse_args()

    if not args.seed.exists():
        print(f"seed not found: {args.seed}", file=sys.stderr)
        return 1
    args.outdir.mkdir(parents=True, exist_ok=True)

    data = args.seed.read_bytes()
    mut = Mutator(args.seed, args.outdir, random.Random(args.random_seed))
    rows = []

    if args.strategy == "all":
        args.strategy = detect_strategy(data)

    if args.strategy == "dng":
        s = DNGStructure(data)
        if s.parse() and (s.samples_per_pixel or s.sof3):
            rows = mut.mutate_dng(s)
    elif args.strategy == "jpeg":
        info = JPEGInfo(data)
        if info.parse():
            rows = mut.mutate_jpeg(info)
    if not rows:
        rows = mut.mutate_generic(args.count)

    if not rows:
        print("no mutations generated", file=sys.stderr)
        return 1

    manifest = args.manifest or (args.outdir / "manifest.tsv")
    with open(manifest, "a") as f:
        for r in rows:
            f.write(r + "\n")
    print(f"[+] {len(rows)} mutations of {args.seed.name} -> {args.outdir}")
    print(f"[+] manifest: {manifest}")
    if args.strategy != "generic":
        print(f"[+] strategy: {args.strategy}")
    else:
        print("[+] no DNG/JPEG structure found — generic mutations only")
    return 0


if __name__ == "__main__":
    sys.exit(main())
