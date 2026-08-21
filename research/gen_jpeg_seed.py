#!/usr/bin/env python3
"""
gen_jpeg_seed.py — bootstrap JPEG corpus for the K4.8 AppleJPEG campaign.

Generates small, valid JPEGs with different codec shapes so the fuzzer has
structure to mutate across the decode paths AppleJPEG parses:
  - baseline 4:2:0  (SOF0, 3 components)   — the common camera/photo shape
  - baseline 4:4:4  (SOF0, 3 comp, no subsampling)
  - grayscale       (SOF0, 1 component)    — the CVE-2025-43539 advisory shape
  - progressive     (SOF2)                 — AppleJPEG's progressive path
  - with EXIF       (APP1 with a real TIFF IFD — exercises EXIF parsing)

Requires Pillow (python3 -m pip install Pillow). Outputs to <outdir>
(default: referenceforAI/projects/CVE-2025-43300-hunters/../jpeg_seeds or
.w0lfsword/fuzz/seeds/jpeg).

Usage: gen_jpeg_seed.py [outdir]
"""

import sys
from pathlib import Path

from PIL import Image


def build_seeds(outdir: Path):
    outdir.mkdir(parents=True, exist_ok=True)
    made = []

    # textured 64x64 so the JPEG has real entropy (not a flat block)
    img = Image.new("RGB", (64, 64))
    px = img.load()  # type: ignore[assignment]
    for y in range(64):
        for x in range(64):
            px[x, y] = ((x * 3) % 256, (y * 5) % 256, (x ^ y) % 256)  # type: ignore[index]
    gray = img.convert("L")

    specs = [
        ("baseline_420", img, {"subsampling": 2}),            # SOF0 4:2:0
        ("baseline_444", img, {"subsampling": 0}),            # SOF0 4:4:4
        ("grayscale", gray, {"subsampling": 2}),              # SOF0 1 comp
        ("progressive", img, {"progressive": True}),          # SOF2
        ("optimized", img, {"optimize": True}),               # custom Huffman
    ]
    for name, im, kw in specs:
        p = outdir / f"{name}.jpg"
        im.save(p, "JPEG", quality=90, **kw)
        made.append(p)

    # EXIF variant: stamp a real APP1 with a TIFF IFD (orientation + dims)
    exif_bytes = Image.Exif()
    exif_bytes[0x0112] = 6          # Orientation
    exif_bytes[0x0100] = 64         # ImageWidth
    exif_bytes[0x0101] = 64         # ImageLength
    p = outdir / "baseline_420_exif.jpg"
    img.save(p, "JPEG", quality=90, subsampling=2, exif=exif_bytes)
    made.append(p)

    for p in made:
        print(f"  {p.name}: {p.stat().st_size} bytes")
    print(f"[+] {len(made)} JPEG seeds -> {outdir}")


if __name__ == "__main__":
    default = Path(__file__).resolve().parent.parent / ".w0lfsword/fuzz/seeds/jpeg"
    build_seeds(Path(sys.argv[1]) if len(sys.argv) > 1 else default)
