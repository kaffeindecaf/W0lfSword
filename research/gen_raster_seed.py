#!/usr/bin/env python3
"""
gen_raster_seed.py — bootstrap raster (PNG/GIF/BMP/WebP) seeds for the
ImageIO fuzz harness.

The jpeg/dng strategies cover AppleJPEG and the TIFF parser; the raster
formats exercise ImageIO's PNG/GIF/BMP/WebP decoders via the mutator's
generic strategy (byte flips + truncations). Includes the shapes that
hit distinct code paths:

  - PNG:   RGB / gray8 / gray16 (16-bit path) / RGBA / palette /
           interlaced (Adam7) / large (row-filter + chunk walk)
  - GIF:   basic palette + animated (extension blocks, LZW streaming)
  - BMP:   24-bit + 8-bit palette (palette index path)
  - WebP:  lossy (VP8) — only when Pillow has WebP support

Requires Pillow. Outputs to <outdir> (default .w0lfsword/fuzz/seeds/raster).

Usage: gen_raster_seed.py [outdir]
"""

import sys
from pathlib import Path

from PIL import Image


def build_seeds(outdir: Path):
    outdir.mkdir(parents=True, exist_ok=True)
    made = []

    def make(name, fmt, mode="RGB", size=(64, 64), **kw):
        img = Image.new(mode, size, color=kw.pop("color", 100))
        img.save(outdir / name, format=fmt, **kw)
        made.append(name)

    make("png_rgb.png", "PNG")
    make("png_gray8.png", "PNG", "L")
    make("png_gray16.png", "PNG", "I;16")
    make("png_rgba.png", "PNG", "RGBA")
    make("png_palette.png", "PNG", "P")
    make("png_interlaced.png", "PNG", "RGB", interlace=1)
    make("png_large.png", "PNG", "RGB", size=(256, 256))
    make("gif_basic.gif", "GIF", "P")
    make("gif_animated.gif", "GIF", "P", save_all=True,
         append_images=[Image.new("P", (64, 64), 150)], duration=100, loop=0)
    make("bmp_24bit.bmp", "BMP")
    make("bmp_8bit_palette.bmp", "BMP", "P")
    try:
        make("webp_lossy.webp", "WEBP", quality=80)
    except Exception:  # Pillow built without WebP
        pass

    print(f"  ✓ {len(made)} raster seed(s) -> {outdir}")
    return made


def main():
    outdir = Path(sys.argv[1]) if len(sys.argv) > 1 else \
        Path(__file__).resolve().parents[2] / ".w0lfsword" / "fuzz" / "seeds" / "raster"
    build_seeds(outdir)
    return 0


if __name__ == "__main__":
    sys.exit(main())
