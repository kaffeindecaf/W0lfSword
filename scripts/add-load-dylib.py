#!/usr/bin/env python3
"""
add-load-dylib.py — inject an LC_LOAD_DYLIB load command into a Mach-O.

Ported from DirtySlide's scripts/add-load-dylib.py (gracecondition) for the
K4.12 MobileHouseArrest re-sign flow. Pure stdlib.

The new load command is inserted just before LC_CODE_SIGNATURE (or at the end
of the load-command area), so the following re-sign pass (ldid) recomputes a
valid signature. Fails cleanly if the load-command padding is too small.

Usage: add-load-dylib.py <input> <output> <dylib-path>
  e.g. add-load-dylib.py Filza Filza.patched @executable_path/FilzaApplySandboxExt.dylib

--strip mode removes any existing LC_LOAD_DYLIB whose dylib path ends with the
given name (e.g. a stale @executable_path/Frameworks/... injection from a
previous re-sign), so re-running the MHA flow on an already-modified IPA is
idempotent instead of stacking duplicate load commands.

Usage: add-load-dylib.py --strip <input> <output> <dylib-name>
  e.g. add-load-dylib.py --strip Filza Filza.clean FilzaApplySandboxExt.dylib
"""

import argparse
import shutil
import struct
import sys
from pathlib import Path

MH_MAGIC_64 = 0xFEEDFACF
LC_SEGMENT_64 = 0x19
LC_LOAD_DYLIB = 0xC
LC_CODE_SIGNATURE = 0x1D


def u32(buf, off):
    return struct.unpack_from("<I", buf, off)[0]


def u64(buf, off):
    return struct.unpack_from("<Q", buf, off)[0]


def put_u32(buf, off, value):
    struct.pack_into("<I", buf, off, value)


def load_commands(buf):
    ncmds = u32(buf, 16)
    off = 32
    for index in range(ncmds):
        cmd = u32(buf, off)
        cmdsize = u32(buf, off + 4)
        if cmdsize < 8:
            raise ValueError(f"bad load command size at index {index}: {cmdsize}")
        yield index, off, cmd, cmdsize
        off += cmdsize


def first_payload_offset(buf):
    first = len(buf)
    for _, off, cmd, _ in load_commands(buf):
        if cmd != LC_SEGMENT_64:
            continue
        nsects = u32(buf, off + 64)
        sect_off = off + 72
        for _ in range(nsects):
            size = u64(buf, sect_off + 40)
            file_offset = u32(buf, sect_off + 48)
            if file_offset != 0 and size != 0:
                first = min(first, file_offset)
            sect_off += 80
        fileoff = u64(buf, off + 40)
        filesize = u64(buf, off + 48)
        if fileoff != 0 and filesize != 0:
            first = min(first, fileoff)
    return first


def existing_dylib_name(buf, off, cmdsize):
    name_off = u32(buf, off + 8)
    start = off + name_off
    end = off + cmdsize
    return bytes(buf[start:end]).split(b"\0", 1)[0].decode("utf-8", "replace")


def strip_load_dylib(data, name_suffix):
    """Remove every LC_LOAD_DYLIB whose path ends with name_suffix. Returns
    (new_data, removed_count).

    CRITICAL: only the load-command region is compacted. The segment data
    (__TEXT/__DATA/__LINKEDIT) must NOT shift — bind_off/rebase_off and all
    segment file offsets stay valid only if file bytes after the load
    commands never move. So we move later load commands UP within the
    command region and leave the tail as padding (ncmds/sizeofcmds shrink,
    file length unchanged). A naive `del` on the bytearray shifts everything
    after the deletion and corrupts the bind table (dyld: "bad bind opcode
    0xFF" at launch)."""
    removed = 0
    ncmds = u32(data, 16)
    sizeofcmds = u32(data, 20)
    load_end = 32 + sizeofcmds
    off = 32
    # Collect matching command regions first (do the compaction on a copy so
    # the offsets stay stable while scanning).
    regions = []
    for _ in range(ncmds):
        cmd = u32(data, off)
        cmdsize = u32(data, off + 4)
        if cmdsize < 8:
            raise ValueError(f"bad load command size: {cmdsize}")
        if cmd == LC_LOAD_DYLIB and existing_dylib_name(data, off, cmdsize).endswith(name_suffix):
            regions.append((off, cmdsize))
            removed += 1
        off += cmdsize
    if not regions:
        return data, 0
    out = bytearray(data)
    # Compact the load-command region: for each removed command, shift the
    # commands that FOLLOW it up by cmdsize. Iterate in reverse so earlier
    # offsets stay valid.
    for start, cmdsize in sorted(regions, reverse=True):
        end = start + cmdsize
        # move everything after this command up by cmdsize, only within the
        # load-command region (never touch segment data past load_end)
        out[start:load_end - cmdsize] = out[end:load_end]
        # the vacated tail stays as padding; zero it for cleanliness
        out[load_end - cmdsize:load_end] = b"\0" * cmdsize
        load_end -= cmdsize
    put_u32(out, 16, ncmds - removed)
    put_u32(out, 20, sizeofcmds - sum(c for _, c in regions))
    return out, removed


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("input", type=Path)
    ap.add_argument("output", type=Path)
    ap.add_argument("name", help="dylib path, e.g. @executable_path/FilzaApplySandboxExt.dylib")
    ap.add_argument("--strip", action="store_true",
                    help="remove existing LC_LOAD_DYLIBs ending with NAME instead of adding")
    args = ap.parse_args()

    data = bytearray(args.input.read_bytes())
    if u32(data, 0) != MH_MAGIC_64:
        raise SystemExit("not a 64-bit Mach-O")

    if args.strip:
        out, removed = strip_load_dylib(data, args.name)
        if removed == 0:
            print(f"[=] no LC_LOAD_DYLIB ending in {args.name!r} to strip")
        else:
            print(f"[-] stripped {removed} LC_LOAD_DYLIB ending in {args.name!r}")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(out)
        shutil.copymode(args.input, args.output)
        return 0

    for _, off, cmd, cmdsize in load_commands(data):
        if cmd == LC_LOAD_DYLIB and existing_dylib_name(data, off, cmdsize) == args.name:
            raise SystemExit(f"already has LC_LOAD_DYLIB {args.name!r}")

    old_ncmds = u32(data, 16)
    old_sizeofcmds = u32(data, 20)
    load_end = 32 + old_sizeofcmds
    insert_off = load_end
    for _, off, cmd_existing, _ in load_commands(data):
        if cmd_existing == LC_CODE_SIGNATURE:
            insert_off = off
            break
    name = args.name.encode() + b"\0"
    cmdsize = (24 + len(name) + 7) & ~7
    cmd = bytearray(cmdsize)
    put_u32(cmd, 0, LC_LOAD_DYLIB)
    put_u32(cmd, 4, cmdsize)
    put_u32(cmd, 8, 24)   # name offset
    put_u32(cmd, 12, 2)   # timestamp
    put_u32(cmd, 16, 0)   # current_version
    put_u32(cmd, 20, 0)   # compatibility_version
    cmd[24:24 + len(name)] = name

    payload_off = first_payload_offset(data)
    if insert_off + len(cmd) > payload_off:
        raise SystemExit(
            f"not enough load-command padding: need 0x{insert_off + len(cmd):x}, "
            f"payload starts at 0x{payload_off:x}")

    if insert_off != load_end:
        data[insert_off + len(cmd):load_end + len(cmd)] = data[insert_off:load_end]
    data[insert_off:insert_off + len(cmd)] = cmd
    put_u32(data, 16, old_ncmds + 1)
    put_u32(data, 20, old_sizeofcmds + len(cmd))

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(data)
    shutil.copymode(args.input, args.output)
    print(f"[+] added LC_LOAD_DYLIB {args.name} to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
