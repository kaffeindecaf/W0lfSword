#!/usr/bin/env python3
"""DeviceTree (FDT) patcher for the usbliter8 boot chain.

Port of the DeviceTree edits the upstream CFW scripts performed with external
helpers (`patch_dt.py` / `dt_patch2.py` / `set_ephemeral.py` / `set_dt_u32.py` /
`set_system_rw.py` from wh1te4ever/usbliter8-fun and 34306/usbliter8-fun), so a
CFW build no longer depends on having that work dir checked out next to this
repo. The edits mirror the QEMU-t8030 DeviceTree patches referenced by those
scripts (macho_populate_dtb + REM_PROPS in xnu.c):

    remove content-protect        /defaults   (zero-length flag: PRESENCE means
                                              "encrypted data volume", so it is
                                              REMOVED to boot without one)
    set  no-effaceable-storage=1  /defaults
    set  boot-ios-diagnostics=1   /product
    set  ephemeral-storage=1      (flag whose location is found by name)
    set  vol.fs_type=rw           for the volume whose vol.fs_name is "System"

Binary layout (little-endian, as produced by Apple's DeviceTree compiler):

    Node: u32 nprops; u32 nchildren; Prop*; Node*
    Prop: char name[32]; u32 length (bit31 = placeholder flag); value[length]
          padded to a 4-byte boundary
    (a node's own name is a property literally called "name")

Usage:
  python3 dt_patch.py <DeviceTree.raw> [--flags remove_content_protect,...] [-o out.raw]
  python3 dt_patch.py <DeviceTree.raw> --dry-run
"""

from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path
import log_utils

FLAG_PLACEHOLDER = 0x80000000
NAME_LEN = 32
U32_1 = struct.pack("<I", 1)


def _align4(x: int) -> int:
    return (x + 3) & ~3


class Prop:
    __slots__ = ("name_raw", "raw_lenfield", "value")

    def __init__(self, name_raw: bytes, raw_lenfield: int, value: bytes):
        self.name_raw = name_raw          # exact 32 bytes (lossless round-trip)
        self.raw_lenfield = raw_lenfield  # low 31 bits = length, bit31 = flag
        self.value = value

    @property
    def name(self) -> str:
        return self.name_raw.split(b"\x00")[0].decode("ascii", "replace")

    @property
    def length(self) -> int:
        return self.raw_lenfield & 0x7FFFFFFF

    @property
    def flags(self) -> int:
        return self.raw_lenfield & FLAG_PLACEHOLDER

    def set_value(self, value: bytes) -> None:
        self.value = bytes(value)
        self.raw_lenfield = self.flags | (len(value) & 0x7FFFFFFF)

    @staticmethod
    def make(name: str, value: bytes = b"") -> "Prop":
        raw = name.encode("ascii")
        if len(raw) >= NAME_LEN:
            raise ValueError(f"property name too long: {name}")
        return Prop(raw + b"\x00" * (NAME_LEN - len(raw)),
                    len(value) & 0x7FFFFFFF, bytes(value))

    def serialize(self) -> bytes:
        pad = _align4(len(self.value)) - len(self.value)
        return self.name_raw + struct.pack("<I", self.raw_lenfield) + self.value + b"\x00" * pad


class Node:
    __slots__ = ("props", "children")

    def __init__(self):
        self.props: list[Prop] = []
        self.children: list[Node] = []

    @property
    def name(self) -> str:
        for prop in self.props:
            if prop.name == "name":
                return prop.value.split(b"\x00")[0].decode("ascii", "replace")
        return ""

    def prop(self, name: str) -> Prop | None:
        return next((p for p in self.props if p.name == name), None)

    def child(self, name: str) -> "Node | None":
        return next((c for c in self.children if c.name == name), None)

    def serialize(self) -> bytes:
        out = bytearray(struct.pack("<II", len(self.props), len(self.children)))
        for prop in self.props:
            out += prop.serialize()
        for child in self.children:
            out += child.serialize()
        return bytes(out)


class DeviceTree:
    def __init__(self, root: Node):
        self.root = root

    @classmethod
    def parse(cls, data: bytes) -> "DeviceTree":
        _offset, root = cls._node(data, 0)
        return cls(root)

    @staticmethod
    def _node(data: bytes, offset: int) -> tuple[int, Node]:
        nprops, nchildren = struct.unpack_from("<II", data, offset)
        offset += 8
        node = Node()
        for _ in range(nprops):
            name_raw = data[offset:offset + NAME_LEN]
            (raw_lenfield,) = struct.unpack_from("<I", data, offset + NAME_LEN)
            vlen = raw_lenfield & 0x7FFFFFFF
            voff = offset + NAME_LEN + 4
            node.props.append(Prop(name_raw, raw_lenfield, data[voff:voff + vlen]))
            offset = voff + _align4(vlen)
        for _ in range(nchildren):
            offset, child = DeviceTree._node(data, offset)
            node.children.append(child)
        return offset, node

    def serialize(self) -> bytes:
        return self.root.serialize()

    def node(self, path: str) -> Node | None:
        node = self.root
        for part in path.strip("/").split("/"):
            if not part:
                continue
            node = node.child(part)
            if node is None:
                return None
        return node

    def find_prop(self, name: str) -> Prop | None:
        """Depth-first search for the first property with this name."""
        stack = [self.root]
        while stack:
            node = stack.pop()
            prop = node.prop(name)
            if prop is not None:
                return prop
            stack.extend(node.children)
        return None


# ── patch primitives ───────────────────────────────────────────────

def set_prop(dt: DeviceTree, node_path: str, name: str, value: bytes) -> str:
    node = dt.node(node_path)
    if node is None:
        return f"node-not-found:{node_path}"
    prop = node.prop(name)
    if prop is None:
        node.props.append(Prop.make(name, value))
        return "added"
    if prop.value == value:
        return "unchanged"
    prop.set_value(value)
    return "updated"


def del_prop(dt: DeviceTree, node_path: str, name: str) -> str:
    node = dt.node(node_path)
    if node is None:
        return f"node-not-found:{node_path}"
    prop = node.prop(name)
    if prop is None:
        return "absent"
    node.props.remove(prop)
    return "removed"


def set_u32_by_name(dt: DeviceTree, name: str, value: int) -> str:
    """Set a u32 property wherever it lives (used for ephemeral-storage)."""
    prop = dt.find_prop(name)
    if prop is None:
        return "absent"
    new = struct.pack("<I", value)
    if prop.value == new:
        return "unchanged"
    prop.set_value(new)
    return "updated"


def set_system_volume_rw(dt: DeviceTree) -> str:
    """vol.fs_type 'ro' -> 'rw' for the volume whose vol.fs_name is 'System'."""
    tainted = "ro"
    for node in _walk(dt.root):
        fs_name = node.prop("vol.fs_name")
        if fs_name is None:
            continue
        if fs_name.value.split(b"\x00")[0] != b"System":
            continue
        fs_type = node.prop("vol.fs_type")
        if fs_type is None:
            return "no-fs_type"
        if fs_type.value == b"rw\x00":
            return "unchanged"
        fs_type.set_value(b"rw\x00")
        return f"{tainted}->rw"
    return "no-system-volume"


def _walk(node: Node):
    yield node
    for child in node.children:
        yield from _walk(child)


# ── profile-driven entry point ─────────────────────────────────────

def apply_profile_flags(data: bytes, flags: dict) -> tuple[bytes, list[tuple[str, str]]]:
    """Apply the DeviceTree part of a profile to raw DTB bytes.

    `flags` is the profile's `patches.devicetree` mapping. Returns the patched
    bytes plus a [(op, status)] report. Ops the profile does not ask for are
    left alone; that keeps the build faithful to the verified profile.
    """
    dt = DeviceTree.parse(data)
    report: list[tuple[str, str]] = []

    if flags.get("remove_content_protect"):
        report.append(("del /defaults/content-protect", del_prop(dt, "/defaults", "content-protect")))
    if flags.get("add_no_effaceable_storage"):
        report.append(("set /defaults/no-effaceable-storage=1",
                       set_prop(dt, "/defaults", "no-effaceable-storage", U32_1)))
    if flags.get("add_boot_ios_diagnostics"):
        report.append(("set /product/boot-ios-diagnostics=1",
                       set_prop(dt, "/product", "boot-ios-diagnostics", U32_1)))
    if flags.get("ephemeral_storage"):
        report.append(("set ephemeral-storage=1", set_u32_by_name(dt, "ephemeral-storage", 1)))
    if flags.get("system_rw"):
        report.append(("set System vol.fs_type=rw", set_system_volume_rw(dt)))

    return dt.serialize(), report


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Apply the boot-chain DeviceTree patches to a raw DTB.")
    ap.add_argument("input", help="DeviceTree.raw (unwrapped im4p payload)")
    ap.add_argument("-o", "--output", help="output path (default: <input>.patched)")
    ap.add_argument("--flags", default="remove_content_protect",
                    help="comma list of profile devicetree flags to apply")
    ap.add_argument("--dry-run", action="store_true", help="report, do not write")
    args = ap.parse_args(argv if argv is not None else sys.argv[1:])

    data = Path(args.input).read_bytes()
    flags = {name: True for name in args.flags.split(",") if name}
    out, report = apply_profile_flags(data, flags)

    for op, status in report:
        print(f"  {op:<44} {status}")
    print(f"  size: {len(data)} -> {len(out)} ({len(out) - len(data):+d} bytes)")

    if args.dry_run:
        return 0

    dest = Path(args.output) if args.output else Path(args.input + ".patched")
    dest.write_bytes(out)
    print(f"  wrote {dest}")
    return 0


if __name__ == "__main__":
    import log_utils
    log_utils.install()
    sys.exit(log_utils.guard(main))
