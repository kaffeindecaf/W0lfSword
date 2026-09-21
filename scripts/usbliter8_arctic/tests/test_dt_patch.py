"""Tests for the native DeviceTree patcher (`dt_patch.py`).

The builder used to shell out to helper scripts from an upstream work dir and
silently skipped the DeviceTree when they were missing, which left a CFW
without the storage flags the boot chain needs. These tests pin the in-tree
implementation: FDT round-trip fidelity, the profile-driven edits, and the
status report the builder prints.
"""

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import dt_patch  # noqa: E402


def _u32(value: int) -> bytes:
    return struct.pack("<I", value)


def _sample_tree() -> dt_patch.DeviceTree:
    """Minimal tree shaped like a real DeviceTree.im4p payload."""
    root = dt_patch.Node()
    root.props.append(dt_patch.Prop.make("name", b"device-tree\x00"))

    defaults = dt_patch.Node()
    defaults.props.append(dt_patch.Prop.make("name", b"defaults\x00"))
    defaults.props.append(dt_patch.Prop.make("content-protect"))       # flag: zero length
    defaults.props.append(dt_patch.Prop.make("no-effaceable-storage", _u32(0)))
    root.children.append(defaults)

    product = dt_patch.Node()
    product.props.append(dt_patch.Prop.make("name", b"product\x00"))
    product.props.append(dt_patch.Prop.make("boot-ios-diagnostics", _u32(0)))
    root.children.append(product)

    volume = dt_patch.Node()
    volume.props.append(dt_patch.Prop.make("name", b"volume\x00"))
    volume.props.append(dt_patch.Prop.make("vol.fs_name", b"System\x00"))
    volume.props.append(dt_patch.Prop.make("vol.fs_type", b"ro\x00"))
    defaults.children.append(volume)

    data = dt_patch.Node()
    data.props.append(dt_patch.Prop.make("name", b"volume\x00"))
    data.props.append(dt_patch.Prop.make("vol.fs_name", b"Data\x00"))
    data.props.append(dt_patch.Prop.make("vol.fs_type", b"ro\x00"))
    defaults.children.append(data)

    return dt_patch.DeviceTree(root)


def test_round_trip_is_byte_identical():
    original = _sample_tree().serialize()
    assert dt_patch.DeviceTree.parse(original).serialize() == original


def test_tree_navigation_and_search():
    dt = _sample_tree()
    assert dt.node("/defaults/volume").prop("vol.fs_name").value.startswith(b"System")
    assert dt.node("/defaults").prop("content-protect") is not None
    assert dt.node("/nope") is None


def test_profile_flags_apply_the_boot_chain_edits():
    tree = _sample_tree()
    patched, report = dt_patch.apply_profile_flags(tree.serialize(), {
        "remove_content_protect": True,
        "add_no_effaceable_storage": True,
        "add_boot_ios_diagnostics": True,
        "ephemeral_storage": True,
    })
    statuses = dict(report)

    assert statuses["del /defaults/content-protect"] == "removed"
    assert statuses["set /defaults/no-effaceable-storage=1"] == "updated"
    assert statuses["set /product/boot-ios-diagnostics=1"] == "updated"
    # absent in the sample tree and not injectable blind -> reported, not invented
    assert statuses["set ephemeral-storage=1"] == "absent"

    out = dt_patch.DeviceTree.parse(patched)
    assert out.node("/defaults").prop("content-protect") is None
    assert out.node("/defaults").prop("no-effaceable-storage").value == _u32(1)
    assert out.node("/product").prop("boot-ios-diagnostics").value == _u32(1)


def test_ephemeral_storage_is_set_wherever_it_lives():
    tree = _sample_tree()
    chosen = dt_patch.Node()
    chosen.props.append(dt_patch.Prop.make("name", b"chosen\x00"))
    chosen.props.append(dt_patch.Prop.make("ephemeral-storage", _u32(0)))
    tree.root.children.append(chosen)

    patched, report = dt_patch.apply_profile_flags(tree.serialize(), {"ephemeral_storage": True})
    assert dict(report)["set ephemeral-storage=1"] == "updated"
    out = dt_patch.DeviceTree.parse(patched)
    assert out.find_prop("ephemeral-storage").value == _u32(1)


def test_flags_are_idempotent():
    tree = _sample_tree()
    flags = {"remove_content_protect": True, "add_no_effaceable_storage": True}
    once, _ = dt_patch.apply_profile_flags(tree.serialize(), flags)
    twice, report = dt_patch.apply_profile_flags(once, flags)
    statuses = dict(report)
    assert statuses["del /defaults/content-protect"] == "absent"
    assert statuses["set /defaults/no-effaceable-storage=1"] == "unchanged"
    assert twice == once


def test_unset_flags_leave_the_tree_alone():
    tree = _sample_tree()
    patched, report = dt_patch.apply_profile_flags(tree.serialize(), {})
    assert report == []
    assert patched == tree.serialize()


def test_missing_node_is_reported_not_raised():
    root = dt_patch.Node()
    root.props.append(dt_patch.Prop.make("name", b"device-tree\x00"))
    tree = dt_patch.DeviceTree(root)
    _patched, report = dt_patch.apply_profile_flags(tree.serialize(),
                                                   {"remove_content_protect": True})
    assert dict(report)["del /defaults/content-protect"] == "node-not-found:/defaults"


def test_system_volume_rw_only_touches_the_system_volume():
    tree = _sample_tree()
    patched, report = dt_patch.apply_profile_flags(tree.serialize(), {"system_rw": True})
    assert dict(report)["set System vol.fs_type=rw"] == "ro->rw"

    out = dt_patch.DeviceTree.parse(patched)
    volumes = [n for n in _walk(out.root) if n.prop("vol.fs_name")]
    by_name = {n.prop("vol.fs_name").value.split(b"\x00")[0]: n.prop("vol.fs_type").value
               for n in volumes}
    assert by_name[b"System"] == b"rw\x00"
    assert by_name[b"Data"] == b"ro\x00"


def test_system_rw_without_a_system_volume_is_reported():
    root = dt_patch.Node()
    root.props.append(dt_patch.Prop.make("name", b"device-tree\x00"))
    _patched, report = dt_patch.apply_profile_flags(
        dt_patch.DeviceTree(root).serialize(), {"system_rw": True})
    assert dict(report)["set System vol.fs_type=rw"] == "no-system-volume"


def test_placeholder_flag_bit_survives_a_rewrite():
    """Apple sets bit31 on properties that are placeholders (e.g. some
    secure-config props); patching must not clear it."""
    prop = dt_patch.Prop.make("some-placeholder", _u32(7))
    prop.raw_lenfield |= 0x80000000
    node = dt_patch.Node()
    node.props = [prop]
    blob = struct.pack("<II", 1, 0) + prop.serialize()

    parsed = dt_patch.DeviceTree.parse(blob)
    reparsed = dt_patch.DeviceTree.parse(parsed.serialize())
    out = reparsed.root.prop("some-placeholder")
    assert out.flags == 0x80000000 and out.length == 4


def test_alignment_is_preserved_for_odd_length_values():
    root = dt_patch.Node()
    root.props.append(dt_patch.Prop.make("name", b"device-tree\x00"))
    root.props.append(dt_patch.Prop.make("odd", b"abc"))          # 3 bytes -> 1 pad byte
    root.props.append(dt_patch.Prop.make("word", _u32(0x11223344)))
    tree = dt_patch.DeviceTree(root)

    blob = tree.serialize()
    assert len(blob) % 4 == 0
    assert dt_patch.DeviceTree.parse(blob).serialize() == blob


def _walk(node):
    yield node
    for child in node.children:
        yield from _walk(child)
