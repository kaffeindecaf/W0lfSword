"""Tests for cross-device profile propagation (`profile_gen.py propagate`),
coverage reporting, and pending-aware validation (`device_offsets.py`).

Propagation carries SoC-shared patch sections (kernel, daemons, restoreramdisk,
devicetree, userland) from a verified base profile to another device of the
same SoC, and marks device-specific bootloader sections (iBSS/iBEC/TXM) as
`pending` until their offsets are discovered (optionally via --comp-dir
cross-device AArch64 fingerprinting).
"""

import random
import struct
import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).parent.parent))

import profile_gen  # noqa: E402
import device_offsets  # noqa: E402

ROOT = Path(__file__).parent.parent
SENTINEL = 0xDEADBEEF

# ── fixtures ────────────────────────────────────────────────────────

IBSS_ENTRIES = {
    "image4_validate_nop": (0x23DB0, b"\x1f\x20\x03\xd5"),
    "image4_validate_ret0": (0x23DB4, b"\x00\x00\x80\xd2"),
    "boot_args_adrp": (0x2AFBC, b"\x42\x00\x05\xb0"),
    "boot_args_add": (0x2AFC0, b"\x42\x21\x40\x91"),
    "boot_args_string": (0xD3850, b"-v wdt=-1 rd=md0 -restore"),
}


def _name_filler(name: str) -> bytes:
    """Deterministic 28-byte context placed after every site (same name →
    same context in every binary), modelling code that moves as a unit."""
    h = 0
    for ch in name:
        h = (h * 131 + ord(ch)) & 0xFFFFFFFF
    out = bytearray()
    for i in range(7):
        out += struct.pack("<I", (h * (i + 3) + 0x9E3779B9) & 0xFFFFFFFF)
    return bytes(out)


def _make_component(entries: dict, size: int = 0x100000) -> bytes:
    data = bytearray(size)
    rng = random.Random(42)
    for i in range(0, size, 4):
        struct.pack_into("<I", data, i, rng.getrandbits(32))
    for name, (off, val) in entries.items():
        data[off:off + len(val)] = val
        ctx = _name_filler(name)
        data[off + len(val):off + len(val) + len(ctx)] = ctx
    return bytes(data)


def _base_profile() -> dict:
    """Minimal A13 (iPhone12,3) base profile mirroring the real profile shape."""
    return {
        "device": "iPhone 11 Pro", "model": "iPhone12,3", "ios_version": "27.0b2",
        "build": "24A5370h", "soc": "A13", "board": "d421ap", "apticket": "t8030",
        "patches": {
            "ibss": {name: {"offset": off, "value": val.hex()}
                     for name, (off, val) in IBSS_ENTRIES.items()},
            "ibec": {"keep_nonce_b": {"offset": 0x36BD0, "value": "28000014"}},
            "kernel": [
                {"name": "USB Restricted Mode bypass", "offset": 0x2894B68,
                 "value": "200080d2c0035fd6", "desc": "restore-mode"},
                {"name": "AMFI trust everything", "offset": 0x1F1EBE0,
                 "value": "200080d2c0035fd6"},
            ],
            "devicetree": {"remove_content_protect": True, "ephemeral_storage": True},
            "restoreramdisk": {"asr_sig_bypass": {"offset": 0x24D34, "value": "1f2003d5"}},
            "txm": {"query_module0": {"offset": 0x39CB0, "value": "000080d2"}},
            "daemons": {"coreauthd": {"anti_sep_crash": {"offset": 0x95C0, "value": "1f2003d5"}}},
            "userland": {"disable_screentime": True, "disable_setup": True},
        },
    }


@pytest.fixture()
def offsets_dir(tmp_path, monkeypatch):
    """Point profile_gen at a scratch offsets/ dir; seed a verified base."""
    monkeypatch.setattr(profile_gen, "OFFSETS_DIR", tmp_path)
    base = tmp_path / "iPhone12,3_27.0b2.yaml"
    base.write_text(yaml.safe_dump(_base_profile(), sort_keys=False))
    return tmp_path


def _load(path: Path) -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


# ── propagate: shared vs pending sections ───────────────────────────

def test_propagate_copies_shared_and_marks_device_sections(offsets_dir, capsys):
    # iPhone12,5 ships the same kernelcache component as iPhone12,3
    # (kernelcache.release.iphone12), so the kernel section may be copied.
    profile_gen.cmd_propagate([str(offsets_dir / "iPhone12,3_27.0b2.yaml"), "iPhone12,5"])

    out = offsets_dir / "iPhone12,5_27.0b2.yaml"
    assert out.exists()
    prof = _load(out)

    assert prof["device"] == "iPhone 11 Pro Max"
    assert prof["model"] == "iPhone12,5"
    assert prof["board"] == "d431ap"
    assert prof["soc"] == "A13"
    assert prof["verification"] == "pending"
    assert prof["propagated_from"] == "iPhone12,3_27.0b2.yaml"

    patches = prof["patches"]
    # shared sections copied verbatim
    assert patches["kernel"][0]["offset"] == 0x2894B68
    assert patches["kernel"][0]["value"] == "200080d2c0035fd6"
    assert patches["daemons"]["coreauthd"]["anti_sep_crash"]["offset"] == 0x95C0
    assert patches["restoreramdisk"]["asr_sig_bypass"]["offset"] == 0x24D34
    assert patches["devicetree"]["remove_content_protect"] is True
    assert patches["userland"]["disable_screentime"] is True

    # device-specific sections → sentinel + pending
    for name in ("image4_validate_nop", "boot_args_string"):
        e = patches["ibss"][name]
        assert e["offset"] == SENTINEL and e["pending"] is True
    assert patches["ibec"]["keep_nonce_b"]["pending"] is True
    assert patches["txm"]["query_module0"]["pending"] is True

    # validation must pass with the pending entries excluded
    passed, failed, errors = device_offsets.validate_offsets(out)
    assert failed == 0, errors
    assert passed == 2 + 1 + 1  # kernel 2 + restoreramdisk 1 + daemons 1
    assert device_offsets.pending_entries(out) == 5 + 1 + 1  # ibss 5 + ibec 1 + txm 1


def test_propagate_refuses_cross_soc_without_force(offsets_dir):
    profile_gen.cmd_propagate([str(offsets_dir / "iPhone12,3_27.0b2.yaml"), "iPhone11,2"])
    assert not (offsets_dir / "iPhone11,2_27.0b2.yaml").exists()

    profile_gen.cmd_propagate([str(offsets_dir / "iPhone12,3_27.0b2.yaml"), "iPhone11,2", "--force"])
    out = offsets_dir / "iPhone11,2_27.0b2.yaml"
    assert out.exists()
    assert _load(out)["soc"] == "A12"


def test_propagate_refuses_kernel_component_mismatch(offsets_dir, capsys):
    """iPhone12,1 ships kernelcache.release.iphone12b while iPhone12,3 ships
    kernelcache.release.iphone12 — kernel offsets must not be copied across."""
    profile_gen.cmd_propagate([str(offsets_dir / "iPhone12,3_27.0b2.yaml"), "iPhone12,1"])
    assert not (offsets_dir / "iPhone12,1_27.0b2.yaml").exists()
    assert "kernel component mismatch" in capsys.readouterr().out

    profile_gen.cmd_propagate(
        [str(offsets_dir / "iPhone12,3_27.0b2.yaml"), "iPhone12,1", "--force"])
    assert (offsets_dir / "iPhone12,1_27.0b2.yaml").exists()


def test_propagate_refuses_pending_base(offsets_dir):
    base = _base_profile()
    base["verification"] = "pending"
    (offsets_dir / "pending_base.yaml").write_text(yaml.safe_dump(base, sort_keys=False))
    profile_gen.cmd_propagate(["pending_base.yaml", "iPhone12,1"])
    assert not (offsets_dir / "iPhone12,1_27.0b2.yaml").exists()


def test_propagate_overwrite_prompt_declined(offsets_dir, monkeypatch, capsys):
    profile_gen.cmd_propagate([str(offsets_dir / "iPhone12,3_27.0b2.yaml"), "iPhone12,5"])
    monkeypatch.setattr("builtins.input", lambda *a, **k: "n")
    profile_gen.cmd_propagate([str(offsets_dir / "iPhone12,3_27.0b2.yaml"), "iPhone12,5"])
    out = _load(offsets_dir / "iPhone12,5_27.0b2.yaml")
    # still the first-generation file (propagated_from unchanged)
    assert out["propagated_from"] == "iPhone12,3_27.0b2.yaml"


# ── propagate --comp-dir: cross-device fingerprint discovery ────────

def test_propagate_comp_dir_discovery(offsets_dir, tmp_path, capsys):
    # target device's iBSS has the same patch sites at different addresses
    shift = 0x5000
    target_entries = {name: (off + shift, val) for name, (off, val) in IBSS_ENTRIES.items()}
    # boot_args_add immediate changes across devices (like b2 -> b3)
    target_entries["boot_args_add"] = (0x2AFC0 + shift, b"\x42\x2d\x40\x91")

    comp_dir = tmp_path / "comp"
    (comp_dir / "base").mkdir(parents=True)
    (comp_dir / "target").mkdir()
    (comp_dir / "base" / "ibss.raw").write_bytes(_make_component(IBSS_ENTRIES))
    (comp_dir / "target" / "ibss.raw").write_bytes(_make_component(target_entries))

    profile_gen.cmd_propagate(
        [str(offsets_dir / "iPhone12,3_27.0b2.yaml"), "iPhone12,5", "--comp-dir", str(comp_dir)])

    prof = _load(offsets_dir / "iPhone12,5_27.0b2.yaml")
    ibss = prof["patches"]["ibss"]

    for name, (base_off, _) in IBSS_ENTRIES.items():
        e = ibss[name]
        assert e["offset"] == base_off + shift, f"{name}: expected shifted offset"
        assert e["pending"] is False, f"{name}: should have been discovered"
        assert e["method"] == "cross-device"
        assert e["confidence"] >= 0.90

    # value change at the site recomputed into the profile
    assert ibss["boot_args_add"]["value"] == "422d4091"
    assert ibss["boot_args_add"]["value_recomputed"] is True

    # ibec/txm have no components → stay pending
    assert prof["patches"]["ibec"]["keep_nonce_b"]["pending"] is True
    assert prof["patches"]["txm"]["query_module0"]["pending"] is True

    passed, failed, _ = device_offsets.validate_offsets(offsets_dir / "iPhone12,5_27.0b2.yaml")
    assert failed == 0
    assert passed == 2 + 1 + 1 + 5  # kernel 2 + ramdisk 1 + daemons 1 + ibss 5


def test_propagate_comp_dir_low_confidence_stays_pending(offsets_dir, tmp_path):
    # target binary without the string site → boot_args_string cannot be found
    shift = 0x5000
    entries = {name: (off + shift, val) for name, (off, val) in IBSS_ENTRIES.items()
               if name != "boot_args_string"}

    comp_dir = tmp_path / "comp"
    (comp_dir / "base").mkdir(parents=True)
    (comp_dir / "target").mkdir()
    (comp_dir / "base" / "ibss.raw").write_bytes(_make_component(IBSS_ENTRIES))
    (comp_dir / "target" / "ibss.raw").write_bytes(_make_component(entries))

    profile_gen.cmd_propagate(
        [str(offsets_dir / "iPhone12,3_27.0b2.yaml"), "iPhone12,5", "--comp-dir", str(comp_dir)])

    ibss = _load(offsets_dir / "iPhone12,5_27.0b2.yaml")["patches"]["ibss"]
    assert ibss["boot_args_string"]["pending"] is True
    assert ibss["boot_args_string"]["offset"] == SENTINEL
    assert ibss["image4_validate_nop"]["pending"] is False


# ── coverage ────────────────────────────────────────────────────────

def test_coverage_lists_devices(offsets_dir, capsys):
    profile_gen.cmd_coverage()
    out = capsys.readouterr().out
    assert "iPhone 11 Pro" in out
    assert "iPhone 11" in out
    assert "iPhone XS" in out


# ── pending-aware validation ────────────────────────────────────────

def test_pending_entries_excluded_from_validation(tmp_path):
    prof = _base_profile()
    prof["patches"]["ibss"]["image4_validate_nop"]["pending"] = True
    prof["patches"]["ibss"]["image4_validate_nop"]["offset"] = SENTINEL
    prof["patches"]["kernel"][0]["pending"] = True
    prof["patches"]["kernel"][0]["offset"] = SENTINEL

    f = tmp_path / "mix.yaml"
    f.write_text(yaml.safe_dump(prof, sort_keys=False))

    passed, failed, errors = device_offsets.validate_offsets(f)
    assert failed == 0, errors
    assert passed == 9  # ibss 4 + ibec 1 + ramdisk 1 + txm 1 + daemons 1 + kernel 1
    assert device_offsets.pending_entries(f) == 2


def test_list_status_pending(tmp_path, monkeypatch):
    monkeypatch.setattr(device_offsets, "OFFSETS_DIR", tmp_path)
    prof = _base_profile()
    prof["patches"]["txm"]["query_module0"]["pending"] = True
    prof["patches"]["txm"]["query_module0"]["offset"] = SENTINEL
    (tmp_path / "iPhone12,1_27.0b2.yaml").write_text(yaml.safe_dump(prof, sort_keys=False))

    rows = device_offsets.list_offset_files()
    assert len(rows) == 1
    assert rows[0]["status"] == "pending"
    assert rows[0]["pending"] == 1

    (tmp_path / "iPhone12,3_27.0b2.yaml").write_text(yaml.safe_dump(_base_profile(), sort_keys=False))
    rows = device_offsets.list_offset_files()
    by_file = {r["file"]: r for r in rows}
    assert by_file["iPhone12,3_27.0b2.yaml"]["status"] == "ready"
    assert by_file["iPhone12,1_27.0b2.yaml"]["status"] == "pending"


def test_set_active_device_refuses_pending(tmp_path, monkeypatch, capsys):
    prof = _base_profile()
    prof["patches"]["ibss"]["image4_validate_nop"]["pending"] = True
    prof["patches"]["ibss"]["image4_validate_nop"]["offset"] = SENTINEL
    f = tmp_path / "pending.yaml"
    f.write_text(yaml.safe_dump(prof, sort_keys=False))

    assert device_offsets.set_active_device(f) is False
    assert "pending" in capsys.readouterr().out.lower()
    # nothing was written
    assert not (Path(__file__).parent.parent / "active_device.yaml").exists()
