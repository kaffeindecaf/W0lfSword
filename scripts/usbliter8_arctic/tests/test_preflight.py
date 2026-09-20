"""Tests for preflight verification (preflight.py).

Preflight is the gate that stops a build when the profile does not match the
firmware component, so the classification rules and the verdict are pinned
here, including the "recorded evidence then wrong component" case that is the
whole point of the feature.
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).parent.parent))

import preflight  # noqa: E402

ROOT = Path(__file__).parent.parent

COMPONENT = bytearray(0x4000)
# real AArch64 encodings, little-endian byte order as they sit in the image:
# b.ne #0x23fdc, mov x0,x20, adrp x2, add x2,x2,#imm, bl, nop
W_BNE = bytes.fromhex("01070054")
W_MOV = bytes.fromhex("e00314aa")
W_ADRP = bytes.fromhex("820800b0")
W_ADD = bytes.fromhex("42341f91")
W_BL = bytes.fromhex("65faff97")
W_NOP = bytes.fromhex("1f2003d5")
COMPONENT[0x1000:0x1004] = W_BNE
COMPONENT[0x1004:0x1008] = W_MOV
COMPONENT[0x2000:0x2004] = W_BL
COMPONENT[0x3000:0x3004] = W_ADRP
COMPONENT[0x3004:0x3008] = W_ADD


@pytest.fixture
def component(tmp_path):
    d = tmp_path / "comp"
    d.mkdir()
    (d / "ibss.raw").write_bytes(bytes(COMPONENT))
    (d / "txm.raw").write_bytes(bytes(COMPONENT))
    return d


@pytest.fixture
def profile_path(tmp_path):
    """Small profile with iBSS sites matching the component above."""
    return _write_profile(tmp_path, {
        "ibss": {
            "image4_validate_nop": {"offset": 0x1000, "value": "1f2003d5"},
            "image4_validate_ret0": {"offset": 0x1004, "value": "000080d2"},
            "boot_args_adrp": {"offset": 0x3000, "value": "021200d0"},
            "boot_args_add": {"offset": 0x3004, "value": "42003f91"},
            "boot_args_string": {"offset": 0x3100, "value": "-v wdt=-1 rd=md0 -restore"},
        },
        "txm": {"query_module0": {"offset": 0x2000, "value": "000080d2"}},
        "kernel": [{"name": "USB Restricted Mode bypass", "offset": 0x1000,
                    "value": "200080d2c0035fd6"}],
    })


def _write_profile(tmp_path: Path, patches: dict) -> Path:
    # a filename no real profile uses, so committed evidence files cannot leak in
    path = tmp_path / "iPhone12,1_99.9.yaml"
    path.write_text(yaml.safe_dump({
        "device": "iPhone 11", "model": "iPhone12,1", "ios_version": "27.0",
        "build": "24A437", "soc": "A13", "board": "n104ap", "apticket": "t8030",
        "patches": patches,
    }, sort_keys=False))
    return path


# ── classification ─────────────────────────────────────────────────

def test_plausible_when_site_decodes_and_value_absent(component, profile_path):
    report = preflight.run_preflight(profile_path, components=component)
    by_name = {(s.section, s.entry): s for s in report.sites}
    site = by_name[("ibss", "image4_validate_nop")]
    assert site.status == "plausible"
    assert "b.ne" in site.detail


def test_string_slot_all_zeros_is_plausible(component, profile_path):
    report = preflight.run_preflight(profile_path, components=component)
    site = next(s for s in report.sites if s.entry == "boot_args_string")
    assert site.status == "plausible"
    assert "empty string slot" in site.detail


def test_already_patched_detected(component, tmp_path):
    comp = bytearray(COMPONENT)
    comp[0x1000:0x1004] = bytes.fromhex("1f2003d5")
    (component / "ibss.raw").write_bytes(bytes(comp))
    path = _write_profile(tmp_path, {"ibss": {
        "image4_validate_nop": {"offset": 0x1000, "value": "1f2003d5"}}})
    report = preflight.run_preflight(path, components=component)
    assert report.sites[0].status == "already-patched"


def test_implausible_when_site_does_not_decode(component, tmp_path):
    comp = bytearray(COMPONENT)
    comp[0x1000:0x1004] = b"\x00\x00\x00\x00"
    (component / "ibss.raw").write_bytes(bytes(comp))
    path = _write_profile(tmp_path, {"ibss": {
        "image4_validate_nop": {"offset": 0x1000, "value": "1f2003d5"}}})
    report = preflight.run_preflight(path, components=component)
    assert report.sites[0].status == "implausible"
    assert report.verdict == "blocked"


def test_out_of_range_detected(component, tmp_path):
    path = _write_profile(tmp_path, {"ibss": {
        "image4_validate_nop": {"offset": 0x900000, "value": "1f2003d5"}}})
    report = preflight.run_preflight(path, components=component)
    assert report.sites[0].status == "out-of-range"
    assert report.verdict == "blocked"


def test_pending_entry_is_skipped_not_failed(component, tmp_path):
    path = _write_profile(tmp_path, {"ibss": {
        "image4_validate_nop": {"offset": 0xDEADBEEF, "value": "1f2003d5", "pending": True}}})
    report = preflight.run_preflight(path, components=component)
    assert report.sites[0].status == "skipped"
    assert "pending" in report.sites[0].detail
    assert report.verdict == "review"
    assert report.pending == 1


def test_sections_without_component_are_skipped(component, profile_path):
    report = preflight.run_preflight(profile_path, components=component)
    kernel = [s for s in report.sites if s.section == "kernel"]
    assert kernel and kernel[0].status == "skipped"
    assert "IMG4-encrypted" in kernel[0].detail


# ── recorded evidence: the self-verifying behaviour ────────────────

def test_record_then_match_and_wrong_component_blocks(component, profile_path):
    report = preflight.run_preflight(profile_path, components=component, record=True)
    assert report.verdict in ("ok", "review")
    evidence = json.loads((ROOT / "offsets" / "evidence" / f"{profile_path.stem}.json").read_text())
    assert evidence["components"]["ibss"]["sha256"]
    assert evidence["entries"]["ibss.image4_validate_nop"]["original"] == W_BNE.hex()

    # same component again: every recorded site matches
    again = preflight.run_preflight(profile_path, components=component)
    matched = [s for s in again.sites if s.status == "match"]
    assert len(matched) >= 5
    assert again.count("changed") == 0

    # a different build/board: recorded bytes are not there any more
    other = component.parent / "comp_other"
    other.mkdir()
    shifted = bytearray(COMPONENT)
    shifted[0x1000:0x1008] = bytes(0x4000)
    (other / "ibss.raw").write_bytes(bytes(shifted))
    wrong = preflight.run_preflight(profile_path, components=other)
    assert wrong.count("changed") >= 1
    assert wrong.verdict == "blocked"


def test_evidence_file_is_cleaned_up(profile_path):
    """The record test writes evidence for a fake profile name only, so real
    profiles' evidence files are never touched by the suite."""
    path = ROOT / "offsets" / "evidence" / f"{profile_path.stem}.json"
    assert profile_path.stem.endswith("_99.9"), "test must not use a real profile name"
    if path.exists():
        path.unlink()


# ── structure checks (no component needed) ─────────────────────────

def test_structure_checks_find_duplicates_and_overlaps(tmp_path):
    path = _write_profile(tmp_path, {"ibss": {
        "a": {"offset": 0x1000, "value": "1f2003d5"},
        "b": {"offset": 0x1000, "value": "000080d2"},
        "c": {"offset": 0x1002, "value": "000080d2c0035fd6"},
    }})
    profile = yaml.safe_load(path.read_text())
    notes = "\n".join(preflight.structure_checks(profile))
    assert "share offset" in notes
    assert "overlaps" in notes


def test_provenance_mismatch_is_an_error(tmp_path, component):
    (component / "provenance.txt").write_text(
        "ipsw: https://example/iPad12,3_27.0_24A437_Restore.ipsw\n"
        "device: iPhone 11 Pro (iPhone12,3) board d421ap\n")
    errors, notes = preflight.component_identity(component, {"model": "iPhone12,1", "build": "24A437"})
    assert errors and "iPhone12,1" in errors[0]


# ── CLI: json, exit codes ──────────────────────────────────────────

def test_cli_json_and_exit_code(component, profile_path):
    out = subprocess.run([sys.executable, str(ROOT / "preflight.py"), str(profile_path),
                          "--components", str(component), "--json"],
                         capture_output=True, text=True, cwd=ROOT)
    assert out.returncode == 0, out.stderr
    data = json.loads(out.stdout)
    assert data["verdict"] in ("ok", "review")
    assert data["summary"]["verified"] >= 4
    assert data["components"]["ibss"]["size"] == len(COMPONENT)
    assert any(s["status"] == "skipped" for s in data["sites"])


def test_cli_blocks_with_exit_code_2(component, tmp_path):
    path = _write_profile(tmp_path, {"ibss": {
        "image4_validate_nop": {"offset": 0x900000, "value": "1f2003d5"}}})
    out = subprocess.run([sys.executable, str(ROOT / "preflight.py"), str(path),
                          "--components", str(component)],
                         capture_output=True, text=True, cwd=ROOT)
    assert out.returncode == 2
    assert "BLOCKED" in out.stdout


def test_cli_json_stays_clean(profile_path, component):
    """--json must not be polluted by the human table or banners."""
    out = subprocess.run([sys.executable, str(ROOT / "preflight.py"), str(profile_path),
                          "--components", str(component), "--json"],
                         capture_output=True, text=True, cwd=ROOT)
    json.loads(out.stdout)  # raises if anything else reached stdout


# ── components from a local IPSW ───────────────────────────────────

def test_read_components_from_ipsw(tmp_path):
    import zipfile
    ipsw = tmp_path / "iPhone12,1_27.0_24A437_Restore.ipsw"
    with zipfile.ZipFile(ipsw, "w") as zf:
        zf.writestr("Firmware/dfu/iBSS.n104.RELEASE.im4p", bytes(COMPONENT[:0x100]))
        zf.writestr("Firmware/dfu/iBEC.n104.RELEASE.im4p", bytes(COMPONENT[:0x100]))
        zf.writestr("Firmware/txm.iphoneos.release.im4p", bytes(COMPONENT[:0x50]))
    out = preflight.read_components_from_ipsw(ipsw, {"model": "iPhone12,1"})
    assert set(out) == {"ibss", "ibec", "txm"}
    assert out["ibss"][1] == bytes(COMPONENT[:0x100])
    assert "iBSS.n104" in out["ibss"][0]
