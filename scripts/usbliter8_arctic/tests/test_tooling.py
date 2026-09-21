"""Tests for the tooling added around the profiles: coverage gaps, the in-repo
canonical snapshot, the migration report verdict/confidence floor, and the
cfw_builder profile gate.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).parent.parent))

import cfw_builder  # noqa: E402
import migrate  # noqa: E402
import profile_gen  # noqa: E402
from device_offsets import SENTINEL  # noqa: E402
from fingerprint import MatchResult  # noqa: E402

ROOT = Path(__file__).parent.parent


def _result(name, target_offset, confidence=0.95, method="pattern", **kw):
    delta = None if target_offset is None else target_offset - 0x1000
    return MatchResult(name=name, base_offset=0x1000, target_offset=target_offset,
                       delta=delta, method=method,
                       confidence=confidence, value_changed=False,
                       old_value="1f2003d5", new_value="1f2003d5", **kw)


def _profile(entries: dict | None = None, **meta) -> dict:
    base = {"device": "iPhone 11", "model": "iPhone12,1", "ios_version": "27.0",
            "build": "24A437", "soc": "A13", "board": "n104ap", "apticket": "t8030"}
    base.update(meta)
    base["patches"] = entries or {"ibss": {"image4_validate_nop": {"offset": 0x1000, "value": "1f2003d5"}}}
    return base


# ── coverage gaps ──────────────────────────────────────────────────

def test_section_stats_counts_pending_as_unfilled():
    stats = profile_gen.section_stats(_profile({
        "ibss": {"a": {"offset": 0x1000, "value": "1f2003d5"},
                 "b": {"offset": SENTINEL, "value": "1f2003d5", "pending": True}},
        "kernel": [{"name": "x", "offset": 0x2000, "value": "1f2003d5"}],
        "daemons": {"ctkd": {"ret0": {"offset": 0x10, "value": "000080d2"}}},
        "devicetree": {"remove_content_protect": True},
    }))
    assert stats["ibss"] == (1, 2)
    assert stats["kernel"] == (1, 1)
    assert stats["daemons"] == (1, 1)
    assert "devicetree" not in stats  # structural flags are not entries


def test_kernel_component_mismatch_flags_cross_component_propagation(tmp_path, monkeypatch):
    monkeypatch.setattr(profile_gen, "OFFSETS_DIR", tmp_path)
    (tmp_path / "iPhone12,3_27.0b2.yaml").write_text(
        yaml.safe_dump(_profile(model="iPhone12,3", device="iPhone 11 Pro")))
    (tmp_path / "iPhone12,1_27.0b2.yaml").write_text(yaml.safe_dump(
        _profile(model="iPhone12,1", propagated_from="iPhone12,3_27.0b2.yaml")))
    (tmp_path / "iPhone12,5_27.0b2.yaml").write_text(yaml.safe_dump(
        _profile(model="iPhone12,5", propagated_from="iPhone12,3_27.0b2.yaml")))

    own, source = profile_gen.kernel_component_mismatch(tmp_path / "iPhone12,1_27.0b2.yaml")
    assert own == "kernelcache.release.iphone12b"
    assert source == "kernelcache.release.iphone12"
    # iPhone12,5 ships the same component as iPhone12,3 — no flag
    assert profile_gen.kernel_component_mismatch(tmp_path / "iPhone12,5_27.0b2.yaml") == ("", "")


def test_coverage_data_shape(monkeypatch, tmp_path):
    monkeypatch.setattr(profile_gen, "OFFSETS_DIR", tmp_path)
    (tmp_path / "iPhone12,3_27.0b2.yaml").write_text(yaml.safe_dump(
        _profile(model="iPhone12,3", ios_version="27.0b2")))
    data = profile_gen.coverage_data()
    assert "devices" in data and "summary" in data
    entry = next(d for d in data["devices"] if d["model"] == "iPhone12,3")
    assert entry["profiles"][0]["sections"]["ibss"] == {"filled": 1, "total": 1}
    json.dumps(data)  # must be JSON-serialisable for --json


def test_offsets_list_json_is_clean_stdout():
    out = subprocess.run([sys.executable, str(ROOT / "device_offsets.py"), "list", "--json"],
                         capture_output=True, text=True, cwd=ROOT)
    assert out.returncode == 0
    data = json.loads(out.stdout)
    assert any(p["model"] == "iPhone12,3" for p in data["profiles"])


# ── canonical snapshot ────────────────────────────────────────────

def test_canonical_path_falls_back_to_repo_copy(monkeypatch, tmp_path):
    monkeypatch.delenv("UL8_OFFSETS_YAML", raising=False)
    monkeypatch.setattr(migrate.Path, "home", classmethod(lambda cls: tmp_path))
    assert migrate._resolve_canonical_path() == ROOT / "offsets" / "canonical.yaml"


def test_canonical_path_env_wins(monkeypatch, tmp_path):
    monkeypatch.setenv("UL8_OFFSETS_YAML", str(tmp_path / "mine.yaml"))
    assert migrate._resolve_canonical_path() == tmp_path / "mine.yaml"


def test_repo_canonical_carries_corrected_b3_values():
    data = yaml.safe_load((ROOT / "offsets" / "canonical.yaml").read_text())
    block = data["constants"]["checkm8"]["ios_27_0b3"]
    assert block["txm_queryModule0"] == "0x39CA8"
    assert block["txm_queryModule1"] == "0x39E10"
    assert block["txm_queryModule2"] == "0x39FA4"
    assert data["constants"]["checkm8"]["ios_27_0b2"]["txm_queryModule0"] == "0x39CB0"


def test_canonical_crosscheck_agrees_with_repo_copy(monkeypatch):
    monkeypatch.setattr(migrate, "CANONICAL_PATH", ROOT / "offsets" / "canonical.yaml")
    base = _profile({"txm": {"query_module0": {"offset": 0x39CB0, "value": "000080d2"}}},
                    ios_version="27.0b2")
    target = _profile({"txm": {"query_module0": {"offset": 0x39CA8, "value": "000080d2"}}},
                      ios_version="27.0b3")
    results = {"txm": [_result("txm.query_module0", 0x39CA8)]}
    conflicts = migrate.check_canonical(base, target, results,
                                        base_version="27.0b2", target_version="27.0b3")
    assert conflicts == []


# ── migrate report verdict + confidence floor ─────────────────────

def test_report_verdict_ready_and_review():
    ready = migrate.format_report(Path("a.yaml"), Path("b.yaml"),
                                  {"kernel": [_result("kernel.x", 0x2000)]})
    assert "VERDICT: READY" in ready.splitlines()[2]

    review = migrate.format_report(Path("a.yaml"), Path("b.yaml"),
                                   {"kernel": [_result("kernel.y", 0x2000, confidence=0.30),
                                               _result("kernel.z", None, confidence=0.0,
                                                       method="failed")]})
    assert "REVIEW REQUIRED" in review.splitlines()[2]


def test_apply_offsets_skips_below_floor(tmp_path, capsys):
    target = tmp_path / "iPhone12,1_99.9.yaml"
    target.write_text(yaml.safe_dump(_profile()))
    migrate.apply_offsets(target, {"ibss": [_result("ibss.image4_validate_nop", 0x2222,
                                                    confidence=0.30)]},
                          _profile())
    written = yaml.safe_load(target.read_text())
    assert written["patches"]["ibss"]["image4_validate_nop"]["offset"] == 0x1000  # untouched
    assert "below the 0.90 confidence floor" in capsys.readouterr().out


def test_apply_offsets_force_low_writes(tmp_path):
    target = tmp_path / "iPhone12,1_99.9.yaml"
    target.write_text(yaml.safe_dump(_profile()))
    migrate.apply_offsets(target, {"ibss": [_result("ibss.image4_validate_nop", 0x2222,
                                                    confidence=0.30)]},
                          _profile(), min_confidence=0.0)
    written = yaml.safe_load(target.read_text())
    entry = written["patches"]["ibss"]["image4_validate_nop"]
    assert entry["offset"] == 0x2222
    assert entry["migrated"]["confidence"] == 0.3


# ── cfw_builder profile gate ──────────────────────────────────────

def test_gate_blocks_pending_profile(tmp_path, capsys):
    path = tmp_path / "iPhone12,1_99.9.yaml"
    path.write_text(yaml.safe_dump(_profile({
        "ibss": {"image4_validate_nop": {"offset": SENTINEL, "value": "1f2003d5",
                                         "pending": True}}})))
    cfw_builder.FORCE = False
    assert cfw_builder._profile_gate(path) is False
    out = capsys.readouterr().out
    assert "unresolved entry" in out


def test_gate_blocks_invalid_profile(tmp_path, capsys):
    path = tmp_path / "iPhone12,1_99.9.yaml"
    path.write_text(yaml.safe_dump(_profile({
        "ibss": {"bad": {"offset": 0, "value": "1f2003d5"}}})))
    cfw_builder.FORCE = False
    assert cfw_builder._profile_gate(path) is False
    assert "invalid" in capsys.readouterr().out


def test_gate_allows_clean_profile(tmp_path, capsys):
    """A clean profile must not be blocked. The name is deliberately one no
    real profile uses, so committed evidence files cannot leak into it."""
    path = tmp_path / "iPhone12,1_99.9.yaml"
    path.write_text(yaml.safe_dump(_profile()))
    cfw_builder.FORCE = False
    assert cfw_builder._profile_gate(path) is True


def test_gate_force_overrides(tmp_path):
    path = tmp_path / "iPhone12,1_99.9.yaml"
    path.write_text(yaml.safe_dump(_profile({
        "ibss": {"image4_validate_nop": {"offset": SENTINEL, "value": "1f2003d5",
                                         "pending": True}}})))
    cfw_builder.FORCE = True
    try:
        assert cfw_builder._profile_gate(path) is True
    finally:
        cfw_builder.FORCE = False


# ── kernel entries from another device's kernelcache are never applied ──

def test_invalid_component_kernel_entries_are_refused():
    import cfw_builder

    entries = [
        {"name": "good", "offset": 0x100, "value": "1f2003d5"},
        {"name": "stolen", "offset": 0x200, "value": "1f2003d5",
         "invalid_component": True, "reason": "iphone12 != ipad12p"},
    ]
    ok_entries, invalid = cfw_builder.appliable_kernel_entries(entries)
    assert [e["name"] for e in ok_entries] == ["good"]
    assert [e["name"] for e in invalid] == ["stolen"]


def test_appliable_kernel_entries_tolerates_junk():
    import cfw_builder

    ok_entries, invalid = cfw_builder.appliable_kernel_entries(
        [None, "nope", {}, {"offset": 1}, {"name": "ok", "offset": 2, "value": "1f2003d5"}])
    assert [e["name"] for e in ok_entries] == ["ok"]
    assert invalid == []


# ── a profile can declare a section blocked (wrong kernelcache component) ──

def test_gate_refuses_a_blocked_section(tmp_path, capsys):
    path = tmp_path / "iPad12,1_99.9.yaml"
    profile = _profile({"kernel": [{"name": "USB Restricted Mode bypass",
                                    "offset": 0x2894B68, "value": "200080d2c0035fd6"}]})
    profile["blockers"] = {"kernel": {"entries": 1, "reason": "iphone12 != ipad12p"}}
    path.write_text(yaml.safe_dump(profile))

    cfw_builder.FORCE = False
    assert cfw_builder._profile_gate(path) is False
    assert "iphone12 != ipad12p" in capsys.readouterr().out


def test_blocked_kernel_section_is_never_patched(monkeypatch):
    """Even with --force, entries from another device's kernelcache are refused."""
    called = []
    monkeypatch.setattr(cfw_builder, "_extract_im4p_to_raw", lambda *a, **k: called.append(a) or True)

    offsets = {"model": "iPad12,1",
               "blockers": {"kernel": {"entries": 1, "reason": "iphone12 != ipad12p"}},
               "patches": {"kernel": [{"name": "x", "offset": 0x100, "value": "1f2003d5"}]}}
    assert cfw_builder.patch_kernel("/nonexistent", offsets, "/tmp") is True
    assert called == [], "a blocked kernel section must not be extracted or patched"
    assert ("kernel", "skipped") == (cfw_builder.MANIFEST[-1][0], cfw_builder.MANIFEST[-1][1])


# ── component extraction without the macOS binaries (issue #4) ──────

def test_bundled_macho_tools_are_not_used_off_macos(monkeypatch, tmp_path):
    """tools/ holds Mach-O binaries: on Linux/Windows they must be skipped so the
    built-in Python codec handles extraction instead of a crash."""
    import cfw_builder

    bundled = tmp_path / "img4"
    bundled.write_bytes(b"\xcf\xfa\xed\xfe" + b"\x00" * 16)     # thin Mach-O magic
    monkeypatch.setattr(cfw_builder, "TOOLS_DIR", tmp_path)
    monkeypatch.setattr(cfw_builder.shutil, "which", lambda _n: None)

    if sys.platform == "darwin":
        assert cfw_builder._tool_available("img4") is True
    else:
        assert cfw_builder._tool_available("img4") is False

    native = tmp_path / "native-tool"
    native.write_bytes(b"\x7fELF" + b"\x00" * 16)
    assert cfw_builder._tool_available("native-tool") is (sys.platform != "darwin")


def test_path_tools_are_always_usable(monkeypatch):
    import cfw_builder
    monkeypatch.setattr(cfw_builder.shutil, "which", lambda name: "/usr/bin/" + name)
    assert cfw_builder._tool_available("img4") is True


def test_extract_falls_back_to_the_python_decoder(monkeypatch, tmp_path):
    import cfw_builder
    import img4wrap

    payload = bytes.fromhex("1f2003d5000080d2") * 64
    container = tmp_path / "iBSS, RELEASE.im4p"
    container.write_bytes(img4wrap.wrap(payload, "ibss", "mBoot-test"))
    out = tmp_path / "iBSS.raw"

    monkeypatch.setattr(cfw_builder, "_tool_available", lambda _n: False)
    assert cfw_builder._extract_im4p_to_raw(container, out) is True
    assert out.read_bytes() == payload


def test_wrap_falls_back_to_the_python_writer(monkeypatch, tmp_path):
    import cfw_builder
    import img4wrap

    payload = bytes.fromhex("000080d2c0035fd6") * 32
    raw = tmp_path / "iBEC.raw"
    raw.write_bytes(payload)
    dest = tmp_path / "iBEC.d421.RELEASE.im4p"
    dest.write_bytes(img4wrap.wrap(b"original" * 8, "ibec", "mBoot-20457"))

    monkeypatch.setattr(cfw_builder, "_tool_available", lambda _n: False)
    assert cfw_builder._wrap_raw_to_im4p(raw, dest, "ibec") is True

    back = img4wrap.unwrap_file(dest)
    assert back.payload == payload
    assert back.fourcc == "ibec"
    assert back.description == "mBoot-20457"      # Apple's metadata is kept


def test_wrap_reports_an_undecodable_payload(monkeypatch, tmp_path):
    import cfw_builder
    monkeypatch.setattr(cfw_builder, "_tool_available", lambda _n: False)
    raw = tmp_path / "iBSS.raw"
    raw.write_bytes(b"payload")
    assert cfw_builder._wrap_raw_to_im4p(raw, tmp_path / "out.im4p", "ibss") is True

    monkeypatch.setitem(sys.modules, "img4wrap", None)   # simulate a broken import
    assert cfw_builder._extract_im4p_to_raw(raw, tmp_path / "x.raw") is False
