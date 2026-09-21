"""Tests for the ranged component fetcher: caching, evidence checks, provenance.

Everything runs against a synthetic local zip (kczip reads local paths like a
server), so no test touches Apple's CDN.
"""

from __future__ import annotations

import hashlib
import json
import sys
import zipfile
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).parent.parent))

import fetch_components  # noqa: E402
import img4wrap  # noqa: E402

PROFILE = {
    "model": "iPhone12,1",
    "device_model": "iPhone12,1",
    "device": "iPhone 11",
    "board": "n104ap",
    "soc": "A13",
    "ios_version": "27.0",
    "build": "24A437",
    "kernel_component": "kernelcache.release.iphone12b",
    "patches": {
        "ibss": [{"offset": 16, "value": "deadbeef"}],
        "ibec": [{"offset": 20, "value": "cafebabe"}],
        "txm": [{"offset": 24, "value": "aabbccdd"}],
        "kernel": [{"offset": 28, "value": "11223344"}],
    },
}

ENTRY_NAMES = {
    "ibss": "Firmware/dfu/iBSS.n104.RELEASE.im4p",
    "ibec": "Firmware/dfu/iBEC.n104.RELEASE.im4p",
    "txm": "Firmware/txm.iphoneos.release.im4p",
    "devicetree": "Firmware/all_flash/DeviceTree.n104ap.im4p",
    "kernelcache": "kernelcache.release.iphone12b",
}


@pytest.fixture
def fake_ipsw(tmp_path):
    """A local zip that looks like an IPSW (stored entries, kczip-readable)."""
    path = tmp_path / "iPhone12,1_27.0_24A437_Restore.ipsw"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_STORED) as zf:
        for comp, name in ENTRY_NAMES.items():
            zf.writestr(name, f"{comp}-payload".encode() * 40)
        zf.writestr("Firmware/RESEARCH/skip-me.im4p", b"x" * 10)
    return path


@pytest.fixture(autouse=True)
def isolated_evidence(tmp_path, monkeypatch):
    """Never read the repo's real evidence files while testing verdicts."""
    empty = tmp_path / "evidence-none"
    empty.mkdir()
    monkeypatch.setattr(fetch_components, "EVIDENCE_DIR", empty)
    yield


@pytest.fixture
def profile_file(tmp_path):
    path = tmp_path / "iPhone12,1_27.0.yaml"
    path.write_text(yaml.safe_dump(PROFILE))
    return path


# ── profile driven planning ─────────────────────────────────────────

def test_components_come_from_the_profile(profile_file):
    values, comps = fetch_components.components_from_profile(profile_file)
    assert values["model"] == "iPhone12,1"
    assert values["build"] == "24A437"
    assert values["kernel_name"] == "kernelcache.release.iphone12b"
    # sections present in the profile, in component order
    assert comps == ["ibss", "ibec", "txm", "kernelcache"]


def test_component_list_is_validated(fake_ipsw, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(fetch_components, "DEFAULT_OUT_ROOT", tmp_path / "out")
    code = fetch_components.main(["--url", str(fake_ipsw), "--device", "iPhone12,1",
                                  "--entries", "ibss,nonsense"])
    assert code == 2
    assert "unknown component" in capsys.readouterr().out


# ── fetching, caching, provenance ───────────────────────────────────

def test_fetch_writes_components_and_provenance(fake_ipsw, tmp_path, capsys):
    out = tmp_path / "components"
    code = fetch_components.cmd_fetch(str(fake_ipsw), "iPhone12,1", out,
                                      ["ibss", "txm"], "", False, build="24A437")
    assert code == 0
    assert (out / "ibss.raw").read_bytes().startswith(b"ibss-payload")
    assert (out / "txm.raw").exists()

    provenance = json.loads((out / "provenance.json").read_text())
    assert provenance["model"] == "iPhone12,1"
    assert provenance["components"]["ibss"]["entry"] == ENTRY_NAMES["ibss"]
    assert provenance["components"]["ibss"]["skipped"] is False
    assert (out / "provenance.txt").read_text().startswith("ipsw:")
    printed = capsys.readouterr().out
    assert "component(s) fetched" in printed
    assert "MB/s" in printed                      # per-component throughput is reported


def test_second_run_skips_what_is_already_there(fake_ipsw, tmp_path, capsys):
    out = tmp_path / "components"
    fetch_components.cmd_fetch(str(fake_ipsw), "iPhone12,1", out, ["ibss"], "", False)
    before = (out / "ibss.raw").stat().st_mtime_ns

    code = fetch_components.cmd_fetch(str(fake_ipsw), "iPhone12,1", out, ["ibss"], "", False)
    assert code == 0
    assert "cached" in capsys.readouterr().out
    assert (out / "ibss.raw").stat().st_mtime_ns == before     # untouched

    fetch_components.cmd_fetch(str(fake_ipsw), "iPhone12,1", out, ["ibss"], "", False,
                               refresh=True)
    provenance = json.loads((out / "provenance.json").read_text())
    assert provenance["components"]["ibss"]["skipped"] is False


def test_parallel_fetch_matches_sequential(fake_ipsw, tmp_path):
    one = tmp_path / "seq"
    many = tmp_path / "par"
    fetch_components.cmd_fetch(str(fake_ipsw), "iPhone12,1", one,
                               ["ibss", "ibec", "txm"], "", False)
    fetch_components.cmd_fetch(str(fake_ipsw), "iPhone12,1", many,
                               ["ibss", "ibec", "txm"], "", False, jobs=3)
    for comp in ("ibss", "ibec", "txm"):
        assert (one / f"{comp}.raw").read_bytes() == (many / f"{comp}.raw").read_bytes()


def test_missing_entry_is_reported_not_fatal(fake_ipsw, tmp_path, capsys):
    code = fetch_components.cmd_fetch(str(fake_ipsw), "iPhone12,1", tmp_path / "o",
                                      ["ibss", "restoreramdisk"], "", False)
    assert code == 1                                # one failed, one fetched
    assert "no matching entry" in capsys.readouterr().out


# ── evidence checking ───────────────────────────────────────────────

def test_evidence_match_and_mismatch(tmp_path, monkeypatch):
    payload = b"ibss-payload" * 40
    digest = hashlib.sha256(payload).hexdigest()

    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    (evidence_dir / "iPhone12,1_27.0.json").write_text(json.dumps({
        "profile": "iPhone12,1_27.0.yaml", "model": "iPhone12,1", "build": "24A437",
        "components": {"ibss": {"size": len(payload), "sha256": digest}},
    }))
    monkeypatch.setattr(fetch_components, "EVIDENCE_DIR", evidence_dir)

    assert fetch_components.check_against_evidence(
        "ibss", digest, "iPhone12,1", "24A437") == "match: iPhone12,1_27.0.json"
    assert fetch_components.check_against_evidence(
        "ibss", "0" * 64, "iPhone12,1", "24A437") == "differs: iPhone12,1_27.0.json"
    # another build, another device, or a component with no record: no verdict
    assert fetch_components.check_against_evidence("ibss", digest, "iPhone12,1", "24A5380h") == ""
    assert fetch_components.check_against_evidence("ibss", digest, "iPhone12,3", "24A437") == ""
    assert fetch_components.check_against_evidence("txm", digest, "iPhone12,1", "24A437") == ""


def test_fetch_reports_evidence_match(fake_ipsw, tmp_path, monkeypatch, capsys):
    # an evidence file that records exactly what this fake component holds
    payload = b"ibss-payload" * 40
    digest = hashlib.sha256(payload).hexdigest()
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    (evidence_dir / "iPhone12,1_27.0.json").write_text(json.dumps({
        "model": "iPhone12,1", "build": "24A437",
        "components": {"ibss": {"size": len(payload), "sha256": digest}},
    }))
    monkeypatch.setattr(fetch_components, "EVIDENCE_DIR", evidence_dir)

    code = fetch_components.cmd_fetch(str(fake_ipsw), "iPhone12,1", tmp_path / "o",
                                      ["ibss"], "", False, build="24A437")
    assert code == 0
    out = capsys.readouterr().out
    assert "matches evidence iPhone12,1_27.0.json" in out


def test_payload_identity_unwraps_containers(tmp_path):
    payload = b"patched" * 100
    container = tmp_path / "ibss.raw"
    container.write_bytes(img4wrap.wrap(payload, "ibss"))
    digest, size = fetch_components.payload_identity(container)
    assert digest == hashlib.sha256(payload).hexdigest()
    assert size == len(payload)

    raw = tmp_path / "plain.raw"
    raw.write_bytes(payload)
    assert fetch_components.payload_identity(raw) == (hashlib.sha256(payload).hexdigest(),
                                                      len(payload))


# ── url resolution ──────────────────────────────────────────────────

def test_url_resolution_prefers_the_cache(tmp_path, monkeypatch):
    monkeypatch.setattr(fetch_components, "URL_CACHE", tmp_path / "urls.json")
    (tmp_path / "urls.json").write_text(json.dumps({
        "iPhone12,1/24A437": {"url": "https://example.invalid/x.ipsw", "version": "27.0"},
    }))
    monkeypatch.setattr(fetch_components.urllib.request, "urlopen",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("network")))
    url, version = fetch_components.resolve_ipsw_url("iPhone12,1", "24A437")
    assert url == "https://example.invalid/x.ipsw" and version == "27.0"
