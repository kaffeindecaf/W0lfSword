"""Tests for `components.py`: per-device IPSW component resolution.

Component file names are not derivable from the board id (iPad 9's iBSS is
`iBSS.ipad12p.RELEASE.im4p`, iPad 8's is `iBSS.ipad11b...`), so the resolver
reads `DEVICE_DB` and refuses to guess when several candidates match.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import components as comp  # noqa: E402

IPAD9 = {"model": "iPad12,1", "board": "j181ap"}
IPAD9_CELL = {"model": "iPad12,2", "board": "j182ap"}
IPHONE123 = {"model": "iPhone12,3", "board": "d421ap"}
IPAD_MINI5 = {"model": "iPad11,1", "board": "j211ap"}
UNKNOWN_DEVICE = {"model": "iPhone99,9", "board": "z999ap"}


def _tree(tmp_path: Path, files: list[str]) -> Path:
    for rel in files:
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"\x00" * 16)
    return tmp_path


# ── naming table ────────────────────────────────────────────────────

def test_ipad_component_name_is_not_the_board_id():
    assert comp.component_stem(IPAD9, "ibss") == "ipad12p"
    assert comp.component_stem(IPAD9_CELL, "ibss") == "ipad12p"
    assert comp.component_stem(IPHONE123, "ibss") == "d421"


def test_ipad_mini_uses_the_sibling_family_name():
    # j211ap boots Firmware/dfu/iBSS.j210.RELEASE.im4p
    assert comp.component_stem(IPAD_MINI5, "ibss") == "j210"


def test_kernel_component_is_per_device():
    assert comp.component_stem(IPAD9, "kernelcache") == "kernelcache.release.ipad12p"
    assert comp.component_stem({"model": "iPhone12,1"}, "kernelcache") == "kernelcache.release.iphone12b"


def test_unknown_device_falls_back_to_the_board_id():
    assert comp.component_stem(UNKNOWN_DEVICE, "ibss") == "z999"
    assert comp.exact_names(UNKNOWN_DEVICE, "devicetree") == ["DeviceTree.z999ap.im4p"]


def test_entry_patterns_match_what_a_ranged_fetch_looks_for():
    assert comp.entry_patterns(IPAD9, "ibss") == [("iBSS.ipad12p.RELEASE.im4p",)]
    assert comp.entry_patterns(IPAD9, "kernelcache") == [("kernelcache.release.ipad12p",)]
    assert comp.entry_patterns(IPHONE123, "ibec") == [("iBEC.d421.RELEASE.im4p",)]
    assert ("Firmware/txm", ".im4p") in comp.entry_patterns(IPHONE123, "txm")


# ── filesystem resolution ───────────────────────────────────────────

def test_ipad9_ibss_resolves_on_a_real_ipad_layout(tmp_path):
    """The board-derived name `iBSS.j181...` does not exist on an iPad 9."""
    root = _tree(tmp_path, ["Firmware/dfu/iBSS.ipad12p.RELEASE.im4p"])
    path, _cands, reason = comp.find_component(root, "ibss", IPAD9)
    assert path is not None and path.name == "iBSS.ipad12p.RELEASE.im4p"
    assert reason == ""


def test_iphone_still_resolves_by_exact_name(tmp_path):
    root = _tree(tmp_path, ["Firmware/dfu/iBSS.d421.RELEASE.im4p",
                            "Firmware/dfu/iBSS.d421.RESEARCH_RELEASE.im4p"])
    path, _cands, _reason = comp.find_component(root, "ibss", IPHONE123)
    assert path is not None and "RESEARCH" not in path.name


def test_research_images_are_never_patched(tmp_path):
    root = _tree(tmp_path, ["Firmware/dfu/iBSS.d421.RESEARCH_RELEASE.im4p"])
    path, cands, reason = comp.find_component(root, "ibss", IPHONE123)
    assert path is None and cands == []
    assert "no iBSS component" in reason


def test_sibling_family_images_do_not_confuse_a_known_device(tmp_path):
    """iPad mini 5's IPSW carries j210 and j217 images; the table picks j210."""
    root = _tree(tmp_path, ["Firmware/dfu/iBSS.j217.RELEASE.im4p",
                            "Firmware/dfu/iBSS.j210.RELEASE.im4p"])
    path, _cands, reason = comp.find_component(root, "ibss", IPAD_MINI5)
    assert path is not None and path.name == "iBSS.j210.RELEASE.im4p"
    assert reason == ""


def test_ambiguous_candidates_are_refused_not_guessed(tmp_path):
    """A device with no table entry and several sibling images must not guess."""
    root = _tree(tmp_path, ["Firmware/dfu/iBSS.z998.RELEASE.im4p",
                            "Firmware/dfu/iBSS.z997.RELEASE.im4p"])
    path, cands, reason = comp.find_component(root, "ibss", UNKNOWN_DEVICE)
    assert path is None
    assert len(cands) == 2
    assert "--force-component" in reason


def test_force_component_takes_a_deterministic_candidate(tmp_path):
    root = _tree(tmp_path, ["Firmware/dfu/iBSS.z998.RELEASE.im4p",
                            "Firmware/dfu/iBSS.z997.RELEASE.im4p"])
    path, _cands, reason = comp.find_component(root, "ibss", UNKNOWN_DEVICE, force=True)
    assert path is not None and path.name == "iBSS.z997.RELEASE.im4p"
    assert reason == "forced"


def test_extracted_raw_payload_wins(tmp_path):
    """fetch_components writes <section>.raw; those are the bytes offsets refer to."""
    root = _tree(tmp_path, ["devicetree.raw", "Firmware/all_flash/DeviceTree.j181ap.im4p"])
    path, _cands, reason = comp.find_component(root, "devicetree", IPAD9)
    assert path is not None and path.name == "devicetree.raw"
    assert reason == ""


def test_kernelcache_matches_the_device_component(tmp_path):
    root = _tree(tmp_path, ["kernelcache.release.ipad12p", "kernelcache.research.ipad12p"])
    path, _cands, _reason = comp.find_component(root, "kernelcache", IPAD9)
    assert path is not None and path.name == "kernelcache.release.ipad12p"


def test_modern_restore_ramdisk_is_flagged(tmp_path):
    """iOS 26/27 IPSWs ship a plain root-level dmg, not an im4p."""
    root = _tree(tmp_path, ["043-69093-771.dmg", "043-69412-662.dmg.aea"])
    path, _cands, reason = comp.find_component(root, "restoreramdisk", IPAD9)
    assert path is not None and path.name == "043-69093-771.dmg"
    assert reason == "modern-dmg-layout"


def test_classic_im4p_ramdisk_still_resolves(tmp_path):
    root = _tree(tmp_path, ["Firmware/all_flash/094-13753-150.dmg",
                            "Firmware/all_flash/094-13753-150.dmg.im4p"])
    path, _cands, reason = comp.find_component(root, "restoreramdisk", IPHONE123)
    assert path is not None and path.name.endswith(".im4p")
    assert reason == ""


def test_missing_component_reports_where_it_looked(tmp_path):
    root = _tree(tmp_path, ["kernelcache.release.ipad12p"])
    path, cands, reason = comp.find_component(root, "ibss", IPAD9)
    assert path is None and cands == []
    assert str(root) in reason


def test_unknown_kind_is_an_error(tmp_path):
    with pytest.raises(ValueError):
        comp.find_component(tmp_path, "sep-firmware", IPAD9)
