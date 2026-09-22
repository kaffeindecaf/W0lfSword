"""Tests for the beta-to-beta offset migration engine.

The milestone tests encode the b2 -> b3 Reference Oracle from
OffsetMigrationChecklist.md as synthetic binaries (or real profiles for
kernel/txm/ramdisk) and require the engine to reproduce the verified b3
offsets with high confidence and no wrong-HIGH results.
"""

import json
import random
import struct
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).parent.parent))

from fingerprint import (  # noqa: E402
    build_pattern,
    mask_insn,
    migrate_site,
    search_pattern,
)
from migrate import apply_delta_fallback  # noqa: E402

ROOT = Path(__file__).parent.parent

# ── mask_insn unit tests (hand-encoded AArch64) ─────────────────────

NOP = 0xD503201F  # nop — must pass through unmasked
RET = 0xD65F03C0  # ret — must pass through unmasked
MOV_X0_0 = 0xD2800000  # mov x0,#0 (imm16=0) — must pass through unchanged
MOV_X0_1 = 0xD2800020  # mov x0,#1 — imm16 must be masked
ADRP_X2_PAGE = 0xB0000542  # adrp x2, #0xa9000 (real b2 value)
ADD_X2_IMM = 0x91402142  # add x2,x2,#0x850 (real b2 value)
B_FWD = 0x14000028  # b #0x28 (real keep_nonce value)
LDR_LITERAL = 0x58000040  # ldr x0, #8


def test_mask_insn_keeps_opcode_register_bits():
    assert mask_insn(NOP) == NOP
    assert mask_insn(RET) == RET
    assert mask_insn(MOV_X0_0) == MOV_X0_0


def test_mask_insn_movz_zeroes_imm16():
    assert mask_insn(MOV_X0_1) == MOV_X0_0


def test_mask_insn_adrp_zeroes_immediates_keeps_rd():
    assert mask_insn(ADRP_X2_PAGE) == 0x90000002  # immlo+immhi zeroed, opcode+Rd kept


def test_mask_insn_add_immediate_zeroes_imm12():
    # shift=bits[23:22]=01 and imm12=bits[21:10] are zeroed
    assert mask_insn(ADD_X2_IMM) == 0x91000142


def test_mask_insn_branch_zeroes_imm26():
    assert mask_insn(B_FWD) == 0x14000000
    assert mask_insn(0x94000001) == 0x94000000  # bl


def test_mask_insn_ldr_literal_zeroes_imm19():
    assert mask_insn(LDR_LITERAL) == 0x58000000


def test_different_registers_still_differ_after_mask():
    other = ADRP_X2_PAGE ^ (0x1F << 0)  # Rd x2 -> x0
    assert mask_insn(other) != mask_insn(ADRP_X2_PAGE)


def test_mask_insn_subs_immediate_zeroes_shift_bits():
    # subs x2,x2,#0x850 (0xF1402142): S=1 add/sub family; must zero the
    # shift bits too (ldr/str-imm branch kept them before the #17 fix)
    assert mask_insn(0xF1402142) == 0xF1000142


def test_placeholder_value_rejected_by_validator(tmp_path):
    import device_offsets
    bad = tmp_path / "placeholder.yaml"
    bad.write_text("patches:\n  ibss:\n    x:\n      offset: 0x1000\n      value: \"????????\"\n")
    passed, failed, errors = device_offsets.validate_offsets(bad)
    assert failed == 1 and errors, (passed, failed, errors)


def test_update_entry_fills_placeholder_from_site(tmp_path):
    from fingerprint import MatchResult
    from migrate import _update_entry
    entry = {"offset": 0xDEADBEEF, "value": "????????"}
    r = MatchResult(name="x", base_offset=0x100, target_offset=0x200, delta=0x100,
                    method="pattern", confidence=0.95, value_changed=False,
                    old_value="420005b0", new_value="420005b0")
    _update_entry(entry, r)
    assert entry["offset"] == 0x200
    assert entry["value"] == "420005b0"
    assert entry["migrated"].get("value_filled_from_site") is True


# ── search_pattern ──────────────────────────────────────────────────

def test_search_pattern_finds_masked_match():
    hay = bytearray(64)
    struct.pack_into("<I", hay, 0x10, ADRP_X2_PAGE)
    struct.pack_into("<I", hay, 0x14, ADD_X2_IMM)
    pattern, mask = build_pattern(hay, 0x10, window=8)
    # moved-immediate variant of add must still match
    struct.pack_into("<I", hay, 0x30, ADRP_X2_PAGE)
    struct.pack_into("<I", hay, 0x34, 0x91404142)  # add x2,x2,#0x1050
    hits = search_pattern(hay, pattern, mask)
    assert 0x10 in hits and 0x30 in hits


def test_search_pattern_rejects_register_change():
    hay = bytearray(64)
    struct.pack_into("<I", hay, 0x10, ADRP_X2_PAGE)
    struct.pack_into("<I", hay, 0x14, ADD_X2_IMM)
    pattern, mask = build_pattern(hay, 0x10, window=8)
    # same opcodes but Rd changed — must NOT match
    struct.pack_into("<I", hay, 0x30, ADRP_X2_PAGE ^ 0x1F)
    struct.pack_into("<I", hay, 0x34, 0x9140214F)  # add x15,x2,#0x850
    assert search_pattern(hay, pattern, mask) == [0x10]


# ── milestone fixtures: b2 -> b3 oracle (iPhone12,3) ────────────────

B2_IBSS = {
    "image4_validate_nop": (0x23DB0, b"\x1f\x20\x03\xd5"),
    "image4_validate_ret0": (0x23DB4, b"\x00\x00\x80\xd2"),
    "boot_args_adrp": (0x2AFBC, b"\x42\x00\x05\xb0"),
    "boot_args_add": (0x2AFC0, b"\x42\x21\x40\x91"),
    "boot_args_string": (0xD3850, b"-v wdt=-1 rd=md0 -restore"),
}

B3_IBSS = {
    "image4_validate_nop": (0x23EFC, b"\x1f\x20\x03\xd5"),
    "image4_validate_ret0": (0x23F00, b"\x00\x00\x80\xd2"),
    "boot_args_adrp": (0x2B0F4, b"\x42\x00\x05\xb0"),
    "boot_args_add": (0x2B0F8, b"\x42\x2d\x40\x91"),  # VALUE CHANGED
    "boot_args_string": (0xD3960, b"-v wdt=-1 rd=md0 -restore"),
}

IBEC_EXTRA_B2 = {"keep_nonce_b": (0x36BD0, b"\x28\x00\x00\x14")}
IBEC_EXTRA_B3 = {"keep_nonce_b": (0x36BD0, b"\x28\x00\x00\x14")}

FIXTURE_SIZE = 0x100000


def _name_filler(name: str) -> bytes:
    """Deterministic 28-byte context placed after every site, identical for
    the same entry name in both builds (models code that moves as a unit)."""
    h = 0
    for ch in name:
        h = (h * 131 + ord(ch)) & 0xFFFFFFFF
    out = bytearray()
    for i in range(7):
        out += struct.pack("<I", (h * (i + 3) + 0x9E3779B9) & 0xFFFFFFFF)
    return bytes(out)


def _make_component(entries: dict) -> bytes:
    data = bytearray(FIXTURE_SIZE)
    rng = random.Random(42)
    for i in range(0, FIXTURE_SIZE, 4):
        struct.pack_into("<I", data, i, rng.getrandbits(32))
    for name, (off, val) in entries.items():
        data[off:off + len(val)] = val
        ctx = _name_filler(name)
        data[off + len(val):off + len(val) + len(ctx)] = ctx
    return bytes(data)


@pytest.fixture(scope="module")
def ibss_pair():
    return _make_component(B2_IBSS), _make_component(B3_IBSS)


@pytest.fixture(scope="module")
def ibec_pair():
    return (_make_component({**B2_IBSS, **IBEC_EXTRA_B2}),
            _make_component({**B3_IBSS, **IBEC_EXTRA_B3}))


def _assert_milestone(entries_b2, entries_b3, base_data, target_data):
    """Every entry must migrate to the oracle target offset with conf >= 0.90
    and only boot_args_add may be flagged VALUE_CHANGED. No wrong-HIGH."""
    for name, (base_off, _) in entries_b2.items():
        r = migrate_site(base_data, target_data, base_off, name=name)
        expected = entries_b3[name][0]
        assert r.target_offset == expected, (
            f"{name}: got 0x{r.target_offset:X}, want 0x{expected:X} "
            f"(conf {r.confidence}, candidates {[hex(c) for c in r.candidates[:3]]})")
        assert r.confidence >= 0.90, f"{name}: confidence {r.confidence} too low"
        if name == "boot_args_add":
            assert r.value_changed, f"{name}: must be flagged VALUE_CHANGED"
        else:
            assert not r.value_changed, f"{name}: unexpected VALUE_CHANGED"


def test_milestone_ibss(ibss_pair):
    _assert_milestone(B2_IBSS, B3_IBSS, *ibss_pair)


def test_milestone_ibec(ibec_pair):
    merged_b2 = {**B2_IBSS, **IBEC_EXTRA_B2}
    merged_b3 = {**B3_IBSS, **IBEC_EXTRA_B3}
    _assert_milestone(merged_b2, merged_b3, *ibec_pair)


def test_value_changed_detects_immediate_only():
    base = _make_component({"x": (0x1000, b"\x42\x21\x40\x91")})
    target = _make_component({"x": (0x2000, b"\x42\x2d\x40\x91")})
    r = migrate_site(base, target, 0x1000, name="x")
    assert r.target_offset == 0x2000
    assert r.value_changed is True
    assert r.old_value == "42214091" and r.new_value == "422d4091"
    assert r.suggested_value == "422d4091"  # 2.4: recomputed immediate


def test_no_hit_returns_failed():
    base = _make_component({"x": (0x1000, b"\x1f\x20\x03\xd5")})
    target = _make_component({})  # nop never placed
    r = migrate_site(base, target, 0x1000, name="x")
    assert r.target_offset is None and r.method == "failed" and r.confidence == 0.0


# ── 2.2/2.5: kernel + txm + restoreramdisk milestones (real profiles) ──

def _load_profile(name: str) -> dict:
    with open(ROOT / "offsets" / name) as f:
        return yaml.safe_load(f)


@pytest.fixture(scope="module")
def b2b3_profiles():
    return (_load_profile("iPhone12,3_27.0b2.yaml"),
            _load_profile("iPhone12,3_27.0b3.yaml"))


def _payload_bytes(value) -> bytes:
    """Kernel entries carry either hex bytes or an ASCII payload (the kernel
    identity strings upstream rewrites to /PATCHED_ARM64_T8030)."""
    try:
        return bytes.fromhex(str(value))
    except ValueError:
        return str(value).encode()


def _kernel_entries(profile: dict) -> list[tuple[str, int, bytes]]:
    return [(e["name"], e["offset"], _payload_bytes(e["value"]))
            for e in profile["patches"]["kernel"]]


def _make_kernel_component(entries: list[tuple[str, int, bytes]]) -> bytes:
    size = max(off for _, off, _ in entries) + 0x100000
    rng = random.Random(7)
    data = bytearray(rng.randbytes(size))
    for name, off, val in entries:
        data[off:off + len(val)] = val
        ctx = _name_filler(name)
        data[off + len(val):off + len(val) + len(ctx)] = ctx
    return bytes(data)


def test_milestone_kernel(b2b3_profiles, kernel_pair):
    """2.2 acceptance: >=15 kernel entries correct at HIGH, zero wrong-HIGH."""
    b2, b3 = b2b3_profiles
    base_data, target_data = kernel_pair
    oracle = {e["name"]: e["offset"] for e in b3["patches"]["kernel"]}

    high = 0
    for name, off, _ in _kernel_entries(b2):
        r = migrate_site(base_data, target_data, off, name=name)
        assert r.target_offset == oracle[name], (
            f"{name}: got 0x{r.target_offset:X}, want 0x{oracle[name]:X} "
            f"(conf {r.confidence}, candidates {[hex(c) for c in r.candidates[:3]]})")
        assert r.confidence >= 0.90, f"{name}: confidence {r.confidence} too low"
        high += 1
    assert high >= 15


@pytest.fixture(scope="module")
def kernel_pair(b2b3_profiles):
    b2, b3 = b2b3_profiles
    return (_make_kernel_component(_kernel_entries(b2)),
            _make_kernel_component(_kernel_entries(b3)))


def _dict_entries(profile: dict, section: str) -> dict[str, tuple[int, bytes]]:
    return {k: (v["offset"], _payload_bytes(v["value"]))
            for k, v in profile["patches"][section].items()}


@pytest.mark.parametrize("section", ["txm", "restoreramdisk"])
def test_milestone_txm_ramdisk(b2b3_profiles, section):
    """2.5 acceptance: txm >=4/6, ramdisk 2/2 vs oracle."""
    b2, b3 = b2b3_profiles
    e2 = _dict_entries(b2, section)
    e3 = _dict_entries(b3, section)
    base_data = _make_component(e2)
    target_data = _make_component(e3)

    correct = 0
    for name, (off, _) in e2.items():
        r = migrate_site(base_data, target_data, off, name=name)
        assert r.target_offset == e3[name][0], (
            f"{section}.{name}: got 0x{r.target_offset:X}, want 0x{e3[name][0]:X} "
            f"(conf {r.confidence})")
        assert r.confidence >= 0.90, f"{section}.{name}: conf {r.confidence} too low"
        correct += 1
    minimum = 4 if section == "txm" else 2
    assert correct >= minimum


# ── 2.3: cluster-delta fallback ─────────────────────────────────────

def test_delta_fallback_infers_neighbor_delta():
    b2_entries = {"a": (0x1000, b"\x1f\x20\x03\xd5"),
                  "b": (0x1010, b"\x1f\x20\x03\xd5"),
                  "c": (0x1060, b"\x1f\x20\x03\xd5")}
    b3_entries = {"a": (0x1800, b"\x1f\x20\x03\xd5"),
                  "b": (0x1810, b"\x1f\x20\x03\xd5")}  # c removed -> no hit
    base = _make_component(b2_entries)
    target = _make_component(b3_entries)

    results = [migrate_site(base, target, off, name=n) for n, (off, _) in b2_entries.items()]
    apply_delta_fallback(results)
    by_name = {r.name: r for r in results}

    assert by_name["c"].method == "delta"
    assert by_name["c"].confidence == 0.30  # delta-inferred is always LOW
    assert by_name["c"].target_offset == 0x1060 + 0x800


def test_delta_fallback_requires_two_neighbors():
    b2_entries = {"a": (0x1000, b"\x1f\x20\x03\xd5"),
                  "z": (0x9000, b"\x1f\x20\x03\xd5")}  # lone entry far from a
    b3_entries = {"a": (0x1800, b"\x1f\x20\x03\xd5")}
    base = _make_component(b2_entries)
    target = _make_component(b3_entries)

    results = [migrate_site(base, target, off, name=n) for n, (off, _) in b2_entries.items()]
    apply_delta_fallback(results)
    by_name = {r.name: r for r in results}

    assert by_name["z"].method == "failed"  # no cluster -> stays failed
    assert by_name["z"].target_offset is None


# ── 2.11: ground-truth regression vs the verified b3 profile ────────

def _fixture_component_for(profile: dict, section: str) -> bytes:
    entries = _dict_entries(profile, section)
    max_off = max(off for off, _ in entries.values())
    size = max_off + 0x100000
    rng = random.Random(9)
    data = bytearray(rng.randbytes(size))
    for name, (off, val) in entries.items():
        data[off:off + len(val)] = val
        ctx = _name_filler(name)
        data[off + len(val):off + len(val) + len(ctx)] = ctx
    return bytes(data)


def test_ground_truth_full_profile(b2b3_profiles, ibss_pair, ibec_pair, kernel_pair):
    """2.11: every section migrated end-to-end must reproduce the verified
    b3 profile offsets at >=0.90 confidence (b2 -> b3 is ground truth)."""
    from migrate import Components, migrate_section, normalize_section
    b2, b3 = b2b3_profiles

    comps = Components(
        base={"ibss": ibss_pair[0], "ibec": ibec_pair[0], "kernelcache": kernel_pair[0]},
        target={"ibss": ibss_pair[1], "ibec": ibec_pair[1], "kernelcache": kernel_pair[1]},
    )
    for section in ("txm", "restoreramdisk"):
        comps.base[section] = _fixture_component_for(b2, section)
        comps.target[section] = _fixture_component_for(b3, section)

    oracle = {s: normalize_section(b3, s) for s in ("ibss", "ibec", "kernel", "txm", "restoreramdisk")}
    total = 0
    for section, o in oracle.items():
        results = migrate_section(b2, section, comps)
        for r in results:
            entry_name = r.name.split(".", 1)[-1]
            assert r.target_offset == o[entry_name]["offset"], (
                f"{r.name}: got 0x{r.target_offset:X}, want 0x{o[entry_name]['offset']:X}")
            assert r.confidence >= 0.90, f"{r.name}: conf {r.confidence} too low"
            total += 1
    assert total == 40  # 5 ibss + 6 ibec + 21 kernel + 6 txm + 2 ramdisk


# ── 2.6: canonical offsets.yaml cross-check ─────────────────────────

CANONICAL = Path.home() / ".config/opencode/skills/master-router/offsets.yaml"

BAD_CANONICAL_YAML = """\
constants:
  checkm8:
    ios_27_0b2:
      ibss_image4_validate: "0x23EFC"      # actually b3's value (mislabeled key)
      ibss_boot_args_ptr: "0x2B0F4"        # actually b3's value
      ibss_boot_args_string: "0xD3960"     # actually b3's value
      txm_queryModule0: "0x39cff"          # matches neither profile
      txm_queryModule1: "0x39e1f"          # matches neither profile
      txm_queryModule2: "0x39fa4"          # actually b3's value
      txm_constraints_sig: "0x3f510"       # actually b3's value
      txm_allowedBeforeSecure: "0x2bcb4"   # agrees everywhere
      mobileactivationd_should_hactivate: "0x2EBB14"
"""


def _canonical_results(b2b3_profiles, ibss_pair, ibec_pair):
    from migrate import Components, migrate_section
    b2, b3 = b2b3_profiles
    comps = Components(
        base={"ibss": ibss_pair[0], "ibec": ibec_pair[0]},
        target={"ibss": ibss_pair[1], "ibec": ibec_pair[1]},
    )
    comps.base["txm"] = _fixture_component_for(b2, "txm")
    comps.target["txm"] = _fixture_component_for(b3, "txm")
    return b2, b3, {s: migrate_section(b2, s, comps) for s in ("ibss", "ibec", "txm")}


def test_canonical_crosscheck_flags_conflicts(b2b3_profiles, ibss_pair, ibec_pair,
                                              tmp_path, monkeypatch):
    """Synthetic bad canonical DB: mislabeled version keys + values matching
    neither profile must be flagged; agreeing entries must not (2.6 machinery).

    The real b3 queryModule0/1 values (0x39CA8 / 0x39E10, from upstream
    work-27.0b3/make_cfw.py) belong to the target build, so this fixture uses
    off-by-more values to keep exercising the MATCHES NEITHER branch."""
    import migrate
    bad = tmp_path / "offsets_bad.yaml"
    bad.write_text(BAD_CANONICAL_YAML)
    monkeypatch.setattr(migrate, "CANONICAL_PATH", bad)

    b2, b3, all_results = _canonical_results(b2b3_profiles, ibss_pair, ibec_pair)
    conflicts = migrate.check_canonical(b2, b3, all_results,
                                        base_version="27.0b2", target_version="27.0b3")
    text = "\n".join(conflicts)

    assert any("image4_validate_nop" in c for c in conflicts), conflicts
    assert any("query_module0" in c and "NEITHER" in c for c in conflicts), conflicts
    assert any("query_module1" in c and "NEITHER" in c for c in conflicts), conflicts
    assert any("boot_args_adrp" in c and "mislabeled" in c for c in conflicts), conflicts
    assert not any("allowed_before_secure_channel" in c for c in conflicts), text


@pytest.mark.skipif(not CANONICAL.exists(), reason="canonical offsets.yaml not installed")
def test_canonical_crosscheck_agrees_after_fix(b2b3_profiles, ibss_pair, ibec_pair):
    """The installed canonical DB now carries corrected per-build checkm8
    blocks — a b2->b3 migration must produce ZERO conflicts (2.7)."""
    import migrate
    b2, b3, all_results = _canonical_results(b2b3_profiles, ibss_pair, ibec_pair)
    conflicts = migrate.check_canonical(b2, b3, all_results,
                                        base_version="27.0b2", target_version="27.0b3")
    assert conflicts == []


# ── #16: bootstrap upsert ───────────────────────────────────────────

def test_apply_offsets_upserts_missing_entries(b2b3_profiles, ibss_pair, ibec_pair,
                                               tmp_path):
    """Migrating into a fresh template skeleton must CREATE missing sections
    and entries (txm absent, kernel subset) instead of silently dropping."""
    from migrate import Components, apply_offsets, migrate_section
    from profile_gen import generate_profile
    b2, b3 = b2b3_profiles
    comps = Components(
        base={"ibss": ibss_pair[0], "ibec": ibec_pair[0]},
        target={"ibss": ibss_pair[1], "ibec": ibec_pair[1]},
    )
    comps.base["txm"] = _fixture_component_for(b2, "txm")
    comps.target["txm"] = _fixture_component_for(b3, "txm")

    results = {s: migrate_section(b2, s, comps) for s in ("ibss", "ibec", "txm")}

    skeleton = tmp_path / "skeleton.yaml"
    profile = generate_profile("iPhone12,3", "27.0b4", "00A0000x")
    skeleton.write_text(yaml.dump(profile, default_flow_style=False))

    apply_offsets(skeleton, results, base_profile=b2)
    written = yaml.safe_load(skeleton.read_text())

    txm = written["patches"].get("txm", {})
    assert set(txm) == set(b2["patches"]["txm"]), "txm section must be created from base"
    oracle = {k: v["offset"] for k, v in b3["patches"]["txm"].items()}
    for name, entry in txm.items():
        assert entry["offset"] == oracle[name], f"txm.{name} upserted with wrong offset"


# ── 4.10 / M2.3: --json output + resumable runs ─────────────────────

SITE_NOP = b"\x1f\x20\x03\xd5"          # the site instruction used by these fixtures


def _write_profile(path: Path, offset: int, ios: str) -> Path:
    """A minimal valid profile whose only entry is NOT in CHECKM8_KEY_MAP, so
    the canonical cross-check stays quiet and the verdict is about the search."""
    profile = {
        "device": "iPhone 14", "model": "iPhone12,8", "ios_version": ios,
        "patches": {"ibss": {"synthetic_site": {"offset": offset, "value": "1f2003d5"}}},
    }
    path.write_text(yaml.dump(profile, default_flow_style=False, sort_keys=False))
    return path


@pytest.fixture
def migrate_cli(tmp_path):
    """Base/target profile pair + raw components: base site 0x1000 -> 0x1010."""
    comp_dir = tmp_path / "comps"
    (comp_dir / "base").mkdir(parents=True)
    (comp_dir / "target").mkdir(parents=True)
    (comp_dir / "base" / "ibss.raw").write_bytes(
        _make_component({"synthetic_site": (0x1000, SITE_NOP)}))
    (comp_dir / "target" / "ibss.raw").write_bytes(
        _make_component({"synthetic_site": (0x1010, SITE_NOP)}))
    return (_write_profile(tmp_path / "iPhone12,8_27.0b2.yaml", 0x1000, "27.0b2"),
            _write_profile(tmp_path / "iPhone12,8_27.0b3.yaml", 0x1010, "27.0b3"),
            comp_dir)


def _empty_comp_dir(tmp_path) -> Path:
    """base/ + target/ present but no components: every entry ends up skipped."""
    empty = tmp_path / "no-comps"
    (empty / "base").mkdir(parents=True)
    (empty / "target").mkdir()
    return empty


def test_result_dict_roundtrip():
    from fingerprint import MatchResult
    from migrate import result_from_dict, result_to_dict
    r = MatchResult("ibss.site", 0x1000, 0x1010, 0x10, "pattern", 0.95, True,
                    "42214091", "422d4091", [0x1010], True, "422d4091")
    assert result_from_dict(result_to_dict(r)) == r
    assert json.loads(json.dumps(result_to_dict(r)))["target_offset"] == 0x1010
    failed = MatchResult("ibss.site", 0x1000, None, None, "failed", 0.0, False, "", "")
    assert result_from_dict(result_to_dict(failed)).target_offset is None


def test_summarize_agrees_with_report_verdict(migrate_cli):
    """One verdict string for both shapes: the markdown report and --json must
    never tell different stories about the same results."""
    from migrate import format_report, run_migration, summarize
    base, target, comp_dir = migrate_cli
    run = run_migration(base, target, comp_dir=comp_dir, json_out=True)
    report = format_report(base, target, run.results, run.conflicts)
    assert f"**VERDICT: {run.stats['verdict']}**" in report
    assert run.as_dict()["verdict"] == report.splitlines()[2].split("VERDICT: ")[1].rstrip("**")
    assert summarize({})["ready"] is True
    assert summarize({})["total"] == 0


def test_skipped_entries_count_as_review_not_failed(migrate_cli):
    """No components = skipped, and skipped is not the same as a failed search:
    --json must not report missing data as a migration failure."""
    from migrate import summarize
    from fingerprint import MatchResult
    results = {"ibss": [MatchResult("ibss.a", 0x10, None, None, "skipped", 0.0, False, "", "")]}
    stats = summarize(results)
    assert stats["skipped"] == 1 and stats["failed"] == 0
    assert stats["ready"] is False and "REVIEW REQUIRED" in stats["verdict"]


def test_checkpoint_roundtrip_and_resume(tmp_path, migrate_cli, monkeypatch):
    """A resumed run reuses finished sections instead of searching again: the
    checkpoint is enough to rebuild the results, with no components at all."""
    import migrate
    base, target, comp_dir = migrate_cli
    checkpoint = tmp_path / "cp.json"

    run1 = migrate.run_migration(base, target, comp_dir=comp_dir, json_out=True)
    assert run1.results["ibss"][0].target_offset == 0x1010
    assert run1.ready is True
    assert run1.as_dict()["counts"]["high"] == 1

    migrate.checkpoint_write(checkpoint, base, target, run1.results, remaining=[],
                             complete=True)
    payload = json.loads(checkpoint.read_text())
    assert payload["schema"] == migrate.CHECKPOINT_SCHEMA
    assert payload["complete"] is True and payload["remaining"] == []
    assert payload["sections"]["ibss"][0]["target_offset"] == 0x1010

    searched = []
    real = migrate.migrate_section

    def spy(profile, section, comps):
        searched.append(section)
        return real(profile, section, comps)

    monkeypatch.setattr(migrate, "migrate_section", spy)
    run2 = migrate.run_migration(base, target, comp_dir=_empty_comp_dir(tmp_path),
                                 json_out=True, resume=checkpoint)
    assert "ibss" not in searched             # the resumed section was not searched
    assert searched == ["ibec", "restoreramdisk", "txm", "kernel"]  # empty sections only
    assert run2.resumed == ["ibss"]
    assert run2.results["ibss"][0].target_offset == 0x1010
    assert run2.results["ibss"][0].confidence == 0.95
    assert run2.as_dict()["sections"]["ibss"]["entries"][0]["method"] == "pattern"


def test_checkpoint_refuses_a_different_pair(tmp_path, migrate_cli, capsys):
    """Offsets from another build are a brick risk, not a shortcut: a stale
    checkpoint is refused in the open, never silently reused."""
    import migrate
    base, target, comp_dir = migrate_cli
    checkpoint = tmp_path / "cp.json"
    run = migrate.run_migration(base, target, comp_dir=comp_dir, json_out=True)
    migrate.checkpoint_write(checkpoint, base, target, run.results, remaining=[])

    other = _write_profile(tmp_path / "iPhone12,8_27.0b4.yaml", 0x2000, "27.0b4")
    with pytest.raises(migrate.CheckpointMismatch) as exc:
        migrate.checkpoint_read(checkpoint, base, other)
    assert "different target profile" in str(exc.value)

    capsys.readouterr()                         # drop the first run's payload
    code = migrate.cli_main([str(base), str(other), "--comp-dir", str(comp_dir),
                             "--resume", str(checkpoint), "--json"])
    assert code == 2                            # refusal, not a clean run
    payload = json.loads(capsys.readouterr().out)
    assert payload["ready"] is False and "different target profile" in payload["error"]


def test_checkpoint_rejects_broken_and_unknown_files(tmp_path, migrate_cli):
    import migrate
    base, target, _ = migrate_cli
    broken = tmp_path / "broken.json"
    broken.write_text("{not json")
    with pytest.raises(ValueError):
        migrate.checkpoint_read(broken, base, target)
    future = tmp_path / "future.json"
    future.write_text(json.dumps({"schema": 99, "sections": {}}))
    with pytest.raises(ValueError):
        migrate.checkpoint_read(future, base, target)
    missing = tmp_path / "nope.json"
    assert migrate.cli_main([str(base), str(target), "--resume", str(missing)]) == 1


def test_json_output_is_one_clean_object(migrate_cli, capsys):
    """--json is a pipe contract: one parsable object, no banner, no table and
    no ANSI escape may reach stdout."""
    import migrate
    base, target, comp_dir = migrate_cli
    code = migrate.cli_main([str(base), str(target), "--comp-dir", str(comp_dir),
                             "--json"])
    out = capsys.readouterr().out
    assert "\x1b" not in out                       # no color codes in the pipe
    assert out.count("{") and out.lstrip().startswith("{")
    payload = json.loads(out)                      # raises on any extra output
    assert code == 0
    assert payload["ready"] is True and payload["counts"]["high"] == 1
    assert payload["counts"]["total"] == 1
    assert payload["base"]["sha256"] and payload["target"]["sha256"]
    entry = payload["sections"]["ibss"]["entries"][0]
    assert entry["name"] == "ibss.synthetic_site"
    assert entry["base_offset"] == 0x1000 and entry["target_offset"] == 0x1010
    assert entry["confidence"] == 0.95 and entry["method"] == "pattern"
    assert payload["review"] == [] and payload["conflicts"] == []


def test_json_exit_code_is_the_verdict(tmp_path, migrate_cli, capsys):
    """A machine consumer gets the verdict as an exit code too: 2 means the
    report says REVIEW REQUIRED, so `migrate --json && ...` cannot ignore it."""
    import migrate
    base, target, _ = migrate_cli
    code = migrate.cli_main([str(base), str(target), "--comp-dir",
                             str(_empty_comp_dir(tmp_path)), "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert code == 2 and payload["ready"] is False
    assert payload["counts"]["skipped"] == 1
    assert "REVIEW REQUIRED" in payload["verdict"]


def test_json_never_prompts(migrate_cli, monkeypatch, capsys):
    """No terminal, no question: under --json the apply step is opt-in via
    --auto, and the payload says a write did not happen."""
    import migrate
    base, target, comp_dir = migrate_cli
    before = target.read_text()

    def boom(*_args, **_kwargs):
        raise AssertionError("--json must not prompt")

    monkeypatch.setattr(migrate.log_utils, "safe_input", boom)
    code = migrate.cli_main([str(base), str(target), "--comp-dir", str(comp_dir),
                             "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert code == 0 and payload["wrote"] is False
    assert target.read_text() == before           # nothing written without --auto


def test_json_auto_write_respects_the_confidence_floor(migrate_cli, capsys):
    """--auto --json writes and reports what the floor kept out, instead of
    only printing it."""
    import migrate
    base, target, comp_dir = migrate_cli
    run = migrate.run_migration(base, target, comp_dir=comp_dir, auto=True,
                                json_out=True, min_confidence=0.90)
    payload = run.as_dict()
    assert run.wrote is True and payload["not_written"] == []
    assert payload["validation"]["valid"] is True
    assert payload["validation"]["passed"] >= 1 and payload["validation"]["failed"] == 0
    assert yaml.safe_load(target.read_text())["patches"]["ibss"]["synthetic_site"]["offset"] == 0x1010

    run2 = migrate.run_migration(base, target, comp_dir=comp_dir, auto=True,
                                 json_out=True, min_confidence=0.99)
    assert run2.wrote is True and run2.not_written == ["ibss.synthetic_site (conf 0.95)"]
    assert run2.as_dict()["not_written"] == ["ibss.synthetic_site (conf 0.95)"]
    capsys.readouterr()


def test_human_path_still_prints_the_report(migrate_cli, monkeypatch, capsys):
    """The two output branches rot independently: without --json the report and
    the verdict must still be on screen (and JSON must not be)."""
    import migrate
    base, target, comp_dir = migrate_cli
    monkeypatch.setattr(migrate.log_utils, "safe_input", lambda *_a, **_k: "n")
    code = migrate.cli_main([str(base), str(target), "--comp-dir", str(comp_dir)])
    out = capsys.readouterr().out
    assert code == 0
    assert "# Offset Migration Report" in out and "VERDICT: READY" in out
    assert '"sections"' not in out                # no JSON in the human path


def test_missing_base_profile_is_not_a_silent_success(tmp_path, capsys):
    """A missing input used to report success (exit 0): exit 1, and in --json
    mode a parsable error object instead of a prose line."""
    import migrate
    missing = tmp_path / "nope.yaml"
    assert migrate.cli_main([str(missing), "27.0b3"]) == 1
    capsys.readouterr()                           # drop the human error line
    assert migrate.cli_main([str(missing), "27.0b3", "--json"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["ready"] is False and "not found" in payload["error"]


def test_real_entry_point_propagates_the_exit_code(tmp_path, migrate_cli):
    """`profile_gen.py migrate` dropped cli_main's return value, so a JSON run
    exited 0 whatever the verdict said. Run the real launcher, not the function."""
    base, target, comp_dir = migrate_cli
    root = Path(__file__).resolve().parent.parent

    def run(*args):
        return subprocess.run([sys.executable, "profile_gen.py", "migrate",
                               str(base), str(target), *args],
                              cwd=root, capture_output=True, text=True)

    ready = run("--comp-dir", str(comp_dir), "--json")
    assert ready.returncode == 0
    assert json.loads(ready.stdout)["ready"] is True

    review = run("--comp-dir", str(_empty_comp_dir(tmp_path)), "--json")
    assert review.returncode == 2
    payload = json.loads(review.stdout)
    assert payload["ready"] is False and payload["counts"]["skipped"] == 1

    assert run("--comp-dir", str(comp_dir), "--resume",
               str(tmp_path / "missing.json")).returncode == 1
