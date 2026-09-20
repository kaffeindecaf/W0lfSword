"""Tests for the Liter8 fixture importer (liter8_import.py).

The importer's value is its refusal logic: a wrong mapping must never produce
a writable offset. These tests pin the gates (payload equality, contiguity,
string fit, byte verification) and the pending discipline for everything the
fixture set does not cover.
"""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import liter8_import as li  # noqa: E402

ROOT = Path(__file__).parent.parent


def _fixture(resolver, component, patches, size=0x1000, sha="ab" * 32):
    return {
        "resolver": resolver,
        "target": {"device": "iPhone 11", "board": "n104ap", "build": "24A435",
                   "component": component},
        "expectedSize": size,
        "sha256": sha,
        "expectedPatches": [
            {"id": pid, "offset": off, "originalBytes": orig, "replacementBytes": repl}
            for pid, off, orig, repl in patches
        ],
    }


@pytest.fixture
def fixtures_dir(tmp_path):
    d = tmp_path / "fixtures" / "24A435" / "n104ap"
    d.mkdir(parents=True)
    (d / "ibss-validate-asn1.json").write_text(json.dumps(_fixture(
        "ibss-validate-asn1", "iBSS",
        [("ibss.validate-asn1.branch", 0x1000, "01070054", "1f2003d5"),
         ("ibss.validate-asn1.result", 0x1004, "e00314aa", "000080d2")])))
    (d / "ibss-ramdisk.json").write_text(json.dumps(_fixture(
        "ibss-ramdisk", "iBSS",
        [("ibss.boot-args.adrp", 0x2000, "620800f0", "021200d0"),
         ("ibss.boot-args.add", 0x2004, "423c3091", "42003f91"),
         ("ibss.boot-args.string", 0x3000, "00" * 64, "2d76207764743d2d312072643d6d6430202d726573746f726500")])))
    (d / "txm-restore.json").write_text(json.dumps(_fixture(
        "txm-restore", "TXM",
        [("txm.query-module.0", 0x5000, "65faff97", "000080d2")])))
    return tmp_path / "fixtures"


def test_load_fixtures_indexes_by_resolver(fixtures_dir):
    fx = li.load_fixtures(fixtures_dir, "24A435", "n104ap")
    assert set(fx) == {"ibss-validate-asn1", "ibss-ramdisk", "txm-restore"}
    assert fx["ibss-ramdisk"].component == "iBSS"
    assert len(fx["ibss-validate-asn1"].patches) == 2


def test_apply_rule_accepts_matching_payload(fixtures_dir):
    fx = li.load_fixtures(fixtures_dir, "24A435", "n104ap")
    rule = li.Rule("ibss", "image4_validate_nop", "ibss-validate-asn1",
                   ["ibss.validate-asn1.branch"], li.P_NOP)
    imp, why = li.apply_rule(rule, fx)
    assert imp is not None, why
    assert imp.offset == 0x1000
    assert imp.value == "1f2003d5"


def test_apply_rule_rejects_payload_mismatch(fixtures_dir):
    """A fixture whose bytes are not our canonical patch must stay pending."""
    fx = li.load_fixtures(fixtures_dir, "24A435", "n104ap")
    rule = li.Rule("ibss", "image4_validate_nop", "ibss-validate-asn1",
                   ["ibss.validate-asn1.branch"], "000080d2")
    imp, why = li.apply_rule(rule, fx)
    assert imp is None
    assert "payload mismatch" in why


def test_apply_rule_rejects_non_contiguous_sites(fixtures_dir):
    fx = li.load_fixtures(fixtures_dir, "24A435", "n104ap")
    fx["ibss-validate-asn1"].patches["ibss.validate-asn1.result"]["offset"] = 0x1010
    rule = li.Rule("ibss", "AMFI", "ibss-validate-asn1",
                   ["ibss.validate-asn1.branch", "ibss.validate-asn1.result"], "")
    imp, why = li.apply_rule(rule, fx)
    assert imp is None
    assert "contiguous" in why


def test_apply_rule_string_must_fit_slot(fixtures_dir):
    fx = li.load_fixtures(fixtures_dir, "24A435", "n104ap")
    rule = li.Rule("ibss", "boot_args_string", "ibss-ramdisk", ["ibss.boot-args.string"],
                   kind=li.K_STR, string="x" * 200)
    imp, why = li.apply_rule(rule, fx)
    assert imp is None
    assert "does not fit" in why


def test_apply_rule_boot_args_string_keeps_our_convention(fixtures_dir):
    fx = li.load_fixtures(fixtures_dir, "24A435", "n104ap")
    rule = li.Rule("ibss", "boot_args_string", "ibss-ramdisk", ["ibss.boot-args.string"],
                   kind=li.K_STR, string="-v wdt=-1 rd=md0 -restore")
    imp, why = li.apply_rule(rule, fx)
    assert imp is not None, why
    assert imp.value == "-v wdt=-1 rd=md0 -restore"


def test_apply_rule_adrp_copies_fixture_immediate(fixtures_dir):
    fx = li.load_fixtures(fixtures_dir, "24A435", "n104ap")
    rule = li.Rule("ibss", "boot_args_adrp", "ibss-ramdisk", ["ibss.boot-args.adrp"],
                   kind=li.K_ADRP)
    imp, why = li.apply_rule(rule, fx)
    assert imp is not None, why
    assert imp.value == "021200d0"


def test_verify_against_component_detects_bytes(tmp_path):
    imp = li.Imported(rule=li.Rule("ibss", "x", "res", ["id"]), offset=0x10,
                      value="1f2003d5", original=bytes.fromhex("01070054"),
                      upstream_ids=["id"])
    raw = bytearray(0x40)
    raw[0x10:0x14] = bytes.fromhex("01070054")
    assert li.verify_against_component(imp, "ibss", bytes(raw)) == "bytes"
    raw[0x10:0x14] = bytes.fromhex("02070054")
    assert li.verify_against_component(imp, "ibss", bytes(raw)) == "bytes-differ"
    assert li.verify_against_component(imp, "ibss", b"\x00" * 8) == "out-of-range"


def test_build_profile_marks_unmapped_entries_pending(fixtures_dir):
    fx = li.load_fixtures(fixtures_dir, "24A435", "n104ap")
    schema = {
        "patches": {
            "ibss": {"image4_validate_nop": {"offset": 0xDEADBEEF, "value": "1f2003d5"},
                     "boot_args_string": {"offset": 0xDEADBEEF, "value": "x"}},
            "txm": {"query_module0": {"offset": 0xDEADBEEF, "value": "000080d2"},
                    "query_module1": {"offset": 0xDEADBEEF, "value": "000080d2"}},
            "devicetree": {"remove_content_protect": True},
        }
    }
    imported = []
    for rule in li.RULES:
        imp, _ = li.apply_rule(rule, fx)
        if imp:
            imported.append(imp)
    profile = li.build_profile(schema, "iPhone12,1", "27.0", "24A437", imported, {}, {})

    ibss = profile["patches"]["ibss"]
    assert ibss["image4_validate_nop"]["offset"] == 0x1000
    assert "pending" not in ibss["image4_validate_nop"]
    assert ibss["boot_args_string"]["source"].startswith("liter8:")
    # query_module1 has no fixture → sentinel + pending
    assert profile["patches"]["txm"]["query_module1"]["pending"] is True
    assert profile["patches"]["txm"]["query_module1"]["offset"] == li.SENTINEL
    # structural flags pass through untouched
    assert profile["patches"]["devicetree"] == {"remove_content_protect": True}
    assert profile["verification"] == "imported"


def test_rules_reference_existing_fixture_ids():
    """Every rule id must be a plausible Liter8 patch id (catches typos)."""
    for rule in li.RULES:
        assert rule.ids, rule.path
        for pid in rule.ids:
            assert "." in pid, f"{rule.path}: {pid}"
        if rule.kind == li.K_EXACT:
            assert rule.payload, f"{rule.path}: exact rules need a canonical payload"
