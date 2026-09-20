"""Tests for the cross-source offset audit (source_audit.py).

The audit is what caught the stale b3 kernel entries, so its classification
rules are pinned here: commented-out script lines are not patch set, split
YAML keys still cover one upstream run, PC-relative sites are REVIEW not
MISMATCH, and anything the profile writes that upstream does not is
PROFILE-ONLY.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from source_audit import (  # noqa: E402
    audit,
    parse_cfw_script,
    parse_liter8_fixtures,
    profile_entries,
)

SCRIPT = '''
import os, struct
fp = None

def patch(offset, data):
    fp.seek(offset); fp.write(data)

fp = open("Ramdisk/iBSS.raw", "r+b")
patch(0x23EFC, 0xd503201f)      # nop
patch(0x23F00, 0xd2800000)      # mov x0, #0
# patch(0x999999, 0xd503201f)   # commented out — not part of the patch set
patch(0xD3960, "-v wdt=-1 rd=md0 -restore\\x00")
patch(0x2AFBC, 0xB0000542)       # adrp x2 (PC-relative)
patch(0x2AFC0, 0x91214042)       # add x2, x2, #0x850
fp.close()

fp = open("kcache.raw", "r+b")
patch(0x1F1CCF8, 0xD503245F)     # BTI c
patch(0x1F1CCF8+4, 0xD2800020)   # MOV X0, #1
patch(0x1F1CCF8+8, 0xB4000043)   # cbz x3, #8
patch(0x1F1CCF8+12, 0xF9000060)  # STR X0, [X3]
patch(0x1F1CCF8+16, 0xD65F03C0)  # RET
patch(0x1F2B8C8, 0x52800020)     # dyld policy
fp.close()
'''


def _script(tmp_path: Path) -> Path:
    p = tmp_path / "make_cfw.py"
    p.write_text(SCRIPT)
    return p


def test_parse_cfw_script_sections_and_comments(tmp_path):
    sites = parse_cfw_script(_script(tmp_path))
    by_component = {}
    for s in sites:
        by_component.setdefault(s.component, []).append(s)

    assert set(by_component) == {"Ramdisk/iBSS.raw", "kcache.raw"}
    assert [s.section for s in by_component["Ramdisk/iBSS.raw"]] == ["ibss", "ibss", "ibss"]
    # commented patch() calls are the experiment log, not the shipped set
    assert all(s.offset != 0x999999 for s in sites)


def test_parse_cfw_script_coalesces_consecutive_words(tmp_path):
    sites = [s for s in parse_cfw_script(_script(tmp_path)) if s.section == "kernel"]
    amfi = [s for s in sites if s.offset == 0x1F1CCF8]
    assert len(amfi) == 1, "the 5-word AMFI sequence must coalesce into one site"
    assert amfi[0].data.hex() == "5f2403d5200080d2430000b4600000f9c0035fd6"
    # an unrelated site 0x80 bytes later must stay separate
    dyld = [s for s in sites if s.offset == 0x1F2B8C8]
    assert len(dyld) == 1


def test_parse_cfw_script_decodes_string_values(tmp_path):
    sites = [s for s in parse_cfw_script(_script(tmp_path)) if s.offset == 0xD3960]
    assert sites[0].data.endswith(b"\x00")
    assert sites[0].data[:-1].decode() == "-v wdt=-1 rd=md0 -restore"


def _profile():
    """Profile mirroring the shape the audit has to understand."""
    return {
        "patches": {
            "ibss": {
                # only the nop half of the upstream nop+mov run
                "image4_validate_nop": {"offset": 0x23EFC, "value": "1f2003d5"},
                "boot_args_string": {"offset": 0xD3960, "value": "-v wdt=-1 rd=md0 -restore"},
                # PC-relative immediate: different bytes, not comparable
                "boot_args_adrp": {"offset": 0x2AFBC, "value": "420005b0"},
            },
            "kernel": [
                {"name": "AMFI trust everything", "offset": 0x1F1CCF8,
                 "value": "200080d2c0035fd6"},                      # truncated on purpose
                {"name": "Check dyld policy internal", "offset": 0x1F2B8C8, "value": "20008052"},
                {"name": "Only in profile", "offset": 0x123456, "value": "1f2003d5"},
            ],
        }
    }


def test_audit_classifies_findings(tmp_path):
    result = audit(parse_cfw_script(_script(tmp_path)), _profile())
    status = {(f.section, f.entry): f.status for f in result.findings}

    # upstream patches nop+mov as one 8-byte run, the profile writes only the nop
    assert status[("ibss", "image4_validate_nop")] == "PARTIAL"
    # upstream writes a trailing NUL the profile does not
    assert status[("ibss", "boot_args_string")] == "PARTIAL"
    # PC-relative site: not comparable, must not be called a mismatch
    assert "REVIEW" in {f.status for f in result.findings if f.entry == "boot_args_adrp"}
    # the truncated AMFI payload differs in its first word, so it is a mismatch
    # (the profile writes mov x0,#1; ret where upstream writes BTI c; mov x0,#1; …)
    assert status[("kernel", "AMFI trust everything")] == "MISMATCH"
    assert status[("kernel", "Check dyld policy internal")] == "COVERED"
    assert status[("kernel", "Only in profile")] == "PROFILE-ONLY"


def test_audit_marks_covered_when_split_keys_cover_the_run(tmp_path):
    profile = {"patches": {"ibss": {
        "image4_validate_nop": {"offset": 0x23EFC, "value": "1f2003d5"},
        "image4_validate_ret0": {"offset": 0x23F00, "value": "000080d2"},
        "boot_args_adrp": {"offset": 0x2AFBC, "value": "420500b0"},
        "boot_args_add": {"offset": 0x2AFC0, "value": "42402191"},
        "boot_args_string": {"offset": 0xD3960, "value": "-v wdt=-1 rd=md0 -restore\x00"},
    }}}
    result = audit(parse_cfw_script(_script(tmp_path)), profile)
    status = {(f.section, f.entry): f.status for f in result.findings}
    assert status[("ibss", "image4_validate_nop")] == "COVERED"
    assert status[("ibss", "boot_args_adrp")] == "COVERED"
    assert status[("ibss", "boot_args_add")] == "COVERED"
    assert result.count("MISMATCH") == 0


def test_audit_flags_missing_and_mismatch(tmp_path):
    profile = {
        "patches": {
            "kernel": [
                {"name": "Post-validation bypass", "offset": 0x1F2B368, "value": "1f00006b"},
            ],
        }
    }
    result = audit(parse_cfw_script(_script(tmp_path)), profile)
    statuses = {f.status for f in result.findings}
    assert "MISSING" in statuses            # kcache sites with no entry at all
    assert result.count("MISSING") >= 5


def test_profile_entries_handles_nested_daemons_and_pending():
    profile = {
        "patches": {
            "daemons": {"ctkd": {"anti_sep_crash_ret0": {"offset": 0x1B38, "value": "000080d2"}}},
            "txm": {"query_module0": {"offset": 0x39CA8, "value": "000080d2", "pending": True}},
        }
    }
    entries = profile_entries(profile)
    assert entries["daemons"][0][0] == "ctkd.anti_sep_crash_ret0"
    assert "txm" not in entries, "pending entries must not count as written offsets"


def test_parse_liter8_fixtures(tmp_path):
    d = tmp_path / "24A435" / "n104ap"
    d.mkdir(parents=True)
    (d / "ibss-n104-24A435.json").write_text(json.dumps({
        "resolver": "ibss-validate-asn1",
        "target": {"board": "n104ap", "component": "iBSS"},
        "expectedSize": 2563464, "sha256": "ab" * 32,
        "expectedPatches": [
            {"id": "ibss.validate-asn1.branch", "offset": 145128,
             "originalBytes": "01070054", "replacementBytes": "1f2003d5"}]}))
    sites = parse_liter8_fixtures(tmp_path, build="24A435", board="n104ap")
    assert len(sites) == 1
    assert sites[0].offset == 145128
    assert sites[0].section == "ibss"
    assert sites[0].entry_id == "ibss.validate-asn1.branch"
