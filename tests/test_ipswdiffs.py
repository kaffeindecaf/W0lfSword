#!/usr/bin/env python3
"""Host tests for scripts/ipswdiffs.py and scripts/offsets_drift.py.

These two tools read a repo they do not control (blacktop/ipsw-diffs), so the
parsers are the whole product: if a heading level or a version line moves, the
tool must fail loudly rather than report "nothing changed". Everything here is
offline — the fixtures are trimmed copies of real dataset output (new-format
pair with KEXTS/*.md files, old-format pair with the diffs inlined in the
README) plus a synthetic pair that drives the drift verdicts.

    python3 -m unittest tests.test_ipswdiffs -v
"""
from __future__ import annotations

import importlib.util
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"

if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    assert spec is not None and spec.loader is not None, name
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


ID = _load("ipswdiffs")
DRIFT = _load("offsets_drift")


INDEX_MD = """# ipsw-diffs

## DIFFS

<a id="ios-27-2-beta"></a>

### iOS 27.2 beta

<details open>
  <summary>View diffs</summary>

- [27.0 (24A437) .vs 27.2 beta 1 (24B5084k)](27_0_24A437_vs_27_2_24B5084k/README.md)

</details>

<a id="ios-26-6"></a>

### iOS 26.6

<details open>
  <summary>View diffs</summary>

- [26.6 (23G71) .vs 26.6.1 (23G83)](26_6_23G71_vs_26_6_1_23G83/README.md)
- [26.3 (23D127) .vs 26.4 beta](23D8133__iPhone17,1__vs_23D771330a__iPhone17,1/README.md)

</details>

### Generating Diffs

Clone the kernel symbolicator signatures
"""

NEW_PAIR_MD = """# 26.6 (23G71) .vs 26.6.1 (23G83)

## Inputs

- `iPhone18,1_26.6_23G71_Restore.ipsw`
- `iPhone18,1_26.6.1_23G83_Restore.ipsw`

## Kernel

### Version

| iOS | Version | Build | Date |
| :-- | :------ | :---- | :--- |
| 26.6 *(23G71)* | 25.6.0 | 12377.162.13~2 | Sat, 11Jul2026 15:47:15 PDT |
| 26.6.1 *(23G83)* | 25.6.0 | 12377.162.14~4 | Thu, 30Jul2026 12:43:49 PDT |

### Kexts

#### ⬆️ Updated (2)

<details>
  <summary><i>View Updated</i></summary>

- [com.apple.driver.AppleAVD](KEXTS/com.apple.driver.AppleAVD.md)
- [com.apple.kernel](KEXTS/com.apple.kernel.md)

</details>

## MachO

### filesystem

#### 🆕 NEW (1)

- [/usr/lib/libnew.dylib](MACHOS/filesystem/usr/lib/libnew.dylib.md)

### 🔑 Entitlements

- [Entitlements DIFF](Entitlements.md)

## Firmware

### ⬆️ Updated (1)

- [Firmware/M3/bin/securem3fw-v5x.im4p](FIRMWARE/Firmware/M3/bin/securem3fw-v5x.im4p.md)

## Files

### 🆕 New

#### filesystem (2)

- [View 2 new files](FILES/filesystem.NEW.md)

## EOF
"""

OLD_PAIR_MD = """# 18.4 (22E240) .vs 18.5 (22F5042g)

## IPSWs

- `iPhone17,1_18.4_22E240_Restore.ipsw`

## Kernel

### Kexts

#### ⬆️ Updated (1)

<details>
  <summary><i>View Updated</i></summary>

>  `com.apple.driver.AppleAOPAudio`

```diff

   __TEXT.__cstring: 0xc591
-  __TEXT_EXEC.__text: 0x31a24
+  __TEXT_EXEC.__text: 0x31a10

```

</details>

## Firmware

### ⬆️ Updated (1)

#### agx_a000

>  `Firmware/agx/armfw_g18p.im4p/agx_a000`

```diff

-  __TEXT.__cstring: 0x10
+  __TEXT.__cstring: 0x20

```

## MachO

### ⬆️ Updated (1)

- [/usr/lib/libsomething.dylib](DYLIBS/usr/lib/libsomething.dylib.md)
"""

KEXT_MD = """## com.apple.kernel

> `com.apple.kernel`

```diff

-12377.162.13.0.0
+12377.162.14.0.0
   __TEXT.__const: 0x36320
-  __TEXT.__cstring: 0x84e16
+  __TEXT.__cstring: 0x85054
   __DATA_CONST.__kalloc_type: 0x14340
-  __DATA_CONST.__kalloc_var: 0x78f0
+  __DATA_CONST.__kalloc_var: 0x7900
-  Functions: 21143
+  Functions: 21146
   Symbols:   0
-  CStrings:  20320
+  CStrings:  20334

CStrings:
+ "object_readonly_copy_overwrite"
- "old string"

```

### Sections with Same Size but Changed Content

- `__TEXT.__text`
"""

SPMIPMU_MD = """## com.apple.driver.AppleSPMIPMU

> `com.apple.driver.AppleSPMIPMU`

```diff

-  __TEXT.__cstring: 0x1
+  __TEXT.__cstring: 0x2

CStrings:
+ "%s::start: %s _pmuNub: %p built 09:47:08 Aug  6 2026\\n"
- "%s::start: %s _pmuNub: %p built 14:47:32 Jul 11 2026\\n"

```
"""


class FakeDataset(ID.Dataset):
    """Dataset whose fetches come from a dict (no network, no cache dir)."""

    def __init__(self, files: dict[str, str]):
        super().__init__(cache=pathlib.Path(tempfile.mkdtemp()), jobs=1)
        self.files = files

    def try_fetch(self, rel: str) -> str | None:
        return self.files.get(rel.lstrip("/"))

    def fetch(self, rel: str) -> str:
        text = self.try_fetch(rel)
        if text is None:
            raise ID.DatasetError(f"fake dataset has no {rel}")
        return text


class IndexTests(unittest.TestCase):
    def test_pairs_and_builds(self):
        entries = ID.parse_index(INDEX_MD)
        pairs = {e.dir: e for e in entries}
        self.assertIn("26_6_23G71_vs_26_6_1_23G83", pairs)
        e = pairs["26_6_23G71_vs_26_6_1_23G83"]
        self.assertEqual((e.os, e.section), ("iOS", "iOS 26.6"))
        self.assertEqual((e.prev_version, e.prev_build), ("26.6", "23G71"))
        self.assertEqual((e.next_version, e.next_build), ("26.6.1", "23G83"))

    def test_label_without_version_falls_back_to_dir(self):
        e = next(x for x in ID.parse_index(INDEX_MD) if x.dir.endswith("iPhone17,1"))
        self.assertEqual((e.prev_build, e.next_build), ("23D8133", "23D771330a"))

    def test_quick_nav_and_prose_links_ignored(self):
        # `## DIFFS` and the "Generating Diffs" prose must not become pairs.
        self.assertEqual(len(ID.parse_index(INDEX_MD)), 3)

    def test_resolve_by_build_and_by_version(self):
        entries = ID.parse_index(INDEX_MD)
        self.assertEqual([e.dir for e in ID.resolve_pair(entries, "23G71", "23G83")],
                         ["26_6_23G71_vs_26_6_1_23G83"])
        self.assertEqual([e.dir for e in ID.resolve_pair(entries, "26.6", "26.6.1")],
                         ["26_6_23G71_vs_26_6_1_23G83"])
        self.assertEqual(ID.resolve_pair(entries, "24A437", "24B5084k")[0].os, "iOS")

    def test_resolve_one_token(self):
        entries = ID.parse_index(INDEX_MD)
        self.assertEqual(len(ID.resolve_pair(entries, "23G83")), 1)
        self.assertEqual(ID.resolve_pair(entries, "nope"), [])


class PairLayoutTests(unittest.TestCase):
    def test_new_layout_manifest(self):
        p = ID.parse_pair("26_6_23G71_vs_26_6_1_23G83", NEW_PAIR_MD)
        self.assertEqual(p.label, "26.6 (23G71) .vs 26.6.1 (23G83)")
        self.assertIn("iPhone18,1_26.6_23G71_Restore.ipsw", p.ipsws)
        kexts = [e.label for e in p.targets("kernel")]
        self.assertEqual(kexts, ["com.apple.driver.AppleAVD", "com.apple.kernel"])
        self.assertEqual([e.label for e in p.targets("macho", "new")],
                         ["/usr/lib/libnew.dylib"])
        self.assertEqual([e.label for e in p.targets("firmware")],
                         ["Firmware/M3/bin/securem3fw-v5x.im4p"])
        # Kernel version table survives for `info` (header row + 2 builds).
        self.assertEqual(len(p.tables.get("Version", [])), 3)

    def test_old_layout_inline_diffs(self):
        p = ID.parse_pair("18_4_22E240__vs_18_5_22F5042g", OLD_PAIR_MD)
        kexts = p.targets("kernel")
        self.assertEqual([e.label for e in kexts], ["com.apple.driver.AppleAOPAudio"])
        self.assertTrue(kexts[0].link.startswith("inline:"))
        self.assertIn("0x31a24", p.inline["com.apple.driver.AppleAOPAudio"])
        # The firmware inline block must NOT be reported as a kext. The label is
        # the blockquoted path (identical to the new layout's link label).
        self.assertEqual([e.label for e in p.targets("firmware")],
                         ["Firmware/agx/armfw_g18p.im4p/agx_a000"])
        self.assertEqual([e.label for e in p.targets("dylibs")],
                         ["/usr/lib/libsomething.dylib"])

    def test_pair_diffs_use_inline_text_without_fetching(self):
        p = ID.parse_pair("18_4_22E240__vs_18_5_22F5042g", OLD_PAIR_MD)
        ds = FakeDataset({})  # any real fetch would fail loudly
        diffs = ID.pair_diffs(ds, p, "kernel", None, jobs=1)
        self.assertEqual([d.name for d in diffs], ["com.apple.driver.AppleAOPAudio"])
        self.assertEqual(diffs[0].sections["__TEXT_EXEC.__text"],
                         {"prev": "0x31a24", "next": "0x31a10"})


class TargetParseTests(unittest.TestCase):
    def setUp(self):
        self.td = ID.parse_target("com.apple.kernel", "KEXTS/com.apple.kernel.md", KEXT_MD)

    def test_version_both_sides(self):
        self.assertEqual(self.td.version, {"prev": "12377.162.13.0.0",
                                           "next": "12377.162.14.0.0"})

    def test_changed_and_unchanged_sections(self):
        # An unprefixed section line means "unchanged" — it must not look like a
        # new section on the next side only.
        self.assertEqual(self.td.sections["__DATA_CONST.__kalloc_type"],
                         {"prev": "0x14340", "next": "0x14340"})
        self.assertEqual(self.td.sections["__DATA_CONST.__kalloc_var"],
                         {"prev": "0x78f0", "next": "0x7900"})
        self.assertEqual(self.td.sections["__TEXT.__const"]["prev"], "0x36320")

    def test_counts(self):
        self.assertEqual(self.td.counts["functions"], {"prev": 21143, "next": 21146})
        self.assertEqual(self.td.counts["symbols"], {"prev": 0, "next": 0})
        self.assertEqual(self.td.counts["cstrings"], {"prev": 20320, "next": 20334})

    def test_cstrings_unquoted(self):
        self.assertEqual(self.td.cstrings["added"], ["object_readonly_copy_overwrite"])
        self.assertEqual(self.td.cstrings["removed"], ["old string"])

    def test_same_size_changed_section_noted(self):
        self.assertEqual(self.td.same_size, ["__TEXT.__text"])

    def test_non_diff_file_is_a_list(self):
        td = ID.parse_target("filesystem", "FILES/filesystem.NEW.md",
                             "## filesystem — NEW (2)\n\n- `/a`\n- `/b`\n")
        self.assertEqual(td.kind, "list")


class NoiseFilterTests(unittest.TestCase):
    def test_timestamp_only_pairs_dropped(self):
        td = ID.parse_target("com.apple.driver.AppleSPMIPMU", "x", SPMIPMU_MD)
        sig_a, sig_r, noise_a, noise_r = ID.split_noise(td.cstrings["added"],
                                                        td.cstrings["removed"])
        self.assertEqual((sig_a, sig_r), ([], []))
        self.assertEqual(len(noise_a), 1)
        self.assertEqual(len(noise_r), 1)

    def test_bare_timestamp_is_noise(self):
        for s in ("09:47:01", "Aug  6 2026", "Jul 30 2026 13:24:10", "2026/07/30",
                  "2026-07-30T13:29:24-07:00", "962.0.0.0.0"):
            self.assertTrue(ID.is_noise(s), s)

    def test_real_code_change_survives(self):
        for s in ("remaining >= cmdSize", "size > originalSize", "inpcb != NULL",
                  "state->cache.body.numRecords <= kCacheSize", "VM object is read-only",
                  "invalid bufIdx %d\\n"):
            self.assertFalse(ID.is_noise(s), s)

    def test_numeric_constant_change_is_not_noise(self):
        # Same text, different digits, no date/time token: MUST stay visible.
        a, r, na, nr = ID.split_noise(["max bufIdx 64"], ["max bufIdx 32"])
        self.assertEqual((a, r), (["max bufIdx 64"], ["max bufIdx 32"]))
        self.assertEqual((na, nr), ([], []))


class DriftGroupingTests(unittest.TestCase):
    def test_struct_grouping_from_offsets_h(self):
        names = DRIFT.read_offset_names()
        self.assertGreater(len(names), 50)
        groups = DRIFT.group_offsets(names)
        self.assertIn("inpcb", groups)
        self.assertIn("thread", groups)
        self.assertIn("arm_saved_state64", groups)
        self.assertIn("arm_saved_state", groups)
        self.assertNotIn("arm", groups)
        self.assertIn("off_inpcb_inp_list_le_next", groups["inpcb"])
        self.assertIn("off_apfs_fsnode_mode", groups["apfs_fsnode"])

    def test_every_offsets_h_name_lands_in_a_group(self):
        groups = DRIFT.group_offsets(DRIFT.read_offset_names())
        total = sum(len(v) for v in groups.values())
        self.assertEqual(total, len(DRIFT.read_offset_names()))

    def test_owner_lookup(self):
        self.assertEqual(DRIFT.kext_owner("apfs_fsnode"),
                         "com.apple.filesystems.apfs")
        self.assertEqual(DRIFT.kext_owner("inpcb"), "com.apple.kernel")

    def test_terms_are_specific(self):
        names = DRIFT.read_offset_names()
        groups = DRIFT.group_offsets(names)
        terms = DRIFT.terms_for("inpcb", groups["inpcb"])
        self.assertIn("inpcb", terms)
        self.assertIn("inp_list", terms)
        self.assertIn("le_next", terms)
        for generic in ("list", "next", "data", "object", "count", "entry"):
            self.assertNotIn(generic, terms, generic)


class DriftVerdictTests(unittest.TestCase):
    """End-to-end verdict logic on a synthetic pair (no network)."""

    def _pair(self, cstrings: str, kext: str = "com.apple.kernel"):
        # returns an ID.Pair (imported dynamically, so no annotation here)
        body = ("```diff\n\n-100.0.0.0\n+100.0.1.0\n"
                "   __DATA_CONST.__kalloc_type: 0x1000\n"
                "-  Functions: 10\n+  Functions: 11\n\n"
                f"CStrings:\n{cstrings}\n```\n")
        p = ID.Pair(dir="synthetic", label="1.0 (AAAA) .vs 1.0.1 (AAAB)")
        p.entries.append(ID.ManifestEntry("Kernel", "Kexts", "⬆️ Updated (1)",
                                          kext, f"inline:{kext}", "updated"))
        p.inline[kext] = body
        return p

    def test_struct_specific_string_marks_reverify(self):
        pair = self._pair('+ "inpcb inp_list corruption detected"\n')
        rows, kctx = DRIFT.analyse(FakeDataset({}), pair, None, jobs=1)
        verdicts = {r["struct"]: r["verdict"] for r in rows}
        self.assertEqual(verdicts["inpcb"], "reverify")
        self.assertEqual(verdicts["socket"], "kext-wide")
        self.assertTrue(kctx["com.apple.kernel"]["functions_changed"])

    def test_unrelated_change_stays_kext_wide(self):
        pair = self._pair('+ "totally unrelated message"\n')
        rows, _kctx = DRIFT.analyse(FakeDataset({}), pair, None, jobs=1)
        verdicts = {r["verdict"] for r in rows}
        self.assertNotIn("reverify", verdicts)
        # apfs_fsnode's kext is not in this pair at all -> no-kext-delta.
        self.assertEqual(verdicts, {"kext-wide", "no-kext-delta"})
        self.assertEqual(
            {r["struct"] for r in rows if r["verdict"] == "kext-wide"},
            {r["struct"] for r in rows if r["kext"] == "com.apple.kernel"})

    def test_kalloc_resize_reported_once_per_kext(self):
        pair = self._pair('+ "unrelated"\n')
        pair.inline["com.apple.kernel"] = pair.inline["com.apple.kernel"].replace(
            "   __DATA_CONST.__kalloc_type: 0x1000",
            "-  __DATA_CONST.__kalloc_type: 0x1000\n+  __DATA_CONST.__kalloc_type: 0x2000")
        rows, kctx = DRIFT.analyse(FakeDataset({}), pair, None, jobs=1)
        self.assertIn("__DATA_CONST.__kalloc_type",
                      kctx["com.apple.kernel"]["kalloc"])
        # It stays kext-level: no struct row claims a kalloc hit of its own.
        self.assertTrue(all(r["verdict"] in ("kext-wide", "no-kext-delta")
                            for r in rows))

    def test_struct_filter(self):
        pair = self._pair('+ "inpcb inp_list corruption detected"\n')
        rows, _kctx = DRIFT.analyse(FakeDataset({}), pair, ["inpcb", "socket"],
                                    jobs=1)
        self.assertEqual(sorted(r["struct"] for r in rows), ["inpcb", "socket"])

    def test_kext_absent_from_pair(self):
        pair = self._pair('+ "unrelated"\n', kext="com.apple.driver.NotHere")
        rows, _kctx = DRIFT.analyse(FakeDataset({}), pair, None, jobs=1)
        self.assertEqual({r["verdict"] for r in rows}, {"no-kext-delta"})

    def test_pair_without_kexts_is_a_valid_empty_answer(self):
        # A published pair whose Kernel section lists no changed kext must be an
        # empty answer, NOT an error: the tool reports it and exits 0.
        pair = ID.Pair(dir="empty", label="1.0 (AAAA) .vs 1.0.1 (AAAB)",
                       readme="# 1.0 (AAAA) .vs 1.0.1 (AAAB)\n\n## Kernel\n\n### Version\n\n")
        with self.assertRaises(DRIFT.NothingToVerify):
            DRIFT.analyse(FakeDataset({}), pair, None, jobs=1)

    def test_missing_kernel_section_says_so(self):
        pair = ID.Pair(dir="ota", label="1.0 .vs 1.0.1", readme="# 1.0 .vs 1.0.1\n")
        with self.assertRaises(DRIFT.NothingToVerify) as ctx:
            DRIFT.analyse(FakeDataset({}), pair, None, jobs=1)
        self.assertIn("no Kernel section", str(ctx.exception))

    def test_kext_entry_that_parses_to_nothing_is_an_error(self):
        # Layout drift must NOT be reported as "nothing changed".
        pair = self._pair('+ "x"\n')
        pair.inline["com.apple.kernel"] = "no fence here at all\n"
        with self.assertRaises(ID.DatasetError):
            DRIFT.analyse(FakeDataset({}), pair, None, jobs=1)


if __name__ == "__main__":
    unittest.main()
