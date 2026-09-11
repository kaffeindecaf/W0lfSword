#!/usr/bin/env python3
"""Host tests for scripts/colorize_diff.py (ROADMAP J7.3 / J8.6).

The colorizer is what the user reads when reviewing a diff, so its two failure
modes matter: colouring when output is piped (log noise / broken captures) and
NOT highlighting the code inside +/- lines (the reason the tool exists).
Both are asserted here, plus the language pick and the pass-through path.

    python3 -m unittest tests.test_colorize_diff -v
"""
from __future__ import annotations

import importlib.util
import os
import pathlib
import re
import subprocess
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "colorize_diff.py"

spec = importlib.util.spec_from_file_location("colorize_diff", SCRIPT)
cd = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cd)

SAMPLE = """diff --git a/Tweak.m b/Tweak.m
index 1234567..89abcde 100644
--- a/Tweak.m
+++ b/Tweak.m
@@ -10,6 +10,7 @@
     int rc = 0;
-    char *buf = malloc(16);
+    static const char *path = "/var/mobile/.sbx_check";
+    if (rc == 0) { return NULL; }
     rc = 1;
diff --git a/scripts/thing.py b/scripts/thing.py
index 1111111..2222222 100644
--- a/scripts/thing.py
+++ b/scripts/thing.py
@@ -1,3 +1,4 @@
 def main():
-    return None
+    value = "hello"
+    return value if value else True
"""

BINARY = """diff --git a/packages/Filza.ipa b/packages/Filza.ipa
index aaaaaaa..bbbbbbb 100644
Binary files a/packages/Filza.ipa and b/packages/Filza.ipa differ
"""

NO_EXT = """diff --git a/notes/README b/notes/README
index 1111111..2222222 100644
--- a/notes/README
+++ b/notes/README
@@ -1 +1 @@
-old text
+new text
"""

ANSI = "\033["
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def strip(s: str) -> str:
    """Drop ANSI codes - the highlighter wraps every token, so a plain
    substring like `static const char *path` is NOT contiguous in the raw
    output. Content assertions must run on stripped text."""
    return _ANSI_RE.sub("", s)


class TestColourDiff(unittest.TestCase):
    def coloured_lines(self, text=SAMPLE):
        return cd.colour_diff(text, enabled=True).splitlines()

    def find(self, lines, needle):
        for l in lines:
            if needle in strip(l):
                return l
        raise AssertionError(f"no line containing {needle!r}")

    def test_no_color_is_byte_identical(self):
        self.assertEqual(cd.colour_diff(SAMPLE, enabled=False), SAMPLE)

    def test_no_color_still_has_every_line(self):
        plain = cd.colour_diff(SAMPLE, enabled=False)
        self.assertEqual(len(plain.splitlines()), len(SAMPLE.splitlines()))

    def test_colour_adds_ansi_and_keeps_content(self):
        out = cd.colour_diff(SAMPLE, enabled=True)
        self.assertIn(ANSI, out)
        plain = strip(out)
        for needle in ("static const char *path", "char *buf = malloc(16)",
                       'value = "hello"', "if (rc == 0)"):
            self.assertIn(needle, plain, f"content lost: {needle}")

    def test_added_line_is_green_removed_line_is_red(self):
        lines = self.coloured_lines()
        added = self.find(lines, "static const char *path")
        removed = self.find(lines, "char *buf = malloc(16)")
        self.assertIn(cd.GREEN, added)
        self.assertNotIn(cd.RED, added)
        self.assertIn(cd.RED, removed)
        self.assertNotIn(cd.GREEN, removed)

    def test_objc_keywords_and_types_are_highlighted(self):
        added = self.find(self.coloured_lines(), "static const char *path")
        self.assertIn(cd.BOLD, added, "keyword highlighting missing on a .m line")
        self.assertIn(cd.FROST, added, "type highlighting missing on a .m line")
        self.assertIn(cd.AMBER, added, "string highlighting missing on a .m line")

    def test_python_line_gets_its_own_rules(self):
        py_added = self.find(self.coloured_lines(), "return value if value else True")
        self.assertIn(cd.BOLD, py_added, "python keywords should be bold")
        self.assertNotIn(cd.FROST, py_added, "C types must not leak into python")
        py_str = self.find(self.coloured_lines(), 'value = "hello"')
        self.assertIn(cd.AMBER, py_str, "python string should be amber")

    def test_tags_hunks_headers_and_languages(self):
        lines = self.coloured_lines()
        header = self.find(lines, "diff --git a/Tweak.m")
        self.assertIn("[c]", strip(header))
        self.assertTrue(any("[py]" in strip(l) for l in lines))
        hunk = self.find(lines, "@@ -10,6 +10,7 @@")
        self.assertIn(cd.MUTED, hunk)

    def test_context_lines_are_dim(self):
        ctx = self.find(self.coloured_lines(), "int rc = 0;")
        self.assertTrue(ctx.startswith(cd.DIM), "context lines should be dimmed")

    def test_binary_diff_line_is_flagged(self):
        out = cd.colour_diff(BINARY, enabled=True)
        self.assertIn(cd.AMBER, out)
        self.assertIn("Binary files", strip(out))
        self.assertIn("Filza.ipa", strip(out))

    def test_unknown_extension_gets_no_language_tag(self):
        lines = self.coloured_lines(NO_EXT)
        header = self.find(lines, "diff --git a/notes/README")
        self.assertEqual(strip(header), "diff --git a/notes/README b/notes/README")
        added = self.find(lines, "new text")
        self.assertIn(cd.GREEN, added)

    def test_line_count_is_preserved(self):
        self.assertEqual(len(cd.colour_diff(SAMPLE, True).splitlines()),
                         len(SAMPLE.splitlines()))

    def test_extensionless_cli_file_gets_shell_rules(self):
        """The repo's main CLI has no extension - it must still be highlighted,
        since that is the file most diffs touch."""
        diff = ("diff --git a/W0lfSword b/W0lfSword\n"
                "index 1111111..2222222 100644\n"
                "--- a/W0lfSword\n"
                "+++ b/W0lfSword\n"
                "@@ -1,2 +1,3 @@\n"
                "+if [ -z \"$1\" ]; then return 1; fi\n")
        lines = self.coloured_lines(diff)
        header = self.find(lines, "diff --git a/W0lfSword")
        self.assertIn("[sh]", strip(header))
        added = self.find(lines, "if [ -z")
        self.assertIn(cd.BOLD, added, "shell keywords should be bold in the CLI diff")

    def test_lang_for_covers_the_repo_layout(self):
        self.assertEqual(cd.lang_for("Tweak.m"), "c")
        self.assertEqual(cd.lang_for("shell/trm_shell.c"), "c")
        self.assertEqual(cd.lang_for("W0lfSword"), "sh")
        self.assertEqual(cd.lang_for("scripts/colorize_diff.py"), "py")
        self.assertEqual(cd.lang_for("notes/README"), "")


class TestCliContract(unittest.TestCase):
    """The CLI is the actual consumer - exercise it as a process."""

    def _run(self, args, env=None, stdin=SAMPLE):
        e = dict(os.environ)
        e.pop("NO_COLOR", None)
        if env:
            e.update(env)
        return subprocess.run([sys.executable, str(SCRIPT)] + args,
                              input=stdin, capture_output=True, text=True, env=e)

    def test_piped_output_is_plain_by_default(self):
        r = self._run([])
        self.assertEqual(r.returncode, 0)
        self.assertNotIn(ANSI, r.stdout, "piped output must stay clean (auto mode)")
        self.assertEqual(r.stdout, SAMPLE)

    def test_color_always_forces_ansi(self):
        r = self._run(["--color=always"])
        self.assertIn(ANSI, r.stdout)

    def test_no_color_flag_beats_color_always(self):
        r = self._run(["--color=always", "--no-color"])
        self.assertNotIn(ANSI, r.stdout)

    def test_no_color_env_forces_plain(self):
        r = self._run(["--color=always"], env={"NO_COLOR": "1"})
        self.assertNotIn(ANSI, r.stdout)

    def test_empty_input_is_safe(self):
        r = self._run(["--color=always"], stdin="")
        self.assertEqual(r.returncode, 0)
        self.assertEqual(r.stdout, "")

    def test_garbage_input_is_passed_through(self):
        junk = "not a diff at all\n\x00 weird\n"
        r = self._run(["--color=always"], stdin=junk)
        self.assertEqual(r.returncode, 0)
        self.assertIn("not a diff at all", r.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
