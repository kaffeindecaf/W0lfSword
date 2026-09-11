#!/usr/bin/env python3
"""Colour a unified diff for terminal review (ROADMAP J7.3 / J8.6).

Reads a unified diff on stdin (git diff, git show, diff -u) and writes it back
with ANSI colour: file headers, hunk headers, added/removed lines plus
language-aware highlighting inside the changed lines for the source types this
project actually uses (.m/.xm/.h/.c/, python, shell).

Why not just `git diff --color`? Git colours the line, not the code. With 40
lines of ObjC in a hunk, the eye still has to parse every keyword. This marks
keywords, types, strings and comments inside the +/- lines, while leaving
context lines dim so the actual change stands out.

Usage:
    git diff | scripts/colorize_diff.py
    git diff --staged | scripts/colorize_diff.py --color=always | less -R
    ./W0lfSword diff [--staged|--stat|<rev>]

Colour policy follows the usual convention: auto (default) colours only when
stdout is a terminal, so piping into a file stays clean. --no-color and
NO_COLOR=1 force plain output.
"""
from __future__ import annotations

import os
import re
import sys

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
# 256-colour palette matching the CLI (frost accent / muted / green / red / amber)
FROST = "\033[38;5;117m"
MUTED = "\033[38;5;244m"
GREEN = "\033[38;5;114m"
RED = "\033[38;5;203m"
AMBER = "\033[38;5;216m"

# ---------------------------------------------------------------- languages

C_TYPES = (
    "void char short int long float double signed unsigned bool size_t ssize_t "
    "uint8_t uint16_t uint32_t uint64_t int8_t int16_t int32_t int64_t "
    "BOOL id SEL Class NSString NSDictionary NSArray NSData NSMutableDictionary "
    "NSMutableArray NSJSONSerialization uintptr_t off_t pid_t FILE DIR "
    "kern_return_t mach_port_t"
)
C_KEYWORDS = (
    "if else for while do return break continue switch case default goto "
    "static const extern inline register volatile struct union enum typedef "
    "sizeof NULL nil Nil YES NO true false self super "
    "#import #include #define #ifdef #ifndef #endif #if pragma"
)
PY_KEYWORDS = (
    "def class return if elif else for while import from as with try except "
    "finally raise yield lambda pass break continue global nonlocal assert "
    "async await True False None and or not in is del with"
)
SH_KEYWORDS = (
    "if then else elif fi for while do done case esac function return local "
    "export readonly declare shift set unset trap source exit echo printf "
    "[[ ]] { }"
)

LANG_BY_SUFFIX = {
    ".m": "c", ".mm": "c", ".xm": "c", ".h": "c", ".c": "c", ".cpp": "c",
    ".py": "py", ".sh": "sh", ".bash": "sh", ".zsh": "sh",
}

# The repo's biggest files have no extension (the CLI itself), so extension
# matching alone leaves the most-read diffs unhighlighted. Map the known
# extensionless scripts/build files by basename.
LANG_BY_BASENAME = {
    "W0lfSword": "sh",
    "W0lfSword-Beta": "sh",
    "control": "sh",          # debian control: key: value, shell-ish comments
    "Makefile": "sh",         # no C keywords; shell set still colours ifeq etc.
}


def _word_alt(words: str) -> str:
    parts = sorted({w for w in words.split() if w}, key=len, reverse=True)
    return "|".join(re.escape(p) for p in parts)


_C_LINE_COMMENT = r"//[^\n]*"
_C_BLOCK = r"/\*.*?\*/"
_STR = r'"(?:[^"\\\n]|\\.)*"'
_CHR = r"'(?:[^'\\\n]|\\.)*'"
_PREPROC = r"^[ \t]*#[a-z]+"

PATTERNS = {
    "c": re.compile(
        "|".join([
            _C_LINE_COMMENT, _C_BLOCK, _STR, _CHR, _PREPROC,
            r"\b(?:" + _word_alt(C_KEYWORDS.replace("#", "")) + r")\b",
            r"\b(?:" + _word_alt(C_TYPES) + r")\b",
        ])
    ),
    "py": re.compile(
        "|".join([
            r"#[^\n]*", _STR, _CHR,
            r"\b(?:" + _word_alt(PY_KEYWORDS) + r")\b",
        ])
    ),
    "sh": re.compile(
        "|".join([
            r"#[^\n]*", _STR, _CHR,
            r"\b(?:" + _word_alt(SH_KEYWORDS.replace("[", "").replace("]", "")) + r")\b",
        ])
    ),
}


def _token_colour(lang: str, token: str) -> str:
    if lang == "c":
        if token.startswith("//") or token.startswith("/*"):
            return MUTED
        if token.startswith("#"):
            return AMBER + BOLD
        if token.startswith('"') or token.startswith("'"):
            return AMBER
        if token in C_TYPES.split():
            return FROST
        return BOLD
    # py / sh: comments dim, strings amber, keywords bold
    if token.startswith("#"):
        return MUTED
    if token.startswith('"') or token.startswith("'"):
        return AMBER
    return BOLD


def highlight(code: str, lang: str, base: str) -> str:
    """Colour one line of code, returning it wrapped in `base` colour."""
    if lang not in PATTERNS:
        return base + code + RESET
    pattern = PATTERNS[lang]
    out = [base]
    pos = 0
    for m in pattern.finditer(code):
        if m.start() > pos:
            out.append(code[pos:m.start()])
        tok = m.group(0)
        out.append(_token_colour(lang, tok) + tok + base)
        pos = m.end()
    out.append(code[pos:])
    out.append(RESET)
    return "".join(out)


# ---------------------------------------------------------------- diff parsing

def lang_for(path: str) -> str:
    base = path.rsplit("/", 1)[-1]
    if base in LANG_BY_BASENAME:
        return LANG_BY_BASENAME[base]
    for suffix, lang in LANG_BY_SUFFIX.items():
        if path.endswith(suffix):
            return lang
    return ""


def colour_diff(text: str, enabled: bool) -> str:
    if not enabled:
        return text
    out = []
    current_lang = ""
    for line in text.splitlines():
        if line.startswith("diff --git "):
            # the file name lives after the second " b/"
            parts = line.split(" b/", 1)
            name = parts[-1] if len(parts) == 2 else line
            current_lang = lang_for(name)
            label = FROST + BOLD + line + RESET
            if current_lang:
                label += MUTED + "   [" + current_lang + "]" + RESET
            out.append(label)
        elif line.startswith(("index ", "old mode ", "new mode ", "similarity ",
                              "rename ", "new file mode ", "deleted file mode ")):
            out.append(MUTED + line + RESET)
        elif line.startswith(("--- ", "+++ ")):
            out.append(FROST + BOLD + line + RESET)
        elif line.startswith("@@"):
            out.append(MUTED + BOLD + line + RESET)
        elif line.startswith("Binary files ") or line.startswith("GIT binary patch"):
            out.append(AMBER + line + RESET)
        elif line.startswith("+") and not line.startswith("+++"):
            out.append(highlight(line, current_lang, GREEN))
        elif line.startswith("-") and not line.startswith("---"):
            out.append(highlight(line, current_lang, RED))
        elif line.startswith("\\"):
            out.append(MUTED + line + RESET)
        else:
            out.append(DIM + line + RESET)
    return "\n".join(out) + ("\n" if text.endswith("\n") else "")


def _parse_colour_arg(argv) -> str:
    if os.environ.get("NO_COLOR"):
        return "never"
    mode = "auto"
    for a in argv:
        if a == "--no-color":
            mode = "never"
        elif a.startswith("--color="):
            mode = a.split("=", 1)[1]
    return mode


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    mode = _parse_colour_arg(argv)
    if mode == "always":
        enabled = True
    elif mode == "never":
        enabled = False
    else:
        enabled = sys.stdout.isatty()
    text = sys.stdin.read()
    sys.stdout.write(colour_diff(text, enabled))
    return 0


if __name__ == "__main__":
    sys.exit(main())
