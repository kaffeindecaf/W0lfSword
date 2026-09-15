#!/usr/bin/env python3
"""T17: check that every evidence path the docs cite actually resolves.

Reads the claim-bearing docs (both roadmaps, the W0lfSword README, the worklog
and this capture's own reconciliation table), extracts every path that points
into docs/verification/2026-09-11-0.12/, and fails on any that does not exist.
That is the mechanical half of "each verified fact is backed by captured
output": a citation that points at a file nobody can open is not evidence.

Handles the shapes the docs actually use: `../W0lfSword/docs/...` prefixes,
`` `t17/...` `` shorthand, brace expansions (`x.{repo,absent}.log`), globs, bare
directory citations, and elisions (`.../t17/`) which are skipped.

It also fails if the capture still points outside the repo (a `$TMPDIR/...`
tree reference), which was the T17 round-1 defect.

Host only; reads files, writes nothing.

    python3 docs/verification/2026-09-11-0.12/t17/check_capture_paths.py
"""
import glob
import os
import re
import sys

SW = "/home/kaffein/Desktop/W0lfSword"
TERM = "/home/kaffein/Desktop/W0lfTerm"
BASE = os.path.join(SW, "docs/verification/2026-09-11-0.12")
HERE = os.path.join(BASE, "t17")

DOCS = [
    os.path.join(SW, "ROADMAP.md"),
    os.path.join(SW, "README.md"),
    os.path.join(SW, "docs/WORKLOG.md"),
    os.path.join(TERM, "ROADMAP.md"),
    os.path.join(TERM, "README.md"),
]
DOCS += sorted(glob.glob(os.path.join(BASE, "*/*.md")))

FULL = re.compile(r"(?:\.\./W0lfSword/)?(docs/verification/2026-09-11-0\.12/[A-Za-z0-9_./*{},-]+)")
SHORT = re.compile(r"`(t17/[A-Za-z0-9_./*{},-]+)`")
TRIM = ".,);:'\""


def expand(p):
    """Expand {a,b,c} into the list of concrete paths it stands for."""
    m = re.search(r"\{([^}]*)\}", p)
    if not m:
        return [p]
    out = []
    for part in m.group(1).split(","):
        out += expand(p[: m.start()] + part + p[m.end():])
    return out


def resolve(match):
    p = match.rstrip(TRIM)
    if "..." in p or p.endswith(".."):
        return None                       # elided citation: nothing to open
    if p.startswith("t17/"):
        return os.path.join(BASE, p)
    return os.path.join(SW, p)


def main():
    cited = {}
    for doc in DOCS:
        if not os.path.exists(doc):
            print("SKIP (missing doc): %s" % doc)
            continue
        text = open(doc, encoding="utf-8", errors="replace").read()
        for rx in (FULL, SHORT):
            for m in rx.finditer(text):
                path = resolve(m.group(1))
                if path is None:
                    continue
                for one in expand(path):
                    cited.setdefault(one, set()).add(os.path.relpath(doc, SW))

    ok = bad = 0
    for path in sorted(cited):
        if "*" in path:
            hits = glob.glob(path)
        elif path.endswith("/"):
            hits = [path] if os.path.isdir(path) else []
        else:
            hits = [path] if os.path.exists(path) else []
        if hits:
            ok += 1
        else:
            bad += 1
            print("BAD  %-72s (cited by %s)"
                  % (os.path.relpath(path, SW), ", ".join(sorted(cited[path]))))

    outside = []
    for root, _dirs, files in os.walk(HERE):
        for f in files:
            p = os.path.join(root, f)
            if p.endswith(".pyc") or "/tree/" in p:
                continue
            try:
                body = open(p, encoding="utf-8", errors="replace").read()
            except OSError:
                continue
            for m in re.finditer(r"(\$TMPDIR|\btmp)/w0lf_t17_revisions", body):
                outside.append("%s: %s" % (os.path.relpath(p, SW), m.group(0)))
    for line in outside:
        print("BAD  capture still points outside the repo: %s" % line)

    print("\ncapture path check: %d ok, %d bad (docs read: %d)"
          % (ok, bad + len(outside), len(DOCS)))
    return 1 if (bad or outside) else 0


if __name__ == "__main__":
    sys.exit(main())
