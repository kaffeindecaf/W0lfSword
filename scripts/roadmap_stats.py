#!/usr/bin/env python3
"""W0lfSword ROADMAP STATS table: generator + drift check (AUD.12).

The STATS table at the bottom of ROADMAP.md was hand-maintained and had
drifted ~6 weeks behind the file: it claimed 290 items / 150 done / 140 open
while the file held 377 checkbox rows / 249 done / 128 open, and its per-row
figures disagreed too (K1 said 11/4/7 against 12 rows / 10 done). A status
table nobody maintains is worse than no table, because it reads as an
authoritative progress figure.

So the table is generated from the file it summarises, and this script is the
single implementation of both halves:

  - the row for a group is the checkbox rows (`- [ ] ` / `- [x] `) under one
    section header. Sections are the file's own `## ` headers; items that sit
    under a level-1 header with no `## ` parent (SECTION E's E1.* rows) fall
    back to that header's name. Rows inside a fenced code block are not items.
  - the table carries one row per group that holds at least one item, in file
    order, plus the bold TOTAL row - which is the file's item count, so the
    table can never undercount a section it does not list.

`--write` regenerates it; the check (default) fails when the table and the
file disagree, which is how it is wired into `./W0lfSword audit`, and
`--selftest` proves the check can fail (nine fixture mutations, including the
real drift shape: a checkbox toggled without regenerating).

Usage:
    python3 scripts/roadmap_stats.py [ROADMAP.md]     # check (default path:
                                                      # the repo's ROADMAP.md)
    python3 scripts/roadmap_stats.py --write [path]   # regenerate the table
    python3 scripts/roadmap_stats.py --json [path]    # machine-readable
    python3 scripts/roadmap_stats.py --selftest       # prove the check fails

Exit: 0 = table matches (or --write/--json/--selftest succeeded),
      1 = drift (findings printed as `  ERROR: ...` lines), 2 = no table.
"""

import json
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_ROADMAP = os.path.join(os.path.dirname(HERE), "ROADMAP.md")

TABLE_HEADER = "| Section | Total Items | Completed | Remaining |"
TABLE_SEP = "|---------|------------|-----------|-----------|"
TOTAL_LABEL = "**TOTAL**"
# a stale table produces one finding per differing line; show this many and
# summarise the rest (the `findings:` count stays the real total)
MAX_SHOWN = 12

H1 = re.compile(r"^# (.+?)\s*$")
H2 = re.compile(r"^## (.+?)\s*$")
ITEM = re.compile(r"^- \[([ xX])\] ")
FENCE = re.compile(r"^\s*(`{3,})")


def group_name(level1, level2):
    """Name of the group an item belongs to (level-2 header wins)."""
    if level2:
        return level2
    if level1:
        # `# SECTION E: iOS Version / Device Expansion` has no `## ` parent,
        # its E1.* rows are the only items on that level.
        return re.sub(r"^SECTION\s+", "", level1)
    return "ROADMAP.md"


def parse(text):
    """Return [(name, done, open)] in file order, and the item totals."""
    groups = []
    index = {}
    level1 = level2 = None
    fence = None
    lines = text.splitlines()

    def register(name):
        """Every header gets a slot so 'sections in file' counts them all;
        only groups that hold items get a table row."""
        if name not in index:
            index[name] = len(groups)
            groups.append([name, 0, 0])
        return index[name]

    for line in lines:
        m = FENCE.match(line)
        if m:
            if fence is None:
                fence = m.group(1)
            elif line.strip().startswith(fence):
                fence = None
            continue
        if fence:
            continue
        m = H1.match(line)
        if m:
            level1, level2 = m.group(1).strip(), None
            register(level1)
            continue
        m = H2.match(line)
        if m:
            level2 = m.group(1).strip()
            register(level2)
            continue
        m = ITEM.match(line)
        if not m:
            continue
        groups[register(group_name(level1, level2))][1 if m.group(1) in "xX" else 2] += 1
    totals = [sum(g[1] for g in groups), sum(g[2] for g in groups)]
    return [(g[0], g[1], g[2]) for g in groups], totals


def render_table(groups, totals):
    """The canonical table lines: header, separator, one row per group, TOTAL."""
    # a marker line, not a table row, so it neither parses as drift nor breaks
    # the contiguous `|` block the checker walks
    rows = [TABLE_HEADER, TABLE_SEP]
    for name, done, open_ in groups:
        if done + open_ == 0:
            continue  # a section with no items carries no status
        rows.append("| %s | %d | %d | %d |" % (name, done + open_, done, open_))
    rows.append("| %s | **%d** | **%d** | **%d** |"
                % (TOTAL_LABEL, totals[0] + totals[1], totals[0], totals[1]))
    return rows


def table_span(lines):
    """(start, end) of the existing table, end exclusive; (-1, -1) if absent."""
    try:
        start = lines.index(TABLE_HEADER)
    except ValueError:
        return (-1, -1)
    end = start + 1
    while end < len(lines) and lines[end].startswith("|"):
        end += 1
    return (start, end)


def check(path):
    """(findings, stats). findings = list of drift strings."""
    with open(path, encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    lines = text.splitlines()
    groups, totals = parse(text)
    want = render_table(groups, totals)
    start, end = table_span(lines)
    stats = {"sections": len(groups),
             "groups": sum(1 for g in groups if g[1] + g[2]),
             "items": totals[0] + totals[1],
             "done": totals[0], "open": totals[1], "path": path,
             "table": start >= 0}
    if start < 0:
        stats["rows"] = 0
        return ["no STATS table found (expected a `%s` header line - run "
                "--write to create it)" % TABLE_HEADER], stats
    found = lines[start:end]
    stats["rows"] = max(0, len(found) - 2)
    findings = []
    for i in range(max(len(want), len(found))):
        w = want[i] if i < len(want) else "<missing>"
        f = found[i] if i < len(found) else "<missing>"
        if w != f:
            findings.append("line %d: expected '%s' but found '%s'"
                            % (start + i + 1, w, f))
    if not findings and len(found) > len(want):
        findings.append("line %d: %d stale row(s) below the TOTAL"
                        % (start + len(want) + 1, len(found) - len(want)))
    return findings, stats


def write_table(path):
    """Regenerate the table in place; every other line stays byte-identical."""
    with open(path, encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    newline = "\r\n" if "\r\n" in text else "\n"
    lines = text.splitlines()
    groups, totals = parse(text)
    want = render_table(groups, totals)
    start, end = table_span(lines)
    if start < 0:
        return False
    lines[start:end] = want
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(newline.join(lines) + newline)
    return True


def missing_table_rc(stats, findings):
    """0 = clean, 1 = drift, 2 = the table is not there at all."""
    if not stats.get("table", True):
        return 2
    return 1 if findings else 0


def run_self(path, extra=None):
    """Run this script as a subprocess; return (rc, stdout+stderr)."""
    cmd = [sys.executable, os.path.abspath(__file__)]
    if extra:
        cmd += extra
    cmd.append(path)
    proc = subprocess.run(cmd, capture_output=True, text=True)
    return proc.returncode, proc.stdout + proc.stderr


FIXTURE = """# fixture ROADMAP

## 0.1 — Quick wins

- [x] `A.1` — done one
  _Done 2026-01-01: yes_
- [ ] `A.2` — open one

## 0.2 — Later work

- [x] `B.1` — done two

## Empty — nothing here

# STATS

> Generated table - do not hand-edit.

| Section | Total Items | Completed | Remaining |
|---------|------------|-----------|-----------|
| 0.1 — Quick wins | 2 | 1 | 1 |
| 0.2 — Later work | 1 | 1 | 0 |
| **TOTAL** | **3** | **2** | **1** |
"""

TABLE_ROW_0102 = "| 0.2 — Later work | 1 | 1 | 0 |"
TABLE_ROW_01 = "| 0.1 — Quick wins | 2 | 1 | 1 |"


def selftest():
    """Mutate a fixture and prove the check fails on each drift shape."""
    base = FIXTURE
    checks = []

    def add(name, ok, detail=""):
        checks.append((name, ok, detail))

    def variant(tmp, name, old, new):
        """Write a copy of the fixture with one replacement; return its path."""
        out = os.path.join(tmp, name)
        with open(out, "w", encoding="utf-8") as fh:
            fh.write(base.replace(old, new))
        return out

    with tempfile.TemporaryDirectory() as tmp:
        good = os.path.join(tmp, "good.md")
        with open(good, "w", encoding="utf-8") as fh:
            fh.write(base)
        rc, out = run_self(good)
        add("a matching table passes", rc == 0, out)

        # 1. a count edited by hand
        bad = variant(tmp, "count.md", TABLE_ROW_01,
                      "| 0.1 — Quick wins | 2 | 2 | 0 |")
        rc, out = run_self(bad)
        add("a hand-edited count is caught", rc == 1 and "line " in out, out)

        # 2. a row deleted
        bad = variant(tmp, "row.md", TABLE_ROW_0102 + "\n", "")
        rc, out = run_self(bad)
        add("a deleted row is caught", rc == 1 and "<missing>" in out, out)

        # 3. a stale row nobody removed
        bad = variant(tmp, "stale.md", TABLE_ROW_0102,
                      TABLE_ROW_0102 + "\n| Z9 — Gone | 4 | 0 | 4 |")
        rc, out = run_self(bad)
        add("a stale extra row is caught", rc == 1 and "expected" in out, out)

        # 4. THE real drift shape: a checkbox toggled, table not regenerated
        bad = variant(tmp, "toggle.md", "- [ ] `A.2` — open one",
                      "- [x] `A.2` — open one")
        rc, out = run_self(bad)
        add("a toggled checkbox is caught", rc == 1 and "**3**" in out, out)

        # 5. an empty section adds no row
        bad = variant(tmp, "empty.md", TABLE_ROW_0102,
                      TABLE_ROW_0102 + "\n| Empty — nothing here | 0 | 0 | 0 |")
        rc, out = run_self(bad)
        add("a zero-item row is caught", rc == 1, out)

        # 6. --write repairs the drift and touches nothing else
        toggled = base.replace("- [ ] `A.2` — open one", "- [x] `A.2` — open one")
        with open(os.path.join(tmp, "repair.md"), "w", encoding="utf-8") as fh:
            fh.write(toggled)
        repair = os.path.join(tmp, "repair.md")
        rc_w, _ = run_self(repair, ["--write"])
        rc, out = run_self(repair)
        add("--write repairs the table", rc_w == 0 and rc == 0, out)
        with open(repair, encoding="utf-8") as fh:
            repaired = fh.read()
        before = toggled.splitlines()
        after = repaired.splitlines()
        s1, e1 = table_span(before)
        s2, e2 = table_span(after)
        same_body = (before[:s1] == after[:s2]) and (before[e1:] == after[e2:])
        add("--write leaves every other line alone", same_body,
            "only the table span differs" if same_body else "file body changed")

        # 7. items inside a fence are not items
        bad = variant(tmp, "fence.md", "## Empty — nothing here",
                      "## Empty — nothing here\n\n```\n- [ ] `X.9` — not an item\n```")
        rc, out = run_self(bad)
        add("a fenced checkbox is not an item", rc == 0, out)

        # 8. no table at all
        bad = variant(tmp, "notable.md", TABLE_HEADER, "no table here")
        rc, out = run_self(bad)
        add("a missing table exits 2", rc == 2 and "no STATS table" in out, out)

        # 9. a level-1 header with no `## ` parent names its group
        bad = variant(tmp, "level1.md", "## 0.2 — Later work",
                      "# SECTION Q: Level one")
        rc_w, _ = run_self(bad, ["--write"])
        rc, _ = run_self(bad)
        with open(bad, encoding="utf-8") as fh:
            repaired = fh.read()
        add("a level-1 group is named and repaired",
            rc_w == 0 and rc == 0 and "| Q: Level one | 1 | 1 | 0 |" in repaired,
            "\n".join(repaired.splitlines()[-4:]))

    failed = [c for c in checks if not c[1]]
    for name, ok, detail in checks:
        print("  %s %s" % ("ok  " if ok else "FAIL", name))
        if not ok and detail:
            print("       %s" % detail.strip().replace("\n", "\n       "))
    print("selftest: %s (%d/%d)"
          % ("all mutations caught" if not failed else "%d mutation(s) survived"
             % len(failed), len(checks) - len(failed), len(checks)))
    return 1 if failed else 0


def main(argv):
    args = [a for a in argv if not a.startswith("--")]
    path = args[0] if args else DEFAULT_ROADMAP
    if "--selftest" in argv:
        return selftest()
    if not os.path.isfile(path):
        sys.stderr.write("roadmap_stats.py: no such file: %s\n" % path)
        return 2
    if "--write" in argv:
        if not write_table(path):
            sys.stderr.write("roadmap_stats.py: no STATS table in %s to "
                             "regenerate\n" % path)
            return 2
        findings, stats = check(path)
        print("  table regenerated: %d row(s) over %d item(s)"
              % (stats.get("rows", 0), stats["items"]))
        return 1 if findings else 0
    findings, stats = check(path)
    if "--json" in argv:
        stats["findings"] = len(findings)
        stats["issues"] = findings
        stats["ok"] = not findings and stats.get("table", True)
        print(json.dumps(stats, indent=2))
        return missing_table_rc(stats, findings)
    print("  roadmap:               %s" % os.path.relpath(path))
    print("  headers (in file):     %d" % stats["sections"])
    print("  rows (with items):     %d" % stats["groups"])
    print("  table rows:            %d" % stats.get("rows", 0))
    print("  items:                 %d" % stats["items"])
    print("  done:                  %d" % stats["done"])
    print("  open:                  %d" % stats["open"])
    shown = findings[:MAX_SHOWN]
    for finding in shown:
        print("  ERROR: %s" % finding)
    if len(findings) > len(shown):
        print("  ERROR: ... and %d more line(s) differ"
              % (len(findings) - len(shown)))
    print("findings: %d" % len(findings))
    if findings:
        print("regenerate: python3 scripts/roadmap_stats.py --write %s"
              % os.path.relpath(path))
    return missing_table_rc(stats, findings)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
