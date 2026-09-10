#!/usr/bin/env python3
"""W0lfSword CLI consistency check (AUD.10).

The CLI surface is declared once, in the W0LF_COMMANDS registry inside the
W0lfSword script, and consumed by several places: main()'s dispatch case, the
interactive menu (rows + shortcuts line), `commands` and explain's fallback
list. This check verifies the registry and those consumers still agree.

Usage:
    python3 scripts/cli_consistency.py [path/to/W0lfSword]

Exit code 0 = consistent, 1 = findings (printed as `  ERROR: ...` lines).
The last line is always `findings: N` so cmd_audit can parse it, and
`commands: N` / `keys: N` give the counts the audit report shows.
"""

import re
import sys

REGISTRY_START = re.compile(r"^W0LF_COMMANDS=\(\s*$")
REGISTRY_ROW = re.compile(r'^ {4}"([^"]*)"\s*$')
FIELD_COUNT = 10
# name slot shortcut aliases group label summary tag docs handler
FIELD_NAMES = ["name", "slot", "shortcut", "aliases", "group", "label",
               "summary", "tag", "docs", "handler"]
GROUPS = {"exploit", "device", "diagnostics", "research", "safety",
          "catalog", "housekeeping", "meta"}
TAGS = {"-", "", "root", "crash", "live", "beta"}
FUNC_DEF = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s*\(\)\s*\{", re.M)
HEREDOC = re.compile(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")


def strip_heredocs(lines):
    """Yield (lineno, line, in_heredoc). Prose inside heredocs (explain_text's
    write-ups) contains lines that look like case patterns, so it must not be
    parsed as code."""
    delim = None
    for n, raw in enumerate(lines, 1):
        line = raw.rstrip("\n")
        if delim is not None:
            if line.strip() == delim:
                delim = None
            yield n, line, True
            continue
        m = HEREDOC.search(line)
        if m:
            delim = m.group(2)
        yield n, line, False


def case_block(lines, header, start_at=0):
    """Return the alternatives of `<header>` ... `esac` as (lineno, pattern)."""
    out = []
    depth = False
    for n, line, in_heredoc in strip_heredocs(lines):
        if in_heredoc:
            continue
        if n - 1 < start_at:
            continue
        if not depth:
            if line.strip() == header:
                depth = True
            continue
        stripped = line.strip()
        if stripped.startswith("esac"):
            break
        if stripped.startswith("#"):
            continue
        m = re.match(r"^([^)]+)\)", stripped)
        if m:
            out.append((n, m.group(1).strip()))
    return out


def parse_registry(lines):
    rows, in_block, errors = [], False, []
    for n, raw in enumerate(lines, 1):
        line = raw.rstrip("\n")
        if not in_block:
            if REGISTRY_START.match(line):
                in_block = True
            continue
        if line.startswith(")"):
            break
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        m = REGISTRY_ROW.match(line)
        if not m:
            errors.append(f"line {n}: registry row does not match the "
                          f"'    \"name|slot|...\"' shape")
            continue
        fields = m.group(1).split("|")
        if len(fields) != FIELD_COUNT:
            errors.append(f"line {n}: registry row has {len(fields)} fields, "
                          f"expected {FIELD_COUNT}")
            continue
        row: dict = dict(zip(FIELD_NAMES, fields))
        row["_line"] = n
        rows.append(row)
    return rows, errors


def case_block_for(lines, func, header="case \"$cmd\" in"):
    """Alternatives of the first <header> appearing after `func() {`."""
    start = None
    for idx, raw in enumerate(lines):
        if raw.startswith(func):
            start = idx
            break
    if start is None:
        return []
    return case_block(lines, header, start_at=start)


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "W0lfSword"
    try:
        with open(path, "r", encoding="utf-8") as fh:
            lines = fh.readlines()
    except OSError as exc:
        print(f"  ERROR: cannot read {path}: {exc}")
        print("findings: 1")
        return 1

    findings = []
    rows, shape_errors = parse_registry(lines)
    findings.extend(shape_errors)
    if not rows:
        print("  ERROR: no W0LF_COMMANDS registry rows found")
        print("findings: 1")
        return 1

    # ---- field values -------------------------------------------------
    seen_names = {}
    for row in rows:
        name = row["name"]
        if not name or name in ("-", ""):
            findings.append(f"line {row['_line']}: empty command name")
        if row["group"] not in GROUPS:
            findings.append(f"{name}: unknown group '{row['group']}' "
                            f"(known: {', '.join(sorted(GROUPS))})")
        if row["tag"] not in TAGS:
            findings.append(f"{name}: unknown tag '{row['tag']}'")
        if row["docs"] not in ("0", "1"):
            findings.append(f"{name}: docs must be 0 or 1, got '{row['docs']}'")
        if name in seen_names:
            findings.append(f"{name}: duplicate registry row "
                            f"(lines {seen_names[name]} and {row['_line']})")
        seen_names[name] = row["_line"]

    # ---- key collisions ------------------------------------------------
    owner = {}
    key_count = 0
    for row in rows:
        keys = []
        for field in ("slot", "shortcut"):
            if row[field] not in ("-", ""):
                keys.append((row[field], field))
        if row["aliases"] not in ("-", ""):
            for alias in row["aliases"].split(","):
                if alias:
                    keys.append((alias, "alias"))
        keys.append((row["name"], "name"))
        for key, field in keys:
            key_count += 1
            if key in owner and owner[key][0] != row["name"]:
                findings.append(
                    f"key '{key}' claimed twice: {owner[key][0]} "
                    f"({owner[key][1]}) and {row['name']} ({field})")
            owner.setdefault(key, (row["name"], field))
        # a key listed twice inside one row is harmless for dispatch but shows
        # up twice in `commands` - flag it so the table stays clean. slot ==
        # shortcut is allowed: same key, two surfaces (menu row + shortcuts).
        own = [k for k, _ in keys]
        for d in {k for k in own if own.count(k) > 1}:
            if d == row["slot"] == row["shortcut"]:
                continue
            findings.append(f"{row['name']}: key '{d}' repeated in its own row "
                            f"(dedup it to keep `commands` readable)")

    # ---- dispatch case --------------------------------------------------
    dispatch = case_block_for(lines, "main() {")
    if not dispatch:
        findings.append('could not find the `case "$cmd" in` dispatch in main()')
    dispatch_alts = set()
    for _, pattern in dispatch:
        if pattern in ("*", ""):
            continue
        for alt in pattern.split("|"):
            alt = alt.strip().strip('"')
            if alt:
                dispatch_alts.add(alt)

    known_keys = set(owner)
    for alt in sorted(dispatch_alts):
        if alt not in known_keys:
            findings.append(f"dispatch: '{alt}' is not in the registry "
                            f"(add a row or drop the alias)")
    for row in rows:
        if row["name"] == "quit":
            continue  # menu-only: it has no CLI dispatch case by design
        keys = {row["name"]}
        if row["aliases"] not in ("-", ""):
            keys |= {a for a in row["aliases"].split(",") if a}
        if not (keys & dispatch_alts):
            findings.append(f"{row['name']}: no dispatch case in main() "
                            f"(a registered command the CLI cannot run)")

    # ---- menu handlers --------------------------------------------------
    functions = set(FUNC_DEF.findall("".join(lines)))
    for row in rows:
        handler = row["handler"]
        if handler in ("-", ""):
            continue
        if handler not in functions:
            findings.append(f"{row['name']}: handler {handler}() is not defined")

    # ---- explain documentation -----------------------------------------
    explain = case_block_for(lines, "explain_text() {")
    if not explain:
        findings.append("could not find explain_text()")
    explain_names = set()
    for _, pattern in explain:
        for alt in pattern.split("|"):
            alt = alt.strip().strip('"')
            if alt and alt != "*":
                explain_names.add(alt)
    for row in rows:
        if row["name"] in ("help",):
            continue
        documented = row["docs"] == "1"
        has_case = row["name"] in explain_names
        if documented and not has_case:
            findings.append(f"{row['name']}: registry says docs=1 but "
                            f"explain_text has no case for it")
        if not documented and has_case:
            findings.append(f"{row['name']}: explain_text HAS a case but the "
                            f"registry says docs=0 (set docs=1)")

    # ---- version sync ---------------------------------------------------
    # The script's VERSION drives the header, `version` and the deb; the
    # control file has its own copy (the "keep in sync" comment at the top of
    # the script was the only thing enforcing it).
    m = re.search(r'^VERSION="([^"]+)"', "".join(lines), re.M)
    script_version = m.group(1) if m else None
    if script_version is None:
        findings.append("could not find the VERSION= assignment")
    else:
        try:
            with open("control", "r", encoding="utf-8") as fh:
                ctl = re.search(r'^Version:\s*(\S+)', fh.read(), re.M)
        except OSError:
            ctl = None
        if ctl and ctl.group(1) != script_version:
            findings.append(f"version drift: W0lfSword says {script_version}, "
                            f"control says {ctl.group(1)}")

    # ---- section map ----------------------------------------------------
    # The MAP block at the top of the script lists every section banner in file
    # order. Same idea as the registry: it is documentation that the audit
    # keeps honest, so adding/renaming/reordering a section cannot silently
    # leave a stale table of contents behind.
    banner_re = re.compile(r"^#  § +(\d+) +(\S.*)$")
    map_re = re.compile(r"^# +§ +(\d+) +(\S.*)$")
    banners, map_entries, in_map = [], [], False
    for n, line, in_heredoc in strip_heredocs(lines):
        if in_heredoc:
            continue
        if line.startswith("#  MAP  -"):
            in_map = True
            continue
        if in_map:
            # inside the MAP block: collect entries, leave at the first blank
            m = map_re.match(line)
            if m:
                entry = m.group(2).split(" · ")[0]
                map_entries.append((int(m.group(1)), " ".join(entry.split())))
            elif not line.strip():
                in_map = False
            continue
        m = banner_re.match(line)
        if m:
            banners.append((int(m.group(1)), " ".join(m.group(2).split())))
            continue
    if not banners:
        findings.append("no numbered section banners (`#  § N  TITLE`) found")
    if not map_entries:
        findings.append("no MAP block entries (`#    § N  TITLE`) found")
    for n, title in banners:
        if n > len(map_entries):
            findings.append(f"section § {n} ({title}) is missing from the MAP")
        elif map_entries[n - 1] != (n, title):
            findings.append(f"MAP § {n} says '{map_entries[n-1][1]}' but the "
                            f"banner says '{title}'")
    if len(map_entries) > len(banners):
        for extra in map_entries[len(banners):]:
            findings.append(f"MAP lists § {extra[0]} ({extra[1]}) but there is "
                            f"no such section banner")

    # ---- report ---------------------------------------------------------
    print(f"  registry rows:        {len(rows)}")
    print(f"  keys (name+slot+...): {key_count}")
    print(f"  dispatch patterns:    {len(dispatch_alts)}")
    print(f"  explain docs:         {len(explain_names)}")
    print(f"  handlers + functions: {len(functions)}")
    print(f"  sections (map):       {len(banners)}")
    if script_version:
        print(f"  version (script):     {script_version}")
    for finding in findings:
        print(f"  ERROR: {finding}")
    print(f"findings: {len(findings)}")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
