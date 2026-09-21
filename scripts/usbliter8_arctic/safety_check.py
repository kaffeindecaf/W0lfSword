#!/usr/bin/env python3
"""Safety check for this repo: run it before pushing, and in CI.

This repo is public and its output is flashed onto real hardware, so the two
expensive mistakes are (a) leaking something personal into the open and
(b) shipping offset data that no longer matches the evidence it was recorded
against. Both are mechanical, so they are checked mechanically.

Checks that FAIL the run:

  1. secrets            private keys, cloud/API tokens, device UDIDs
  2. machine-local      absolute home paths ("/home/<you>/...") in tracked files
  3. generated files    usbliter8.log, session.log, research/, firmware/,
                        config.yaml, checklist.md, __pycache__ tracked by git
  4. shadowed imports   an import shadowed inside a function and called there
                        (crashes at runtime as a str/None "not callable")
  5. profiles           every offsets/*.yaml validates; the file name matches
                        its model + ios_version; a profile claiming to be
                        verified has no pending entries and no blockers
  5. evidence drift     offsets/evidence/*.json entries must still match the
                        profile's offsets (evidence recorded, then profile
                        edited by hand = silently unverified data)

Checks that only WARN (use --strict to fail on them too):

  6. badge drift        README "tests-N passing" vs the collected test count
  7. docs style         em dashes in the README (house style: none)

Usage:
  python3 safety_check.py [--json] [--quiet] [--strict]
  # allow one line on purpose: append  # safety-allow: <reason>
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
import log_utils

ROOT = Path(__file__).parent
OFFSETS = ROOT / "offsets"
EVIDENCE = OFFSETS / "evidence"
EVIDENCE_REL = f"{EVIDENCE.parent.name}/{EVIDENCE.name}"      # offsets/evidence

ALLOW_MARKER = "safety-allow"
GENERATED = ("usbliter8.log", "session.log", "active_device.yaml", "config.yaml",
             "checklist.md", "__pycache__", "research/", "firmware/", ".usbliter8/")

SECRET_PATTERNS = [
    ("private key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("github token", re.compile(r"\b(?:gh[pousr]|github_pat)_[A-Za-z0-9_]{20,}\b")),
    ("aws access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("openai key", re.compile(r"\bsk-[A-Za-z0-9]{24,}\b")),
    ("slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{12,}\b")),
    ("google api key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("device udid", re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{16}\b")),
    ("inline password", re.compile(r"""(?:password|passwd|secret|api_key)\s*[:=]\s*"""
                                   r"""["'][^"'\s]{8,}["']""", re.IGNORECASE)),
]
GENERIC_USERS = {"user", "you", "username", "your-user", "me", "example", "name",
                 "<user>", "<you>", "someone"}
HOME_PATTERN = re.compile(r"(?:/home/|/Users/|C:\\\\Users\\\\)([A-Za-z0-9._-]+)")
# text files scanned for leaks/paths; binaries are skipped by extension
TEXT_SUFFIXES = {".md", ".txt", ".rst", ".yaml", ".yml", ".json", ".toml", ".cfg", ".ini",
                 ".sh", ".py", ".c", ".h", ".m", ".swift", ".plist", ".service", ".desktop"}
BINARY_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".im4p", ".dmg", ".zip",
                   ".uf2", ".bin", ".pdf", ".woff", ".woff2", ".ttf"}


def git_files() -> list[str]:
    """Tracked files plus untracked-but-not-ignored ones.

    Including untracked files matters locally: a leak in a file that is staged
    but not yet committed is exactly what this check exists to stop, and a bare
    `git ls-files` would not see it (CI would, one push later).
    """
    try:
        out = subprocess.run(["git", "ls-files", "--cached", "--others", "--exclude-standard"],
                             cwd=ROOT, capture_output=True, text=True, timeout=60, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        return sorted(str(p.relative_to(ROOT)) for p in ROOT.rglob("*") if p.is_file())
    return [line for line in out.stdout.splitlines() if line.strip()]


def read(path: str) -> str:
    try:
        return (ROOT / path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _allowed(line: str) -> bool:
    return ALLOW_MARKER in line


def check_secrets(files: list[str]) -> list[str]:
    problems = []
    for rel in files:
        if Path(rel).suffix.lower() in BINARY_SUFFIXES:
            continue
        if rel in ("safety_check.py",) or rel.endswith(("test_safety_check.py",)):
            continue                       # this file documents the patterns
        for lineno, line in enumerate(read(rel).splitlines(), 1):
            if _allowed(line):
                continue
            for label, pattern in SECRET_PATTERNS:
                if pattern.search(line):
                    problems.append(f"{rel}:{lineno}: possible {label}")
                    break
    return problems


def check_machine_paths(files: list[str]) -> list[str]:
    problems = []
    for rel in files:
        if Path(rel).suffix.lower() not in TEXT_SUFFIXES:
            continue
        for lineno, line in enumerate(read(rel).splitlines(), 1):
            if _allowed(line):
                continue
            match = HOME_PATTERN.search(line)
            if match and match.group(1).lower() not in GENERIC_USERS:
                problems.append(f"{rel}:{lineno}: machine-local path "
                                f"(/{'home' if '/home/' in line else 'user'}/"
                                f"{match.group(1)}/)")
    return problems


def check_generated(files: list[str]) -> list[str]:
    problems = []
    for rel in files:
        for name in GENERATED:
            if rel == name.rstrip("/") or rel.startswith(name):
                if rel.endswith(".gitignore") or rel == ".gitignore":
                    continue
                problems.append(f"{rel}: generated/local file is tracked by git")
                break
    return problems


def check_profiles(files: list[str]) -> list[str]:
    import yaml
    sys.path.insert(0, str(ROOT))
    from device_offsets import pending_entries, validate_offsets

    problems = []
    for rel in sorted(files):
        if not rel.startswith("offsets/") or not rel.endswith(".yaml"):
            continue
        if rel == "offsets/template.yaml":
            continue
        path = ROOT / rel
        if "patches:" not in path.read_text():
            continue                       # auxiliary data (canonical/sources), not a profile
        _passed, failed, errors = validate_offsets(path)
        if failed:
            problems.append(f"{rel}: {failed} invalid entry/entries: {errors[0]}")
            continue

        data = yaml.safe_load(path.read_text()) or {}
        model, ios = data.get("model"), data.get("ios_version")
        stem = path.stem
        if model and ios and stem != f"{model}_{ios}":
            problems.append(f"{rel}: file name does not match model + ios_version "
                            f"({model}_{ios})")

        claim = str(data.get("verification", "")).strip().lower()
        claim_is_verified = claim in ("verified", "ready", "complete", "flashable") or \
            claim.startswith(("verified", "ready", "complete"))
        if claim_is_verified:
            pending = pending_entries(path)
            blockers = data.get("blockers") or []
            if pending or blockers:
                problems.append(f"{rel}: claims verification '{data.get('verification')}' "
                                f"but has {pending} pending and {len(blockers)} blocker(s)")
    return problems


def check_evidence(files: list[str]) -> tuple[list[str], list[str]]:
    """Verify recorded evidence still describes its profile.

    Returns (problems, informational notes). Staleness is covered by the offset
    comparison itself: a profile edited after recording no longer matches.
    """
    import yaml
    problems, summary = [], []
    for rel in sorted(files):
        if not rel.startswith(f"{EVIDENCE_REL}/") or not rel.endswith(".json"):
            continue
        try:
            evidence = json.loads(read(rel))
        except json.JSONDecodeError as exc:
            problems.append(f"{rel}: unreadable evidence ({exc})")
            continue
        profile_rel = f"offsets/{evidence.get('profile', '')}"
        profile_path = ROOT / profile_rel
        if not profile_path.exists():
            problems.append(f"{rel}: points at missing profile {profile_rel}")
            continue
        profile = yaml.safe_load(profile_path.read_text()) or {}
        entries = profile.get("patches") or {}
        for key, recorded in (evidence.get("entries") or {}).items():
            section, _, name = key.partition(".")
            body = entries.get(section)
            entry = None
            if isinstance(body, dict):
                entry = body.get(name)
            elif isinstance(body, list):
                entry = next((e for e in body if isinstance(e, dict)
                              and e.get("name") == name), None)
            if not isinstance(entry, dict):
                problems.append(f"{rel}: recorded {key} is gone from {profile_rel}")
                continue
            if "offset" in recorded and "offset" in entry and recorded["offset"] != entry["offset"]:
                problems.append(f"{rel}: {key} recorded 0x{recorded['offset']:X} but "
                                f"{profile_rel} has 0x{entry['offset']:X} "
                                f"(re-run preflight --record)")
        recorded_count = len(evidence.get("entries") or {})
        summary.append(f"{evidence.get('profile', rel)}: {recorded_count} site(s) "
                       f"recorded against {evidence.get('build', '?')}")
    return problems, summary


def check_shadowed_imports(files: list[str]) -> list[str]:
    """An import shadowed inside a function and then called there is a crash.

    `from colors import section` + `for section in ...` + `section("title")` in
    the same function raises `'str' object is not callable` at runtime. Static
    tools flag the shadowing; this check flags the combination that actually
    breaks, so a harmless shadow does not block a push.
    """
    import ast

    problems: list[str] = []
    for rel in files:
        if not rel.endswith(".py"):
            continue
        try:
            tree = ast.parse(read(rel))
        except SyntaxError as exc:
            problems.append(f"{rel}: does not parse ({exc.msg})")
            continue

        imported = set()
        for node in tree.body:
            if isinstance(node, ast.ImportFrom):
                imported.update(a.asname or a.name for a in node.names)
            elif isinstance(node, ast.Import):
                imported.update((a.asname or a.name).split(".")[0] for a in node.names)

        for func in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
            shadowed = set()
            for node in ast.walk(func):
                targets = []
                if isinstance(node, ast.For):
                    targets = (node.target.elts if isinstance(node.target, ast.Tuple)
                               else [node.target])
                elif isinstance(node, ast.Assign):
                    targets = list(node.targets)
                for target in targets:
                    if isinstance(target, ast.Name) and target.id in imported:
                        shadowed.add(target.id)
            called = {n.func.id for n in ast.walk(func)
                      if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
            for name in sorted(shadowed.intersection(called)):
                problems.append(
                    f"{rel}: {func.name}() shadows the imported '{name}' and calls it "
                    f"(rename the local or the import)")

            # A function-local import makes the name local for the WHOLE
            # function, so using it *above* that line raises UnboundLocalError.
            # Only the combination is a bug: an inner import used earlier.
            # (preflight.run_preflight and main.py's dispatcher both shipped it.)
            uses: dict[str, list[int]] = {}
            for node in ast.walk(func):
                if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
                    uses.setdefault(node.value.id, []).append(node.lineno)
                elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                    uses.setdefault(node.func.id, []).append(node.lineno)
            for node in ast.walk(func):
                if not isinstance(node, (ast.Import, ast.ImportFrom)):
                    continue
                for alias in node.names:
                    name = (alias.asname or alias.name).split(".")[0]
                    earlier = [line for line in uses.get(name, []) if line < node.lineno]
                    if earlier and name in imported:
                        problems.append(
                            f"{rel}: {func.name}() imports '{name}' on line {node.lineno} "
                            f"but uses it on line {earlier[0]} (drop the inner import: it "
                            f"makes the name local and the earlier use raises "
                            f"UnboundLocalError)")
    return problems


def check_badge(files: list[str]) -> list[str]:
    if "README.md" not in files:
        return []
    match = re.search(r"tests-(\d+)%20passing", read("README.md"))
    if not match:
        return ["README.md: no 'tests-N passing' badge found"]
    claimed = int(match.group(1))
    try:
        out = subprocess.run([sys.executable, "-m", "pytest", "tests/", "--collect-only",
                              "-q"], cwd=ROOT, capture_output=True, text=True, timeout=600)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return ["could not count tests (pytest unavailable)"]
    counts = [int(n) for n in re.findall(r"(\d+) tests? collected", out.stdout)]
    if not counts:
        return ["could not parse the collected test count"]
    actual = max(counts)
    if actual != claimed:
        return [f"README.md: badge says {claimed} tests, {actual} are collected"]
    return []


def check_docs_style(files: list[str]) -> list[str]:
    problems = []
    for rel in files:
        if Path(rel).suffix not in TEXT_SUFFIXES or not rel.startswith(("README", "docs/")):
            continue
        count = read(rel).count("\u2014")
        if count:
            problems.append(f"{rel}: {count} em dash(es) (house style: use a hyphen or a comma)")
    return problems


def main(argv: list[str] | None = None) -> int:
    import deps
    deps.ensure(("security",))          # offer to install what is missing

    ap = argparse.ArgumentParser(description="safety check for the usbliter8-arctic repo")
    ap.add_argument("--json", action="store_true", help="machine-readable result")
    ap.add_argument("--quiet", action="store_true", help="only print problems")
    ap.add_argument("--strict", action="store_true", help="treat warnings as failures")
    args = ap.parse_args(argv if argv is not None else sys.argv[1:])

    try:
        from colors import C
    except ImportError:                                          # pragma: no cover
        class C:                                                 # type: ignore
            GRN = RED = AMB = DIM = FROST = NC = ""

    files = git_files()
    failures: list[str] = []
    warnings: list[str] = []

    results = {}
    for name, runner in (("secrets", check_secrets),
                         ("machine-local paths", check_machine_paths),
                         ("generated files", check_generated),
                         ("shadowed imports", check_shadowed_imports),
                         ("offset profiles", check_profiles)):
        found = runner(files)
        results[name] = found
        failures += found

    evidence_problems, evidence_notes = check_evidence(files)
    results["evidence drift"] = evidence_problems
    failures += evidence_problems
    for name, runner in (("test badge", check_badge), ("docs style", check_docs_style)):
        found = runner(files)
        results[name] = found
        warnings += found

    ok = not failures and not (args.strict and warnings)

    if args.json:
        print(json.dumps({"ok": ok, "files_checked": len(files), "failures": failures,
                          "warnings": warnings, "checks": results}, indent=2))
        return 0 if ok else 1

    if not args.quiet:
        print(f"\n  {C.FROST}safety check{C.NC}  {C.DIM}{len(files)} tracked file(s){C.NC}")
        for note in evidence_notes:
            print(f"  {C.DIM}evidence  {note}{C.NC}")
        for name, found in results.items():
            mark = f"{C.RED}✗{C.NC}" if found and name in (
                "secrets", "machine-local paths", "generated files", "shadowed imports",
                "offset profiles", "evidence drift") else (
                f"{C.AMB}⚠{C.NC}" if found else f"{C.GRN}✓{C.NC}")
            print(f"  {mark} {name:<20} {C.DIM}{'clean' if not found else str(len(found)) + ' issue(s)'}{C.NC}")

    for problem in failures:
        print(f"  {C.RED}✗{C.NC} {problem}")
    for problem in warnings:
        print(f"  {C.AMB}⚠{C.NC} {problem}")

    if not args.quiet:
        print()
        if ok:
            print(f"  {C.GRN}✓ nothing to hide and nothing stale{C.NC}")
        elif failures:
            print(f"  {C.RED}✗ {len(failures)} problem(s) — fix before pushing{C.NC}")
        else:
            print(f"  {C.AMB}⚠ {len(warnings)} warning(s) only (--strict to fail on them){C.NC}")
        print()
    return 0 if ok else 1


if __name__ == "__main__":
    import log_utils
    log_utils.install()          # usbliter8.log + unhandled-exception logging
    sys.exit(log_utils.guard(main))
