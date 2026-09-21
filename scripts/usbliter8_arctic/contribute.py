#!/usr/bin/env python3
"""Offset contribution helper for usbliter8-arctic.

Makes adding new offset profiles easy:

  python3 contribute.py new <model> <ios> [build]   create a profile
  python3 contribute.py status                       list profiles + validation status
  python3 contribute.py pr <file>                    generate a PR description + git commands

The `usbliter8` bash script wraps this in an interactive wizard
(./usbliter8 contribute). The PR output is a ready-to-paste
markdown description with the exact git commands to submit it.
"""

import sys
from pathlib import Path

import yaml

from colors import C, ok, err, warn, info, section, key_value, header
import log_utils
from device_offsets import (
    validate_offsets,
    pending_entries,
    list_offset_files,
    dump_profile_yaml,
)
from profile_gen import generate_profile, DEVICE_DB, OFFSETS_DIR

SENTINEL = 0xDEADBEEF


def _fmt_count(n: int, total: int) -> str:
    if n == total:
        return f"{C.GRN}{n}/{total}{C.NC}"
    if n == 0:
        return f"{C.RED}0/{total}{C.NC}"
    return f"{C.AMB}{n}/{total}{C.NC}"


def _count_sentinels(path: Path) -> int:
    """Count entries whose offset is the DEADBEEF sentinel (or zero).

    Fresh profiles use sentinels instead of `pending: true` flags, so
    pending_entries() alone under-reports what still needs filling.
    """
    try:
        with open(path) as f:
            data = yaml.safe_load(f)
    except (yaml.YAMLError, OSError):
        return 0
    if not isinstance(data, dict):
        return 0
    patches = data.get("patches", {})
    if not isinstance(patches, dict):
        return 0

    count = 0
    for section_data in patches.values():
        if isinstance(section_data, list):
            for e in section_data:
                if isinstance(e, dict):
                    off = e.get("offset")
                    if isinstance(off, int) and (off == SENTINEL or off == 0):
                        count += 1
        elif isinstance(section_data, dict):
            for entry in section_data.values():
                if not isinstance(entry, dict):
                    continue
                if isinstance(entry.get("offset"), int):
                    off = entry["offset"]
                    if off == SENTINEL or off == 0:
                        count += 1
                else:
                    for sub in entry.values():
                        if isinstance(sub, dict) and isinstance(sub.get("offset"), int):
                            off = sub["offset"]
                            if off == SENTINEL or off == 0:
                                count += 1
    return count


def cmd_new(args: list[str]) -> int:
    """create <model> <ios> [build] — new profile from template + device DB."""
    if len(args) < 2:
        print(err("Usage: contribute.py new <model> <ios> [build]"))
        return 1

    model, ios = args[0], args[1]
    build = args[2] if len(args) > 2 else "unknown"

    dev = DEVICE_DB.get(model)
    if not dev:
        print(warn(f"Device {model} not in database — profile will use defaults"))
        print(f"  {C.DIM}Known models: {', '.join(sorted(DEVICE_DB))}{C.NC}")

    fname = f"{model}_{ios}.yaml"
    out_path = OFFSETS_DIR / fname

    if out_path.exists():
        overwrite = log_utils.safe_input(f"  {C.AMB}{fname} already exists. Overwrite? [y/N]:{C.NC} ")
        if overwrite.lower() not in ("y", "yes"):
            print(info("Cancelled"))
            return 0

    profile = generate_profile(model, ios, build)
    dump_profile_yaml(profile, out_path)

    print(ok(f"Created: {fname}"))
    if dev:
        print(key_value("Device", f"{dev['name']} ({model})"))
        print(key_value("SoC / board", f"{dev['soc']} / {dev['board']}"))
        print(key_value("APTicket", dev["apticket"]))
    print(key_value("iOS", ios))
    print(key_value("Build", build))
    print()

    passed, failed, errors = validate_offsets(out_path)
    pending = pending_entries(out_path)
    sentinels = _count_sentinels(out_path)

    print(section("Validation"))
    if failed == 0:
        print(ok(f"All {passed} filled patches valid"))
    else:
        print(err(f"{passed} passed, {failed} failed"))
        for e in errors[:10]:
            print(f"    {C.RED}{e}{C.NC}")
    if sentinels:
        print(warn(f"{sentinels} entries still use the DEADBEEF sentinel"))
        print(f"  {C.DIM}Fill them in, then re-run:{C.NC} python3 contribute.py pr {fname}")
    elif pending:
        print(warn(f"{pending} entries still pending"))
        print(f"  {C.DIM}Fill them in, then re-run:{C.NC} python3 contribute.py pr {fname}")
    else:
        print(ok("No pending entries — profile looks complete"))

    print()
    print(section("Next steps"))
    print(f"  {C.DIM}1. Edit the profile:{C.NC}      $EDITOR {out_path}")
    print(f"  {C.DIM}2. Re-validate:{C.NC}          python3 device_offsets.py validate {fname}")
    print(f"  {C.DIM}3. Prepare the PR:{C.NC}       ./usbliter8 contribute pr {fname}")
    return 0


def cmd_status() -> int:
    """status — list profiles with validation + pending counts."""
    files = list_offset_files()
    if not files:
        print(warn("No offset profiles yet — create one with: ./usbliter8 contribute new <model> <ios>"))
        return 0

    print(section("Offset Profiles"))
    for f in files:
        icon = {"ready": C.GRN + "✓", "pending": C.AMB + "⚠", "incomplete": C.RED + "✗"}.get(
            f["status"], C.GREY + "?"
        )
        total = f["passed"] + f["failed"]
        count = _fmt_count(f["passed"], total) if total else C.GREY + "0/0" + C.NC
        extra = ""
        if f["pending"]:
            extra = f"  {C.AMB}{f['pending']} pending{C.NC}"
        print(f"  {icon}{C.NC} {C.SNOW}{f['device']}{C.NC} ({C.DIM}{f['model']}{C.NC}) "
              f"iOS {C.FROST}{f['ios']}{C.NC}  [{f['soc']}]  {count}{extra}")
    return 0


def cmd_pr(args: list[str]) -> int:
    """pr <file> — generate a PR-ready description + git commands."""
    if len(args) < 1:
        print(err("Usage: contribute.py pr <file>"))
        return 1

    path = Path(args[0])
    if not path.exists():
        print(err(f"File not found: {path}"))
        return 1

    passed, failed, errors = validate_offsets(path)
    if failed > 0:
        print(err(f"Profile has {failed} invalid entries — fix before submitting:"))
        for e in errors[:10]:
            print(f"    {C.RED}{e}{C.NC}")
        return 1

    try:
        with open(path) as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        print(err(f"Invalid YAML: {e}"))
        return 1

    device = data.get("device", "?")
    model = data.get("model", "?")
    ios = data.get("ios_version", "?")
    build = data.get("build", "?")
    soc = data.get("soc", "?")
    board = data.get("board", "?")
    apticket = data.get("apticket", "?")
    pending = pending_entries(path)
    fname = path.name

    patches = data.get("patches", {})
    total_entries = 0
    for sec, sec_data in patches.items():
        if isinstance(sec_data, list):
            total_entries += len(sec_data)
        elif isinstance(sec_data, dict):
            for entry in sec_data.values():
                if isinstance(entry, dict):
                    total_entries += 1
                    if isinstance(list(entry.values())[0], dict):
                        total_entries += len(entry) - 1

    print(header("PR Description (copy-paste ready)"))
    print()
    print(f"  {C.SNOW}## Offsets: {device} ({model}) — iOS {ios}{C.NC}")
    print()
    print(f"  {C.DIM}| Field | Value |{C.NC}")
    print(f"  {C.DIM}|---|---|{C.NC}")
    print(f"  {C.DIM}| Device |{C.NC} {device}")
    print(f"  {C.DIM}| Model |{C.NC} {model}")
    print(f"  {C.DIM}| iOS |{C.NC} {ios} ({build})")
    print(f"  {C.DIM}| SoC |{C.NC} {soc} ({apticket})")
    print(f"  {C.DIM}| Board |{C.NC} {board}")
    print(f"  {C.DIM}| Patches |{C.NC} {passed} valid" + (f", {pending} pending" if pending else ""))
    print()
    print("  ---")
    print()
    print("  ```")
    print("  git add offsets/" + fname)
    print("  git commit -m \"offsets: add " + f"{device} {ios} profile\"")
    print("  git push")
    print("  ```")
    print()
    print("  ### Notes for reviewers")
    print("  - Method: manual discovery / migrate / propagate (state which)")
    print("  - Verified with: python3 device_offsets.py validate offsets/" + fname)
    print("  - Tests: python3 -m pytest tests/ -q")

    print()
    print(section("Submit commands"))
    print(f"  git add offsets/{fname}")
    print(f'  git commit -m "offsets: add {device} {ios} profile"')
    print("  git push")
    print(f"  {C.DIM}Then open a PR against kaffeindecaf/usbliter8-arctic{C.NC}")
    return 0


def usage() -> None:
    print(f"\n  {C.FROST}usbliter8 offset contribution helper{C.NC}\n")
    print("  Commands:")
    print(f"    {C.EYE}new{C.NC}     <model> <ios> [build]   create a profile")
    print(f"    {C.EYE}status{C.NC}                         list profiles + status")
    print(f"    {C.EYE}pr{C.NC}      <file>                  generate PR description + git commands")
    print(f"    {C.EYE}share{C.NC}     [status|preview|send|on|off]  send this device's data back")
    print()


def cli(argv: list[str] | None = None) -> int:
    """Command line entry point: whatever it raises, guard() turns into an exit code."""
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        usage()
        return log_utils.EXIT_OK

    cmd, args = argv[0], argv[1:]
    if cmd == "new":
        return cmd_new(args) or log_utils.EXIT_OK
    if cmd == "status":
        return cmd_status() or log_utils.EXIT_OK
    if cmd == "pr":
        return cmd_pr(args) or log_utils.EXIT_OK
    if cmd == "share":
        import share
        return share.cli(args)

    print(err(f"Unknown command: {cmd}"))
    usage()
    return log_utils.EXIT_ERROR


if __name__ == "__main__":
    import log_utils

    log_utils.install()          # usbliter8.log + clean exits
    sys.exit(log_utils.guard(cli))
