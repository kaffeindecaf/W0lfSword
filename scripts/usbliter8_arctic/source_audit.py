#!/usr/bin/env python3
"""Cross-source offset audit for usbliter8-arctic.

Our offset profiles are only as good as the upstream artefacts they came
from. This tool re-reads those artefacts and diffs them against a profile:

  usbliter8-fun scripts (wh1te4ever/34306 `make_cfw.py`) — literal patch
  sites for one build+board, parsed from `patch(0x..., 0x...)` calls.

  Liter8 fixtures (Xplo8E/Liter8 `fixtures/<build>/<board>/*.json`) —
  resolver output oracles: offset + originalBytes + replacementBytes +
  component sha256 for one build+board.

Findings per section:

  COVERED     every upstream byte is written by one of our entries, identical
  MISSING     upstream patches a site we do not patch at all
  PARTIAL     we patch the same site but write fewer bytes than upstream
  MISMATCH    we patch the same site with different bytes
  PROFILE-ONLY  we patch a site no upstream artefact in scope patches

Usage:
  python3 source_audit.py script <make_cfw.py> <profile.yaml>
  python3 source_audit.py liter8 <fixtures_dir> [--build B] [--board n104ap] [--profile P]

Nothing is written: the audit is evidence for a human decision.
"""

from __future__ import annotations

import json
import re
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from colors import C, err, info, section, warn
import log_utils

ROOT = Path(__file__).parent

# ── component -> profile section ──
COMPONENT_SECTION = {
    "iBSS.raw": "ibss",
    "iBSS": "ibss",
    "iBEC.raw": "ibec",
    "iBEC diagnostic": "ibec",
    "TXM.raw": "txm",
    "TXM": "txm",
    "kcache.raw": "kernel",
    "kernelcache.release.iphone12b": "kernel",
    "kernelcache.release.iphone12": "kernel",
    "kernelcache.release.iphone12c": "kernel",
    "kernelcache.release.iphone11": "kernel",
    "kernelcache.release.iphone11b": "kernel",
    "kernelcache.release.ipad11": "kernel",
    "kernelcache.release.ipad11b": "kernel",
    "kernelcache.release.ipad12p": "kernel",
    "restored_external": "restoreramdisk",
    "asr": "restoreramdisk",
}


# Profile entry names whose payload is a PC-relative immediate (adrp/add
# redirects into the image): the correct value depends on the instruction's
# own address, so upstream and local values are not comparable directly.
PC_RELATIVE_TOKENS = ("adrp", "add")


@dataclass
class Site:
    """One upstream patch site (one contiguous byte run)."""
    source: str
    component: str
    section: str
    offset: int
    data: bytes
    label: str = ""
    entry_id: str = ""


@dataclass
class Finding:
    section: str
    entry: str
    status: str
    detail: str = ""
    upstream: Site | None = None


@dataclass
class AuditResult:
    findings: list[Finding] = field(default_factory=list)

    def count(self, status: str) -> int:
        return sum(1 for f in self.findings if f.status == status)


# ── upstream parsers ──

def parse_cfw_script(path: Path | str) -> list[Site]:
    """Parse a usbliter8-fun `make_cfw.py` into coalesced patch sites.

    Only executable `patch(...)` calls count: commented-out lines are the
    experiment log, not the shipped patch set. `patch(0xX+N, ...)` offsets
    are resolved. Consecutive words at one site are merged into one site so
    a 5-word AMFI sequence compares as a unit.
    """
    lines = Path(path).read_text().splitlines()
    component = None
    raw: list[tuple[str, int, bytes, str]] = []
    for line in lines:
        if line.strip().startswith("#"):
            continue
        m = re.match(r'\s*fp\s*=\s*open\("([^"]+)"', line)
        if m:
            component = m.group(1)
            continue
        m = re.match(r'\s*patch\((0x[0-9a-fA-F]+)(\+\d+)?\s*,\s*(0x[0-9a-fA-F]+|"[^"]*")\s*\)(.*)', line)
        if not (m and component):
            continue
        offset = int(m.group(1), 16) + (int(m.group(2)[1:]) if m.group(2) else 0)
        value = m.group(3)
        if value.startswith('"'):
            data = value[1:-1].encode().decode("unicode_escape").encode("latin-1")
        else:
            data = struct.pack("<I", int(value, 16))
        comment = m.group(4).strip().lstrip("#").strip()
        raw.append((component, offset, data, comment))

    sites: list[Site] = []
    for component, offset, data, comment in raw:
        section = COMPONENT_SECTION.get(Path(component).name, COMPONENT_SECTION.get(component))
        if section is None:
            continue
        if sites and sites[-1].component == component and sites[-1].offset + len(sites[-1].data) == offset:
            prev = sites[-1]
            sites[-1] = Site(prev.source, component, section, prev.offset, prev.data + data,
                             (prev.label + " | " + comment).strip(" |") if comment else prev.label)
            continue
        sites.append(Site(str(path), component, section, offset, data, comment))
    return sites


def parse_liter8_fixtures(root: Path | str, build: str = "", board: str = "") -> list[Site]:
    """Parse Liter8 fixture JSONs into patch sites (one per expectedPatch).

    Fixtures carry originalBytes, so callers get byte-level evidence for the
    site, not just an offset.
    """
    root = Path(root)
    sites: list[Site] = []
    pattern = f"{build}/*/*.json" if build else "*/*/*.json"
    for path in sorted(root.glob(pattern)):
        if board and path.parent.name != board:
            continue
        try:
            fixture = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        target = fixture.get("target", {})
        if board and target.get("board") != board:
            continue
        component = target.get("component", "")
        section = COMPONENT_SECTION.get(component)
        if section is None:
            continue
        for patch in fixture.get("expectedPatches", []):
            sites.append(Site(
                source=f"liter8:{path.parent.parent.name}/{path.parent.name}/{fixture.get('resolver', '?')}",
                component=component,
                section=section,
                offset=int(patch["offset"]),
                data=bytes.fromhex(patch["replacementBytes"]),
                label=patch.get("id", ""),
                entry_id=patch.get("id", ""),
            ))
    return sites


def liter8_fixture_meta(root: Path | str, build: str, board: str = "") -> list[dict]:
    """Fixture metadata (component size + sha256) for the requested build."""
    root = Path(root)
    out = []
    for path in sorted(root.glob(f"{build}/*/*.json")):
        if board and path.parent.name != board:
            continue
        fixture = json.loads(path.read_text())
        out.append({
            "file": path.name,
            "resolver": fixture.get("resolver"),
            "component": fixture.get("target", {}).get("component"),
            "size": fixture.get("expectedSize"),
            "sha256": fixture.get("sha256"),
            "output_sha256": fixture.get("expectedOutputSHA256"),
            "patches": len(fixture.get("expectedPatches", [])),
        })
    return out


# ── profile side ──

def profile_entries(profile: dict) -> dict[str, list[tuple[str, int, bytes]]]:
    """section -> [(entry_name, offset, bytes)] for both dict and list sections."""
    out: dict[str, list[tuple[str, int, bytes]]] = {}
    patches = profile.get("patches", {})
    for sec, data in patches.items():
        items: list[tuple[str, int, bytes]] = []
        if isinstance(data, list):
            for entry in data:
                if isinstance(entry, dict) and "offset" in entry and "value" in entry:
                    if entry.get("pending"):
                        continue
                    items.append((entry.get("name", "kernel[]"),
                                  int(entry["offset"]), _value_bytes(entry["value"])))
        elif isinstance(data, dict):
            for name, entry in data.items():
                if not isinstance(entry, dict):
                    continue
                if "offset" in entry and "value" in entry and not entry.get("pending"):
                    items.append((name, int(entry["offset"]), _value_bytes(entry["value"])))
                else:
                    for sub, sub_entry in entry.items():
                        if isinstance(sub_entry, dict) and "offset" in sub_entry \
                                and "value" in sub_entry and not sub_entry.get("pending"):
                            items.append((f"{name}.{sub}", int(sub_entry["offset"]),
                                          _value_bytes(sub_entry["value"])))
        if items:
            out[sec] = items
    return out


def _value_bytes(value) -> bytes:
    if isinstance(value, int):
        return struct.pack("<I", value)
    clean = str(value).replace(" ", "")
    try:
        return bytes.fromhex(clean)
    except ValueError:
        return str(value).encode("latin-1", "replace")


def audit(sites: list[Site], profile: dict) -> AuditResult:
    """Diff upstream sites against the profile, byte by byte.

    Our section is turned into an offset->byte map, so an upstream run split
    across two of our entries (e.g. `nop` + `mov x0,#0` written as two YAML
    keys) still counts as COVERED. Entries whose payload is a PC-relative
    immediate (adrp/add redirects) are not comparable across builds and are
    reported as REVIEW instead of MISMATCH.
    """
    result = AuditResult()
    entries = profile_entries(profile)

    byte_map: dict[str, dict[int, int]] = {}
    for sec, items in entries.items():
        for _name, offset, data in items:
            sec_map = byte_map.setdefault(sec, {})
            for i, b in enumerate(data):
                sec_map[offset + i] = b

    touched: dict[tuple[str, str], tuple[int, str]] = {}
    for site in sites:
        sec_map = byte_map.get(site.section, {})
        missing = partial = mismatch = 0
        tail = b""
        for i, want in enumerate(site.data):
            got = sec_map.get(site.offset + i)
            if got is None:
                if i == 0 or missing == 0 and partial == 0:
                    tail = site.data[i:i + 8]
                missing += 1
            elif got != want:
                mismatch += 1
        owner = _owner_entry(entries.get(site.section, []), site.offset)
        for name in _overlapping_entries(entries.get(site.section, []), site):
            if name != owner:
                touched[(site.section, name)] = (site.offset, owner)
        review = any(tok in owner for tok in PC_RELATIVE_TOKENS)

        if mismatch:
            status = "REVIEW" if review else "MISMATCH"
            detail = (f"at 0x{site.offset:X}: upstream {site.data.hex()[:32]} "
                      f"vs {owner or 'nothing'}")
            result.findings.append(Finding(site.section, owner, status, detail, site))
        elif missing and partial == 0 and not _any_covered(entries.get(site.section, []), site):
            result.findings.append(Finding(
                site.section, site.label or owner, "MISSING",
                f"upstream writes {len(site.data)}B at 0x{site.offset:X} ({tail.hex()})", site))
        elif missing:
            result.findings.append(Finding(
                site.section, owner, "PARTIAL",
                f"{missing} of {len(site.data)}B at 0x{site.offset:X} not written by the "
                f"profile (first missing {tail.hex()})", site))
        else:
            result.findings.append(Finding(site.section, owner, "COVERED", "", site))

    # entries an upstream site wrote but that were not named as the owner:
    # they are part of a covered run (e.g. the second key of a nop+mov pair)
    reported = {(f.section, f.entry) for f in result.findings}
    for sec, items in entries.items():
        for name, offset, data in items:
            if (sec, name) in reported:
                continue
            part_of = touched.get((sec, name))
            if part_of:
                result.findings.append(Finding(
                    sec, name, "COVERED",
                    f"part of the upstream run at 0x{part_of[0]:X} (owner {part_of[1]})"))
                continue
            result.findings.append(Finding(sec, name, "PROFILE-ONLY",
                                           f"0x{offset:X} {data.hex()} not patched by this source"))
    return result


def _owner_entry(items: list[tuple[str, int, bytes]], offset: int) -> str:
    for name, start, data in items:
        if start <= offset < start + len(data):
            return name
    return ""


def _overlapping_entries(items: list[tuple[str, int, bytes]], site: Site) -> list[str]:
    """Names of our entries whose written range intersects the upstream site."""
    return [name for name, start, data in items
            if start < site.offset + len(site.data) and site.offset < start + len(data)]


def _any_covered(items: list[tuple[str, int, bytes]], site: Site) -> bool:
    """True when at least one byte of the upstream run is written by us."""
    for _name, start, data in items:
        if start < site.offset + len(site.data) and site.offset < start + len(data):
            return True
    return False


# ── reporting ──

STATUS_COLOR = {
    "COVERED": C.GRN,
    "REVIEW": C.FROST,
    "MISSING": C.AMB,
    "PARTIAL": C.AMB,
    "MISMATCH": C.RED,
    "PROFILE-ONLY": C.DIM,
}


def report_text(title: str, result: AuditResult, profile_name: str) -> str:
    order = ["MISSING", "PARTIAL", "MISMATCH", "REVIEW", "COVERED", "PROFILE-ONLY"]
    lines = [f"# offset source audit — {profile_name}", "",
             f"source: {title}", ""]
    lines.append("| status | count |")
    lines.append("|---|---|")
    for status in order:
        lines.append(f"| {status} | {result.count(status)} |")
    lines.append("")
    for status in order:
        rows = [f for f in result.findings if f.status == status]
        if not rows:
            continue
        lines.append(f"## {status}")
        for f in rows:
            label = f.upstream.label if f.upstream and f.upstream.label else f.entry
            lines.append(f"- `{f.section}` **{f.entry}** — {label} — {f.detail}")
        lines.append("")
    return "\n".join(lines)


def print_report(title: str, result: AuditResult, profile_name: str) -> None:
    print(section(f"Source audit — {profile_name}"))
    print(f"  {C.DIM}{title}{C.NC}")
    print()
    for status in ["MISSING", "PARTIAL", "MISMATCH", "REVIEW", "COVERED", "PROFILE-ONLY"]:
        rows = [f for f in result.findings if f.status == status]
        if not rows:
            continue
        color = STATUS_COLOR[status]
        print(f"  {color}{status}{C.NC} ({len(rows)})")
        for f in rows:
            label = f.upstream.label if f.upstream and f.upstream.label else ""
            print(f"    {C.EYE}{f.section}.{f.entry}{C.NC} {C.DIM}{label}{C.NC}")
            if f.detail:
                print(f"      {C.DIM}{f.detail}{C.NC}")
        print()


def _load_profile(path: Path) -> dict:
    with open(path) as fh:
        return yaml.safe_load(fh)


def cmd_script(args: list[str]) -> int:
    if len(args) < 2:
        print(err("Usage: script <make_cfw.py> <profile.yaml>"))
        return 2
    script, profile_path = Path(args[0]), Path(args[1])
    if not script.exists() or not profile_path.exists():
        print(err("script and profile must both exist"))
        return 2
    sites = parse_cfw_script(script)
    result = audit(sites, _load_profile(profile_path))
    print_report(str(script), result, profile_path.name)
    out = ROOT / "research" / "work" / f"audit_{script.stem}_{profile_path.stem}.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(report_text(str(script), result, profile_path.name))
    print(info(f"report: {out}"))
    blocking = result.count("MISMATCH") + result.count("MISSING")
    if blocking:
        print(warn(f"{blocking} blocking finding(s) — review before flashing"))
    return 0 if blocking == 0 else 1


def cmd_liter8(args: list[str]) -> int:
    fixtures, build, board, profile_path = (args[0] if args else ""), "", "", None
    i = 1
    while i < len(args):
        if args[i] == "--build" and i + 1 < len(args):
            build, i = args[i + 1], i + 2
        elif args[i] == "--board" and i + 1 < len(args):
            board, i = args[i + 1], i + 2
        elif args[i] == "--profile" and i + 1 < len(args):
            profile_path, i = Path(args[i + 1]), i + 2
        else:
            print(err(f"unknown argument: {args[i]}"))
            return 2
    if not fixtures:
        print(err("Usage: liter8 <fixtures_dir> [--build B] [--board n104ap] [--profile P]"))
        return 2
    root = Path(fixtures)
    if not root.is_dir():
        print(err(f"fixtures dir not found: {root}"))
        return 2

    sites = parse_liter8_fixtures(root, build=build, board=board)
    if not sites:
        print(warn("no fixture sites parsed — check --build/--board"))
        return 1
    print(section("Liter8 fixtures"))
    for meta in liter8_fixture_meta(root, build, board):
        print(f"  {C.EYE}{meta['component']:<26}{C.NC} {meta['resolver']:<24} "
              f"{meta['size'] if meta['size'] else '?':>10} B  {meta['patches']:>3} patches  "
              f"{C.DIM}{(meta['sha256'] or '')[:16]}{C.NC}")
    print(info(f"{len(sites)} sites parsed"))

    if profile_path:
        result = audit(sites, _load_profile(profile_path))
        print_report(str(root), result, profile_path.name)
        return 0
    return 0


def find_work_dirs() -> list[Path]:
    """Upstream usbliter8-fun work directories, newest layout first.

    Both the TUI build flow (main.py) and the migration engine (migrate.py) read
    `make_cfw.py` out of these; the search order lives here once.
    """
    candidates = [
        Path(__file__).parent.parent / "referenceforAI",
        Path.home() / "Desktop" / "W0lfSword" / "referenceforAI",
        Path.home() / "Desktop" / "W0lfSword" / "referenceforAI" / "projects",
    ]
    dirs: list[Path] = []
    for base in candidates:
        if base.exists():
            dirs.extend(sorted(base.glob("usbliter8-fun*/work-*")))
    return dirs


def main(argv: list[str]) -> int:
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    if argv[0] == "script":
        return cmd_script(argv[1:])
    if argv[0] == "liter8":
        return cmd_liter8(argv[1:])
    print(err(f"unknown command: {argv[0]}"))
    return 2


if __name__ == "__main__":
    import log_utils
    log_utils.install()
    sys.exit(log_utils.guard(main, sys.argv[1:]))
