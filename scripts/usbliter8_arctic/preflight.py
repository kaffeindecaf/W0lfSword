#!/usr/bin/env python3
"""Preflight verification for offset profiles.

The one thing no usbliter8 fork does: check the offsets against the actual
firmware binary *before* a build or restore. A stale or wrong-board offset is
the difference between a tethered boot and a bricked flash, so every entry is
classified against the real component instead of being trusted:

  match            the site holds the original bytes recorded for this profile
                   (inline `original:` field or offsets/evidence/<profile>.json)
  plausible        no recording yet: the site decodes as a real instruction and
                   the profile's patch value is not already there
  already-patched  the patch value is already present: the component was built
                   from a patched or wrong-build image
  changed          the recorded original bytes are NOT at the site: the profile
                   does not belong to this component (wrong board or build)
  implausible      the site does not decode as an instruction / is all zeros
  out-of-range     the entry points past the end of the component
  skipped          no raw component for this section (encrypted kernelcache,
                   missing daemon payload, no extraction tool)

`--record` writes the verified sites to offsets/evidence/<profile>.json
(component sha256 + original bytes + timestamp), which turns the profile into a
self-verifying artefact: every later run re-checks the recording and fails when
the two disagree, and a contributor can attach the evidence file to a PR.

Exit codes: 0 ok/warn, 2 blocked (a `fail` class finding), so CI can gate.

Usage:
  python3 preflight.py offsets/iPhone12,1_27.0.yaml --components research/extracted/iPhone121_27.0_24A437
  python3 preflight.py offsets/iPhone12,1_27.0.yaml --fetch          # resolve + range-fetch components
  python3 preflight.py offsets/iPhone12,1_27.0.yaml --components DIR --record
  python3 preflight.py offsets/iPhone12,1_27.0.yaml --json
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path

import yaml

from colors import C, err, info, ok, section, warn
from device_offsets import _hex_to_bytes, pending_entries, validate_offsets
from profile_gen import DEVICE_DB

ROOT = Path(__file__).parent
OFFSETS_DIR = ROOT / "offsets"
EVIDENCE_DIR = OFFSETS_DIR / "evidence"
EXTRACTED_DIR = ROOT / "research" / "extracted"

# profile section -> component file stem + the component's role
SECTION_COMPONENT = {
    "ibss": ("ibss", "iBSS", "not encrypted"),
    "ibec": ("ibec", "iBEC", "not encrypted"),
    "txm": ("txm", "TXM", "not encrypted"),
    "devicetree": ("devicetree", "DeviceTree", "not encrypted"),
    "kernel": ("kernelcache", "kernelcache", "IMG4-encrypted, needs the wiki IV+key"),
    "restoreramdisk": ("restoreramdisk", "RestoreRamdisk", "APFS-encrypted, needs the wiki IV+key"),
    "daemons": ("restoreramdisk", "rootfs daemons", "lives on the restored rootfs"),
}

STATUS_COLOR = {
    "match": C.GRN,
    "plausible": C.GRN,
    "already-patched": C.AMB,
    "changed": C.RED,
    "implausible": C.RED,
    "out-of-range": C.RED,
    "skipped": C.DIM,
    "unverifiable": C.AMB,
}
FAIL_STATUSES = {"changed", "implausible", "out-of-range"}
WARN_STATUSES = {"already-patched", "unverifiable", "skipped"}


@dataclass
class Site:
    section: str
    entry: str
    offset: int
    status: str
    detail: str = ""
    original: str = ""
    current: str = ""
    value: str = ""
    component: str = ""

    @property
    def severity(self) -> str:
        if self.status in FAIL_STATUSES:
            return "fail"
        if self.status in WARN_STATUSES:
            return "warn"
        return "ok"


@dataclass
class Report:
    profile: str
    model: str = ""
    ios: str = ""
    build: str = ""
    components: dict = field(default_factory=dict)
    sites: list[Site] = field(default_factory=list)
    profile_errors: list[str] = field(default_factory=list)
    structure: list[str] = field(default_factory=list)
    pending: int = 0

    @property
    def verdict(self) -> str:
        if self.profile_errors or any(s.severity == "fail" for s in self.sites):
            return "blocked"
        if self.structure or self.pending or any(s.severity == "warn" for s in self.sites):
            return "review"
        return "ok"

    def count(self, *statuses: str) -> int:
        return sum(1 for s in self.sites if s.status in statuses)

    def summary(self) -> dict:
        return {
            "verified": self.count("match", "plausible"),
            "changed": self.count("changed"),
            "already_patched": self.count("already-patched"),
            "implausible": self.count("implausible"),
            "out_of_range": self.count("out-of-range"),
            "skipped": self.count("skipped"),
        }

    def to_json(self) -> dict:
        return {
            "profile": self.profile,
            "model": self.model,
            "ios": self.ios,
            "build": self.build,
            "verdict": self.verdict,
            "summary": self.summary(),
            "pending_entries": self.pending,
            "profile_errors": list(self.profile_errors),
            "structure_notes": list(self.structure),
            "components": self.components,
            "sites": [asdict(s) | {"severity": s.severity} for s in self.sites],
        }


# ── component discovery ────────────────────────────────────────────

def evidence_path(profile_path: Path) -> Path:
    return EVIDENCE_DIR / f"{profile_path.stem}.json"


def load_evidence(profile_path: Path) -> dict:
    path = evidence_path(profile_path)
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return {}


def discovered_component_dir(profile: dict) -> Path | None:
    """research/extracted/<Model>_<ios>_<build>/ if it exists (fetch naming)."""
    model = str(profile.get("model", "")).replace(",", "")
    ios = str(profile.get("ios_version", ""))
    build = str(profile.get("build", ""))
    for candidate in (EXTRACTED_DIR / f"{model}_{ios}_{build}",
                      EXTRACTED_DIR / f"{model}_{ios}",
                      EXTRACTED_DIR / f"{model}_{build}"):
        if candidate.is_dir():
            return candidate
    return None


def read_component_dir(comp_dir: Path) -> dict[str, tuple[str, bytes]]:
    """Load raw components; `<section>.raw` preferred, `<section>.im4p` noted."""
    out: dict[str, tuple[str, bytes]] = {}
    for section, (stem, _label, _note) in SECTION_COMPONENT.items():
        for name in (f"{stem}.raw", f"{stem}.im4p", "restoreramdisk.dmg" if stem == "restoreramdisk" else ""):
            if not name:
                continue
            path = comp_dir / name
            if path.exists():
                out[section] = (str(path), path.read_bytes())
                break
    return out


def fetch_components_for(profile: dict, device: str, url: str = "") -> tuple[dict[str, tuple[str, bytes]], Path | None]:
    """Range-fetch iBSS/iBEC/TXM (and friends) and extract their payloads."""
    import fetch_components as fc
    import kczip

    if not url:
        url, _version = fc.resolve_ipsw_url(device, str(profile.get("build", "")))
        if not url:
            print(warn(f"  no IPSW url found for {device} {profile.get('build', '')}"))
            return {}, None

    out_dir = EXTRACTED_DIR / f"{device.replace(',', '')}_{profile.get('ios_version', 'ios')}_{profile.get('build', 'build')}"
    out_dir.mkdir(parents=True, exist_ok=True)
    print(info(f"  fetching components from {url}"))
    rc = fc.cmd_fetch(url, device, out_dir, ["ibss", "ibec", "txm"], "", True)
    if rc not in (0, 1):
        return {}, out_dir

    # unwrap the im4p containers we just wrote
    for section, (stem, _l, _n) in SECTION_COMPONENT.items():
        im4p = out_dir / f"{stem}.im4p"
        if im4p.exists():
            fc._pyimg4_extract(im4p)
    return read_component_dir(out_dir), out_dir


def component_identity(comp_dir: Path | None, profile: dict) -> tuple[list[str], list[str]]:
    """Cross-check provenance.txt against the profile: (errors, notes)."""
    errors: list[str] = []
    notes: list[str] = []
    if comp_dir is None:
        return errors, notes
    prov = comp_dir / "provenance.txt"
    if not prov.exists():
        return errors, notes
    text = prov.read_text()
    model = str(profile.get("model", ""))
    if model and model not in text:
        errors.append(f"component provenance is not for {model} ({prov.name})")
    build = str(profile.get("build", ""))
    if build and build != "unknown" and build not in text:
        notes.append(f"component provenance does not mention build {build}: it may be another build")
    return errors, notes


# ── site checks ────────────────────────────────────────────────────

def _decode_word(data: bytes, offset: int) -> tuple[int, str]:
    import struct
    word = struct.unpack_from("<I", data, offset)[0]
    try:
        from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
        ins = next(Cs(CS_ARCH_ARM64, CS_MODE_ARM).disasm(data[offset:offset + 4], offset), None)
        return word, (f"{ins.mnemonic} {ins.op_str}" if ins else "")
    except ImportError:  # pragma: no cover - capstone is a hard dep in practice
        return word, ""


def check_site(section: str, name: str, entry: dict, raw: bytes,
               recorded: dict | None, component: str) -> Site:
    """Classify one profile entry against the component bytes."""
    offset = entry.get("offset")
    value = entry.get("value")
    if entry.get("pending"):
        return Site(section, name, -1, "skipped", "pending: offset not discovered for this device")
    if not isinstance(offset, int) or offset <= 0:
        return Site(section, name, offset if isinstance(offset, int) else -1,
                    "implausible", "entry has no usable offset", component=component)

    original = str(entry.get("original", "") or (recorded or {}).get("original", ""))
    try:
        value_bytes = _hex_to_bytes(str(value))
    except (ValueError, TypeError):
        value_bytes = str(value).encode("latin-1")

    size = len(raw)
    if offset + max(len(value_bytes), 4) > size:
        return Site(section, name, offset, "out-of-range",
                    f"0x{offset:X} + {len(value_bytes)}B is past the end of the "
                    f"{size / 1e6:.1f} MB component", original=original, value=str(value))

    current = raw[offset:offset + max(len(original) // 2 or 4, len(value_bytes))]
    current_hex = current.hex()

    if original:
        want = bytes.fromhex(original)
        got = raw[offset:offset + len(want)]
        if got == want:
            return Site(section, name, offset, "match",
                        f"recorded original bytes present ({len(want)} B)",
                        original=original, current=got.hex(), value=str(value))
        if got == value_bytes:
            return Site(section, name, offset, "already-patched",
                        "the patch value is already at the site (patched or wrong-build image)",
                        original=original, current=got.hex(), value=str(value))
        return Site(section, name, offset, "changed",
                    f"recorded original {original[:24]} != current {got.hex()[:24]}",
                    original=original, current=got.hex(), value=str(value))

    # no recording: fall back to structural plausibility
    if _is_string_entry(name, value):
        if raw[offset:offset + len(value_bytes)] == value_bytes:
            return Site(section, name, offset, "already-patched",
                        "the string is already at the site", current=current_hex, value=str(value))
        if raw[offset:offset + 4] == b"\x00\x00\x00\x00":
            return Site(section, name, offset, "plausible",
                        "empty string slot (boot-args / identity payload goes here)",
                        current=current_hex, value=str(value))
        word, disasm = _decode_word(raw, offset)
        return Site(section, name, offset, "plausible",
                    f"string slot holds {current_hex[:16]} (whatever is there is overwritten)",
                    current=current_hex, value=str(value))

    word, disasm = _decode_word(raw, offset)
    if word == 0 or not disasm:
        return Site(section, name, offset, "implausible",
                    f"site word 0x{word:08X} does not decode as an instruction",
                    current=current_hex, value=str(value))
    if raw[offset:offset + len(value_bytes)] == value_bytes:
        return Site(section, name, offset, "already-patched",
                    "the patch value is already at the site", current=current_hex, value=str(value))
    return Site(section, name, offset, "plausible",
                f"site decodes as `{disasm}` (no recorded original bytes yet)",
                current=current_hex, value=str(value))


def structure_checks(profile: dict) -> list[str]:
    """Offset-space sanity that does not need any component."""
    notes: list[str] = []
    patches = profile.get("patches", {})
    for sec, data in patches.items():
        entries: list[tuple[str, int, int]] = []
        if isinstance(data, list):
            for e in data:
                if isinstance(e, dict) and isinstance(e.get("offset"), int) and not e.get("pending"):
                    entries.append((e.get("name", "?"), e["offset"], _value_len(e.get("value"))))
        elif isinstance(data, dict):
            for name, e in data.items():
                if not isinstance(e, dict) or e.get("pending"):
                    continue
                if isinstance(e.get("offset"), int) and "value" in e:
                    entries.append((name, e["offset"], _value_len(e.get("value"))))
                else:
                    for sub, se in e.items():
                        if isinstance(se, dict) and isinstance(se.get("offset"), int) and "value" in se:
                            entries.append((f"{name}.{sub}", se["offset"], _value_len(se.get("value"))))
        seen: dict[int, str] = {}
        for name, offset, length in entries:
            if offset in seen:
                notes.append(f"{sec}: {name} and {seen[offset]} share offset 0x{offset:X}")
            seen[offset] = name
        for i, (name, offset, length) in enumerate(entries):
            for other, o_offset, o_length in entries[i + 1:]:
                if offset < o_offset and offset + length > o_offset:
                    notes.append(f"{sec}: {name} (0x{offset:X}+{length}) overlaps {other} "
                                 f"(0x{o_offset:X}+{o_length})")
    return notes


def _is_string_entry(name: str, value) -> bool:
    """True when the entry writes ASCII data (boot-args, identity string)."""
    if any(tok in name.lower() for tok in ("string", "identity", "boot_args_string")):
        return True
    try:
        _hex_to_bytes(str(value))
        return False
    except (ValueError, TypeError):
        return True


def _value_len(value) -> int:
    try:
        return len(_hex_to_bytes(str(value)))
    except (ValueError, TypeError):
        return len(str(value).encode("latin-1"))


# ── the run ────────────────────────────────────────────────────────

def run_preflight(profile_path: Path, *, components: Path | None = None,
                  ipsw: Path | None = None, url: str = "", fetch: bool = False,
                  device: str = "", record: bool = False) -> Report:
    profile = yaml.safe_load(profile_path.read_text()) or {}
    report = Report(profile=profile_path.name,
                    model=str(profile.get("model", "")),
                    ios=str(profile.get("ios_version", "")),
                    build=str(profile.get("build", "")))

    passed, failed, errors = validate_offsets(profile_path)
    report.profile_errors = list(errors) if failed else []
    report.pending = pending_entries(profile_path)
    report.structure = structure_checks(profile)

    comp_dir = components
    if fetch or ipsw or url:
        model = report.model or device
        raw_components, fetched_dir = fetch_components_for(profile, model, url)
        if fetched_dir:
            comp_dir = fetched_dir
        if not raw_components:
            report.profile_errors.append("no components fetched")
    elif comp_dir is None:
        comp_dir = discovered_component_dir(profile)
    if comp_dir is not None and not comp_dir.is_dir():
        comp_dir = None

    raw_by_section: dict[str, tuple[str, bytes]] = read_component_dir(comp_dir) if comp_dir else {}
    if ipsw is not None:
        raw_by_section.update(read_components_from_ipsw(ipsw, profile))

    ident_errors, ident_notes = component_identity(comp_dir, profile)
    report.profile_errors += ident_errors
    report.structure += ident_notes

    recorded = load_evidence(profile_path).get("entries", {})

    for section, data in profile.get("patches", {}).items():
        label = SECTION_COMPONENT.get(section, (section, section, "unknown component"))[1]
        raw_entry = raw_by_section.get(section)
        if raw_entry is None:
            note = SECTION_COMPONENT.get(section, ("", "", "no component"))[2]
            report.sites.append(Site(section, "*", 0, "skipped",
                                     f"no raw {label} to check ({note})"))
            continue
        comp_path, raw = raw_entry
        report.components[section] = {"path": comp_path, "size": len(raw)}
        for name, entry in _iter_entries(section, data):
            site = check_site(section, name, entry, raw,
                              recorded.get(f"{section}.{name}"), label)
            report.sites.append(site)

    if record:
        write_evidence(profile_path, profile, report, raw_by_section)

    try:
        import log_utils
        log_utils.log("ERROR" if report.verdict == "blocked"
                      else "WARN" if report.verdict == "review" else "INFO",
                      f"preflight {profile_path.name}: {report.verdict} "
                      f"({report.count('match', 'plausible')} checked, "
                      f"{report.count('fail')} bad, {report.pending} pending)", module="preflight")
        for site in report.sites:
            if site.severity == "fail":
                log_utils.log_warn(f"preflight {site.section}.{site.entry}: {site.detail}",
                                   module="preflight")
    except Exception:                                        # noqa: BLE001
        pass
    return report


def read_components_from_ipsw(ipsw: Path, profile: dict) -> dict[str, tuple[str, bytes]]:
    """Pull the components a profile needs straight out of a local IPSW file."""
    import kczip
    import zipfile

    out: dict[str, tuple[str, bytes]] = {}
    try:
        with zipfile.ZipFile(ipsw) as zf:
            names = zf.namelist()
            board = str(profile.get("board") or
                        DEVICE_DB.get(profile.get("model", ""), {}).get("board", ""))
            offsets = {"model": profile.get("model", ""), "board": board}
            import components
            stem = components.component_stem(offsets, "ibss")
            wanted = {"ibss": f"iBSS.{stem}.RELEASE", "ibec": f"iBEC.{stem}.RELEASE",
                      "txm": "Firmware/txm", "devicetree": f"DeviceTree.{board}"}
            for section, needle in wanted.items():
                for name in names:
                    if "RESEARCH" in name:
                        continue
                    if needle in name and name.endswith(".im4p"):
                        out[section] = (f"{ipsw.name}:{name}", zf.read(name))
                        break
    except (zipfile.BadZipFile, OSError):
        pass
    return out


def _iter_entries(section: str, data):
    """Yield (entry_name, entry_dict) for dict, list and nested daemon sections."""
    if isinstance(data, list):
        for entry in data:
            if isinstance(entry, dict):
                yield entry.get("name", "?"), entry
    elif isinstance(data, dict):
        for name, entry in data.items():
            if not isinstance(entry, dict):
                continue
            if "offset" in entry and "value" in entry:
                yield name, entry
            else:
                for sub, se in entry.items():
                    if isinstance(se, dict) and "offset" in se:
                        yield f"{name}.{sub}", se


def write_evidence(profile_path: Path, profile: dict, report: Report,
                   raw_by_section: dict[str, tuple[str, bytes]]) -> Path | None:
    """Record verified originals so later runs can re-check the same bytes."""
    import hashlib

    entries: dict[str, dict] = {}
    for site in report.sites:
        if site.status not in ("match", "plausible") or site.offset <= 0:
            continue
        raw = raw_by_section.get(site.section)
        if raw is None:
            continue
        length = _value_len(site.value) or 4
        entries[f"{site.section}.{site.entry}"] = {
            "offset": site.offset,
            "original": raw[1][site.offset:site.offset + max(length, 4)].hex(),
        }
    if not entries:
        return None

    payload = {
        "profile": profile_path.name,
        "model": profile.get("model"),
        "ios_version": profile.get("ios_version"),
        "build": profile.get("build"),
        "recorded": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "tool": "preflight.py",
        "components": {
            section: {"size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
            for section, (_src, raw) in raw_by_section.items()
        },
        "entries": dict(sorted(entries.items())),
    }
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    path = evidence_path(profile_path)
    path.write_text(json.dumps(payload, indent=2) + "\n")
    return path


# ── output ─────────────────────────────────────────────────────────

def print_report(report: Report, *, verbose: bool = True) -> None:
    print(section(f"Preflight — {report.profile}"))
    ident = f"{report.model} {report.ios} ({report.build})".strip()
    print(f"  {C.DIM}{ident}{C.NC}")
    print()

    if report.components:
        for sec, meta in sorted(report.components.items()):
            print(f"  {C.EYE}{sec:<15}{C.NC} {C.DIM}{meta['path']} "
                  f"({meta['size'] / 1e6:.1f} MB){C.NC}")
        print()

    if report.profile_errors:
        for e in report.profile_errors:
            print(f"  {C.RED}✗{C.NC} {e}")
        print()
    for note in report.structure:
        print(f"  {C.AMB}!{C.NC} {note}")
    if report.structure:
        print()

    order = ["changed", "implausible", "out-of-range", "already-patched",
             "unverifiable", "plausible", "match", "skipped"]
    for status in order:
        rows = [s for s in report.sites if s.status == status]
        if not rows or (not verbose and status == "match"):
            continue
        color = STATUS_COLOR.get(status, "")
        print(f"  {color}{status}{C.NC} ({len(rows)})")
        for s in rows[:40]:
            where = f"0x{s.offset:X}" if s.offset > 0 else "-"
            print(f"    {C.EYE}{s.section}.{s.entry}{C.NC} {where}  {C.DIM}{s.detail}{C.NC}")
        if len(rows) > 40:
            print(f"    {C.DIM}… {len(rows) - 40} more{C.NC}")
        print()

    if report.pending:
        print(warn(f"  {report.pending} pending entry/entries — this profile is not flashable yet"))
    verdict_color = {"ok": C.GRN, "review": C.AMB, "blocked": C.RED}[report.verdict]
    label = {"ok": "clear to build", "review": "review before flashing",
             "blocked": "BLOCKED — do not flash"}[report.verdict]
    print(f"  {verdict_color}{label}{C.NC}  "
          f"{C.DIM}{report.count('match', 'plausible')} verified · "
          f"{report.count('changed') + report.count('implausible') + report.count('out-of-range')} bad · "
          f"{report.count('skipped')} unchecked{C.NC}")
    print()


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="preflight.py", description=__doc__.splitlines()[0])
    p.add_argument("profile", help="offset profile YAML")
    p.add_argument("--components", default="", help="directory of raw components")
    p.add_argument("--ipsw", default="", help="local IPSW to read components from")
    p.add_argument("--url", default="", help="IPSW url to range-fetch components from")
    p.add_argument("--fetch", action="store_true",
                   help="resolve the IPSW url (ipsw.me/ipsw.dev) and fetch components")
    p.add_argument("--device", default="", help="device model override for --fetch")
    p.add_argument("--record", action="store_true",
                   help="write offsets/evidence/<profile>.json with the verified bytes")
    p.add_argument("--json", action="store_true", help="machine-readable report on stdout")
    p.add_argument("--quiet", "-q", action="store_true", help="hide matched entries in the table")
    args = p.parse_args(argv if argv is not None else sys.argv[1:])

    profile_path = Path(args.profile)
    if not profile_path.exists():
        print(err(f"profile not found: {profile_path}"))
        return 2

    report = run_preflight(
        profile_path,
        components=Path(args.components) if args.components else None,
        ipsw=Path(args.ipsw) if args.ipsw else None,
        url=args.url, fetch=args.fetch, device=args.device, record=args.record,
    )

    if args.json:
        print(json.dumps(report.to_json(), indent=2))
    else:
        print_report(report, verbose=not args.quiet)
        if args.record:
            path = evidence_path(profile_path)
            if path.exists():
                print(ok(f"evidence recorded: {path}"))

    if report.verdict == "blocked":
        return 2
    return 0


if __name__ == "__main__":
    import log_utils
    log_utils.install()          # usbliter8.log + unhandled-exception logging
    sys.exit(main())
