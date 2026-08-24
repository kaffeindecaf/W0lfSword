"""Beta-to-beta offset migration for usbliter8 profiles.

Migrates patch offsets from a base profile (e.g. iOS 27.0b2) to a target
build (e.g. iOS 27.0b3) using the AArch64 fingerprint engine.

Component sourcing order:
  1. --comp-dir base/ + target/ layout (raw extracted components)
  2. auto-discovery of extracted raw files in known usbliter8 work dirs
  3. --fetch: shell out to the work dir's get_fw.py / make_cfw.py
     (downloads + decrypts firmware; opt-in because it is network-heavy)
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from colors import C, ok, err, warn, info, section, header, prompt
from fingerprint import MatchResult, migrate_site

SCRIPT_DIR = Path(__file__).parent
OFFSETS_DIR = SCRIPT_DIR / "offsets"

CANONICAL_PATH = Path(os.environ.get("UL8_OFFSETS_YAML",
                                     Path.home() / ".config/opencode/skills/master-router/offsets.yaml"))

# canonical checkm8 block key -> (profile section, entry name)
CHECKM8_KEY_MAP = {
    ("ibss", "image4_validate_nop"): "ibss_image4_validate",
    ("ibss", "boot_args_adrp"): "ibss_boot_args_ptr",
    ("ibss", "boot_args_string"): "ibss_boot_args_string",
    ("ibec", "image4_validate_nop"): "ibss_image4_validate",
    ("ibec", "boot_args_adrp"): "ibss_boot_args_ptr",
    ("ibec", "boot_args_string"): "ibss_boot_args_string",
    ("txm", "query_module0"): "txm_queryModule0",
    ("txm", "query_module1"): "txm_queryModule1",
    ("txm", "query_module2"): "txm_queryModule2",
    ("txm", "validate_constraints_sig_nop1"): "txm_constraints_sig",
    ("txm", "allowed_before_secure_channel"): "txm_allowedBeforeSecure",
}

COMPONENTS = ("kernelcache", "ibss", "ibec", "restoreramdisk", "txm")

FILE_PATTERNS = {
    "kernelcache": ("kernelcache",),
    "ibss": ("ibss",),
    "ibec": ("ibec",),
    "restoreramdisk": ("restoreramdisk", "ramdisk"),
    "txm": ("txm",),
}

_RAW_EXTS = (".raw", ".bin", ".img4", ".im4p")


@dataclass
class Components:
    base: dict[str, bytes] = field(default_factory=dict)
    target: dict[str, bytes] = field(default_factory=dict)


# ── YAML helpers ─────────────────────────────────────────────────────

def _load_yaml(path: Path) -> dict:
    with open(path) as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        raise ValueError(f"Not a valid profile: {path}")
    return data


def normalize_section(profile: dict, section: str) -> dict[str, dict]:
    """Return {name: {offset, value}} for a patches section.

    Handles both dict-style sections (ibss/ibec/restoreramdisk/txm) and
    list-style (kernel).
    """
    raw = profile.get("patches", {}).get(section)
    out: dict[str, dict] = {}
    if isinstance(raw, dict):
        for name, entry in raw.items():
            if isinstance(entry, dict) and "offset" in entry:
                out[name] = {"offset": entry["offset"], "value": entry.get("value", "")}
    elif isinstance(raw, list):
        for entry in raw:
            if isinstance(entry, dict) and "offset" in entry:
                out[entry.get("name", f"{section}[]")] = {
                    "offset": entry["offset"], "value": entry.get("value", ""),
                }
    return out


def diff_section(base: dict, target: dict, section: str) -> dict[str, str]:
    """Classify entries: same / offset_changed / value_changed / added / removed."""
    b = normalize_section(base, section)
    t = normalize_section(target, section)
    result: dict[str, str] = {}
    for name, bentry in b.items():
        if name not in t:
            result[name] = "removed"
        elif t[name]["offset"] != bentry["offset"]:
            result[name] = "offset_changed"
        elif t[name]["value"] != bentry["value"]:
            result[name] = "value_changed"
        else:
            result[name] = "same"
    for name in t:
        if name not in b:
            result[name] = "added"
    return result


# ── Component loading ────────────────────────────────────────────────

def _find_work_dirs() -> list[Path]:
    candidates = [
        SCRIPT_DIR.parent / "referenceforAI",
        Path.home() / "Desktop" / "W0lfSword" / "referenceforAI",
        Path.home() / "Desktop" / "W0lfSword" / "referenceforAI" / "projects",
    ]
    dirs = []
    for base in candidates:
        if base.exists():
            dirs.extend(sorted(base.glob("usbliter8-fun*/work-*")))
    return dirs


def _discover_raw_files() -> dict[str, dict[str, Path]]:
    """Search work dirs for extracted raw components keyed by build tag.

    Returns {build: {component: path}} where build is e.g. "27.0b2".
    """
    found: dict[str, dict[str, Path]] = {}
    for work_dir in _find_work_dirs():
        build = work_dir.name.split("-", 1)[-1]
        for comp, patterns in FILE_PATTERNS.items():
            if comp in found.get(build, {}):
                continue
            for p in work_dir.rglob("*"):
                if not p.is_file() or p.suffix.lower() not in _RAW_EXTS:
                    continue
                if any(pat in p.name.lower() for pat in patterns):
                    found.setdefault(build, {})[comp] = p
                    break
    return found


def _fetch_via_workdir(build: str, component: str) -> Path | None:
    """Run the work dir's get_fw.py to fetch/decrypt components. Opt-in."""
    script = None
    for work_dir in _find_work_dirs():
        if work_dir.name.endswith(build):
            for name in ("get_fw.py", "make_cfw.py"):
                candidate = work_dir / name
                if candidate.exists():
                    script = candidate
                    break
            if script:
                break
    if not script:
        return None

    print(info(f"Running {script.name} in {script.parent} (this may download firmware)..."))
    subprocess.run([sys.executable, str(script)], cwd=str(script.parent))

    discovered = _discover_raw_files()
    return discovered.get(build, {}).get(component)


def load_components(comp_dir: Path | None = None, base_build: str = "",
                    target_build: str = "", fetch: bool = False) -> Components:
    """Load raw component bytes for base and target builds."""
    comps = Components()

    if comp_dir:
        base_dir = comp_dir / "base"
        target_dir = comp_dir / "target"
        if not base_dir.is_dir() or not target_dir.is_dir():
            raise SystemExit(err(f"--comp-dir must contain base/ and target/ subdirectories: {comp_dir}"))
        for comp in COMPONENTS:
            b = base_dir / f"{comp}.raw"
            t = target_dir / f"{comp}.raw"
            if b.exists():
                comps.base[comp] = b.read_bytes()
            if t.exists():
                comps.target[comp] = t.read_bytes()
    else:
        discovered = _discover_raw_files()
        for comp in COMPONENTS:
            b = discovered.get(base_build, {}).get(comp)
            t = discovered.get(target_build, {}).get(comp)
            if b:
                comps.base[comp] = b.read_bytes()
            if t:
                comps.target[comp] = t.read_bytes()
            elif fetch:
                fetched = _fetch_via_workdir(target_build, comp)
                if fetched:
                    comps.target[comp] = fetched.read_bytes()

    missing = [c for c in COMPONENTS if c not in comps.base or c not in comps.target]
    if missing:
        print(warn(f"Missing components (base or target): {', '.join(missing)}"))
        print(info("Provide --comp-dir with base/ and target/ raw files, or use "
                   "--fetch to run the work dir's get_fw.py."))
    return comps


# ── Migration ────────────────────────────────────────────────────────

SECTION_TO_COMPONENT = {
    "ibss": "ibss",
    "ibec": "ibec",
    "restoreramdisk": "restoreramdisk",
    "txm": "txm",
    "kernel": "kernelcache",
}

CLUSTER_RADIUS = 0x1000  # ±4KB = same compilation unit neighborhood


def apply_delta_fallback(results: list[MatchResult]) -> None:
    """For pattern-failed entries, infer a LOW-confidence guess from the
    median delta of nearby (same ±4KB cluster) successfully migrated entries.

    Delta-inferred offsets are ALWAYS LOW confidence (0.30) and flagged
    for manual review — never trusted for flashing without verification.
    """
    succeeded = [r for r in results if r.method == "pattern" and r.target_offset is not None]
    if not succeeded:
        return
    for r in results:
        if r.method != "failed":
            continue
        neighbors = [s for s in succeeded
                     if abs(s.base_offset - r.base_offset) <= CLUSTER_RADIUS]
        if len(neighbors) < 2:
            continue
        deltas = sorted(s.delta for s in neighbors)
        median = deltas[len(deltas) // 2]
        r.method = "delta"
        r.target_offset = r.base_offset + median
        r.delta = median
        r.confidence = 0.30


def migrate_section(base_profile: dict, section: str,
                    comps: Components) -> list[MatchResult]:
    """Migrate every patch entry of a section from base to target binary."""
    base_entries = normalize_section(base_profile, section)
    component = SECTION_TO_COMPONENT[section]
    base_data = comps.base.get(component)
    target_data = comps.target.get(component)

    results: list[MatchResult] = []
    for name, entry in base_entries.items():
        if base_data is None or target_data is None:
            results.append(MatchResult(name, entry["offset"], None, None, "skipped", 0.0,
                                       False, "", ""))
            continue
        results.append(migrate_site(base_data, target_data, entry["offset"], name=f"{section}.{name}"))

    apply_delta_fallback(results)
    return results


# ── Canonical cross-check ───────────────────────────────────────────

def _normalize_version(v: str) -> str:
    """'27.0b2' -> '27_0b2' (offsets.yaml key style)."""
    return str(v).replace(".", "_").replace(" ", "")


def _version_from_path(path: Path) -> str:
    """Extract the version from a profile filename like 'iPhone12,3_27.0b2.yaml'."""
    import re
    m = re.search(r"(\d+\.\d+(?:b\d+)?)", path.stem)
    return m.group(1) if m else ""


def _load_canonical_checkm8() -> dict:
    if not CANONICAL_PATH.exists():
        return {}
    try:
        with open(CANONICAL_PATH) as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError:
        return {}
    if not isinstance(data, dict):
        return {}
    return data.get("constants", {}).get("checkm8", {}) or {}


def check_canonical(base_profile: dict, target_profile: dict,
                    all_results: dict[str, list[MatchResult]],
                    base_version: str = "", target_version: str = "") -> list[str]:
    """Compare migrated offsets against the canonical offsets.yaml checkm8
    block. Returns human-readable conflict lines (2.6)."""
    canonical = _load_canonical_checkm8()
    if not canonical:
        return []

    base_v = _normalize_version(base_version or base_profile.get("ios_version", ""))
    target_v = _normalize_version(target_version or target_profile.get("ios_version", ""))
    conflict_lines = []

    # canonical block keys look like "ios_27_0b2" — accept with/without prefix
    blocks: dict[str, dict] = {}
    for k, v in canonical.items():
        if isinstance(v, dict):
            blocks[k] = v
            if k.startswith("ios_"):
                blocks.setdefault(k[4:], v)

    for section, results in all_results.items():
        for r in results:
            entry_name = r.name.split(".", 1)[-1]
            key = CHECKM8_KEY_MAP.get((section, entry_name))
            if not key:
                continue
            cv = None
            from_target_block = False
            for block_name in (target_v, base_v):
                block = blocks.get(block_name)
                if block and key in block:
                    try:
                        cv = int(str(block[key]), 16)
                    except ValueError:
                        cv = None
                    if cv is not None:
                        from_target_block = (block_name == target_v)
                        break
            if cv is None:
                continue
            if from_target_block:
                # canonical value belongs to the target build: agree only if
                # it matches the migrated target offset
                if cv == r.target_offset:
                    continue
                target_str = f"0x{r.target_offset:X}" if r.target_offset is not None else "—"
                conflict_lines.append(
                    f"{r.name}: canonical {target_v} block says 0x{cv:X} but "
                    f"migration found {target_str}")
            elif r.target_offset is not None and cv == r.target_offset and cv == r.base_offset:
                continue  # unchanged entry — base, target, and canonical all agree
            elif r.target_offset is not None and cv == r.target_offset:
                conflict_lines.append(
                    f"{r.name}: canonical matches TARGET build only "
                    f"(0x{cv:X}) — canonical version key may be mislabeled "
                    f"(local base profile says 0x{r.base_offset:X})")
            elif cv == r.base_offset:
                conflict_lines.append(
                    f"{r.name}: canonical matches BASE build only (0x{cv:X}) — "
                    f"canonical entry is stale for {target_v}")
            else:
                target_str = f"0x{r.target_offset:X}" if r.target_offset is not None else "—"
                conflict_lines.append(
                    f"{r.name}: canonical 0x{cv:X} matches NEITHER base "
                    f"(0x{r.base_offset:X}) nor target ({target_str})")
    return conflict_lines


# ── Report ───────────────────────────────────────────────────────────

def format_report(base_path: Path, target_path: Path,
                  all_results: dict[str, list[MatchResult]],
                  conflicts: list[str] | None = None) -> str:
    lines = [
        "# Offset Migration Report",
        "",
        f"Base:   `{base_path}`",
        f"Target: `{target_path}`",
        "",
    ]
    review: list[str] = []

    for section, results in all_results.items():
        if not results:
            continue
        lines += [f"## {section}", ""]
        lines.append("| name | base | target | delta | method | conf | value_changed | site b2 | site b3 | candidates |")
        lines.append("|---|---|---|---|---|---|---|---|---|---|")
        for r in results:
            conf = f"{r.confidence:.2f}"
            vc = "YES" if r.value_changed else "no"
            cands = ",".join(f"0x{c:X}" for c in r.candidates[:5]) or "—"
            lines.append(
                f"| {r.name} | 0x{r.base_offset:X} | "
                f"{f'0x{r.target_offset:X}' if r.target_offset is not None else '—'} | "
                f"{r.delta if r.delta is not None else '—'} | {r.method} | {conf} | {vc} | "
                f"`{r.old_value}` | `{r.new_value}` | {cands} |"
            )
            if r.target_offset is not None and r.confidence < 0.90:
                review.append(f"{r.name} (conf {r.confidence:.2f}, method {r.method})")
        lines.append("")

    if review:
        lines += ["## REVIEW REQUIRED", ""]
        lines += [f"- {x}" for x in review]
        lines.append("")

    if conflicts:
        lines += ["## CANONICAL CONFLICTS", ""]
        lines += [f"- {x}" for x in conflicts]
        lines.append("")
    return "\n".join(lines)


# ── CLI ──────────────────────────────────────────────────────────────

def run_migration(base_path: Path, target_path: Path, comp_dir: Path | None = None,
                  fetch: bool = False, auto: bool = False,
                  report_path: Path | None = None) -> dict[str, list[MatchResult]]:
    base_profile = _load_yaml(base_path)
    target_profile = _load_yaml(target_path) if target_path.exists() else {
        "patches": {}, "device": base_profile.get("device"),
        "model": base_profile.get("model"), "ios_version": base_profile.get("ios_version"),
    }

    base_build = base_profile.get("ios_version", "")
    target_build = target_profile.get("ios_version", "")
    comps = load_components(comp_dir, base_build, target_build, fetch=fetch)

    all_results: dict[str, list[MatchResult]] = {}
    for sec in ("ibss", "ibec", "restoreramdisk", "txm", "kernel"):
        diff = diff_section(base_profile, target_profile, sec)
        results = migrate_section(base_profile, sec, comps)
        if results:
            all_results[sec] = results
        changed = {k: v for k, v in diff.items() if v not in ("same",)}
        if changed:
            print(f"  {C.DIM}diff {sec}: " +
                  ", ".join(f"{k}({v})" for k, v in sorted(changed.items())) + C.NC)

    print()
    print(section("Results"))
    for sec, results in all_results.items():
        good = sum(1 for r in results if r.confidence >= 0.90)
        failed = sum(1 for r in results if r.target_offset is None and r.method == "failed")
        skipped = sum(1 for r in results if r.method == "skipped")
        print(f"  {C.EYE}{sec:<16}{C.NC} {C.GRN}{good}{C.NC} high-conf  "
              f"{C.RED}{failed}{C.NC} failed  {C.DIM}{skipped}{C.NC} skipped  /  {len(results)} total")

    conflicts = check_canonical(base_profile, target_profile, all_results,
                                base_version=_version_from_path(base_path),
                                target_version=_version_from_path(target_path))
    if conflicts:
        print()
        print(section("Canonical conflicts"))
        for line in conflicts:
            print(f"  {C.AMB}⚠{C.NC} {line}")

    report = format_report(base_path, target_path, all_results, conflicts)
    if report_path:
        report_path.write_text(report)
        print(ok(f"Report written: {report_path}"))
    else:
        print()
        print(report)

    if auto and target_path.exists():
        apply_offsets(target_path, all_results, base_profile)
    elif not auto and target_path.exists() and all_results:
        ans = input(prompt("Apply migrated offsets to the target profile? [y/N]: ") or "n")
        if ans.lower() in ("y", "yes"):
            apply_offsets(target_path, all_results, base_profile)

    return all_results


def _update_entry(entry: dict, r: MatchResult):
    entry["offset"] = r.target_offset
    meta = {"method": r.method, "confidence": round(r.confidence, 2),
            "base_offset": r.base_offset}
    if r.candidates:
        meta["candidates"] = [f"0x{c:X}" for c in r.candidates]
    old_val = str(entry.get("value", "")).replace(" ", "")
    if "?" in old_val and r.new_value:
        # template placeholder — fill from the target site word
        entry["value"] = r.new_value
        meta["value_filled_from_site"] = True
    if r.value_changed and r.suggested_value:
        clean = str(entry.get("value", "")).replace(" ", "")
        if len(clean) == 8:  # single 4-byte instruction — recompute the immediate
            entry["value"] = r.suggested_value
            meta["value_recomputed"] = True
    entry["migrated"] = meta


def _find_entry(entries, name: str) -> dict | None:
    if isinstance(entries, dict):
        e = entries.get(name)
        return e if isinstance(e, dict) else None
    if isinstance(entries, list):
        for e in entries:
            if isinstance(e, dict) and e.get("name") == name:
                return e
    return None


def apply_offsets(target_path: Path, all_results: dict[str, list[MatchResult]],
                  base_profile: dict | None = None):
    """Write migrated offsets into the target profile (with metadata).

    Upserts: entries missing from the target profile (e.g. a fresh template
    skeleton without a txm section, or only a subset of kernel entries) are
    created from the base profile's entry shape instead of silently dropped.
    """
    profile = _load_yaml(target_path)
    patches = profile.setdefault("patches", {})
    base_sections = (base_profile or {}).get("patches", {})

    for section, results in all_results.items():
        entries = patches.get(section)
        if entries is None:
            # section absent entirely (e.g. txm in the template) — create it
            base_raw = base_sections.get(section)
            entries = [] if isinstance(base_raw, list) else {}
            patches[section] = entries

        for r in results:
            if r.target_offset is None:
                continue
            entry_name = r.name.split(".", 1)[-1]
            entry = _find_entry(entries, entry_name)
            if entry is None:
                if not base_profile:
                    continue
                base_entry = normalize_section(base_profile, section).get(entry_name)
                if not base_entry:
                    continue
                entry = {"offset": base_entry["offset"], "value": base_entry.get("value", "")}
                if isinstance(entries, list):
                    entry["name"] = entry_name
                    entries.append(entry)
                else:
                    entries[entry_name] = entry
            _update_entry(entry, r)

    with open(target_path, "w") as f:
        yaml.dump(profile, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
    print(ok(f"Offsets written to {target_path}"))

    # 2.10: post-write validation
    from device_offsets import validate_offsets
    passed, failed, errors = validate_offsets(target_path)
    if failed == 0:
        print(ok(f"Post-write validation: {passed} patches valid"))
    else:
        print(warn(f"Post-write validation: {passed} valid, {failed} failed:"))
        for e in errors:
            print(f"    {C.AMB}{e}{C.NC}")


def cli_main(args: list[str]):
    p = argparse.ArgumentParser(prog="profile_gen.py migrate",
                                description="Migrate patch offsets across beta builds")
    p.add_argument("base", help="Base offset profile YAML (e.g. offsets/iPhone12,3_27.0b2.yaml)")
    p.add_argument("target", help="Target profile YAML, or iOS version string for a new build")
    p.add_argument("--build", help="Build number for a new target profile")
    p.add_argument("--comp-dir", type=Path, help="Directory with base/ and target/ raw components")
    p.add_argument("--fetch", action="store_true", help="Run work-dir get_fw.py to fetch components")
    p.add_argument("--auto", action="store_true", help="Write migrated offsets into the target profile")
    p.add_argument("--report", type=Path, default=None, help="Write report to file")
    a = p.parse_args(args)

    base_path = Path(a.base)
    if not base_path.exists():
        print(err(f"Base profile not found: {base_path}"))
        return

    try:
        base_profile = _load_yaml(base_path)
    except ValueError as e:
        print(err(f"Invalid base profile: {e}"))
        return

    if Path(a.target).exists():
        target_path = Path(a.target)
    else:
        model = base_profile.get("model", "unknown")
        target_path = OFFSETS_DIR / f"{model}_{a.target}.yaml"
        if not target_path.exists():
            from profile_gen import generate_profile
            profile = generate_profile(model, a.target, a.build or "unknown")
            target_path.parent.mkdir(parents=True, exist_ok=True)
            with open(target_path, "w") as f:
                yaml.dump(profile, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
            print(ok(f"Created target skeleton: {target_path.name}"))

    run_migration(base_path, target_path, comp_dir=a.comp_dir, fetch=a.fetch,
                  auto=a.auto, report_path=a.report)


if __name__ == "__main__":
    cli_main(sys.argv[1:])
