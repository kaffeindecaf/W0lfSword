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
import hashlib
import json
import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from colors import C, ok, err, warn, info, section, prompt
import log_utils
from fingerprint import MatchResult, migrate_site
from source_audit import find_work_dirs

SCRIPT_DIR = Path(__file__).parent
OFFSETS_DIR = SCRIPT_DIR / "offsets"

def _resolve_canonical_path() -> Path:
    """Canonical checkm8 DB: env override, then the user's dotfiles copy, then
    the in-repo snapshot (offsets/canonical.yaml) so the cross-check works
    without any local dotfile layout."""
    env = os.environ.get("UL8_OFFSETS_YAML")
    if env:
        return Path(env)
    user_copy = Path.home() / ".config/opencode/skills/master-router/offsets.yaml"
    if user_copy.exists():
        return user_copy
    return SCRIPT_DIR / "offsets" / "canonical.yaml"


CANONICAL_PATH = _resolve_canonical_path()

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


# ── Machine-readable output + resumable runs ─────────────────────────

CHECKPOINT_SCHEMA = 1
DEFAULT_CHECKPOINT = SCRIPT_DIR / "research" / "work" / "migrate_checkpoint.json"


class CheckpointMismatch(ValueError):
    """A checkpoint belongs to a different base/target pair. Refusing to
    reuse it: offsets from another build are a brick risk, not a shortcut."""


def result_to_dict(r: MatchResult) -> dict:
    """MatchResult -> JSON-safe dict (offsets in decimal; hex strings are for
    humans, a machine consumer wants ints)."""
    return {
        "name": r.name,
        "base_offset": r.base_offset,
        "target_offset": r.target_offset,
        "delta": r.delta,
        "method": r.method,
        "confidence": round(r.confidence, 2),
        "value_changed": r.value_changed,
        "old_value": r.old_value,
        "new_value": r.new_value,
        "candidates": list(r.candidates),
        "disasm_class_ok": r.disasm_class_ok,
        "suggested_value": r.suggested_value,
    }


def result_from_dict(d: dict) -> MatchResult:
    return MatchResult(
        name=str(d.get("name", "")),
        base_offset=int(d.get("base_offset", 0)),
        target_offset=(None if d.get("target_offset") is None else int(d["target_offset"])),
        delta=(None if d.get("delta") is None else int(d["delta"])),
        method=str(d.get("method", "failed")),
        confidence=float(d.get("confidence", 0.0)),
        value_changed=bool(d.get("value_changed", False)),
        old_value=str(d.get("old_value", "")),
        new_value=str(d.get("new_value", "")),
        candidates=[int(c) for c in d.get("candidates", [])],
        disasm_class_ok=d.get("disasm_class_ok"),
        suggested_value=str(d.get("suggested_value", "")),
    )


def _file_identity(path: Path) -> dict:
    """Where a profile lives and what it contains, so a checkpoint can prove
    it belongs to this run before any of it is reused."""
    if not path.exists():
        return {"path": str(path), "sha256": None}
    return {"path": str(path),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


def _checkpoint_identity(base_path: Path, target_path: Path) -> dict:
    return {"base": _file_identity(base_path), "target": _file_identity(target_path)}


def checkpoint_write(path: Path, base_path: Path, target_path: Path,
                     sections: dict[str, list[MatchResult]],
                     remaining: list[str], complete: bool = False) -> None:
    """Record what is already migrated. Written after every section, so a run
    killed mid-search (the kernel section alone takes 20-25s) can be resumed
    instead of restarted."""
    payload = {
        "schema": CHECKPOINT_SCHEMA,
        "identity": _checkpoint_identity(base_path, target_path),
        "complete": complete,
        "remaining": remaining,
        "sections": {name: [result_to_dict(r) for r in results]
                     for name, results in sections.items()},
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n")


def checkpoint_read(path: Path, base_path: Path, target_path: Path
                    ) -> dict[str, list[MatchResult]]:
    """Load finished sections, refusing a checkpoint that is not from this run.

    Raises CheckpointMismatch (not a silent ignore) when the base or target
    profile differs, and ValueError when the file itself is unusable.
    """
    try:
        payload = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as e:
        raise ValueError(f"unreadable checkpoint {path}: {e}") from None
    if not isinstance(payload, dict) or "sections" not in payload:
        raise ValueError(f"not a migrate checkpoint: {path}")
    if payload.get("schema") != CHECKPOINT_SCHEMA:
        raise ValueError(f"checkpoint schema {payload.get('schema')!r} is not "
                         f"{CHECKPOINT_SCHEMA}: {path}")
    want = _checkpoint_identity(base_path, target_path)
    got = payload.get("identity") or {}
    for side in ("base", "target"):
        if got.get(side) != want[side]:
            raise CheckpointMismatch(
                f"checkpoint {path} was made for a different {side} profile: "
                f"{got.get(side, {}).get('path', '?')} "
                f"(sha256 {str(got.get(side, {}).get('sha256'))[:12]})")
    sections = payload.get("sections") or {}
    return {name: [result_from_dict(d) for d in entries]
            for name, entries in sections.items() if entries}


def summarize(all_results: dict[str, list[MatchResult]],
              conflicts: list[str] | None = None) -> dict:
    """One set of counts and one verdict string, shared by the markdown report
    and the --json output so the two can never disagree."""
    high = sum(1 for results in all_results.values() for r in results
               if r.target_offset is not None and r.confidence >= 0.90)
    total = sum(len(results) for results in all_results.values())
    below = total - high
    failed = sum(1 for results in all_results.values() for r in results
                 if r.target_offset is None and r.method != "skipped")
    skipped = sum(1 for results in all_results.values() for r in results
                  if r.method == "skipped")
    # "unresolved" = no target offset at all: a failed search OR a section with
    # no component to search (skipped). Kept apart so --json can tell them apart.
    unresolved = failed + skipped
    n_conflicts = len(conflicts or [])
    ready = not (below or unresolved or n_conflicts)
    if ready:
        verdict = (f"READY: {high}/{total} entries at HIGH confidence, "
                   f"0 unresolved, 0 canonical conflicts — safe to write with --auto")
    else:
        verdict = (f"REVIEW REQUIRED: {below} entr{'y' if below == 1 else 'ies'} below 0.90"
                   f", {unresolved} unresolved, {n_conflicts} canonical conflict(s)")
    return {
        "verdict": verdict,
        "ready": ready,
        "total": total,
        "high": high,
        "below": below,
        "failed": failed,
        "skipped": skipped,
        "unresolved": unresolved,
        "conflicts": n_conflicts,
    }


def review_entries(all_results: dict[str, list[MatchResult]]) -> list[str]:
    """Entries a human has to look at: below the 0.90 write floor."""
    return [f"{r.name} (conf {r.confidence:.2f}, method {r.method})"
            for results in all_results.values() for r in results
            if r.target_offset is not None and r.confidence < 0.90]


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


def _discover_raw_files() -> dict[str, dict[str, Path]]:
    """Search work dirs for extracted raw components keyed by build tag.

    Returns {build: {component: path}} where build is e.g. "27.0b2".
    """
    found: dict[str, dict[str, Path]] = {}
    for work_dir in find_work_dirs():
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


def _fetch_via_workdir(build: str, component: str, quiet: bool = False) -> Path | None:
    """Run the work dir's get_fw.py to fetch/decrypt components. Opt-in.

    `quiet` (--json) keeps stdout a clean JSON channel: the script's own
    output goes to stderr instead of into the pipe.
    """
    script = None
    for work_dir in find_work_dirs():
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

    if not quiet:
        print(info(f"Running {script.name} in {script.parent} (this may download firmware)..."))
    subprocess.run([sys.executable, str(script)], cwd=str(script.parent),
                   stdout=sys.stderr if quiet else None)

    discovered = _discover_raw_files()
    return discovered.get(build, {}).get(component)


def load_components(comp_dir: Path | None = None, base_build: str = "",
                    target_build: str = "", fetch: bool = False,
                    quiet: bool = False) -> Components:
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
                fetched = _fetch_via_workdir(target_build, comp, quiet=quiet)
                if fetched:
                    comps.target[comp] = fetched.read_bytes()

    missing = [c for c in COMPONENTS if c not in comps.base or c not in comps.target]
    if missing and not quiet:
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

# Report order, and the unit a resumed run skips: one section per checkpoint write.
SECTIONS = ("ibss", "ibec", "restoreramdisk", "txm", "kernel")

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

    for sec_name, results in all_results.items():
        for r in results:
            entry_name = r.name.split(".", 1)[-1]
            key = CHECKM8_KEY_MAP.get((sec_name, entry_name))
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
    stats = summarize(all_results, conflicts)
    verdict = stats["verdict"]

    lines = [
        "# Offset Migration Report",
        "",
        f"**VERDICT: {verdict}**",
        "",
        f"Base:   `{base_path}`",
        f"Target: `{target_path}`",
        "",
    ]
    review = review_entries(all_results)

    for sec_name, results in all_results.items():
        if not results:
            continue
        lines += [f"## {sec_name}", ""]
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

def _console(quiet: bool):
    """Human output, silenced in --json mode: stdout carries one JSON object
    and nothing else, so `migrate --json | jq` never sees a banner or a table."""
    return (lambda *_args, **_kwargs: None) if quiet else print


@dataclass
class MigrationRun:
    """Everything a migration produced, in both shapes: the entry objects the
    report/apply steps need, and the machine-readable summary --json prints."""
    base_path: Path
    target_path: Path
    results: dict[str, list[MatchResult]] = field(default_factory=dict)
    stats: dict = field(default_factory=dict)
    conflicts: list[str] = field(default_factory=list)
    resumed: list[str] = field(default_factory=list)
    wrote: bool = False
    not_written: list[str] = field(default_factory=list)
    validation: dict = field(default_factory=dict)
    min_confidence: float = 0.90
    checkpoint: Path | None = None

    @property
    def ready(self) -> bool:
        return bool(self.stats.get("ready"))

    def as_dict(self) -> dict:
        counts = ("total", "high", "below", "failed", "skipped", "unresolved", "conflicts")
        return {
            "schema": CHECKPOINT_SCHEMA,
            "verdict": self.stats.get("verdict", ""),
            "ready": self.ready,
            "counts": {k: self.stats.get(k, 0) for k in counts},
            "base": _file_identity(self.base_path),
            "target": _file_identity(self.target_path),
            "min_confidence": self.min_confidence,
            "sections": {
                sec: {
                    "counts": {k: summarize({sec: entries}).get(k, 0) for k in counts},
                    "entries": [result_to_dict(r) for r in entries],
                }
                for sec, entries in self.results.items()
            },
            "review": review_entries(self.results),
            "conflicts": list(self.conflicts),
            "resumed_sections": list(self.resumed),
            "checkpoint": str(self.checkpoint) if self.checkpoint else None,
            "wrote": self.wrote,
            "not_written": list(self.not_written),
            "validation": dict(self.validation),
        }


@dataclass
class ApplyResult:
    """Outcome of writing a migrated profile: what the floor held back, and
    whether the written file still validates."""
    skipped_low: list[str] = field(default_factory=list)
    passed: int = 0
    failed: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def valid(self) -> bool:
        return self.failed == 0

    def as_dict(self) -> dict:
        return {"passed": self.passed, "failed": self.failed,
                "valid": self.valid, "errors": list(self.errors)}


def run_migration(base_path: Path, target_path: Path, comp_dir: Path | None = None,
                  fetch: bool = False, auto: bool = False,
                  report_path: Path | None = None,
                  min_confidence: float = 0.90,
                  checkpoint: Path | None = None, resume: Path | None = None,
                  json_out: bool = False) -> MigrationRun:
    say = _console(json_out)
    base_profile = _load_yaml(base_path)
    target_profile = _load_yaml(target_path) if target_path.exists() else {
        "patches": {}, "device": base_profile.get("device"),
        "model": base_profile.get("model"), "ios_version": base_profile.get("ios_version"),
    }

    base_build = base_profile.get("ios_version", "")
    target_build = target_profile.get("ios_version", "")
    comps = load_components(comp_dir, base_build, target_build, fetch=fetch,
                            quiet=json_out)

    # Resuming reuses finished sections instead of re-running their search; a
    # checkpoint from another base/target pair is refused, never applied.
    done: dict[str, list[MatchResult]] = {}
    if resume is not None:
        done = checkpoint_read(resume, base_path, target_path)
        if done:
            n_entries = sum(len(v) for v in done.values())
            say(ok(f"Resumed {len(done)} section(s), {n_entries} entries from {resume}"))
            log_utils.log_info(f"migrate: resumed {sorted(done)} from {resume}",
                               module="migrate")
        else:
            say(info(f"Nothing to resume from {resume} — running a full search"))

    all_results: dict[str, list[MatchResult]] = {}
    for sec in SECTIONS:
        if sec in done:
            all_results[sec] = done[sec]
            continue
        diff = diff_section(base_profile, target_profile, sec)
        results = migrate_section(base_profile, sec, comps)
        if results:
            all_results[sec] = results
        changed = {k: v for k, v in diff.items() if v not in ("same",)}
        if changed:
            say(f"  {C.DIM}diff {sec}: " +
                ", ".join(f"{k}({v})" for k, v in sorted(changed.items())) + C.NC)
        if checkpoint:
            # after every section: the kernel search is the slow part of a run
            checkpoint_write(checkpoint, base_path, target_path, all_results,
                             remaining=[s for s in SECTIONS if s not in all_results])

    say("")
    say(section("Results"))
    for sec, results in all_results.items():
        good = sum(1 for r in results if r.confidence >= 0.90)
        failed = sum(1 for r in results if r.target_offset is None and r.method == "failed")
        skipped = sum(1 for r in results if r.method == "skipped")
        say(f"  {C.EYE}{sec:<16}{C.NC} {C.GRN}{good}{C.NC} high-conf  "
            f"{C.RED}{failed}{C.NC} failed  {C.DIM}{skipped}{C.NC} skipped  /  {len(results)} total")

    conflicts = check_canonical(base_profile, target_profile, all_results,
                                base_version=_version_from_path(base_path),
                                target_version=_version_from_path(target_path))
    if conflicts:
        say("")
        say(section("Canonical conflicts"))
        for line in conflicts:
            say(f"  {C.AMB}⚠{C.NC} {line}")

    run = MigrationRun(base_path=base_path, target_path=target_path,
                       results=all_results, stats=summarize(all_results, conflicts),
                       conflicts=list(conflicts), resumed=sorted(done),
                       min_confidence=min_confidence, checkpoint=checkpoint)

    report = format_report(base_path, target_path, all_results, conflicts)
    if report_path:
        report_path.write_text(report)
        say(ok(f"Report written: {report_path}"))
    else:
        say("")
        say(report)

    if auto and target_path.exists():
        applied = apply_offsets(target_path, all_results, base_profile,
                                min_confidence=min_confidence, quiet=json_out)
        run.not_written = applied.skipped_low
        run.validation = applied.as_dict()
        run.wrote = True
    elif not auto and not json_out and target_path.exists() and all_results:
        ans = log_utils.safe_input(prompt("Apply migrated offsets to the target profile? [y/N]: ") or "n")
        if ans.lower() in ("y", "yes"):
            applied = apply_offsets(target_path, all_results, base_profile,
                                    min_confidence=min_confidence)
            run.not_written = applied.skipped_low
            run.validation = applied.as_dict()
            run.wrote = True

    if checkpoint:
        checkpoint_write(checkpoint, base_path, target_path, all_results,
                         remaining=[], complete=True)
        say(info(f"Checkpoint written: {checkpoint}"))

    if json_out:
        print(json.dumps(run.as_dict(), indent=2))
    else:
        say("")
        say(ok(f"VERDICT: {run.stats['verdict']}") if run.ready
            else warn(f"VERDICT: {run.stats['verdict']}"))
    return run


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
                  base_profile: dict | None = None, min_confidence: float = 0.90,
                  quiet: bool = False) -> ApplyResult:
    """Write migrated offsets into the target profile (with metadata).

    Upserts: entries missing from the target profile (e.g. a fresh template
    skeleton without a txm section, or only a subset of kernel entries) are
    created from the base profile's entry shape instead of silently dropped.

    Returns what the caller (and a --json consumer) needs to tell a good write
    from a partial one: the entries the confidence floor kept out, and the
    post-write validation verdict.
    """
    say = _console(quiet)
    profile = _load_yaml(target_path)
    patches = profile.setdefault("patches", {})
    base_sections = (base_profile or {}).get("patches", {})
    skipped_low: list[str] = []

    for sec_name, results in all_results.items():
        entries = patches.get(sec_name)
        if entries is None:
            # sec_name absent entirely (e.g. txm in the template) — create it
            base_raw = base_sections.get(sec_name)
            entries = [] if isinstance(base_raw, list) else {}
            patches[sec_name] = entries

        for r in results:
            if r.target_offset is None:
                continue
            if r.confidence < min_confidence:
                skipped_low.append(f"{r.name} (conf {r.confidence:.2f})")
                continue
            entry_name = r.name.split(".", 1)[-1]
            entry = _find_entry(entries, entry_name)
            if entry is None:
                if not base_profile:
                    continue
                base_entry = normalize_section(base_profile, sec_name).get(entry_name)
                if not base_entry:
                    continue
                entry = {"offset": base_entry["offset"], "value": base_entry.get("value", "")}
                if isinstance(entries, list):
                    entry["name"] = entry_name
                    entries.append(entry)
                else:
                    entries[entry_name] = entry
            _update_entry(entry, r)

    from device_offsets import dump_profile_yaml, validate_offsets
    if skipped_low:
        say(warn(f"{len(skipped_low)} entry/entries below the {min_confidence:.2f} "
                 f"confidence floor were NOT written:"))
        for name in skipped_low[:10]:
            say(f"    {C.AMB}{name}{C.NC}")
        say(f"  {C.DIM}review them and write manually, or migrate with --force-low "
            f"to accept the risk{C.NC}")
    dump_profile_yaml(profile, target_path)
    say(ok(f"Offsets written to {target_path}"))
    passed, failed, errors = validate_offsets(target_path)
    if failed == 0:
        say(ok(f"Post-write validation: {passed} patches valid"))
    else:
        say(warn(f"Post-write validation: {passed} valid, {failed} failed:"))
        for e in errors:
            say(f"    {C.AMB}{e}{C.NC}")
    return ApplyResult(skipped_low=skipped_low, passed=passed,
                       failed=failed, errors=list(errors))


def _checkpoint_arg(parser: argparse.ArgumentParser, name: str, help_text: str):
    """`--checkpoint` / `--resume` with an optional path: bare means the default
    location under research/work (gitignored), which is where reports land."""
    parser.add_argument(name, type=Path, nargs="?", const=DEFAULT_CHECKPOINT,
                        default=None, metavar="FILE", help=help_text)


def cli_main(args: list[str]):
    with log_utils.timed('migrate', 'migrate'):
        p = argparse.ArgumentParser(prog="profile_gen.py migrate",
                                    description="Migrate patch offsets across beta builds")
        p.add_argument("base", help="Base offset profile YAML (e.g. offsets/iPhone12,3_27.0b2.yaml)")
        p.add_argument("target", help="Target profile YAML, or iOS version string for a new build")
        p.add_argument("--build", help="Build number for a new target profile")
        p.add_argument("--comp-dir", type=Path, help="Directory with base/ and target/ raw components")
        p.add_argument("--fetch", action="store_true", help="Run work-dir get_fw.py to fetch components")
        p.add_argument("--auto", action="store_true", help="Write migrated offsets into the target profile")
        p.add_argument("--report", type=Path, default=None, help="Write report to file")
        p.add_argument("--json", dest="json_out", action="store_true",
                       help="one JSON summary on stdout (no prompts, no tables); "
                            "exit 2 means REVIEW REQUIRED")
        _checkpoint_arg(p, "--checkpoint",
                        "record progress after every section, so a killed run can resume")
        _checkpoint_arg(p, "--resume",
                        "reuse the finished sections in a checkpoint instead of searching again")
        p.add_argument("--force-low", dest="force_low", action="store_true",
                       help="write entries below the 0.90 confidence floor too (NOT recommended)")
        a = p.parse_args(args)

        json_out = a.json_out

        def fail(message: str, code: int = log_utils.EXIT_ERROR) -> int:
            """Errors stay machine-readable in --json mode: still one object."""
            if json_out:
                print(json.dumps({"schema": CHECKPOINT_SCHEMA, "ready": False,
                                  "error": message}, indent=2))
            else:
                print(err(message))
            return code

        base_path = Path(a.base)
        if not base_path.exists():
            return fail(f"Base profile not found: {base_path}")

        try:
            base_profile = _load_yaml(base_path)
        except ValueError as e:
            return fail(f"Invalid base profile: {e}")

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
                _console(json_out)(ok(f"Created target skeleton: {target_path.name}"))

        if a.force_low:
            _console(json_out)(warn("--force-low: writing entries below 0.90 — a wrong offset "
                                    "rated HIGH is a brick risk, review the report first"))
        try:
            run = run_migration(base_path, target_path, comp_dir=a.comp_dir, fetch=a.fetch,
                                auto=a.auto, report_path=a.report,
                                min_confidence=0.0 if a.force_low else 0.90,
                                checkpoint=a.checkpoint, resume=a.resume, json_out=json_out)
        except CheckpointMismatch as e:
            # a checkpoint from another build is a brick risk, not a shortcut
            return fail(str(e), log_utils.EXIT_BLOCKED)
        except ValueError as e:
            return fail(str(e))

        # A machine consumer gets the verdict twice: in the payload and as the
        # exit code, so `migrate --json && echo written` cannot ignore a REVIEW.
        if json_out and not run.ready:
            return log_utils.EXIT_BLOCKED
    return log_utils.EXIT_OK


if __name__ == "__main__":
    import log_utils
    log_utils.install()
    sys.exit(log_utils.guard(cli_main, sys.argv[1:]))
