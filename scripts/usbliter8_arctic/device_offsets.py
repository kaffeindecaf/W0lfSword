"""Device offset manager for usbliter8-arctic.

Loads YAML offset files, validates patches, finds online sources,
and manages the active device configuration.
"""

import os
import sys
from pathlib import Path
from typing import Any

import yaml

from colors import C, ok, err, warn, info, section

OFFSETS_DIR = Path(__file__).parent / "offsets"
SENTINEL = 0xDEADBEEF


def _hex_to_bytes(hex_str: str) -> bytes:
    """Convert hex string (with or without spaces) to bytes."""
    clean = hex_str.replace(" ", "").lower()
    return bytes.fromhex(clean)


def _is_valid_offset(val: int) -> bool:
    """An offset is valid if it's non-zero and not the sentinel."""
    return val > 0 and val != SENTINEL and val < 0x100000000


def _is_valid_patch_value(val: str | int) -> bool:
    """A patch value is valid hex bytes OR a non-empty ASCII string (e.g. boot-args)."""
    if isinstance(val, int):
        return True
    if not isinstance(val, str) or not val.strip():
        return False
    # try hex first
    clean = val.replace(" ", "").lower()
    if len(clean) >= 2 and len(clean) % 2 == 0 and all(c in "0123456789abcdef" for c in clean):
        return True
    # otherwise treat as ASCII string (boot-args etc.)
    return True


def _has_offset_value(d: dict) -> bool:
    return isinstance(d, dict) and "offset" in d and "value" in d


def _extract_section_offsets(data: dict, section: str) -> list[dict[str, Any]]:
    """Walk a patches section (supports dict, list, and nested dicts like daemons)."""
    items = []
    section_data = data.get("patches", {}).get(section, {})

    if isinstance(section_data, list):
        for entry in section_data:
            if _has_offset_value(entry):
                items.append({"name": entry.get("name", f"{section}[]"), "offset": entry["offset"], "value": entry["value"]})

    elif isinstance(section_data, dict):
        for name, entry in section_data.items():
            if _has_offset_value(entry):
                items.append({"name": f"{section}.{name}", "offset": entry["offset"], "value": entry["value"]})
            elif isinstance(entry, dict):
                # walk one level deeper (e.g. daemons.coreauthd.anti_sep_crash)
                for sub_name, sub_entry in entry.items():
                    if _has_offset_value(sub_entry):
                        items.append({"name": f"{section}.{name}.{sub_name}", "offset": sub_entry["offset"], "value": sub_entry["value"]})
                    elif isinstance(sub_entry, dict):
                        for sub2_name, sub2_entry in sub_entry.items():
                            if _has_offset_value(sub2_entry):
                                items.append({"name": f"{section}.{name}.{sub_name}.{sub2_name}", "offset": sub2_entry["offset"], "value": sub2_entry["value"]})

    return items


def validate_offsets(filepath: Path) -> tuple[int, int, list[str]]:
    """Validate a YAML offset file. Returns (pass_count, fail_count, error_messages)."""
    if not filepath.exists():
        return 0, 1, [f"File not found: {filepath}"]

    with open(filepath) as f:
        data = yaml.safe_load(f)

    if not isinstance(data, dict) or "patches" not in data:
        return 0, 1, ["Invalid YAML: missing 'patches' top-level key"]

    device_info = data.get("device", "unknown")
    model = data.get("model", "unknown")
    ios = data.get("ios_version", "unknown")

    passed, failed = 0, 0
    errors = []

    sections_to_check = ["ibss", "ibec", "restoreramdisk", "txm"]
    for section in sections_to_check:
        for item in _extract_section_offsets(data, section):
            off = item["offset"]
            val = item["value"]
            if not _is_valid_offset(off):
                failed += 1
                errors.append(f"[{model}/{ios}] {item['name']}: offset 0x{off:X} is not valid (sentinel or zero)")
            elif not _is_valid_patch_value(val):
                failed += 1
                errors.append(f"[{model}/{ios}] {item['name']}: patch value '{val}' is not valid")
            else:
                passed += 1

    for item in _extract_section_offsets(data, "daemons"):
        off = item["offset"]
        val = item["value"]
        if not _is_valid_offset(off):
            failed += 1
            errors.append(f"[{model}/{ios}] {item['name']}: offset 0x{off:X} is not valid")
        elif not _is_valid_patch_value(val):
            failed += 1
            errors.append(f"[{model}/{ios}] {item['name']}: patch value '{val}' is not valid")
        else:
            passed += 1

    kernel_patches = data.get("patches", {}).get("kernel", [])
    if isinstance(kernel_patches, list):
        for entry in kernel_patches:
            if isinstance(entry, dict):
                off = entry.get("offset", SENTINEL)
                val = entry.get("value", "")
                name = entry.get("name", "kernel[]")
                if not _is_valid_offset(off):
                    failed += 1
                    errors.append(f"[{model}/{ios}] {name}: offset 0x{off:X} is not valid")
                elif not _is_valid_patch_value(val):
                    failed += 1
                    errors.append(f"[{model}/{ios}] {name}: patch value '{val}' is not valid")
                else:
                    passed += 1

    return passed, failed, errors


def load_offset_file(filepath: Path) -> dict[str, Any] | None:
    """Load and validate a single offset YAML file. Returns dict or None if invalid."""
    passed, failed, errors = validate_offsets(filepath)
    if failed > 0:
        for e in errors:
            print(err(e))
        return None
    with open(filepath) as f:
        return yaml.safe_load(f)


def list_offset_files() -> list[dict[str, Any]]:
    """List all YAML offset files with validation status."""
    results = []
    for f in sorted(OFFSETS_DIR.glob("*.yaml")):
        if f.name in ("sources.yaml", "template.yaml"):
            continue
        passed, failed, _ = validate_offsets(f)
        with open(f) as fh:
            data = yaml.safe_load(fh)
        results.append({
            "file": f.name,
            "model": data.get("model", "?"),
            "device": data.get("device", "?"),
            "ios": data.get("ios_version", "?"),
            "soc": data.get("soc", "?"),
            "passed": passed,
            "failed": failed,
            "status": "ready" if failed == 0 else "incomplete",
        })
    return results


def find_online_sources(model: str, ios_version: str = "") -> list[dict[str, Any]]:
    """Search sources.yaml for repos that may have offsets for a given device."""
    sources_path = OFFSETS_DIR / "sources.yaml"
    if not sources_path.exists():
        return []

    with open(sources_path) as f:
        sources = yaml.safe_load(f)

    matches = []
    for repo in sources.get("repos", []):
        if model in repo.get("devices", []) or not repo.get("devices"):
            matches.append(repo)

    if not matches:
        for entry in sources.get("device_database", []):
            if entry.get("model") == model:
                matches.append({"name": "device_database", "url": "built-in", "devices": [model], "notes": f"Board: {entry.get('board')}, SoC: {entry.get('soc')}"})

    return matches


def set_active_device(filepath: Path) -> bool:
    """Set the active device YAML and write to .w0lfsword config."""
    passed, failed, errors = validate_offsets(filepath)
    if failed > 0:
        print(err(f"Offset file has {failed} error(s) — fix before activating:"))
        for e in errors:
            print(f"    {C.RED}{e}{C.NC}")
        return False

    config_dir = Path.home() / ".w0lfsword" / "usbliter8"
    config_dir.mkdir(parents=True, exist_ok=True)
    config_path = config_dir / "active_device.yaml"

    with open(filepath) as f:
        data = yaml.safe_load(f)

    data["_source_file"] = str(filepath.resolve())
    with open(config_path, "w") as f:
        yaml.dump(data, f, default_flow_style=False, allow_unicode=True)

    print(ok(f"Active device set to {data['device']} ({data['model']}) — iOS {data['ios_version']}"))
    return True


def get_active_device() -> dict[str, Any] | None:
    """Load the currently active device offset configuration."""
    config_path = Path.home() / ".w0lfsword" / "usbliter8" / "active_device.yaml"
    if not config_path.exists():
        return None
    with open(config_path) as f:
        return yaml.safe_load(f)


# ── CLI (for testing / standalone use) ──

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"\n  {C.FROST}usbliter8-arctic — device offset manager{C.NC}\n")
        print(f"  Usage:")
        print(f"    {C.EYE}list{C.NC}              Show all offset files with status")
        print(f"    {C.EYE}validate <file>{C.NC}    Check a specific YAML file")
        print(f"    {C.EYE}find <model>{C.NC}      Search online sources for a device")
        print(f"    {C.EYE}activate <file>{C.NC}   Set active device configuration")
        print()
        sys.exit(0)

    cmd = sys.argv[1]

    if cmd == "list":
        files = list_offset_files()
        if not files:
            print(info("No offset files found"))
        else:
            print(section("Offset Files"))
            print()
            for f in files:
                status_color = C.GRN if f["status"] == "ready" else C.AMB
                status_icon = "✓" if f["status"] == "ready" else "⚠"
                print(f"  {status_color}{status_icon}{C.NC} {C.EYE}{f['device']}{C.NC} ({C.DIM}{f['model']}{C.NC}) — iOS {C.FROST}{f['ios']}{C.NC}  [{f['soc']}]  {f['passed']} patches ok, {f['failed']} missing")
            print()

    elif cmd == "validate":
        target = Path(sys.argv[2]) if len(sys.argv) > 2 else None
        if not target or not target.exists():
            print(err(f"File not found: {target}"))
            sys.exit(1)
        passed, failed, errors = validate_offsets(target)
        if failed == 0:
            print(ok(f"All {passed} patches valid"))
        else:
            print(err(f"{passed} passed, {failed} failed:"))
            for e in errors:
                print(f"    {C.RED}{e}{C.NC}")

    elif cmd == "find":
        model = sys.argv[2] if len(sys.argv) > 2 else ""
        if not model:
            print(err("Specify a model string (e.g. iPhone12,3)"))
            sys.exit(1)
        sources = find_online_sources(model)
        if sources:
            print(section(f"Online sources for {model}"))
            print()
            for s in sources:
                print(f"  {C.EYE}{s['name']}{C.NC}")
                print(f"    {C.DIM}{s.get('url', 'N/A')}{C.NC}")
                if s.get("notes"):
                    print(f"    {C.GREY}{s['notes']}{C.NC}")
                print()
        else:
            print(warn(f"No known online sources for {model}"))

    elif cmd == "activate":
        target = Path(sys.argv[2]) if len(sys.argv) > 2 else None
        if not target:
            print(err("Specify an offset YAML file to activate"))
            sys.exit(1)
        set_active_device(target)
