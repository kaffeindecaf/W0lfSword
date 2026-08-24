#!/usr/bin/env python3
"""Offset profile generator for usbliter8-arctic.

Creates valid YAML offset files from a device model, iOS version,
and optionally merges kernel offsets from an existing DarkSword
offsets.m source file.

Usage:
  python3 profile_gen.py create iPhone12,1 27.0
  python3 profile_gen.py merge iPhone12,1_27.0b2.yaml kernel_offsets.txt
  python3 profile_gen.py diff base.yaml updated.yaml
"""

import sys
import yaml
from pathlib import Path
from typing import Any

from colors import C, ok, err, warn, info, section, header

SCRIPT_DIR = Path(__file__).parent
OFFSETS_DIR = SCRIPT_DIR / "offsets"
TEMPLATE_PATH = OFFSETS_DIR / "template.yaml"
SENTINEL = 0xDEADBEEF

DEVICE_DB = {
    "iPhone11,2": {"name": "iPhone XS",           "soc": "A12", "board": "d321ap",  "apticket": "t8020"},
    "iPhone11,4": {"name": "iPhone XS Max (CN)",   "soc": "A12", "board": "d331pap", "apticket": "t8020"},
    "iPhone11,6": {"name": "iPhone XS Max",        "soc": "A12", "board": "d331ap",  "apticket": "t8020"},
    "iPhone11,8": {"name": "iPhone XR",            "soc": "A12", "board": "n841ap",  "apticket": "t8020"},
    "iPhone12,1": {"name": "iPhone 11",            "soc": "A13", "board": "n104ap",  "apticket": "t8030"},
    "iPhone12,3": {"name": "iPhone 11 Pro",        "soc": "A13", "board": "d421ap",  "apticket": "t8030"},
    "iPhone12,5": {"name": "iPhone 11 Pro Max",    "soc": "A13", "board": "d431ap",  "apticket": "t8030"},
    "iPhone12,8": {"name": "iPhone SE (2nd gen)",  "soc": "A13", "board": "d79ap",   "apticket": "t8030"},
    "iPad11,1":   {"name": "iPad mini 5 (WiFi)",   "soc": "A12", "board": "j211ap",  "apticket": "t8020"},
    "iPad11,3":   {"name": "iPad Air 3 (WiFi)",    "soc": "A12", "board": "j213ap",  "apticket": "t8020"},
    "iPad11,6":   {"name": "iPad 8 (WiFi)",        "soc": "A12", "board": "j171ap",  "apticket": "t8020"},
    "iPad12,1":   {"name": "iPad 9 (WiFi)",        "soc": "A13", "board": "j181ap",  "apticket": "t8030"},
}


def generate_profile(model: str, ios_version: str, build: str = "unknown") -> dict:
    """Generate a new offset profile from template + device database."""
    dev = DEVICE_DB.get(model)
    if not dev:
        print(warn(f"Device {model} not in database — using defaults"))
        dev = {"name": model, "soc": "A12", "board": "unknown", "apticket": "t8020"}

    with open(TEMPLATE_PATH) as f:
        template = yaml.safe_load(f)

    template["device"] = dev["name"]
    template["model"] = model
    template["ios_version"] = ios_version
    template["build"] = build
    template["soc"] = dev["soc"]
    template["board"] = dev["board"]
    template["apticket"] = dev["apticket"]

    return template


def merge_kernel_offsets(profile: dict, kernel_file: Path) -> dict:
    """Merge kernel offsets from a DarkSword offsets.m style file into a profile."""
    if not kernel_file.exists():
        print(warn(f"Kernel offset file not found: {kernel_file}"))
        return profile

    with open(kernel_file) as f:
        content = f.read()

    patches = profile.get("patches", {}).get("kernel", [])
    merged = 0

    import re
    for pattern_name, regex, fmt in [
        ("usb_restricted", r"off_usb_restricted\s*=\s*(0x[0-9a-fA-F]+)", "value"),
        ("sandbox_mmap",  r"off_sandbox_mmap\s*=\s*(0x[0-9a-fA-F]+)", "value"),
        ("amfi_trust",    r"off_amfi_trust\s*=\s*(0x[0-9a-fA-F]+)", "value"),
    ]:
        m = re.search(regex, content)
        if m:
            for entry in patches:
                if isinstance(entry, dict) and pattern_name in entry.get("name", "").lower():
                    entry["offset"] = int(m.group(1), 16)
                    merged += 1
                    break

    if merged:
        print(ok(f"Merged {merged} kernel offsets from kernel offset file"))
    else:
        print(warn("No kernel offsets could be merged — offsets.m may not contain matching labels"))

    return profile


def diff_profiles(base: Path, updated: Path) -> bool:
    """Show differences between two offset profiles."""
    with open(base) as f:
        data_a = yaml.safe_load(f)
    with open(updated) as f:
        data_b = yaml.safe_load(f)

    print(section("Profile Diff"))
    print(f"  {C.DIM}A: {base.name}  —  B: {updated.name}{C.NC}")
    print()

    changes = 0
    for sec in ["ibss", "ibec", "restoreramdisk", "kernel", "daemons"]:
        patches_a = data_a.get("patches", {}).get(sec, {})
        patches_b = data_b.get("patches", {}).get(sec, {})

        if sec == "kernel":
            offsets_a = {e.get("name", "?"): e.get("offset", 0) for e in patches_a if isinstance(e, dict)}
            offsets_b = {e.get("name", "?"): e.get("offset", 0) for e in patches_b if isinstance(e, dict)}
        elif isinstance(patches_a, dict) and isinstance(patches_b, dict):
            offsets_a = {k: v.get("offset", 0) for k, v in patches_a.items() if isinstance(v, dict)}
            offsets_b = {k: v.get("offset", 0) for k, v in patches_b.items() if isinstance(v, dict)}
        else:
            continue

        all_keys = set(offsets_a) | set(offsets_b)
        for key in sorted(all_keys):
            off_a = offsets_a.get(key, 0)
            off_b = offsets_b.get(key, 0)
            if off_a != off_b:
                diff_val = off_b - off_a
                sign = "+" if diff_val > 0 else ""
                print(f"  {C.EYE}{sec}.{key}{C.NC}")
                print(f"    {C.DIM}{base.name}:{C.NC} 0x{off_a:X}")
                print(f"    {C.DIM}{updated.name}:{C.NC} 0x{off_b:X}  {C.AMB}({sign}{diff_val:+d}){C.NC}")
                changes += 1

    if changes == 0:
        print(ok("No differences found — profiles are identical"))
    else:
        print(f"\n  {C.AMB}{changes} changed offset(s){C.NC}")
    print()
    return changes > 0


def cmd_create(args: list[str]):
    model = args[0] if len(args) > 0 else ""
    ios = args[1] if len(args) > 1 else ""
    build = args[2] if len(args) > 2 else "unknown"
    kernel_file = Path(args[3]) if len(args) > 3 else None

    if not model or not ios:
        print(err("Usage: create <Model> <iOS_version> [build] [kernel_offsets_file]"))
        return

    fname = f"{model}_{ios}.yaml"
    out_path = OFFSETS_DIR / fname

    if out_path.exists():
        overwrite = input(f"  {C.AMB}{fname} already exists. Overwrite? [y/N]:{C.NC} ")
        if overwrite.lower() not in ("y", "yes"):
            print(info("Cancelled"))
            return

    profile = generate_profile(model, ios, build)
    if kernel_file:
        profile = merge_kernel_offsets(profile, kernel_file)

    with open(out_path, "w") as f:
        yaml.dump(profile, f, default_flow_style=False, allow_unicode=True, sort_keys=False)

    print(ok(f"Created: {fname}"))
    print(f"  {C.DIM}Fill in the 0x{SENTINEL:8X} sentinel values with real offsets.{C.NC}")
    print(f"  {C.DIM}Validate with: python3 device_offsets.py validate {fname}{C.NC}")


def cmd_diff(args: list[str]):
    if len(args) < 2:
        print(err("Usage: diff <base.yaml> <updated.yaml>"))
        return
    diff_profiles(Path(args[0]), Path(args[1]))


def cmd_list_templates():
    """List all known device models in the database."""
    print(section("Device Database"))
    print()
    for model, info in sorted(DEVICE_DB.items()):
        has_profile = list(OFFSETS_DIR.glob(f"{model}_*.yaml"))
        status = C.GRN + "✓" if has_profile else C.AMB + "⚠"
        print(f"  {status}{C.NC} {C.EYE}{info['name']:<22}{C.NC} {C.DIM}{model:<12}{C.NC} [{info['soc']}]  {info['board']}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"\n  {C.FROST}usbliter8 profile generator{C.NC}\n")
        print(f"  Commands:")
        print(f"    {C.EYE}create{C.NC} <Model> <iOS> [build] [kernel_file]")
        print(f"    {C.EYE}diff{C.NC}   <base.yaml> <updated.yaml>")
        print(f"    {C.EYE}migrate{C.NC} <base.yaml> <target.yaml|iOS> [--comp-dir DIR] [--auto] [--report FILE]")
        print(f"    {C.EYE}list{C.NC}   Show all known devices")
        print()
        sys.exit(0)

    cmd = sys.argv[1]
    args = sys.argv[2:]

    if cmd == "create":
        cmd_create(args)
    elif cmd == "diff":
        cmd_diff(args)
    elif cmd == "migrate":
        from migrate import cli_main
        cli_main(args)
    elif cmd == "list":
        cmd_list_templates()
    else:
        print(err(f"Unknown command: {cmd}"))
        sys.exit(1)
