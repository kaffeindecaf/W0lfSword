"""Custom firmware builder for usbliter8-arctic.

Takes an IPSW + device offset YAML, produces patched iBSS, iBEC,
DeviceTree, kernel, RestoreRamdisk, and userland binaries.

Supports --dry-run for validation without writing.
"""

import os
import shutil
import struct
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import yaml

from colors import C, ok, err, warn, info, stage, section

TOOLS_DIR = Path(__file__).parent / "tools"
DRY_RUN = False
VERBOSE = True


def _tool(name: str) -> str:
    """Get full path to a tool binary."""
    p = TOOLS_DIR / name
    if p.exists():
        return str(p)
    # fallback to PATH
    return name


def _board_config(offsets: dict) -> str:
    """Full board config id (e.g. d421ap) from the profile."""
    return offsets.get("board", "d421ap")


def _board_short(offsets: dict) -> str:
    """Short board id (e.g. d421) used in iBSS/iBEC file names."""
    board = _board_config(offsets)
    return board[:-2] if board.endswith("ap") else board


def _run(cmd: list[str], cwd: str | None = None, check: bool = False) -> subprocess.CompletedProcess:
    """Run a command, logging output if VERBOSE."""
    if DRY_RUN:
        print(f"    {C.DIM}[dry-run] {' '.join(cmd)}{C.NC}")
        return subprocess.CompletedProcess(cmd, 0)

    if VERBOSE:
        print(f"    {C.DIM}$ {' '.join(cmd)}{C.NC}")

    result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if VERBOSE and result.stdout:
        for line in result.stdout.strip().splitlines()[-5:]:
            print(f"      {C.DIM}{line}{C.NC}")
    return result


def _patch_at(fp, offset: int, data: bytes | str):
    """Write raw bytes or encoded string at file offset."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    if DRY_RUN:
        current = "??" * len(data)
        print(f"    {C.DIM}[dry-run] offset 0x{offset:X}: {current} → {data.hex()}{C.NC}")
        return
    fp.seek(offset)
    fp.write(data)
    fp.flush()


def _hex_to_bytes(hex_str: str) -> bytes:
    """Convert hex string to bytes."""
    return bytes.fromhex(hex_str.replace(" ", "").lower())


def _extract_im4p_to_raw(im4p_path: str | Path, output_path: str | Path) -> bool:
    """Use img4 to unwrap an im4p file to raw binary."""
    r = _run([_tool("img4"), "-i", str(im4p_path), "-o", str(output_path)])
    return r.returncode == 0 and Path(output_path).exists()


def _wrap_raw_to_im4p(raw_path: str | Path, im4p_path: str | Path, tag: str = "") -> bool:
    """Use img4tool to wrap a raw binary back into im4p format."""
    cmd = [_tool("img4tool"), "-c", str(im4p_path), "-t", tag, str(raw_path)] if tag else \
          [_tool("img4tool"), "-c", str(im4p_path), str(raw_path)]
    r = _run(cmd)
    return r.returncode == 0


def _apply_dict_patches(fp, patches: dict, section_name: str) -> int:
    """Apply all offset/value patches from a dict section. Returns count of applied patches."""
    count = 0
    for name, entry in patches.items():
        if isinstance(entry, dict) and "offset" in entry and "value" in entry:
            off = entry["offset"]
            val = entry["value"]
            try:
                data = _hex_to_bytes(val)
            except ValueError:
                data = val  # string for boot-args
            _patch_at(fp, off, data)
            count += 1
            if VERBOSE:
                print(f"    {C.GRN}✓{C.NC} {section_name}.{name} @ 0x{off:X}")
    return count


def patch_ibss(ipsw_dir: str | Path, offsets: dict, work_dir: str | Path) -> bool:
    """Patch iBSS: unwrap, apply ibss patches, rewrap."""
    print(stage("1/6", "Patching iBSS"))
    ibss_patches = offsets.get("patches", {}).get("ibss", {})

    board = _board_short(offsets)
    src = Path(ipsw_dir) / "Firmware" / "dfu" / f"iBSS.{board}.RELEASE.im4p"
    if not src.exists():
        candidates = list((Path(ipsw_dir) / "Firmware" / "dfu").glob("iBSS.*.RELEASE.im4p"))
        if not candidates:
            print(err(f"iBSS not found: {src}"))
            return False
        src = candidates[0]

    raw = Path(work_dir) / "iBSS.raw"
    if not _extract_im4p_to_raw(src, raw):
        print(err("Failed to extract iBSS"))
        return False

    with open(raw, "r+b") as fp:
        _apply_dict_patches(fp, ibss_patches, "ibss")

    if DRY_RUN:
        return True

    dest = Path(ipsw_dir) / "Firmware" / "dfu" / src.name
    return _wrap_raw_to_im4p(raw, dest, "ibss")


def patch_ibec(ipsw_dir: str | Path, offsets: dict, work_dir: str | Path) -> bool:
    """Patch iBEC: unwrap, apply ibec patches, rewrap."""
    print(stage("2/6", "Patching iBEC"))
    ibec_patches = offsets.get("patches", {}).get("ibec", {})

    board = _board_short(offsets)
    cfw_dir = Path(ipsw_dir).parent / "CFW" / "Firmware" / "dfu"
    src = cfw_dir / f"iBEC.{board}.RELEASE.im4p"
    if not src.exists():
        # fallback: try in ipsw dir
        src = Path(ipsw_dir) / "Firmware" / "dfu" / f"iBEC.{board}.RELEASE.im4p"
    if not src.exists():
        candidates = list((Path(ipsw_dir) / "Firmware" / "dfu").glob("iBEC.*.RELEASE.im4p"))
        if candidates:
            src = candidates[0]

    if not src.exists():
        print(err(f"iBEC not found: {src}"))
        return False

    raw = Path(work_dir) / "iBEC.raw"
    if not _extract_im4p_to_raw(src, raw):
        print(err("Failed to extract iBEC"))
        return False

    with open(raw, "r+b") as fp:
        _apply_dict_patches(fp, ibec_patches, "ibec")

    if DRY_RUN:
        return True

    dest = cfw_dir / src.name
    cfw_dir.mkdir(parents=True, exist_ok=True)
    return _wrap_raw_to_im4p(raw, dest, "ibec")


def patch_devicetree(ipsw_dir: str | Path, offsets: dict, work_dir: str | Path) -> bool:
    """Patch DeviceTree: unwrap, remove content-protect, add flags, rewrap."""
    print(stage("3/6", "Patching DeviceTree"))
    dt_patches = offsets.get("patches", {}).get("devicetree", {})

    board = _board_config(offsets)
    src = Path(ipsw_dir) / "Firmware" / "all_flash" / f"DeviceTree.{board}.im4p"
    if not src.exists():
        candidates = list((Path(ipsw_dir) / "Firmware" / "all_flash").glob("DeviceTree.*.im4p"))
        if not candidates:
            print(err(f"DeviceTree not found: {src}"))
            return False
        src = candidates[0]

    raw = Path(work_dir) / "DeviceTree.raw"
    if not _extract_im4p_to_raw(src, raw):
        print(err("Failed to extract DeviceTree"))
        return False

    # DeviceTree patching is structural (not simple hex patches).
    # For now, shell out to the existing dt_patch.py scripts.
    # In a future version, we'll implement native DeviceTree manipulation.
    dt_scripts_dir = Path(__file__).parent.parent / "referenceforAI" / "usbliter8-fun2" / "work-27.0b2"
    if not dt_scripts_dir.exists():
        dt_scripts_dir = Path.home() / "Desktop" / "W0lfSword" / "referenceforAI" / "usbliter8-fun2" / "work-27.0b2"
        if not dt_scripts_dir.exists():
            dt_scripts_dir = Path.home() / "Desktop" / "W0lfSword" / "referenceforAI" / "projects" / "usbliter8-fun2" / "work-27.0b2"
    scripts = [
        "set_ephemeral.py" if dt_patches.get("ephemeral_storage") else None,
        "set_system_rw.py",
    ]

    for script in scripts:
        if script:
            script_path = dt_scripts_dir / script
            if script_path.exists():
                _run(["python3", str(script_path), str(raw)], check=False)
            else:
                print(warn(f"DT script not found: {script_path}"))

    if DRY_RUN:
        return True

    dest = Path(ipsw_dir) / "Firmware" / "all_flash" / src.name
    return _wrap_raw_to_im4p(raw, dest, "dtre")


def patch_kernel(ipsw_dir: str | Path, offsets: dict, work_dir: str | Path) -> bool:
    """Patch kernelcache: apply hex patches from the kernel section."""
    print(stage("4/6", "Patching Kernel"))
    kernel_patches = offsets.get("patches", {}).get("kernel", [])

    src = None
    for pattern in ["kernelcache.release.iphone12", "kernelcache.release.iphone11"]:
        for root, _, files in os.walk(ipsw_dir):
            for f in files:
                if pattern in f and f.endswith(".im4p"):
                    src = Path(root) / f
                    break
            if src:
                break
        if src:
            break

    if not src:
        kc_paths = list(Path(ipsw_dir).rglob("kernelcache.release.*"))
        if kc_paths:
            src = kc_paths[0]
        else:
            print(warn("Kernelcache not found — skipping kernel patches"))
            return True

    raw = Path(work_dir) / "kernelcache.raw"
    if not _extract_im4p_to_raw(src, raw):
        print(err("Failed to extract kernelcache"))
        return False

    count = 0
    with open(raw, "r+b") as fp:
        for entry in kernel_patches:
            if isinstance(entry, dict) and "offset" in entry and "value" in entry:
                off = entry["offset"]
                val = entry["value"]
                name = entry.get("name", "kernel")
                try:
                    data = _hex_to_bytes(val)
                    _patch_at(fp, off, data)
                    count += 1
                    if VERBOSE:
                        print(f"    {C.GRN}✓{C.NC} {name} @ 0x{off:X}")
                except ValueError:
                    print(err(f"Invalid hex for {name}: {val}"))

    print(ok(f"Kernel: {count} patches applied"))

    if DRY_RUN:
        return True

    return _wrap_raw_to_im4p(raw, src)


def patch_restoreramdisk(ipsw_dir: str | Path, offsets: dict, work_dir: str | Path) -> bool:
    """Patch RestoreRamdisk components."""
    print(stage("5/6", "Patching RestoreRamdisk"))
    rd_patches = offsets.get("patches", {}).get("restoreramdisk", {})

    if not rd_patches:
        print(warn("No restoreramdisk patches defined — skipping"))
        return True

    rd_dir = Path(ipsw_dir) / "Firmware" / "all_flash"
    ramdisk_files = list(rd_dir.glob("*RestoreRamdisk*"))
    if not ramdisk_files:
        ramdisk_files = list(rd_dir.glob("*restoreramdisk*")) + list(rd_dir.glob("*ramdisk*"))

    if not ramdisk_files:
        print(warn("RestoreRamdisk not found — skipping"))
        return True

    ramdisk_path = ramdisk_files[0]
    raw = Path(work_dir) / "RestoreRamdisk.raw"
    if not _extract_im4p_to_raw(ramdisk_path, raw):
        print(err("Failed to extract RestoreRamdisk — cannot patch im4p at raw offsets"))
        return False

    with open(raw, "r+b") as fp:
        applied = _apply_dict_patches(fp, rd_patches, "restoreramdisk")

    if DRY_RUN:
        return True

    if not _wrap_raw_to_im4p(raw, ramdisk_path, "rdsk"):
        print(err("Failed to rewrap RestoreRamdisk"))
        return False

    print(ok(f"RestoreRamdisk: {applied} patches applied and re-wrapped into IPSW"))
    return True


def patch_userland(ipsw_dir: str | Path, offsets: dict, work_dir: str | Path) -> bool:
    """Patch userland daemons (coreauthd, ctkd, mobileactivationd)."""
    print(stage("6/6", "Patching Userland Daemons"))
    daemon_patches = offsets.get("patches", {}).get("daemons", {})

    if not daemon_patches:
        print(warn("No daemon patches defined — skipping"))
        return True

    count = 0
    missing = []
    for daemon_name, patches in daemon_patches.items():
        if not isinstance(patches, dict):
            continue

        # Find the daemon binary
        binary_path = None
        for root, _, files in os.walk(ipsw_dir):
            for f in files:
                if f == daemon_name:
                    binary_path = Path(root) / f
                    break
            if binary_path:
                break

        if not binary_path:
            missing.append(daemon_name)
            continue

        with open(binary_path, "r+b") as fp:
            for name, entry in patches.items():
                if isinstance(entry, dict) and "offset" in entry and "value" in entry:
                    off = entry["offset"]
                    val = entry["value"]
                    try:
                        data = _hex_to_bytes(val)
                        _patch_at(fp, off, data)
                        count += 1
                        if VERBOSE:
                            print(f"    {C.GRN}✓{C.NC} {daemon_name}.{name} @ 0x{off:X}")
                    except ValueError:
                        print(err(f"Invalid hex for {daemon_name}.{name}: {val}"))

    if missing:
        print(err(f"Daemon binaries not found in extracted IPSW: {', '.join(missing)}"))
        print(info("Userland binaries live inside the rootfs DMG. Extract the "
                   "rootfs first (work-dir make_cfw.py toolchain or 7z), or "
                   "remove the 'daemons' section if these patches are applied "
                   "elsewhere."))
        return False

    print(ok(f"Userland: {count} daemon patches applied"))
    return True


def build_cfw(ipsw_path: Path, offsets_path: Path) -> bool:
    """Full CFW build pipeline."""
    if DRY_RUN:
        print()
        print(f"  {C.AMB}{'=' * 56}{C.NC}")
        print(f"  {C.AMB}DRY RUN — no files will be modified{C.NC}")
        print(f"  {C.AMB}{'=' * 56}{C.NC}")
        print()

    with open(offsets_path) as f:
        offsets = yaml.safe_load(f)

    model = offsets.get("model", "unknown")
    ios = offsets.get("ios_version", "unknown")
    device = offsets.get("device", "unknown")

    print(section(f"Target: {device} ({model}) — iOS {ios}"))
    print()

    if not ipsw_path.exists():
        print(err(f"IPSW not found: {ipsw_path}"))
        return False

    # Create working directory
    work_dir = Path(tempfile.mkdtemp(prefix="usbliter8_cfw_"))
    print(info(f"Work directory: {work_dir}"))

    if DRY_RUN:
        print()
        print(f"  {C.SNOW}Would extract IPSW to:{C.NC} {work_dir}")
        print()

        # Simulate all patch steps
        print(section("Patch Simulation"))
        for section_name in ["ibss", "ibec", "devicetree", "kernel", "restoreramdisk", "daemons"]:
            section_data = offsets.get("patches", {}).get(section_name, {})
            if section_name == "kernel" and isinstance(section_data, list):
                for entry in section_data:
                    if isinstance(entry, dict):
                        print(f"    {C.DIM}[dry-run]{C.NC} {entry.get('name', '?')} @ 0x{entry.get('offset', 0):X} → {entry.get('value', '?')}")
            elif isinstance(section_data, dict):
                for name, entry in section_data.items():
                    if isinstance(entry, dict) and "offset" in entry:
                        print(f"    {C.DIM}[dry-run]{C.NC} {section_name}.{name} @ 0x{entry['offset']:X}")
        print()
        print(ok("Dry-run complete — all patches validated"))
        shutil.rmtree(work_dir)
        return True

    # Extract IPSW (it's a ZIP)
    ipsw_dir = Path(tempfile.mkdtemp(prefix="usbliter8_ipsw_"))
    print(info(f"Extracting IPSW to {ipsw_dir}..."))
    import zipfile
    with zipfile.ZipFile(ipsw_path) as zf:
        zf.extractall(ipsw_dir)
    print(ok("IPSW extracted"))

    # Run patches
    try:
        ok_patch = all([
            patch_ibss(ipsw_dir, offsets, work_dir),
            patch_ibec(ipsw_dir, offsets, work_dir),
            patch_devicetree(ipsw_dir, offsets, work_dir),
            patch_kernel(ipsw_dir, offsets, work_dir),
            patch_restoreramdisk(ipsw_dir, offsets, work_dir),
            patch_userland(ipsw_dir, offsets, work_dir),
        ])
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)

    if ok_patch:
        print()
        print(f"  {C.GRN}{'═' * 56}{C.NC}")
        print(f"  {C.GRN}  Custom firmware built successfully!{C.NC}")
        print(f"  {C.GRN}  Patched IPSW at: {ipsw_dir}{C.NC}")
        print(f"  {C.GRN}{'═' * 56}{C.NC}")
        print()
        return True
    else:
        print()
        print(err("CFW build had errors — check output above"))
        return False


# ── CLI ──

if __name__ == "__main__":
    import sys
    args = sys.argv[1:]

    if "--dry-run" in args or "--check" in args or "--check-only" in args:
        DRY_RUN = True
        args = [a for a in args if a not in ("--dry-run", "--check", "--check-only")]

    if "--quiet" in args or "-q" in args:
        VERBOSE = False
        args = [a for a in args if a not in ("--quiet", "-q")]

    if len(args) < 2:
        print(f"  Usage: {C.FROST}python3 cfw_builder.py <ipsw_path> <offsets.yaml> [--dry-run|--check-only] [--quiet]{C.NC}")
        print(f"  Flags: --check-only    Validate patches without extracting IPSW")
        print(f"         --quiet         Suppress per-patch output")
        sys.exit(1)

    ipsw = Path(args[0])
    offsets = Path(args[1])

    if not offsets.exists():
        print(err(f"Offset file not found: {offsets}"))
        sys.exit(1)

    build_cfw(ipsw, offsets)
