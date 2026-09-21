"""Custom firmware builder for usbliter8-arctic.

Takes an IPSW + device offset YAML, produces patched iBSS, iBEC,
DeviceTree, kernel, RestoreRamdisk, and userland binaries.

Supports --dry-run for validation without writing.
"""

from __future__ import annotations

import os
import shutil
import struct
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import yaml

import components
import dt_patch
from colors import C, ok, err, warn, info, stage, section

TOOLS_DIR = Path(__file__).parent / "tools"
DRY_RUN = False
VERBOSE = True
FORCE = False          # --force: build despite failed preflight / pending entries
FORCE_COMPONENT = False  # --force-component: take the first component when several match
# per-section outcome of this build, printed at the end so a user can see what
# was actually patched and what was skipped (and why)
MANIFEST: list[tuple[str, str, str]] = []


def _note(section: str, status: str, detail: str = "") -> None:
    MANIFEST.append((section, status, detail))


def blocked_sections(offsets: dict) -> list[dict]:
    """Sections this profile declares as blocked (see device_offsets.blocked_sections)."""
    from device_offsets import blocked_sections as _blocked
    blockers = offsets.get("blockers")
    if isinstance(blockers, dict):
        out = []
        for name, body in blockers.items():
            out.append({"section": name, **(body if isinstance(body, dict) else {"reason": body})})
        return out
    return [b for b in blockers or [] if isinstance(b, dict)]


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


MACHO_MAGICS = (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe")


def _is_macho(path: Path) -> bool:
    try:
        with open(path, "rb") as fh:
            return fh.read(4) in MACHO_MAGICS
    except OSError:
        return False


def _tool_available(name: str) -> bool:
    """True when a tool can actually run here.

    tools/ holds macOS Mach-O binaries, so on Linux/Windows they exist but are
    unusable; those users get the built-in Python codec instead of a crash.
    """
    import shutil
    import sys

    if shutil.which(name):
        return True
    bundled = TOOLS_DIR / name
    if not bundled.is_file():
        return False
    if sys.platform == "darwin":
        return True
    return not _is_macho(bundled)


def _extract_im4p_to_raw(im4p_path: str | Path, output_path: str | Path) -> bool:
    """Unwrap an im4p container to its raw payload.

    tools/img4 first (the long-standing macOS path), then the in-tree pure-Python
    decoder: the bundled binaries are Mach-O, so a Windows or Linux user has no
    way to extract a component otherwise (issue #4).
    """
    if _tool_available("img4"):
        r = _run([_tool("img4"), "-i", str(im4p_path), "-o", str(output_path)])
        if r.returncode == 0 and Path(output_path).exists():
            return True
        if VERBOSE:
            print(warn(f"img4 could not unwrap {Path(im4p_path).name}, trying the "
                       f"built-in decoder"))

    try:
        import img4wrap
        payload = img4wrap.payload_of(im4p_path)
    except Exception as exc:                                  # noqa: BLE001
        print(err(f"cannot unwrap {Path(im4p_path).name}: {exc}"))
        return False
    Path(output_path).write_bytes(payload)
    if VERBOSE:
        print(f"    {C.DIM}{Path(im4p_path).name} -> {len(payload):,} B payload{C.NC}")
    return True


def _wrap_raw_to_im4p(raw_path: str | Path, im4p_path: str | Path, tag: str = "") -> bool:
    """Wrap a raw binary back into an im4p container.

    img4tool first, then the built-in writer. The container carries no signature
    either way: the device is pwned, which is the whole point of the chain.
    """
    if _tool_available("img4tool"):
        cmd = [_tool("img4tool"), "-c", str(im4p_path), "-t", tag, str(raw_path)] if tag else \
              [_tool("img4tool"), "-c", str(im4p_path), str(raw_path)]
        if _run(cmd).returncode == 0:
            return True
        if VERBOSE:
            print(warn(f"img4tool failed for {Path(im4p_path).name}, using the "
                       f"built-in writer"))

    try:
        import img4wrap
        description = ""
        destination = Path(im4p_path)
        if destination.exists():                 # keep Apple's metadata on rewrap
            try:
                description = img4wrap.unwrap_file(destination).description
            except Exception:                                 # noqa: BLE001
                description = ""
        container = img4wrap.wrap(Path(raw_path).read_bytes(), tag or "IM4P", description)
    except Exception as exc:                                  # noqa: BLE001
        print(err(f"cannot wrap {Path(im4p_path).name}: {exc}"))
        return False
    Path(im4p_path).write_bytes(container)
    return True


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
    """Patch iBSS: resolve the device's iBSS, apply the ibss patches, rewrap."""
    print(stage("1/6", "Patching iBSS"))
    ibss_patches = offsets.get("patches", {}).get("ibss", {})

    src, candidates, reason = components.find_component(ipsw_dir, "ibss", offsets,
                                                       force=FORCE_COMPONENT)
    if src is None:
        print(err(f"iBSS not found for {offsets.get('model', '?')}: {reason}"))
        _note("ibss", "failed", reason)
        return False
    if reason == "forced":
        print(warn(f"iBSS: several candidates, using {src.name}"))
    print(f"    {C.DIM}component: {src.name} ({components.component_stem(offsets, 'ibss')}){C.NC}")

    raw = Path(work_dir) / "iBSS.raw"
    if not _extract_im4p_to_raw(src, raw):
        print(err("Failed to extract iBSS"))
        _note("ibss", "failed", "extract")
        return False

    with open(raw, "r+b") as fp:
        count = _apply_dict_patches(fp, ibss_patches, "ibss")
    _note("ibss", "patched", f"{count} entries → {src.name}")

    if DRY_RUN:
        return True

    dest = Path(ipsw_dir) / "Firmware" / "dfu" / src.name
    return _wrap_raw_to_im4p(raw, dest, "ibss")


def patch_ibec(ipsw_dir: str | Path, offsets: dict, work_dir: str | Path) -> bool:
    """Patch iBEC: resolve the device's iBEC, apply the ibec patches, rewrap."""
    print(stage("2/6", "Patching iBEC"))
    ibec_patches = offsets.get("patches", {}).get("ibec", {})

    cfw_dir = Path(ipsw_dir).parent / "CFW" / "Firmware" / "dfu"
    search_roots = [Path(ipsw_dir)] + ([Path(ipsw_dir).parent / "CFW"] if cfw_dir.exists() else [])
    src = None
    reason = "no iBEC component found"
    for root in search_roots:
        src, _candidates, reason = components.find_component(root, "ibec", offsets,
                                                            force=FORCE_COMPONENT)
        if src is not None:
            break
    if src is None:
        print(err(f"iBEC not found for {offsets.get('model', '?')}: {reason}"))
        _note("ibec", "failed", reason)
        return False

    raw = Path(work_dir) / "iBEC.raw"
    if not _extract_im4p_to_raw(src, raw):
        print(err("Failed to extract iBEC"))
        _note("ibec", "failed", "extract")
        return False

    with open(raw, "r+b") as fp:
        count = _apply_dict_patches(fp, ibec_patches, "ibec")
    _note("ibec", "patched", f"{count} entries → {src.name}")

    if DRY_RUN:
        return True

    dest = cfw_dir / src.name
    cfw_dir.mkdir(parents=True, exist_ok=True)
    return _wrap_raw_to_im4p(raw, dest, "ibec")


def patch_devicetree(ipsw_dir: str | Path, offsets: dict, work_dir: str | Path) -> bool:
    """Patch DeviceTree with the native FDT patcher (dt_patch.py)."""
    print(stage("3/6", "Patching DeviceTree"))
    dt_flags = offsets.get("patches", {}).get("devicetree", {}) or {}

    src, _candidates, reason = components.find_component(ipsw_dir, "devicetree", offsets,
                                                        force=FORCE_COMPONENT)
    if src is None:
        print(err(f"DeviceTree not found for {offsets.get('model', '?')}: {reason}"))
        _note("devicetree", "failed", reason)
        return False

    raw = Path(work_dir) / "DeviceTree.raw"
    if not _extract_im4p_to_raw(src, raw):
        print(err("Failed to extract DeviceTree"))
        _note("devicetree", "failed", "extract")
        return False

    data = Path(raw).read_bytes()
    patched, report = dt_patch.apply_profile_flags(data, dt_flags)
    for op, status in report:
        color = C.GRN if status in ("removed", "updated", "added", "unchanged") else C.AMB
        print(f"    {color}{status:<10}{C.NC} {op}")
    Path(raw).write_bytes(patched)
    failed = [f"{op}={status}" for op, status in report
              if status.startswith("node-not-found")]
    _note("devicetree", "patched" if not failed else "partial",
          ", ".join(f"{op}: {status}" for op, status in report) or "no flags set")
    if failed:
        print(warn(f"DeviceTree: {', '.join(failed)}"))

    if DRY_RUN:
        return True

    dest = Path(ipsw_dir) / "Firmware" / "all_flash" / src.name
    return _wrap_raw_to_im4p(raw, dest, "dtre")


def appliable_kernel_entries(kernel_patches: list) -> tuple[list, list]:
    """Split kernel entries into (appliable, refused).

    Entries marked `invalid_component` were derived from another device's
    kernelcache (e.g. iPhone offsets in an iPad profile); applying them would
    patch unrelated code, so they are refused even with --force.
    """
    ok, invalid = [], []
    for entry in kernel_patches or []:
        if not isinstance(entry, dict):
            continue
        if entry.get("invalid_component"):
            invalid.append(entry)
        elif "offset" in entry and "value" in entry:
            ok.append(entry)
        # entries without offset/value cannot be applied; validate_offsets reports them
    return ok, invalid


def patch_kernel(ipsw_dir: str | Path, offsets: dict, work_dir: str | Path) -> bool:
    """Patch kernelcache: resolve the device's own kernelcache, apply patches."""
    print(stage("4/6", "Patching Kernel"))
    kernel_patches = offsets.get("patches", {}).get("kernel", [])

    src, candidates, reason = components.find_component(ipsw_dir, "kernelcache", offsets,
                                                       force=FORCE_COMPONENT)
    if src is None:
        print(warn(f"Kernelcache not found for {offsets.get('model', '?')}: {reason}"))
        _note("kernel", "skipped", reason)
        return True
    expected = components.component_stem(offsets, "kernelcache")
    if reason == "forced" and expected:
        print(warn(f"kernelcache: using {src.name}, profile expects {expected}"))
    if expected and expected not in src.name:
        print(warn(f"kernelcache {src.name} does not match this device's component "
                   f"({expected}) — kernel offsets are per component"))
        _note("kernel", "mismatch", f"{src.name} != {expected}")
    print(f"    {C.DIM}component: {src.name}{C.NC}")

    raw = Path(work_dir) / "kernelcache.raw"
    if not _extract_im4p_to_raw(src, raw):
        print(err("Failed to extract kernelcache (decryption needs the wiki IV+key)"))
        _note("kernel", "failed", "extract")
        return False

    blocked = blocked_sections(offsets)
    if blocked:
        print(err(f"kernel section is BLOCKED for {offsets.get('model', '?')} — refusing to patch"))
        for entry in blocked:
            print(f"    {C.DIM}{entry.get('reason', '').strip()}{C.NC}")
        _note("kernel", "skipped", f"blocked: {blocked[0].get('reason', '').strip()[:120]}")
        return True

    count = 0
    _appliable, invalid = appliable_kernel_entries(kernel_patches)
    if invalid:
        print(err(f"kernel: {len(invalid)} entry/entries belong to a different "
                  f"kernelcache component — refusing to apply them"))
        print(f"    {C.DIM}{invalid[0].get('reason', '')}{C.NC}")
        _note("kernel", "skipped",
              f"{len(invalid)} invalid-component entries (not applied)")
    with open(raw, "r+b") as fp:
        for entry in kernel_patches:
            if isinstance(entry, dict) and entry.get("invalid_component"):
                continue
            if isinstance(entry, dict) and "offset" in entry and "value" in entry:
                off = entry["offset"]
                val = entry["value"]
                name = entry.get("name", "kernel")
                try:
                    try:
                        data = _hex_to_bytes(val)
                    except ValueError:
                        # ASCII payloads (e.g. the kernel identity string
                        # "/PATCHED_ARM64_T8030") are written verbatim
                        data = val.encode() if isinstance(val, str) else bytes(val)
                    _patch_at(fp, off, data)
                    count += 1
                    if VERBOSE:
                        print(f"    {C.GRN}✓{C.NC} {name} @ 0x{off:X}")
                except ValueError:
                    print(err(f"Invalid hex for {name}: {val}"))

    print(ok(f"Kernel: {count} patches applied"))
    _note("kernel", "patched", f"{count} entries → {src.name}")

    if DRY_RUN:
        return True

    return _wrap_raw_to_im4p(raw, src)


def patch_restoreramdisk(ipsw_dir: str | Path, offsets: dict, work_dir: str | Path) -> bool:
    """Patch RestoreRamdisk components.

    On iOS 26/27 IPSWs the restore ramdisk is a plain root-level `<build>.dmg`
    and the offsets in a profile target `restored_external` and `asr` *inside*
    the mounted image. That needs mounting + re-signing (hdiutil/ldid), which
    this pure-Python path does not do, so the section is reported as skipped
    instead of silently "succeeding".
    """
    print(stage("5/6", "Patching RestoreRamdisk"))
    rd_patches = offsets.get("patches", {}).get("restoreramdisk", {})

    if not rd_patches:
        print(warn("No restoreramdisk patches defined — skipping"))
        _note("restoreramdisk", "skipped", "no patches in profile")
        return True

    src, candidates, reason = components.find_component(ipsw_dir, "restoreramdisk", offsets)
    if src is None:
        print(warn(f"RestoreRamdisk not found ({reason}) — skipping"))
        _note("restoreramdisk", "skipped", reason)
        return True

    if reason == "modern-dmg-layout":
        print(warn(f"RestoreRamdisk is {src.name} (a plain dmg, not an im4p)"))
        print(f"    {C.DIM}the profile targets restored_external/asr inside the mounted image;"
              f" this build path cannot mount + re-sign it{C.NC}")
        print(f"    {C.DIM}the CFW will be built WITHOUT {len(rd_patches)} ramdisk patch(es) —"
              f" expect asr/FDR checks to fail on restore{C.NC}")
        _note("restoreramdisk", "skipped",
              f"{src.name}: needs mount+resign ({len(rd_patches)} patches not applied)")
        return True

    raw = Path(work_dir) / "RestoreRamdisk.raw"
    if not _extract_im4p_to_raw(src, raw):
        print(err("Failed to extract RestoreRamdisk — cannot patch im4p at raw offsets"))
        _note("restoreramdisk", "failed", "extract")
        return False

    with open(raw, "r+b") as fp:
        applied = _apply_dict_patches(fp, rd_patches, "restoreramdisk")

    if DRY_RUN:
        _note("restoreramdisk", "patched", f"{applied} entries → {src.name}")
        return True

    if not _wrap_raw_to_im4p(raw, src, "rdsk"):
        print(err("Failed to rewrap RestoreRamdisk"))
        _note("restoreramdisk", "failed", "rewrap")
        return False

    print(ok(f"RestoreRamdisk: {applied} patches applied and re-wrapped into IPSW"))
    _note("restoreramdisk", "patched", f"{applied} entries → {src.name}")
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


def _profile_gate(offsets_path: Path, source: Path | None = None) -> bool:
    """Refuse to patch with an invalid, pending or unverified profile.

    This is the C1.3 gate: the patch manifest is compared against the profile
    and, when components are available, every site is byte-checked first
    (preflight.py). Skipped only with --force.
    """
    from device_offsets import pending_entries, validate_offsets

    passed, failed, errors = validate_offsets(offsets_path)
    profile_data = yaml.safe_load(offsets_path.read_text()) or {}
    blocked_list = blocked_sections(profile_data)
    pend = pending_entries(offsets_path) + sum(int(b.get("entries", 0) or 0) for b in blocked_list)

    blocked = False
    if failed:
        print(err(f"profile has {failed} invalid entry/entries — refusing to patch"))
        for e in errors[:8]:
            print(f"    {C.RED}{e}{C.NC}")
        blocked = True
    if pend:
        print(warn(f"profile has {pend} unresolved entry/entries (pending sentinels or "
                   f"blocked sections) — not flashable"))
        blocked = True
    for blocker in blocked_list:
        print(warn(f"{blocker.get('section', '?')} section blocked: "
                   f"{str(blocker.get('reason', '')).strip()[:160]}"))

    try:
        import preflight
        # verify against the exact bytes being built from, when we have them
        src = Path(source) if source else None
        report = preflight.run_preflight(
            offsets_path,
            ipsw=src if src and src.is_file() else None,
            components=src if src and src.is_dir() else None)
    except Exception as exc:                                  # noqa: BLE001
        print(info(f"preflight unavailable ({exc}) — offsets not verified"))
        return not blocked or FORCE

    if report.verdict == "blocked":
        print(err("preflight blocked this build: the profile does not match the component"))
        for site in report.sites:
            if site.severity == "fail":
                print(f"    {C.RED}{site.section}.{site.entry}: {site.detail}{C.NC}")
        blocked = True
    elif report.components:
        print(ok(f"preflight: {report.count('match', 'plausible')} site(s) checked against "
                 f"{len(report.components)} component(s), "
                 f"{report.count('match')} matched recorded evidence"))
    else:
        print(warn("preflight: no components found — pass --components/--fetch to verify "
                   "offsets before flashing"))

    if blocked and not FORCE:
        print(info("fix the profile or re-run with --force to build anyway"))
        return False
    return True


def _print_manifest() -> None:
    """Per-section patch manifest: what this build actually wrote."""
    if not MANIFEST:
        return
    try:
        import log_utils
        for sec, status, detail in MANIFEST:
            log_utils.log("WARN" if status in ("skipped", "mismatch", "failed", "partial")
                          else "INFO", f"manifest {sec}: {status} {detail}".strip(),
                          module="cfw_builder")
    except Exception:                                        # noqa: BLE001
        pass
    print()
    print(section("Patch manifest"))
    for section, status, detail in MANIFEST:
        color = {"patched": C.GRN, "skipped": C.AMB, "mismatch": C.RED,
                 "failed": C.RED, "partial": C.AMB}.get(status, C.DIM)
        print(f"  {color}{status:<9}{C.NC} {section:<15} {C.DIM}{detail}{C.NC}")
    print()


def build_cfw(ipsw_path: Path, offsets_path: Path) -> bool:
    """Full CFW build pipeline."""
    if DRY_RUN:
        print()
        print(f"  {C.AMB}{'=' * 56}{C.NC}")
        print(f"  {C.AMB}DRY RUN — no files will be modified{C.NC}")
        print(f"  {C.AMB}{'=' * 56}{C.NC}")
        print()

    MANIFEST.clear()
    with open(offsets_path) as f:
        offsets = yaml.safe_load(f)

    model = offsets.get("model", "unknown")
    try:
        import log_utils
        log_utils.install()
        log_utils.log_info(f"build start: {model} iOS {offsets.get('ios_version', '?')} "
                           f"({offsets.get('build', '?')}) ipsw={ipsw_path} dry_run={DRY_RUN}",
                           module="cfw_builder")
    except Exception:                                        # noqa: BLE001
        pass
    ios = offsets.get("ios_version", "unknown")
    device = offsets.get("device", "unknown")

    print(section(f"Target: {device} ({model}) — iOS {ios}"))
    print()

    if not _profile_gate(offsets_path, ipsw_path):
        return False

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
        if ipsw_path.is_dir():
            for kind in ("ibss", "ibec", "devicetree", "kernelcache", "restoreramdisk"):
                path, _cands, _reason = components.find_component(ipsw_path, kind, offsets)
                stem = components.component_stem(offsets, kind)
                label = f"{C.DIM}{kind}{C.NC}"
                if path is not None:
                    print(f"    {C.GRN}✓{C.NC} {label}: {path.name}")
                elif stem:
                    print(f"    {C.AMB}—{C.NC} {label}: not found (expected {stem})")
        rd_reason = ""
        if ipsw_path.is_dir():
            _rd, _cands, rd_reason = components.find_component(ipsw_path, "restoreramdisk",
                                                            offsets)
        blocked_names = {b.get("section") for b in blocked_sections(offsets)}
        skipped = 0
        for section_name in ["ibss", "ibec", "devicetree", "kernel", "restoreramdisk", "daemons"]:
            section_data = offsets.get("patches", {}).get(section_name, {})
            if section_name == "kernel" and isinstance(section_data, list):
                for entry in section_data:
                    if not isinstance(entry, dict):
                        continue
                    if entry.get("invalid_component") or section_name in blocked_names:
                        skipped += 1
                        continue
                    print(f"    {C.DIM}[dry-run]{C.NC} {entry.get('name', '?')} @ 0x{entry.get('offset', 0):X} → {entry.get('value', '?')}")
            elif isinstance(section_data, dict):
                for name, entry in section_data.items():
                    if isinstance(entry, dict) and "offset" in entry:
                        if entry.get("pending"):
                            skipped += 1
                            continue
                        if section_name == "restoreramdisk" and rd_reason == "modern-dmg-layout":
                            skipped += 1
                            continue
                        print(f"    {C.DIM}[dry-run]{C.NC} {section_name}.{name} @ 0x{entry['offset']:X}")
        print()
        if skipped:
            print(warn(f"{skipped} entry/entries would be SKIPPED (pending, invalid for "
                       f"this device's component, or not appliable by this build path)"))
        if blocked_names:
            print(warn(f"blocked section(s): {', '.join(sorted(n for n in blocked_names if n))} "
                       f"(see the profile's blockers:)"))
        if rd_reason == "modern-dmg-layout":
            print(warn("restore ramdisk is a bare .dmg: those offsets target "
                       "restored_external/asr inside the mounted image"))
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

    _print_manifest()

    try:
        import log_utils
        log_utils.log("INFO" if ok_patch else "ERROR",
                      f"build {'finished' if ok_patch else 'FAILED'}: {model} -> {ipsw_dir}",
                      module="cfw_builder")
    except Exception:                                        # noqa: BLE001
        pass

    if ok_patch:
        blocked = [m for m in MANIFEST if m[1] in ("skipped", "mismatch", "failed")]
        print()
        print(f"  {C.GRN}{'═' * 56}{C.NC}")
        if blocked:
            print(f"  {C.AMB}  Custom firmware built, {len(blocked)} section(s) NOT fully applied{C.NC}")
        else:
            print(f"  {C.GRN}  Custom firmware built successfully!{C.NC}")
        print(f"  {C.GRN}  Patched IPSW at: {ipsw_dir}{C.NC}")
        print(f"  {C.GRN}{'═' * 56}{C.NC}")
        if blocked:
            print()
            print(warn("Do not restore this build blindly: the sections above were skipped "
                       "or mismatched."))
        print()
        return True
    else:
        print()
        print(err("CFW build had errors — check output above"))
        return False


# ── CLI ──

if __name__ == "__main__":
    import log_utils
    log_utils.install()          # usbliter8.log + unhandled-exception logging
    import sys
    args = sys.argv[1:]

    if "--force" in args:
        FORCE = True
        args = [a for a in args if a != "--force"]

    if "--force-component" in args:
        FORCE_COMPONENT = True
        args = [a for a in args if a != "--force-component"]

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
        print(f"         --force         Build even when preflight fails (NOT recommended)")
        print(f"         --force-component  Use the first component when several match")
        sys.exit(1)

    ipsw = Path(args[0])
    offsets = Path(args[1])

    if not offsets.exists():
        print(err(f"Offset file not found: {offsets}"))
        sys.exit(1)

    build_cfw(ipsw, offsets)
