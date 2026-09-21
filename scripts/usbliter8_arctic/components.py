#!/usr/bin/env python3
"""IPSW component resolution.

Firmware component file names are NOT derivable from the board id:

    iPhone12,3 (d421ap)  -> Firmware/dfu/iBSS.d421.RELEASE.im4p
    iPad12,1   (j181ap)  -> Firmware/dfu/iBSS.ipad12p.RELEASE.im4p   <- family name
    iPad11,6   (j171ap)  -> Firmware/dfu/iBSS.ipad11b.RELEASE.im4p
    iPad11,1   (j211ap)  -> Firmware/dfu/iBSS.j210.RELEASE.im4p      <- not even the board
    iPhone11,2 (d321ap)  -> Firmware/dfu/iBSS.d321.RELEASE.im4p, plus d331 + d331p
                            (the XS/XS Max IPSWs carry every sibling image)

So: look the name up per device (`DEVICE_DB[...]["ibss_component"]`, verified
from shipped IPSWs), fall back to the board id only as a hint, and when a glob
is the only way to find a file, refuse to guess between candidates. Research
images (`*RESEARCH_RELEASE*`) and `.plist`/`.aea` sidecars are never the file a
CFW build should patch.
"""

from __future__ import annotations

from pathlib import Path

from profile_gen import DEVICE_DB

# kind -> human label, expected subdirectory ("" = anywhere/root), globs
SPEC = {
    "ibss":          ("iBSS",          "Firmware/dfu",       ("iBSS.*.im4p",)),
    "ibec":          ("iBEC",          "Firmware/dfu",       ("iBEC.*.im4p",)),
    "devicetree":    ("DeviceTree",    "Firmware/all_flash", ("DeviceTree.*.im4p",)),
    "txm":           ("txm",           "Firmware",           ("txm*.im4p", "TXM*.im4p")),
    "kernelcache":   ("kernelcache",   "",                   ("kernelcache.release.*",)),
    # classic layouts wrap the dmg in an im4p (094-13753-150.dmg.im4p); iOS 26/27
    # ship the dmg bare at the archive root
    "restoreramdisk": ("RestoreRamdisk", "", ("*.dmg", "*.dmg.im4p", "*RestoreRamdisk*.im4p")),
}

# never patch these: the research images are unused by a tethered restore and
# sidecars are metadata, not payloads
EXCLUDE_TOKENS = ("RESEARCH", ".plist", ".aea", ".root_hash", ".trustcache")


def board_short(offsets: dict) -> str:
    board = str(offsets.get("board", ""))
    return board[:-2] if board.endswith("ap") else board


def component_stem(offsets: dict, kind: str) -> str:
    """Component name Apple uses for this device (iBSS/iBEC stem)."""
    info = DEVICE_DB.get(str(offsets.get("model", "")), {})
    if kind in ("ibss", "ibec"):
        return str(info.get("ibss_component") or board_short(offsets))
    if kind == "devicetree":
        return str(offsets.get("board", ""))
    if kind == "kernelcache":
        return str(info.get("kernel_component", ""))
    return ""


def exact_names(offsets: dict, kind: str) -> list[str]:
    """Exact file names for this device, most specific first."""
    stem = component_stem(offsets, kind)
    if kind == "ibss":
        return [f"iBSS.{stem}.RELEASE.im4p"] if stem else []
    if kind == "ibec":
        return [f"iBEC.{stem}.RELEASE.im4p"] if stem else []
    if kind == "devicetree":
        return [f"DeviceTree.{stem}.im4p"] if stem else []
    if kind == "kernelcache":
        return [stem] if stem else []
    return []


def entry_patterns(offsets: dict, kind: str) -> list:
    """Patterns for matching component *zip entries* (kczip.match_entries).

    Same names as the filesystem resolver, so a ranged fetch and a local IPSW
    agree on which image belongs to which device.
    """
    names = exact_names(offsets, kind)
    if names:
        return [(name,) for name in names]
    # fall back to the family patterns when the device table has no entry
    if kind == "txm":
        return [("Firmware/txm", ".im4p"), ("TXM.", ".im4p")]
    if kind == "restoreramdisk":
        return [(".dmg",)]
    label = SPEC[kind][0]
    return [(f"{label}.", ".im4p")]


def raw_path_for(root: Path | str, kind: str) -> Path | None:
    """Already-extracted payload (`<kind>.raw`) next to the components."""
    candidate = Path(root) / f"{kind}.raw"
    return candidate if candidate.is_file() else None


def _is_payload(path: Path) -> bool:
    return not any(tok in path.name for tok in EXCLUDE_TOKENS)


def _glob(root: Path, kind: str) -> list[Path]:
    """Candidate component files, excluding research images and sidecars."""
    _label, subdir, patterns = SPEC[kind]
    bases = [root / subdir] if subdir else [root]
    candidates: list[Path] = []
    for base in bases:
        if not base.is_dir():
            continue
        for pattern in patterns:
            candidates += [p for p in base.glob(pattern) if p.is_file() and _is_payload(p)]
    if not candidates:
        for pattern in patterns:
            candidates += [p for p in root.rglob(pattern) if p.is_file() and _is_payload(p)]
    return sorted(set(candidates))


def _exact_paths(root: Path, kind: str, offsets: dict) -> list[Path]:
    _label, subdir, _patterns = SPEC[kind]
    out: list[Path] = []
    for name in exact_names(offsets, kind):
        out.append((root / subdir / name) if subdir else (root / name))
    return out


def find_component(root: Path | str, kind: str, offsets: dict,
                   force: bool = False) -> tuple[Path | None, list[Path], str]:
    """Resolve one component file.

    Returns (path or None, candidates, reason). `reason` explains a refusal so
    the caller prints something actionable instead of silently patching the
    wrong image or skipping a patch the device needs. `force` accepts the first
    candidate when several match (and no exact name exists for this device).
    """
    if kind not in SPEC:
        raise ValueError(f"unknown component kind: {kind}")
    root = Path(root)
    label = SPEC[kind][0]

    # an already-extracted payload wins: those are the bytes the profiles'
    # offsets were derived from (fetch_components writes <kind>.raw)
    raw = raw_path_for(root, kind)
    if raw is not None:
        return raw, [raw], ""

    for hit in _exact_paths(root, kind, offsets):
        if hit.is_file():
            return hit, [hit], ""

    candidates = _glob(root, kind)
    if not candidates:
        return None, [], f"no {label} component found under {root}"

    if kind == "restoreramdisk":
        # an im4p is patchable in place; a bare .dmg is not (the offsets target
        # restored_external/asr inside the mounted image)
        im4p = [p for p in candidates if p.suffix == ".im4p" or p.name.endswith(".dmg.im4p")]
        if im4p:
            return im4p[0], candidates, ""
        return candidates[0], candidates, "modern-dmg-layout"

    if len(candidates) == 1:
        return candidates[0], candidates, ""

    if force:
        return candidates[0], candidates, "forced"

    names = ", ".join(p.name for p in candidates[:4])
    return None, candidates, (
        f"{len(candidates)} {label} candidates and no exact match for this "
        f"device ({names}) — pass --force-component to take the first one")
