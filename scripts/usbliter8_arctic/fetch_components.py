#!/usr/bin/env python3
"""Ranged IPSW component fetcher for usbliter8-arctic.

Pulls just the components an offset profile needs (iBSS, iBEC, TXM,
DeviceTree, kernelcache, RestoreRamdisk) out of a multi-GB IPSW on Apple's
CDN using HTTP Range requests — no full download. Ported from W0lfSword's
`scripts/fetch_kernelcache.py` + `scripts/kczip.py` (kcwatch method), which
proved the method on >4GB zip64 IPSWs.

The raw components this writes are exactly what `profile_gen.py migrate`
and `profile_gen.py propagate --comp-dir` consume, so a new build can be
offset-discovered without ever storing an IPSW.

Usage:
  python3 fetch_components.py --url <ipsw-url> --device iPhone12,3 --ios 27.0 --build 24A437
  python3 fetch_components.py --url <ipsw-url> --device iPhone12,1 --list
  python3 fetch_components.py --url <ipsw-url> --device iPhone12,1 --entries ibss,ibec,txm --out DIR

Notes:
  - iBSS/iBEC/TXM/DeviceTree are NOT encrypted: fetching them is all that is
    needed for device-specific offset discovery.
  - kernelcache and the RestoreRamdisk are encrypted (IMG4/APFS): the fetched
    .im4p is kept, payload extraction needs IV+key from The iPhone Wiki
    (see research/README.md).
  - --extract-payload shells out to pyimg4 when it is installed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

import components
import kczip
from colors import C, err, info, ok, section, warn
from profile_gen import DEVICE_DB

ROOT = Path(__file__).parent
DEFAULT_OUT_ROOT = ROOT / "research" / "extracted"

# component -> (filename in the extracted dir, entry-name patterns)
# A pattern is a tuple of literals that must all appear in the zip entry name.
COMPONENT_PATTERNS = {
    "ibss": "ibss.raw",
    "ibec": "ibec.raw",
    "txm": "txm.raw",
    "devicetree": "devicetree.raw",
    "kernelcache": "kernelcache.im4p",
    "restoreramdisk": "restoreramdisk.dmg",
}
ALL_COMPONENTS = tuple(COMPONENT_PATTERNS)
DEFAULT_COMPONENTS = ("ibss", "ibec", "txm")


IPSW_ME_API = "https://api.ipsw.me/v4/device/%s?type=ipsw"
IPSW_DEV_PAGE = "https://ipsw.dev/download/%s/%s"
URL_CACHE = ROOT / "research" / "ipsw_urls.json"
_CDN_RE = re.compile(r"https://updates\.cdn-apple\.com[^\"'<> ]*?\.ipsw")


def _url_cache() -> dict:
    try:
        return json.loads(URL_CACHE.read_text())
    except (OSError, json.JSONDecodeError):
        return {}


def _cache_url(device: str, build: str, url: str, version: str) -> None:
    cache = _url_cache()
    cache[f"{device}/{build}"] = {"url": url, "version": version}
    try:
        URL_CACHE.parent.mkdir(parents=True, exist_ok=True)
        URL_CACHE.write_text(json.dumps(cache, indent=2, sort_keys=True) + "\n")
    except OSError:
        pass


def resolve_ipsw_url(device: str, build: str, use_cache: bool = True) -> tuple[str, str]:
    """Find the Apple CDN url for a device+build. Returns (url, version).

    Sources, in order: local cache, the ipsw.me API (public releases), the
    ipsw.dev download page (betas, which ipsw.me does not index).
    """
    if not device or not build:
        return "", ""
    key = f"{device}/{build}"
    if use_cache:
        hit = _url_cache().get(key)
        if hit and hit.get("url"):
            return hit["url"], hit.get("version", "")

    try:
        with urllib.request.urlopen(IPSW_ME_API % device, timeout=30) as r:
            data = json.loads(r.read().decode())
        for fw in data.get("firmwares", []):
            if str(fw.get("buildid", "")).lower() == build.lower():
                _cache_url(device, build, fw["url"], fw.get("version", ""))
                return fw["url"], fw.get("version", "")
    except (urllib.error.URLError, json.JSONDecodeError, TimeoutError):
        pass

    try:
        req = urllib.request.Request(IPSW_DEV_PAGE % (device, build),
                                     headers={"User-Agent": "usbliter8-arctic/fetch_components"})
        with urllib.request.urlopen(req, timeout=30) as r:
            html = r.read().decode("utf-8", "replace").replace("\\/", "/")
        hits = _CDN_RE.findall(html)
        if hits:
            version = ""
            m = re.search(r"_(\d+\.\d+)_" + re.escape(build), hits[0])
            if m:
                version = m.group(1)
            _cache_url(device, build, hits[0], version)
            return hits[0], version
    except (urllib.error.URLError, TimeoutError):
        pass
    return "", ""


def _short_board(board: str) -> str:
    return board[:-2] if board.endswith("ap") else board


def patterns_for(component: str, board: str, kernel_name: str = "", model: str = "") -> list:
    """Entry-name patterns for a component of one device.

    The component name is per device, not derivable from the board (iPad 9's
    iBSS is `iBSS.ipad12p.RELEASE.im4p`), so this defers to components.py. The
    board argument is kept for callers that only have a board id.
    """
    offsets = {"model": model or _model_for_board(board), "board": board}
    patterns = components.entry_patterns(offsets, component)
    if kernel_name:
        return [kernel_name]
    return patterns


def _model_for_board(board: str) -> str:
    for model, info in DEVICE_DB.items():
        if info.get("board") == board:
            return model
    return ""


def _device_entry(model: str) -> dict:
    dev = DEVICE_DB.get(model)
    if not dev:
        raise SystemExit("unknown model %r — known: %s"
                         % (model, ", ".join(sorted(DEVICE_DB))))
    return dev


def cmd_list(url: str, model: str, components: list[str], kernel_name: str) -> int:
    """List matching IPSW entries for the requested components."""
    dev = _device_entry(model)
    stage = (f"{dev['name']} ({model}) board {dev['board']} "
             f"kernel {dev.get('kernel_component', 'unknown')}")
    print(section("IPSW entries"))
    print(f"  {C.DIM}{stage}{C.NC}")
    print()
    entries = kczip.central_directory(url)
    print(f"  {C.DIM}{len(entries)} entries in central directory{C.NC}")
    print()
    found_any = False
    for comp in components:
        hits = kczip.match_entries(entries, patterns_for(comp, dev["board"], kernel_name,
                                                        model))
        if not hits:
            print(f"  {C.AMB}—{C.NC} {comp:<14} {C.DIM}no match for {model}{C.NC}")
            continue
        found_any = True
        for e in hits[:6]:
            print(f"  {C.GRN}✓{C.NC} {comp:<14} {e['name']:<52} "
                  f"{e['ucsize'] / 1e6:8.2f} MB")
    if not found_any:
        print()
        print(warn("nothing matched — check the board id with: python3 profile_gen.py list"))
    return 0 if found_any else 1


def cmd_fetch(url: str, model: str, out_dir: Path, components: list[str],
              kernel_name: str, extract_payload: bool) -> int:
    dev = _device_entry(model)
    entries = [e for e in kczip.central_directory(url)
               if "RESEARCH" not in e["name"]]
    print(info(f"{len(entries)} entries in central directory (research images skipped)"))

    out_dir.mkdir(parents=True, exist_ok=True)
    provenance = [f"ipsw: {url}",
                  f"device: {dev['name']} ({model}) board {dev['board']}",
                  f"fetched-by: fetch_components.py (range fetch, kczip)"]
    failures = 0

    for comp in components:
        hits = kczip.match_entries(entries, patterns_for(comp, dev["board"], kernel_name,
                                                        model))
        if not hits:
            print(warn(f"{comp}: no matching entry for {model} ({dev['board']}) — skipped"))
            failures += 1
            continue
        if comp == "kernelcache" and len(hits) > 1 and not kernel_name:
            names = ", ".join(e["name"] for e in hits)
            print(warn(f"kernelcache: {len(hits)} candidates ({names}) — "
                       f"pass --kernel-name to choose"))
            failures += 1
            continue
        entry = hits[0]
        dest = out_dir / COMPONENT_PATTERNS[comp]
        print(f"  {C.EYE}{comp}{C.NC} ← {entry['name']} "
              f"({C.DIM}{entry['ucsize'] / 1e6:.1f} MB{C.NC})")
        try:
            _, n = kczip.fetch_entry(url, entry, dest)
        except RuntimeError as exc:
            print(err(f"    {exc}"))
            failures += 1
            continue
        digest = hashlib.sha256(dest.read_bytes()).hexdigest()
        print(f"    {C.GRN}✓{C.NC} {dest}  {n / 1e6:.1f} MB  sha256 {digest[:16]}…")
        provenance.append(f"{comp}: {entry['name']} -> {dest.name} "
                          f"({n} bytes, sha256 {digest})")

        if extract_payload and comp in ("ibss", "ibec", "txm", "devicetree"):
            if _pyimg4_extract(dest):
                provenance.append(f"{comp}: payload extracted -> {dest.with_suffix('.raw')}")

    (out_dir / "provenance.txt").write_text("\n".join(provenance) + "\n")
    print()
    print(ok(f"Wrote {len(components) - failures} component(s) + provenance.txt to {out_dir}"))
    if "kernelcache" in components:
        print(info("kernelcache is IMG4-encrypted: decrypt with the IV/key from "
                   "research/README.md before using it as a migrate base/target"))
    return 0 if failures == 0 else 1


def _pyimg4_extract(path: Path) -> bool:
    """Extract the im4p payload with pyimg4 when available (Linux/macOS)."""
    import shutil
    import subprocess
    if not shutil.which("pyimg4"):
        print(info(f"    pyimg4 not installed — kept {path.name} as fetched"))
        return False
    out = path.parent / (path.name.split(".")[0] + ".raw")
    r = subprocess.run(["pyimg4", "im4p", "extract", "-i", str(path), "-o", str(out)],
                       capture_output=True, text=True)
    if r.returncode != 0:
        print(warn(f"    pyimg4 extract failed: {(r.stderr or r.stdout).strip()[:120]}"))
        return False
    print(f"    {C.GRN}✓{C.NC} payload → {out}")
    return True


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="fetch_components.py", add_help=True,
                                description="Fetch IPSW components over HTTP Range")
    p.add_argument("--url", default="",
                   help="IPSW url (Apple CDN); omit to resolve it from --device/--build")
    p.add_argument("--device", required=True, help="device model, e.g. iPhone12,3")
    p.add_argument("--ios", default="", help="iOS version tag, e.g. 27.0 (naming only)")
    p.add_argument("--build", default="", help="build id, e.g. 24A437 (naming only)")
    p.add_argument("--entries", default=",".join(DEFAULT_COMPONENTS),
                   help=f"comma list from: {', '.join(ALL_COMPONENTS)}")
    p.add_argument("--out", default="", help="output dir (default research/extracted/<Device>_<ios>_<build>)")
    p.add_argument("--kernel-name", default="", help="kernelcache entry name when several match")
    p.add_argument("--list", action="store_true", help="list matching entries, fetch nothing")
    p.add_argument("--extract-payload", action="store_true",
                   help="run pyimg4 im4p extract after fetching (iBSS/iBEC/TXM/DeviceTree)")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    dev = _device_entry(args.device)
    comps = [c.strip() for c in args.entries.split(",") if c.strip()]
    bad = [c for c in comps if c not in ALL_COMPONENTS]
    if bad:
        print(err(f"unknown component(s): {', '.join(bad)}"))
        return 2

    url = args.url
    if not url:
        if not args.build:
            print(err("pass --url, or --device plus --build to resolve the url automatically"))
            return 2
        print(info(f"resolving IPSW url for {args.device} {args.build}..."))
        url, version = resolve_ipsw_url(args.device, args.build)
        if not url:
            print(err(f"no IPSW url found for {args.device} {args.build} — pass --url explicitly"))
            return 2
        if version and not args.ios:
            args.ios = version
        print(ok(f"found {url}"))

    print(section("Ranged IPSW fetch"))
    print(f"  {C.DIM}{url}{C.NC}")
    print()

    if args.list:
        return cmd_list(url, args.device, comps, args.kernel_name)

    out_dir = Path(args.out) if args.out else (
        DEFAULT_OUT_ROOT / f"{args.device.replace(',', '')}_{args.ios or 'ios'}_{args.build or 'build'}")
    print(info(f"output: {out_dir}"))
    return cmd_fetch(url, args.device, out_dir, comps,
                     args.kernel_name, args.extract_payload)


if __name__ == "__main__":
    import log_utils
    log_utils.install()          # usbliter8.log + unhandled-exception logging
    try:
        sys.exit(main())
    except RuntimeError as exc:
        print(err(str(exc)))
        sys.exit(1)
