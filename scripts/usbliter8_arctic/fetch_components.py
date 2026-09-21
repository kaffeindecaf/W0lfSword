#!/usr/bin/env python3
"""Ranged IPSW component fetcher for usbliter8-arctic.

Pulls just the components an offset profile needs (iBSS, iBEC, TXM,
DeviceTree, kernelcache, RestoreRamdisk) out of a multi-GB IPSW on Apple's
CDN using HTTP Range requests, so a new build can be offset-discovered
without ever storing an IPSW. Ported from W0lfSword's
`scripts/fetch_kernelcache.py` + `scripts/kczip.py` (kcwatch method), which
proved the method on >4GB zip64 IPSWs.

Usage:
  python3 fetch_components.py --profile offsets/iPhone12,3_27.0b3.yaml   # everything that profile needs
  python3 fetch_components.py --device iPhone12,3 --build 24A5380h --all
  python3 fetch_components.py --device iPhone12,1 --build 24A437 --list
  python3 fetch_components.py --url <ipsw-url> --device iPhone12,1 --entries ibss,ibec --out DIR

What it does for you:
  - resolves the IPSW url (local cache, ipsw.me, then ipsw.dev for betas)
  - skips components that are already on disk with the right size, `--refresh`
    re-downloads anyway
  - verifies every fetched component against the recorded evidence
    (offsets/evidence/*.json), so a fetch can confirm the profile's bytes
  - writes provenance.txt + provenance.json (entry name, size, sha256 of the
    file and of the payload) next to the components, and logs every step with
    its duration

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
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

import components
import img4wrap
import kczip
from colors import C, err, info, ok, section, warn
from profile_gen import DEVICE_DB
import log_utils

ROOT = Path(__file__).parent
DEFAULT_OUT_ROOT = ROOT / "research" / "extracted"
EVIDENCE_DIR = ROOT / "offsets" / "evidence"

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

# profile section -> component it needs (preflight reads these names back)
SECTION_TO_COMPONENT = {
    "ibss": "ibss",
    "ibec": "ibec",
    "txm": "txm",
    "devicetree": "devicetree",
    "kernel": "kernelcache",
    "kernelcache": "kernelcache",
    "restored_external": "restoreramdisk",
    "restoreramdisk": "restoreramdisk",
    "asr": "restoreramdisk",
}


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
            log_utils.log_debug(f"ipsw url from cache: {hit['url']}", module="fetch")
            return hit["url"], hit.get("version", "")

    try:
        with urllib.request.urlopen(IPSW_ME_API % device, timeout=30) as r:
            data = json.loads(r.read().decode())
        for fw in data.get("firmwares", []):
            if str(fw.get("buildid", "")).lower() == build.lower():
                _cache_url(device, build, fw["url"], fw.get("version", ""))
                log_utils.log_info(f"ipsw.me: {device} {build} -> {fw['url']}", module="fetch")
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
            log_utils.log_info(f"ipsw.dev: {device} {build} -> {hits[0]}", module="fetch")
            return hits[0], version
    except (urllib.error.URLError, TimeoutError):
        pass
    return "", ""


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
    for model, dev_info in DEVICE_DB.items():
        if dev_info.get("board") == board:
            return model
    return ""


def _device_entry(model: str) -> dict:
    dev = DEVICE_DB.get(model)
    if not dev:
        raise SystemExit("unknown model %r — known: %s"
                         % (model, ", ".join(sorted(DEVICE_DB))))
    return dev


# ── profile driven fetching ─────────────────────────────────────────

def components_from_profile(path: Path) -> tuple[dict, list[str]]:
    """Read a profile and return (values, components it needs).

    `fetch --profile X` is the one-command pull: device, build and the component
    list all come from the profile, and the default output directory is the one
    preflight looks in.
    """
    import yaml

    try:
        data = yaml.safe_load(path.read_text()) or {}
    except (yaml.YAMLError, OSError) as exc:
        raise SystemExit(f"cannot read profile {path}: {exc}")

    model = str(data.get("device_model") or data.get("model") or "")
    kernel = str(data.get("kernel_component") or "")
    comps: list[str] = []
    patches = data.get("patches") or {}
    if isinstance(patches, dict):
        for name in patches:
            comp = SECTION_TO_COMPONENT.get(str(name))
            if comp and comp not in comps:
                comps.append(comp)
        for name in (data.get("blockers") or {}):
            comp = SECTION_TO_COMPONENT.get(str(name))
            if comp and comp not in comps:
                comps.append(comp)
    if not comps:
        comps = list(DEFAULT_COMPONENTS)

    values = {
        "model": model,
        "board": str(data.get("board") or ""),
        "ios": str(data.get("ios_version") or ""),
        "build": str(data.get("build") or ""),
        "kernel_name": kernel,
    }
    return values, [c for c in ALL_COMPONENTS if c in comps]


# ── evidence checking ───────────────────────────────────────────────

def evidence_records() -> list[dict]:
    """Every recorded evidence file, as {profile, model, build, components}."""
    out: list[dict] = []
    for path in sorted(EVIDENCE_DIR.glob("*.json")):
        try:
            data = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        data["_file"] = path
        out.append(data)
    return out


def check_against_evidence(component: str, payload_sha: str, model: str, build: str) -> str:
    """Compare a fetched payload against the recorded evidence for that build.

    Returns "match: <profile>", "differs: <profile>" or "" when nothing covers
    this component+build. This is the cheap proof that a fetch produced the
    bytes a committed profile was verified against.
    """
    for record in evidence_records():
        if record.get("model") != model:
            continue
        if build and str(record.get("build", "")).lower() != build.lower():
            continue
        recorded = (record.get("components") or {}).get(component)
        if not recorded:
            continue
        name = Path(record["_file"]).name
        if recorded.get("sha256") == payload_sha:
            return f"match: {name}"
        return f"differs: {name}"
    return ""


def payload_identity(path: Path) -> tuple[str, int]:
    """sha256 of the component payload: unwrap IMG4 containers, else the file.

    Evidence files record the decompressed payload, which is what profile
    offsets index into, so comparing containers directly would always "differ".
    """
    try:
        payload = img4wrap.payload_of(path)
        return hashlib.sha256(payload).hexdigest(), len(payload)
    except Exception:                                          # noqa: BLE001
        raw = path.read_bytes()
        return hashlib.sha256(raw).hexdigest(), len(raw)


# ── fetching ────────────────────────────────────────────────────────

def fetch_one(url: str, entry: dict, dest: Path, component: str, *,
              extract_payload: bool, refresh: bool) -> dict:
    """Fetch one component. No printing: the caller reports (thread safe)."""
    result = {"component": component, "entry": entry["name"], "dest": dest,
              "bytes": 0, "seconds": 0.0, "skipped": False, "error": "",
              "sha256": "", "payload_sha256": "", "payload_size": 0,
              "payload_extracted": False}
    started = time.monotonic()
    if dest.exists() and not refresh and dest.stat().st_size == entry["ucsize"]:
        result.update(skipped=True, bytes=dest.stat().st_size,
                      sha256=hashlib.sha256(dest.read_bytes()).hexdigest())
        result["seconds"] = time.monotonic() - started
        return result

    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
        _, written = kczip.fetch_entry(url, entry, dest)
    except RuntimeError as exc:
        result["error"] = str(exc)[:300]
        result["seconds"] = time.monotonic() - started
        return result

    result["bytes"] = written
    result["sha256"] = hashlib.sha256(dest.read_bytes()).hexdigest()
    if extract_payload and component in ("ibss", "ibec", "txm", "devicetree"):
        result["payload_extracted"] = _pyimg4_extract(dest)
    result["seconds"] = time.monotonic() - started
    return result


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
              kernel_name: str, extract_payload: bool, *, refresh: bool = False,
              jobs: int = 1, build: str = "") -> int:
    dev = _device_entry(model)
    print(info(f"reading the central directory of {Path(url).name}"))
    entries = [e for e in kczip.central_directory(url)
               if "RESEARCH" not in e["name"]]
    print(info(f"{len(entries)} entries (research images skipped)"))

    out_dir.mkdir(parents=True, exist_ok=True)
    jobs = max(1, min(jobs, len(components) or 1))
    print(f"  {C.DIM}output: {out_dir}  ·  {len(components)} component(s)"
          f"{f'  ·  {jobs} at a time' if jobs > 1 else ''}{C.NC}")
    print()

    planned: list[tuple[str, dict]] = []
    failures = 0
    for comp in components:
        hits = kczip.match_entries(entries, patterns_for(comp, dev["board"], kernel_name,
                                                        model))
        if not hits:
            print(warn(f"{comp}: no matching entry for {model} ({dev['board']}) — skipped"))
            log_utils.log_warn(f"{comp}: no matching entry for {model} ({dev['board']})",
                               module="fetch")
            failures += 1
            continue
        if comp == "kernelcache" and len(hits) > 1 and not kernel_name:
            names = ", ".join(e["name"] for e in hits)
            print(warn(f"kernelcache: {len(hits)} candidates ({names}) — pass --kernel-name"))
            log_utils.log_warn(f"kernelcache: {len(hits)} candidates, none selected", module="fetch")
            failures += 1
            continue
        planned.append((comp, hits[0]))

    results: list[dict] = []
    if jobs == 1:
        for comp, entry in planned:
            print(f"  {C.EYE}{comp}{C.NC} ← {C.DIM}{entry['name']} "
                  f"({entry['ucsize'] / 1e6:.1f} MB){C.NC}")
            with log_utils.timed("fetch", f"{comp} ({entry['name']})"):
                result = fetch_one(url, entry, out_dir / COMPONENT_PATTERNS[comp], comp,
                                   extract_payload=extract_payload, refresh=refresh)
            results.append(result)
            _report_result(result, model, build)
    else:
        with ThreadPoolExecutor(max_workers=jobs) as pool:
            futures = {}
            for comp, entry in planned:
                print(f"  {C.EYE}{comp}{C.NC} ← {C.DIM}{entry['name']} "
                      f"({entry['ucsize'] / 1e6:.1f} MB){C.NC}")
                futures[pool.submit(fetch_one, url, entry,
                                    out_dir / COMPONENT_PATTERNS[comp], comp,
                                    extract_payload=extract_payload, refresh=refresh)] = comp
            for future in as_completed(futures):
                result = future.result()
                results.append(result)
                _report_result(result, model, build)

    for result in results:
        if result["error"]:
            failures += 1

    payloads: dict[str, dict] = {
        result["component"]: {
            "entry": result["entry"], "file": result["dest"].name,
            "bytes": result["bytes"], "sha256": result["sha256"],
            "payload_sha256": result.get("payload_sha256", ""),
            "payload_size": result.get("payload_size", 0),
            "evidence": result.get("evidence", ""), "skipped": result["skipped"],
        }
        for result in results if not result["error"]
    }

    _write_provenance(out_dir, url, dev, model, build, payloads)

    fetched = [r for r in results if not r["error"] and not r["skipped"]]
    cached = [r for r in results if r["skipped"]]
    total = sum(r["bytes"] for r in fetched)
    print()
    if fetched:
        print(ok(f"{len(fetched)} component(s) fetched, {total / 1e6:.1f} MB in "
                 f"{sum(r['seconds'] for r in fetched):.1f}s"))
    if cached:
        print(info(f"{len(cached)} already on disk (use --refresh to re-download)"))
    if failures:
        print(warn(f"{failures} component(s) could not be fetched"))
    log_utils.log_info(f"fetch: {len(fetched)} fetched, {len(cached)} cached, "
                       f"{failures} failed -> {out_dir}", module="fetch")
    if "kernelcache" in components:
        print(info("kernelcache is IMG4-encrypted: decrypt with the IV/key from "
                   "research/README.md before using it as a migrate base/target"))
    return 0 if failures == 0 else 1


def _report_result(result: dict, model: str, build: str) -> None:
    """One component's outcome: what came down, then what it proves."""
    _print_result(result)
    if result["error"]:
        return
    digest, size = payload_identity(result["dest"])
    result["payload_sha256"] = digest
    result["payload_size"] = size
    verdict = check_against_evidence(result["component"], digest, model, build) if build else ""
    result["evidence"] = verdict
    if verdict.startswith("differs"):
        print(warn(f"    payload DIFFERS from {verdict[9:]} — wrong build or wrong board"))
        log_utils.log_warn(f"{result['component']}: payload {digest[:16]} differs from "
                           f"{verdict[9:]}", module="fetch")
    elif verdict.startswith("match"):
        print(f"    {C.GRN}✓{C.NC} payload matches evidence {verdict[7:]}")


def _print_result(result: dict) -> None:
    if result["error"]:
        print(err(f"    {result['error']}"))
        log_utils.log_error(f"{result['component']} fetch failed: {result['error']}",
                            module="fetch")
        return
    if result["skipped"]:
        print(f"    {C.DIM}cached · {result['bytes'] / 1e6:.1f} MB{C.NC}")
        return
    speed = result["bytes"] / 1e6 / result["seconds"] if result["seconds"] else 0.0
    extra = "  payload extracted" if result["payload_extracted"] else ""
    print(f"    {C.GRN}✓{C.NC} {result['dest'].name}  {result['bytes'] / 1e6:.1f} MB  "
          f"{result['seconds']:.1f}s ({speed:.1f} MB/s)  sha256 {result['sha256'][:16]}…{extra}")


def _write_provenance(out_dir: Path, url: str, dev: dict, model: str, build: str,
                      payloads: dict) -> None:
    """provenance.txt for humans, provenance.json for tooling (merged per run)."""
    lines = [f"ipsw: {url}",
             f"device: {dev['name']} ({model}) board {dev['board']}",
             f"build: {build or 'unknown'}",
             f"fetched: {datetime.now(timezone.utc).isoformat(timespec='seconds')}",
             "fetched-by: fetch_components.py (range fetch, kczip)"]
    for comp, info_row in payloads.items():
        lines.append(f"{comp}: {info_row['entry']} -> {info_row['file']} "
                     f"({info_row['bytes']} bytes, sha256 {info_row['sha256']})")

    json_path = out_dir / "provenance.json"
    try:
        merged = json.loads(json_path.read_text())
    except (OSError, json.JSONDecodeError):
        merged = {"components": {}}
    merged.setdefault("components", {})
    merged["components"].update(payloads)
    merged["ipsw"] = url
    merged["model"] = model
    merged["device"] = dev["name"]
    merged["board"] = dev["board"]
    merged["fetched"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    merged["tool"] = "fetch_components.py"

    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "provenance.txt").write_text("\n".join(lines) + "\n")
    json_path.write_text(json.dumps(merged, indent=2, sort_keys=True) + "\n")
    log_utils.log_info(f"provenance written: {json_path}", module="fetch")


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
    p.add_argument("--profile", default="",
                   help="offset profile: device, build and the needed components come from it")
    p.add_argument("--device", default="", help="device model, e.g. iPhone12,3")
    p.add_argument("--ios", default="", help="iOS version tag, e.g. 27.0 (naming only)")
    p.add_argument("--build", default="", help="build id, e.g. 24A437 (naming only)")
    p.add_argument("--entries", default="",
                   help=f"comma list from: {', '.join(ALL_COMPONENTS)} "
                        f"(default: {','.join(DEFAULT_COMPONENTS)})")
    p.add_argument("--all", action="store_true", help="every component, not just the defaults")
    p.add_argument("--out", default="", help="output dir (default research/extracted/<Device>_<ios>_<build>)")
    p.add_argument("--kernel-name", default="", help="kernelcache entry name when several match")
    p.add_argument("--list", action="store_true", help="list matching entries, fetch nothing")
    p.add_argument("--refresh", action="store_true",
                   help="re-download components that are already on disk")
    p.add_argument("--jobs", type=int, default=1,
                   help="fetch this many components at once (default 1)")
    p.add_argument("--extract-payload", action="store_true",
                   help="run pyimg4 im4p extract after fetching (iBSS/iBEC/TXM/DeviceTree)")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    import deps
    deps.ensure(("profiles", "fetch"))          # offer to install what is missing

    args = parse_args(argv if argv is not None else sys.argv[1:])

    model, ios, build, kernel_name = (args.device, args.ios, args.build,
                                      args.kernel_name)
    comps: list[str] = []
    profile_path: Path | None = None

    if args.profile:
        profile_path = Path(args.profile)
        if not profile_path.exists():
            print(err(f"profile not found: {profile_path}"))
            return log_utils.EXIT_ERROR
        values, profile_comps = components_from_profile(profile_path)
        model = model or values["model"]
        ios = ios or values["ios"]
        build = build or values["build"]
        kernel_name = kernel_name or values["kernel_name"]
        comps = profile_comps
        print(info(f"profile {profile_path.name}: {model} {ios} ({build or 'build unknown'}), "
                   f"needs {', '.join(comps) or 'no components'}"))

    if not model:
        print(err("pass --device, or --profile to take the device from a profile"))
        return log_utils.EXIT_BLOCKED      # usage error, same code argparse uses
    _device_entry(model)          # validates the model, exits on an unknown one

    if args.entries:
        comps = [c.strip() for c in args.entries.split(",") if c.strip()]
    elif args.all:
        comps = list(ALL_COMPONENTS)
    elif not comps:
        comps = list(DEFAULT_COMPONENTS)
    bad = [c for c in comps if c not in ALL_COMPONENTS]
    if bad:
        print(err(f"unknown component(s): {', '.join(bad)}"))
        return log_utils.EXIT_BLOCKED

    url = args.url
    if not url:
        if not build:
            print(err("pass --url, or --device plus --build (or --profile) to resolve it"))
            return log_utils.EXIT_BLOCKED
        print(info(f"resolving IPSW url for {model} {build}..."))
        url, version = resolve_ipsw_url(model, build)
        if not url:
            print(err(f"no IPSW url found for {model} {build} — pass --url explicitly"))
            return log_utils.EXIT_BLOCKED
        if version and not ios:
            ios = version
        print(ok(f"found {url}"))

    print(section("Ranged IPSW fetch"))
    print(f"  {C.DIM}{url}{C.NC}")
    print()

    if args.list:
        return cmd_list(url, model, comps, kernel_name)

    out_dir = Path(args.out) if args.out else (
        DEFAULT_OUT_ROOT / f"{model.replace(',', '')}_{ios or 'ios'}_{build or 'build'}")
    code = cmd_fetch(url, model, out_dir, comps, kernel_name, args.extract_payload,
                     refresh=args.refresh, jobs=args.jobs, build=build)
    if code == 0 and profile_path is not None:
        print()
        print(info(f"next: python3 preflight.py {profile_path}   "
                   f"(uses {out_dir.name}/)"))
    return code


if __name__ == "__main__":
    import log_utils
    log_utils.install()          # usbliter8.log + clean exits
    try:
        sys.exit(log_utils.guard(main))
    except RuntimeError as exc:
        print(err(str(exc)))
        sys.exit(1)
