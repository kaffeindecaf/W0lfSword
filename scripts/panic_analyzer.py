#!/usr/bin/env python3
"""panic_analyzer.py — classify an iOS .ips crash report or raw panic log.

Maps kernel / SEP / MTE panics and userspace crashes to known CVEs and the
W0lfSword BUG_BOUNTY findings (BB-032..037). Pure stdlib, no dependencies.

Usage:
    panic_analyzer.py <file.ips | panic.log>
    panic_analyzer.py <file> --json        # machine-readable verdict

Exit code is always 0 (analysis ran); errors print to stderr and exit 1.
"""
import json
import re
import sys

# (regex, kind, cve, bb, note) — first match in priority order wins.
RULES = [
    (re.compile(r"SEP Panic|:sks /sks|sks /sks", re.I), "SEP", "—", "BB-036",
     "SEP firmware panic (AppleKeyStore selector-2 exhaustion, ~41 calls)"),
    (re.compile(r"0x0006fe[9a]7", re.I), "SEP", "—", "BB-036",
     "SEP SKS panic address range (0x0006fe9x/0x0006fea7)"),
    (re.compile(r"AppleJPEGDriver", re.I), "KERNEL", "CVE-2026-20687", "BB-033",
     "AppleJPEGDriver kernel UAF — stale queue node (patched iOS 26.4)"),
    (re.compile(r"tag check fault|MTE|mted", re.I), "MTE", "—", "—",
     "Memory Tagging Extension fault (A19/M5 era)"),
    (re.compile(r"vm_shared_region_slide_page_v5|reslide|slide.?walk", re.I),
     "KERNEL", "CVE-2026-43724", "BB-034",
     "DirtySlide — dyld v5 slide-walk OOB (patched macOS 26.5.2)"),
    (re.compile(r"cluster_read_ext|cluster_write_ext|UPL_PHYS_CONTIG", re.I),
     "KERNEL", "CVE-2025-43520", "—",
     "DarkSword class — VFS cluster TOCTOU (patched iOS 26.1)"),
    (re.compile(r"0x4141414141414151|EXC_GUARD", re.I), "USERSPACE", "CVE-2026-28990", "BB-035",
     "EXR ImageIO int-overflow heap overflow (patched iOS 26.5)"),
    (re.compile(r"containermanagerd|MCM|MobileHouseArrest", re.I), "USERSPACE", "—", "BB-032/037",
     "containermanagerd traversal / MHA container lease activity"),
]


def first_line(haystack, limit=180):
    """First non-empty line of the haystack, truncated."""
    for ln in haystack.splitlines():
        ln = ln.strip()
        if ln:
            return ln[:limit]
    return ""


def from_ips(path):
    """Extract a 'haystack' + metadata from an .ips (JSON crash report).

    Modern .ips files are NDJSON-ish: line 1 is a one-line header object,
    then the actual report object follows. Plain json.load fails on those
    (the header is not a full document), so decode object-by-object with
    raw_decode and use the LARGEST object (the report, not the header).
    """
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except Exception as e:
        return None, {"error": str(e)}

    doc = None
    decoder = json.JSONDecoder()
    idx = 0
    n = len(text)
    while idx < n:
        while idx < n and text[idx] in " \t\r\n":
            idx += 1
        if idx >= n:
            break
        try:
            obj, idx = decoder.raw_decode(text, idx)
        except Exception:
            break
        # keep the biggest object seen so far — the header is small, the
        # report is large; a single-object .ips just takes this branch once
        if doc is None or len(json.dumps(obj)) > len(json.dumps(doc)):
            doc = obj
    if doc is None:
        return None, {"error": "no JSON object found"}

    # Crash reports nest the actual report under a key when the file has
    # a metadata preamble ("crashReporterKey" / "tailspin" style). Flatten.
    for key in ("crashReport", "report", "body", "crash", "rootCause"):
        if isinstance(doc.get(key), dict):
            doc = doc[key]
            break

    osv = doc.get("osVersion", {})
    ios_ver = osv.get("version", "?") if isinstance(osv, dict) else str(osv)
    build = osv.get("build", "?") if isinstance(osv, dict) else "?"

    xnu = "?"
    for img in doc.get("usedImages", []) or []:
        if "kernelcache" in img.get("name", "").lower() or "kernel" == img.get("name", "").lower():
            xnu = img.get("version", "?")
            break

    exc = doc.get("exception", {}) or {}
    exc_type = exc.get("type", "")
    exc_signal = exc.get("signal", "")
    termination = doc.get("termination", {}) or {}
    term_reason = termination.get("reason", "")

    panic_str = doc.get("panicString", "") or doc.get("ktriageinfo", "") or ""
    if isinstance(panic_str, list):
        panic_str = "\n".join(str(x) for x in panic_str)

    # faulting thread's first frames
    frames = []
    ft = doc.get("faultingThread", 0)
    threads = doc.get("threads", []) or []
    if isinstance(ft, int) and ft < len(threads):
        for fr in (threads[ft].get("frames", []) or [])[:8]:
            frames.append(fr.get("symbol", "") or fr.get("imageIndex", ""))
    elif isinstance(ft, dict):
        for fr in (ft.get("frames", []) or [])[:8]:
            frames.append(fr.get("symbol", "") or "")

    hay = "\n".join([
        str(panic_str), str(term_reason), str(exc_type), str(exc_signal),
        " ".join(str(f) for f in frames),
    ])

    meta = {
        "ios": f"{ios_ver} ({build})",
        "xnu": xnu,
        "exception": f"{exc_type} signal={exc_signal}" if exc_type else "",
        "termination": term_reason,
        "capture": doc.get("captureTime", ""),
    }
    return hay, meta


def from_text(path):
    """Raw panic log: whole text is the haystack."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            txt = fh.read()
    except Exception as e:
        return None, {"error": str(e)}
    meta = {}
    m = re.search(r"Darwin Kernel Version[^\n]*", txt)
    if m:
        meta["xnu"] = m.group(0)
    m = re.search(r"panic\(cpu[^\n]*", txt)
    if m:
        meta["panic"] = m.group(0)
    return txt, meta


def main():
    if len(sys.argv) < 2:
        print("usage: panic_analyzer.py <file.ips|panic.log> [--json]", file=sys.stderr)
        return 1
    path = sys.argv[1]
    as_json = "--json" in sys.argv[2:]

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            head = fh.read(4096).lstrip()
    except OSError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    if head.startswith("{"):
        hay, meta = from_ips(path)
    else:
        hay, meta = from_text(path)

    if hay is None:
        print(f"error: could not parse {path}: {meta.get('error')}", file=sys.stderr)
        return 1

    verdict = None
    for rx, kind, cve, bb, note in RULES:
        if rx.search(hay):
            verdict = {"kind": kind, "cve": cve, "bb": bb, "note": note}
            break

    if verdict is None:
        if re.search(r"panic\(cpu|panicString|kernel panic", hay, re.I):
            verdict = {"kind": "KERNEL", "cve": "—", "bb": "—",
                       "note": "kernel panic (no known mapping)"}
        elif meta.get("exception"):
            verdict = {"kind": "USERSPACE", "cve": "—", "bb": "—",
                       "note": f"app crash: {meta['exception']}"}
        else:
            verdict = {"kind": "UNKNOWN", "cve": "—", "bb": "—", "note": "no recognizable signature"}

    if as_json:
        out = {
            "file": path,
            "verdict": verdict,
            "meta": {k: v for k, v in meta.items() if v},
            "signature": meta.get("panic") or first_line(hay, 220),
        }
        print(json.dumps(out, indent=2))
        return 0

    print(f"  file       {path}")
    print(f"  kind       {verdict['kind']}")
    if meta.get("ios"):
        print(f"  iOS        {meta['ios']}")
    if meta.get("xnu") and meta["xnu"] != "?":
        print(f"  xnu        {meta['xnu']}")
    if meta.get("capture"):
        print(f"  captured   {meta['capture']}")
    if verdict["cve"] != "—":
        print(f"  mapping    {verdict['cve']}  ({verdict['bb']})")
    elif verdict["bb"] != "—":
        print(f"  mapping    {verdict['bb']}")
    print(f"  note       {verdict['note']}")
    sig = meta.get("panic") or first_line(hay, 200)
    if sig:
        print(f"  signature  {sig}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
