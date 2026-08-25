#!/usr/bin/env python3
"""kcwatch.py — Kernelcache Delta Watcher (poll → fetch → resolve → diff → render).

Watches a board's release feed (ipsw.me), and for every new build:
  - ranged-fetches just the kernelcache (kczip.py, no full IPSW)
  - resolves every XPF offset (tools/xpf-cli)
  - diffs against the previous build (xpf_diff.parse)
  - renders a markdown report + appends to the kernel-deltas.md feed
  - prints the offsets.m verdict (does the newest offsets block still apply?)

Subcommands:
  poll            check for a new build; fetch+resolve+diff+render if found
  status          show watched state for a board
  diff            diff the two most recent cached builds for the board
  verify          compare the cached build's XPF struct offsets against
                  the values kexploit/offsets.m would set for that version
  index           render the cumulative multi-board feed (kernel-deltas.md)
  atom            render an Atom feed (atom.xml) from the report files

Options:  --board t8030|t8103|t8110   --version <ver> (backfill)
          --dry-run   --json   (env: KCWATCH_DIR, KCWATCH_FEED_URL)   --yes

State/cache lives in <repo>/.w0lfsword/kcwatch/<board>/ (gitignored).
"""
import argparse
import datetime as _dt
import json
import os
import re
import subprocess
import sys
import urllib.request

REPO_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = os.path.join(REPO_DIR, "scripts")
sys.path.insert(0, SCRIPTS)
import kczip          # noqa: E402
from xpf_diff import parse as parse_dump   # noqa: E402

IPSW_ME = "https://api.ipsw.me/v4/device/%s"
BOARDS = {
    "t8030": {"device": "iPhone12,8", "soc": "A13", "label": "t8030 (A13, iPhone SE 2)"},
    "t8103": {"device": "iPhone13,1", "soc": "A14", "label": "t8103 (A14, iPhone 12 mini)"},
    "t8110": {"device": "iPhone14,7", "soc": "A15", "label": "t8110 (A15, iPhone 14)"},
}
DEFAULT_BOARD = "t8030"
XPF_CLI = os.path.join(REPO_DIR, "tools", "xpf-cli", "xpf-cli")
OFFSETS_M = os.path.join(REPO_DIR, "kexploit", "offsets.m")
VERSION_RE = re.compile(r'SYSTEM_VERSION_GREATER_THAN_OR_EQUAL_TO\(@"(\d+\.\d+)"\)')
KC_NAME = "kernelcache.release."          # prefix in the IPSW zip


# ── state / cache layout ──────────────────────────────────────────
# KCWATCH_DIR overrides the base (default: <repo>/.w0lfsword/kcwatch)
# so the public feed repo can keep everything under state/.
def kc_base():
    return os.environ.get("KCWATCH_DIR") or os.path.join(REPO_DIR, ".w0lfsword", "kcwatch")


def kc_dir(board):
    return os.path.join(kc_base(), board)


def state_file(board):
    return os.path.join(kc_dir(board), "state.json")


def load_state(board):
    try:
        with open(state_file(board)) as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {"board": board, "last": None, "history": []}


def save_state(board, st):
    os.makedirs(kc_dir(board), exist_ok=True)
    with open(state_file(board), "w") as fh:
        json.dump(st, fh, indent=2)
        fh.write("\n")


def kc_path(board, rel):
    return os.path.join(kc_dir(board), rel)


# ── ipsw.me release feed ──────────────────────────────────────────
def api_get(url):
    with urllib.request.urlopen(url, timeout=30) as r:
        return json.load(r)


def list_releases(board_cfg):
    """Return [{version, buildid, signed, date, url, sha256sum}] newest-last."""
    dev = board_cfg["device"]
    data = api_get(IPSW_ME % dev)
    fws = data.get("releases") or data.get("firmwares") or []
    out = []
    for f in fws:
        out.append({
            "version": f.get("version"),
            "buildid": f.get("buildid"),
            "signed": bool(f.get("signed")),
            "date": f.get("releasedate") or f.get("date") or "",
            "url": f.get("url"),
            "sha256sum": f.get("sha256sum"),
        })
    out.sort(key=lambda r: r["date"])
    return out


def newest_release(board_cfg, prefer_signed=True):
    rels = [r for r in list_releases(board_cfg) if r.get("url")]
    if prefer_signed:
        signed = [r for r in rels if r["signed"]]
        if signed:
            return signed[-1], rels
    return rels[-1], rels


# ── pipeline steps ────────────────────────────────────────────────
def fetch_kc(board_cfg, rel, board, dry_run=False):
    """Ranged-fetch + decompress the kernelcache IMG4 for a release."""
    entry = kczip.locate_entry(rel["url"], prefix=KC_NAME)
    out = kc_path(board, "%s-%s.img4" % (rel["version"], rel["buildid"]))
    if dry_run:
        print("  [fetch] would download %s (%d bytes)" % (entry["name"], entry["csize"]))
        return out
    print("  [fetch] %s (%.1f MB)..." % (entry["name"], entry["csize"] / 1e6))
    path, n = kczip.fetch_entry(rel["url"], entry, out)
    print("  [fetch] saved %s (%.1f MB, crc verified)" % (path, n / 1e6))
    return out


def resolve_kc(kc_file, board, dry_run=False):
    dump = kc_file.replace(".img4", ".txt")
    if dry_run:
        return dump
    print("  [xpf]   resolving %s ..." % os.path.basename(kc_file))
    r = subprocess.run([XPF_CLI, kc_file], capture_output=True, text=True, timeout=600)
    if r.returncode != 0:
        print(r.stderr[-2000:] if r.stderr else "(no stderr)")
        raise RuntimeError("xpf-cli exited %d on %s" % (r.returncode, kc_file))
    with open(dump, "w") as fh:
        fh.write(r.stdout)
    hdr, _ = parse_dump(dump)
    print("  [xpf]   %s - %s" % (hdr.get("kernel", "?").split(";")[0],
                                 hdr.get("xnu", "?")))
    return dump


def summarize_diff(a_path, b_path):
    """Extend xpf_diff.parse with the resolved→UNRESOLVED (degraded) class."""
    ha, ia = parse_dump(a_path)
    hb, ib = parse_dump(b_path)
    names = sorted(set(ia) | set(ib))
    same, changed, degraded, only_a, only_b = [], [], [], [], []
    for n in names:
        va, vb = ia.get(n), ib.get(n)
        if n not in ib:
            only_a.append(n)
        elif n not in ia:
            only_b.append(n)
        elif va is None or vb is None:
            if va != vb:
                degraded.append(n)
            else:                       # both unresolved → same
                same.append(n)
        elif va == vb:
            same.append(n)
        else:
            changed.append(n)
    return {
        "kernel_a": ha.get("kernel", "?"), "kernel_b": hb.get("kernel", "?"),
        "xnu_a": ha.get("xnu", "?"), "xnu_b": hb.get("xnu", "?"),
        "resolved_a": sum(1 for v in ia.values() if v is not None),
        "resolved_b": sum(1 for v in ib.values() if v is not None),
        "identical": same, "changed": changed,
        "changed_values": {n: [ia.get(n), ib.get(n)] for n in changed},
        "degraded": degraded, "only_in_a": only_a, "only_in_b": only_b,
    }


def offsets_thresholds():
    """Sorted [(version, line)] from offsets.m, highest applicable first."""
    vers = []
    try:
        with open(OFFSETS_M) as fh:
            for line in fh:
                m = VERSION_RE.search(line)
                if m:
                    vers.append(m.group(1))
    except OSError:
        return []
    return sorted(set(vers), key=lambda v: tuple(int(x) for x in v.split(".")))


OFF_VAR_RE = re.compile(
    r"^\s*(?:uint(?:32|64)_t\s+)?(off_\w+)\s*=\s*(0x[0-9a-fA-F]+|\d+)\s*;")


def parse_offsets_m():
    """{version_threshold: {var: value}} — last-wins per block."""
    blocks = {}
    cur = None
    try:
        lines = open(OFFSETS_M).read().splitlines()
    except OSError:
        return {}
    for line in lines:
        m = VERSION_RE.search(line)
        if m:
            cur = m.group(1)
            blocks.setdefault(cur, {})
            continue
        m = OFF_VAR_RE.match(line)
        if m and cur:
            blocks[cur][m.group(1)] = int(m.group(2), 0)
    return blocks


def effective_offsets(version):
    """offsets.m values that apply for `version`: cumulative over every
    block whose threshold is <= version (later blocks override earlier)."""
    blocks = parse_offsets_m()
    key = tuple(int(x) for x in version.split("."))
    eff = {}
    for thr in sorted(blocks, key=lambda v: tuple(int(x) for x in v.split("."))):
        if tuple(int(x) for x in thr.split(".")) <= key:
            eff.update(blocks[thr])
    return eff


def cmd_verify(args):
    """Compare the XPF-resolved struct offsets of a cached build against
    the values kexploit/offsets.m would set for that version."""
    st = load_state(args.board)
    version = args.version or (st.get("last") or {}).get("version")
    if not version:
        print("no cached build for %s - run poll first" % args.board)
        return 1
    dump_rel = (st.get("last") or {}).get("dump", "")
    dump = os.path.join(kc_base(), dump_rel)
    if not os.path.isfile(dump):
        print("dump missing: %s" % dump)
        return 1
    _, items = parse_dump(dump)
    eff = effective_offsets(version)
    rows, skipped = [], []
    for name, xv in sorted(items.items()):
        if not name.startswith("kernelStruct."):
            continue
        var = "off_" + name[len("kernelStruct."):].replace(".", "_")
        if var not in eff:
            continue
        if xv == 0:
            # XPF prints 0x0 for patchfinder misses (thread.machine_* on
            # fileset builds) - not a real value, not a mismatch
            skipped.append(var)
            continue
        rows.append((var, eff[var], xv, "OK" if eff[var] == xv else "MISMATCH"))
    print("offsets.m vs XPF - iOS %s, board %s, dump %s" % (
        version, args.board, os.path.basename(dump)))
    if not rows and not skipped:
        print("no overlap between offsets.m variables and XPF struct items")
        return 0
    bad = 0
    for var, om, xv, sts in rows:
        print("  %s %-38s offsets.m=0x%x  xpf=0x%x" % (sts, var, om, xv))
        if sts != "OK":
            bad += 1
    for var in skipped:
        print("  SKIP %-38s (xpf unresolved 0x0 - per-SoC value, not verifiable)" % var)
    print("VERDICT: %s (%d/%d matched, %d skipped)" % (
        "ALL MATCH" if bad == 0 else "MISMATCH", len(rows) - bad, len(rows), len(skipped)))
    return 1 if bad else 0


def cmd_index(args):
    """Render the cumulative multi-board feed index (kernel-deltas.md)."""
    base = kc_base()
    rows = []
    for board in sorted(os.listdir(base)):
        sf = os.path.join(base, board, "state.json")
        if not os.path.isfile(sf):
            continue
        try:
            st = json.load(open(sf))
        except (OSError, ValueError):
            continue
        for h in st.get("history", []):
            rows.append((
                h.get("date", ""), board, h.get("version"), h.get("buildid"),
                h.get("xnu", "?"), h.get("identical", "?"), h.get("changed", "?"),
                h.get("verdict", "?")))
    rows.sort()
    lines = [
        "# kernel-deltas feed", "",
        "Latest entries across all watched boards. Full reports:",
        "reports/<board>-<version>-<buildid>.md", "",
        "| date | board | release | build | xnu | identical | changed | verdict |",
        "|------|-------|---------|-------|-----|-----------|---------|---------|",
    ]
    for r in rows[-25:]:
        lines.append("| %s | %s | %s | %s | %s | %s | %s | %s |" % r)
    lines.append("")
    with open("kernel-deltas.md", "w") as fh:
        fh.write("\n".join(lines))
    print("wrote kernel-deltas.md (%d entries)" % len(rows))
    return 0


def cmd_atom(args):
    """Render an Atom feed (atom.xml) from the report files."""
    import datetime
    base = kc_base()
    feed_url = os.environ.get("KCWATCH_FEED_URL",
                              "https://github.com/kaffeindecaf/kernel-deltas")
    entries = []
    for board in sorted(os.listdir(base)):
        rdir = os.path.join(base, board, "reports")
        if not os.path.isdir(rdir):
            continue
        for fn in sorted(os.listdir(rdir)):
            if not fn.endswith(".md") or fn == "kernel-deltas.md":
                continue
            p = os.path.join(rdir, fn)
            mtime = datetime.datetime.fromtimestamp(
                os.path.getmtime(p)).strftime("%Y-%m-%dT%H:%M:%SZ")
            body = open(p).read()
            summary = body.split("VERDICT")[0].strip().replace("\n", " ")
            entries.append((mtime, fn[:-3], feed_url + "/reports/" + fn, summary))
    entries.sort(reverse=True)
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    xml = ['<?xml version="1.0" encoding="utf-8"?>',
           '<feed xmlns="http://www.w3.org/2005/Atom">',
           "  <title>kernel-deltas</title>",
           "  <id>%s</id>" % feed_url,
           "  <updated>%s</updated>" % now,
           "  <link rel=\"self\" href=\"%s/atom.xml\"/>" % feed_url]
    for mtime, title, url, summary in entries[:25]:
        xml += ["  <entry>",
                "    <title>%s</title>" % title,
                "    <id>%s</id>" % url,
                "    <updated>%s</updated>" % mtime,
                "    <summary>%s</summary>" % summary,
                "    <link href=\"%s\"/>" % url,
                "  </entry>"]
    xml.append("</feed>")
    with open("atom.xml", "w") as fh:
        fh.write("\n".join(xml))
    print("wrote atom.xml (%d entries)" % len(entries))
    return 0


def offsets_verdict(version, diff):
    """Which offsets.m block applies to `version`, and do the struct offsets
    still match the previous build? Struct items are kernelStruct.* /
    kernelConstant.* — symbol addresses shift every build and are noise."""
    thr = offsets_thresholds()
    if not thr:
        return "offsets.m not found: verdict unavailable"
    applicable = [t for t in thr if tuple(int(x) for x in t.split("."))
                  <= tuple(int(x) for x in version.split("."))]
    if not applicable:
        return "NO: version %s is BELOW the lowest offsets.m block (>= %s)" % (version, thr[0])
    block = applicable[-1]
    structs = [n for n in diff["changed"] + diff["degraded"] + diff["only_in_a"] + diff["only_in_b"]
               if n.startswith(("kernelStruct.", "kernelConstant."))]
    if structs:
        return ("NO: offsets.m block '>= %s' does NOT cover %s: struct/constant "
                "items moved (%s)" % (block, version, ", ".join(structs[:4])))
    return ("YES: offsets.m block '>= %s' applies to %s (all struct/constant "
            "offsets identical to previous build)" % (block, version))


def render_report(board_cfg, rel, prev, diff, verdict):
    d = diff
    lines = []
    lines.append("## iOS %s (%s) - %s - %s" % (
        rel["version"], rel["buildid"], board_cfg["label"], _dt.date.today().isoformat()))
    lines.append("")
    lines.append("xnu: %s -> %s" % (d["xnu_a"] or "?", d["xnu_b"] or "?"))
    lines.append("resolved: A=%d  B=%d   identical: %d   changed: %d"
                 % (d["resolved_a"], d["resolved_b"], len(d["identical"]), len(d["changed"])))
    if d["degraded"]:
        lines.append("degraded (resolved <-> UNRESOLVED): %d" % len(d["degraded"]))
    lines.append("")
    if d["changed"]:
        lines.append("CHANGED:")
        for n in d["changed"]:
            va, vb = d.get("changed_values", {}).get(n, ["?", "?"])
            lines.append("  %s: 0x%016x -> 0x%016x" % (n, va, vb))
    for surf in ("kernelConstant.nsysent", "kernelConstant.mach_trap_count"):
        if surf in d.get("changed_values", {}):
            va, vb = d["changed_values"][surf]
            lines.append("")
            lines.append("SURFACE: %s 0x%x -> 0x%x - syscall table changed, "
                         "new attack surface" % (surf, va, vb))
    if d["degraded"]:
        lines.append("")
        lines.append("DEGRADED (structural change, investigate):")
        for n in d["degraded"]:
            lines.append("  %s" % n)
    if d["only_in_a"] or d["only_in_b"]:
        lines.append("")
        lines.append("ONE-SIDED:")
        for n in d["only_in_a"]:
            lines.append("  %s: only in previous" % n)
        for n in d["only_in_b"]:
            lines.append("  %s: only in new build" % n)
    lines.append("")
    lines.append("VERDICT: %s" % verdict)
    lines.append("")
    return "\n".join(lines)

# ── subcommands ───────────────────────────────────────────────────
def cmd_poll(args):
    board_cfg = BOARDS[args.board]
    os.makedirs(kc_dir(args.board), exist_ok=True)
    st = load_state(args.board)
    rels = list_releases(board_cfg)
    if args.version:
        rel = next((r for r in rels if r["version"] == args.version), None)
        if not rel:
            print("no release iOS %s for %s" % (args.version, args.board))
            return 1
    else:
        rel = newest_release(board_cfg)[0] if not args.dry_run else (rels[-1] if rels else None)
    if not rel:
        print("no releases for %s" % board_cfg["device"])
        return 1
    last = st.get("last") or {}
    same = last.get("buildid") == rel["buildid"]
    print("board: %s   newest: iOS %s (%s)  signed=%s  date=%s" % (
        args.board, rel["version"], rel["buildid"], rel["signed"], rel["date"]))
    if same:
        print("no new build since %s, nothing to do" % last.get("version"))
        return 0
    if args.dry_run:
        print("dry-run: would fetch+resolve+diff iOS %s (%s)" % (rel["version"], rel["buildid"]))
        return 0
    kc = fetch_kc(board_cfg, rel, args.board)
    dump = resolve_kc(kc, args.board)
    diff = verdict = None
    if st.get("last") and st["last"].get("dump"):
        prev_dump = st["last"]["dump"]
        diff = summarize_diff(prev_dump, dump)
        verdict = offsets_verdict(rel["version"], diff)
        report = render_report(board_cfg, rel, st["last"], diff, verdict)
        rpath = kc_path(args.board, "reports")
        os.makedirs(rpath, exist_ok=True)
        rfile = os.path.join(rpath, "%s-%s-%s.md" % (args.board, rel["version"], rel["buildid"]))
        with open(rfile, "w") as fh:
            fh.write(report)
        feed = os.path.join(rpath, "kernel-deltas.md")
        with open(feed, "a") as fh:
            fh.write(report)
            fh.write("\n---\n\n")
        print(report)
        print("report: %s" % rfile)
    else:
        print("baseline build (no previous dump to diff against)")
        thr = offsets_thresholds()
        top = thr[-1] if thr else "?"
        print("VERDICT: %s, offsets.m block '>= %s' is the highest applicable; "
              "structural identity unverified (no previous build cached)" % (args.board, top))
    st["last"] = {"version": rel["version"], "buildid": rel["buildid"],
                  "date": rel["date"], "signed": rel["signed"], "dump": dump}
    # carry the diff summary into history so `index` can render the table
    if diff is not None:
        st["last"].update({
            "xnu": diff.get("xnu_b", "?"),
            "identical": len(diff.get("identical", [])),
            "changed": len(diff.get("changed", [])),
            "degraded": len(diff.get("degraded", [])),
            "verdict": verdict or "?",
        })
    st["history"] = [h for h in st.get("history", [])
                     if h.get("buildid") != rel["buildid"]]
    st["history"].append(st["last"])
    save_state(args.board, st)
    return 0


def cmd_status(args):
    st = load_state(args.board)
    last = st.get("last")
    if not last:
        print("%s: no state yet — run 'kcwatch poll'" % args.board)
        return 0
    print("%s: last seen iOS %s (%s, %s) signed=%s" % (
        args.board, last["version"], last["buildid"], last["date"], last["signed"]))
    print("  dump: %s" % last.get("dump"))
    print("  history: %d build(s)" % len(st.get("history", [])))
    return 0


def cmd_diff(args):
    st = load_state(args.board)
    if not st.get("history") or len(st["history"]) < 2:
        print("need at least 2 cached builds for %s (run poll twice)" % args.board)
        return 1
    h = st["history"]
    a, b = h[-2], h[-1]
    d = summarize_diff(a["dump"], b["dump"])
    print("A: iOS %s (%s)  B: iOS %s (%s)" % (a["version"], a["buildid"], b["version"], b["buildid"]))
    print("resolved: A=%d B=%d   identical=%d  changed=%d  degraded=%d  one-sided=%d" % (
        d["resolved_a"], d["resolved_b"], len(d["identical"]), len(d["changed"]),
        len(d["degraded"]), len(d["only_in_a"]) + len(d["only_in_b"])))
    for n in d["changed"]:
        print("  CHANGED %s" % n)
    for n in d["degraded"]:
        print("  DEGRADED %s" % n)
    for n in d["only_in_a"]:
        print("  ONLY-A %s" % n)
    for n in d["only_in_b"]:
        print("  ONLY-B %s" % n)
    print("VERDICT: %s" % offsets_verdict(b["version"], d))
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cmd", nargs="?", default="poll",
                    choices=["poll", "status", "diff", "verify", "index", "atom"])
    ap.add_argument("--board", default=DEFAULT_BOARD, choices=sorted(BOARDS))
    ap.add_argument("--version", help="process a specific release version instead of the newest (backfill)")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    if args.json:
        import json as _json
        st = load_state(args.board)
        print(_json.dumps(st, indent=2))
        return 0

    if args.cmd == "poll":
        return cmd_poll(args)
    if args.cmd == "status":
        return cmd_status(args)
    if args.cmd == "diff":
        return cmd_diff(args)
    if args.cmd == "verify":
        return cmd_verify(args)
    if args.cmd == "index":
        return cmd_index(args)
    if args.cmd == "atom":
        return cmd_atom(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
