#!/usr/bin/env python3
"""offsets_drift.py — which kexploit offsets need re-verification between builds.

`scripts/ipswdiffs.py` answers "what changed in Apple's binaries between build A
and build B" for free (pre-computed `ipsw diff` markdown, no IPSW download).
This tool asks the question this tree actually cares about:

    which structs my offset table walks changed in a build I don't have yet?

How it works:

  1. read `kexploit/offsets.h` and group every `off_<struct>_<field>` by the
     kernel struct it walks (inpcb, socket, proc, thread, zone, vm_map, ...),
  2. resolve the build pair in the ipsw-diffs dataset (explicit --pair, or the
     newest iOS pair),
  3. fetch that pair's per-kext diffs and derive signals per owning kext:
       - `__DATA_CONST.__kalloc_type` / `__kalloc_var` size change
         (these sections hold the kalloc type descriptors, so the sprayed
         object layouts moved -> the sharpest layout signal available),
       - symbol adds/removes, function-count change, "same size but changed
         content" sections (code edited without shifting anything),
       - added/removed CStrings whose text names one of the struct's own tokens
         (progress/assert/bounds-check messages Apple added next to the code),
  4. write a markdown report and print a per-struct verdict.

The report goes to `<repo>/.w0lfsword/offsets-drift/<prev>__<next>.md` (env
OFFSETS_DRIFT_DIR, or --out), the same gitignored data dir kcwatch uses.

A hit is a SIGNAL, never proof: it says "re-verify these offsets against the
new kernelcache" (kcwatch / kc_zone_fields.py / tools/xpf-cli), which is the
rule in offsets.m already. This tool only makes sure you look before shipping
a build you never verified.

The dataset diffs an iOS release on ONE device (iPhone18,1). Kext-level deltas
track the build and are shared across SoCs; kernel text layout does not, so
treat this as "which areas to re-verify", not as a per-SoC diff.

Usage:
    python3 scripts/offsets_drift.py                      # newest iOS pair
    python3 scripts/offsets_drift.py --pair 23G71 23G83
    python3 scripts/offsets_drift.py --pair 26.6 26.6.1 --json
    python3 scripts/offsets_drift.py 26_6_23G71_vs_26_6_1_23G83
    python3 scripts/offsets_drift.py --structs inpcb,socket,vnode
    python3 scripts/offsets_drift.py --no-write --fail-on layout
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))

import ipswdiffs as ID  # noqa: E402  (same-directory sibling script)

OFFSETS_H = ROOT / "kexploit" / "offsets.h"
OFFSETS_M = ROOT / "kexploit" / "offsets.m"


def report_dir(override: str | None = None) -> Path:
    """<repo>/.w0lfsword/offsets-drift unless --out/env says otherwise.

    Same convention as kcwatch: generated analysis lives under the gitignored
    .w0lfsword/ data dir, not next to the local-only bounty reports/ tree.
    """
    path = (override or os.environ.get("OFFSETS_DRIFT_DIR")
            or str(ROOT / ".w0lfsword" / "offsets-drift"))
    return Path(path)

# (struct token, kext bundle that owns it). Longest token wins, so list
# composites before their prefixes (proc_ro before proc, thread_ro before
# thread, ipc_space before ipc_*).
STRUCTS: tuple[tuple[str, str], ...] = (
    ("apfs_fsnode", "com.apple.filesystems.apfs"),
    ("arm_kernel_saved_state", "com.apple.kernel"),
    ("arm_saved_state64", "com.apple.kernel"),
    ("arm_saved_state", "com.apple.kernel"),
    ("kalloc_type_view", "com.apple.kernel"),
    ("vm_named_entry", "com.apple.kernel"),
    ("vm_map_entry", "com.apple.kernel"),
    ("vm_map_header", "com.apple.kernel"),
    ("vm_object", "com.apple.kernel"),
    ("vm_map", "com.apple.kernel"),
    ("inpcbinfo", "com.apple.kernel"),
    ("inpcb", "com.apple.kernel"),
    ("ipc_entry", "com.apple.kernel"),
    ("ipc_port", "com.apple.kernel"),
    ("ipc_space", "com.apple.kernel"),
    ("namecache", "com.apple.kernel"),
    ("fileglob", "com.apple.kernel"),
    ("fileproc", "com.apple.kernel"),
    ("filedesc", "com.apple.kernel"),
    ("proc_ro", "com.apple.kernel"),
    ("proc", "com.apple.kernel"),
    ("thread_ro", "com.apple.kernel"),
    ("thread", "com.apple.kernel"),
    ("socket", "com.apple.kernel"),
    ("ucred", "com.apple.kernel"),
    ("label", "com.apple.kernel"),
    ("mount", "com.apple.kernel"),
    ("vnode", "com.apple.kernel"),
    ("task", "com.apple.kernel"),
    ("zone", "com.apple.kernel"),
)

# Tokens too generic to search for; they match half the kernel's strings.
STOP_TOKENS = {"off", "in", "to", "of", "is", "it", "le", "p", "l", "t", "ro",
               "ss", "us", "or", "and", "next", "prev", "first", "data", "flag",
               "size", "io", "vm", "ip", "list", "object", "copy", "count",
               "name", "type", "code", "id", "ptr", "addr", "value", "index",
               "mask", "ref", "entry", "link", "links", "field", "elem", "zone"}  # noqa: E501

NAME_RE = re.compile(r"^extern\s+uint32_t\s+(off_[a-z0-9_]+)\s*;", re.M)
ASSIGN_RE = re.compile(r"^\s*(off_[a-z0-9_]+)\s*=\s*(0x[0-9a-fA-F]+|\d+)\s*;", re.M)


def read_offset_names(path: Path = OFFSETS_H) -> list[str]:
    text = path.read_text(encoding="utf-8")
    names = NAME_RE.findall(text)
    if not names:
        raise SystemExit(f"offsets_drift: no `extern uint32_t off_*` in {path}")
    return names


def struct_of(name: str) -> str:
    body = name[len("off_"):]
    for token, _kext in STRUCTS:
        if body == token or body.startswith(token + "_"):
            return token
    parts = body.split("_")
    for n in (3, 2):
        if len(parts) >= n:
            joined = "_".join(parts[:n])
            for token, _kext in STRUCTS:
                if joined.startswith(token):
                    return token
    return parts[0]


def group_offsets(names: list[str]) -> dict[str, list[str]]:
    groups: dict[str, list[str]] = {}
    for n in names:
        groups.setdefault(struct_of(n), []).append(n)
    return groups


def terms_for(struct: str, offsets: list[str]) -> list[str]:
    """Search terms specific enough to sit in a diff without false hits.

    Single words like `list` or `object` appear in unrelated strings all over
    the kernel, so the useful terms are the struct name itself plus two-token
    composites built from the flattened member path (`inp_list`, `le_next`,
    `vou_size`) — those only show up in messages about that struct.
    """
    terms = {struct}
    for n in offsets:
        body = n[len("off_"):]
        if body.startswith(struct + "_"):
            body = body[len(struct) + 1:]
        toks = [t for t in body.split("_") if t]
        # Adjacent-token composites are safe even when one half is a common
        # word: "inp_list" / "ie_object" only appear next to this struct.
        for i in range(len(toks) - 1):
            pair = f"{toks[i]}_{toks[i + 1]}"
            if len(pair) >= 7 and pair not in STOP_TOKENS:
                terms.add(pair)
        for t in toks:
            if len(t) >= 6 and t not in STOP_TOKENS:
                terms.add(t)
    return sorted(terms, key=lambda s: (-len(s), s))


def kext_owner(struct: str) -> str:
    for token, kext in STRUCTS:
        if token == struct:
            return kext
    return "com.apple.kernel"


def pair_dir_for(ds: ID.Dataset, want: list[str] | None, os_name: str) -> tuple[str, ID.Entry]:
    entries = ID.parse_index(ds.fetch("README.md"))
    ios = [e for e in entries if e.os == os_name] or entries
    if want:
        if len(want) == 1:
            hit = next((e for e in entries if e.dir == want[0]), None)
            if hit is None:
                raise SystemExit(
                    f"offsets_drift: no pair dir {want[0]!r} in ipsw-diffs "
                    f"(run `python3 scripts/ipswdiffs.py index`)")
            return hit.dir, hit
        if len(want) != 2:
            raise SystemExit("offsets_drift: --pair takes one dir or two builds")
        hits = ID.resolve_pair(ios, want[0], want[1])
        if not hits:
            raise SystemExit(
                f"offsets_drift: no pair {want[0]} -> {want[1]} in ipsw-diffs "
                f"(run `python3 scripts/ipswdiffs.py index`); the dataset only "
                f"has what blacktop has diffed so far"
            )
        if len(hits) > 1:
            hits = sorted(hits, key=lambda e: e.dir)
            print(f"offsets_drift: {len(hits)} pairs match, using {hits[0].dir} "
                  f"({', '.join(h.dir for h in hits[1:])})", file=sys.stderr)
        return hits[0].dir, hits[0]
    if not ios:
        raise SystemExit("offsets_drift: dataset index has no iOS pairs")
    e = ios[0]
    return e.dir, e


class NothingToVerify(Exception):
    """The pair is fine, it just has no changed kext (a valid, empty answer)."""


def kext_context(diffs: list[ID.TargetDiff]) -> dict[str, dict]:
    """Kext-wide deltas, computed once — they apply to every struct the kext owns."""
    ctx: dict[str, dict] = {}
    for d in diffs:
        raw_add = d.cstrings.get("added", [])
        raw_del = d.cstrings.get("removed", [])
        cadd, cdel, _na, _nb = ID.split_noise(raw_add, raw_del)
        fn = d.counts.get("functions", {})
        kalloc = {sec: dict(s) for sec, s in d.sections.items()
                  if sec.startswith("__DATA_CONST.__kalloc")
                  and s.get("prev") != s.get("next")}
        ctx[d.name] = {
            "prev_version": d.version.get("prev", ""),
            "next_version": d.version.get("next", ""),
            "functions": dict(fn),
            "functions_changed": bool(fn) and fn.get("prev") != fn.get("next"),
            "kalloc": kalloc,
            "same_size": list(d.same_size),
            "sym_added": d.symbols.get("added", []),
            "sym_removed": d.symbols.get("removed", []),
            "str_added": len(cadd), "str_removed": len(cdel),
            "str_examples": cadd[:6],
            "str_added_all": cadd, "str_removed_all": cdel,
            "code_signal": bool(cadd or cdel or kalloc or d.same_size
                                or d.symbols.get("added") or d.symbols.get("removed")
                                or (fn and fn.get("prev") != fn.get("next"))),
        }
    return ctx


def analyse(ds: ID.Dataset, pair: ID.Pair, each: list[str] | None,
            jobs: int) -> tuple[list[dict], dict[str, dict]]:
    diffs = ID.pair_diffs(ds, pair, "kernel", None, jobs=jobs)
    by_kext = {d.name: d for d in diffs}
    if not diffs:
        # Some published pairs carry a Kernel version table but no Kexts
        # section at all: nothing changed below the kernel banner. That is an
        # answer (no group can be affected), not a failure — but say which case
        # it is instead of printing an empty table.
        if "## Kernel" in pair.readme:
            raise NothingToVerify(
                f"{pair.dir}: the dataset lists no changed kext for this pair, so "
                f"no offset group can be affected (a valid empty answer, not a "
                f"parse failure)")
        raise NothingToVerify(
            f"{pair.dir}: this pair has no Kernel section (the dataset entry "
            f"holds no kernel/kext diff) - nothing to re-verify")
    if not any(d.kind == "diff" for d in diffs):
        raise ID.DatasetError(
            f"{pair.dir}: {len(diffs)} kext target(s) found but none parsed as a "
            f"diff - the dataset layout changed, do not trust an empty result"
        )
    kctx = kext_context(diffs)
    groups = group_offsets(read_offset_names())
    rows: list[dict] = []
    for struct, offsets in sorted(groups.items()):
        if each and struct not in each:
            continue
        owner = kext_owner(struct)
        td = by_kext.get(owner)
        terms = terms_for(struct, offsets)
        row: dict = {
            "struct": struct, "kext": owner, "offsets": sorted(offsets),
            "offset_count": len(offsets), "terms": terms,
            "hits": {}, "verdict": "quiet", "reason": [],
        }
        if td is None:
            row["verdict"] = "no-kext-delta"
            row["reason"].append(f"{owner} is not in this pair's changed-kext list")
            rows.append(row)
            continue
        cadd, cdel, _na, _nb = ID.split_noise(td.cstrings.get("added", []),
                                             td.cstrings.get("removed", []))
        # Struct-specific evidence only: the kext-wide deltas (version bump,
        # function count, kalloc sections) are reported ONCE per kext, not
        # smeared across the ~29 struct groups that kext owns.
        for term in terms:
            rx = re.compile(re.escape(term), re.I)
            hits = {
                "added": [s for s in cadd if rx.search(s)],
                "removed": [s for s in cdel if rx.search(s)],
                "sym_added": [s for s in td.symbols.get("added", []) if rx.search(s)],
                "sym_removed": [s for s in td.symbols.get("removed", []) if rx.search(s)],
            }
            if any(hits.values()):
                row["hits"][term] = hits
        ctx = kctx.get(owner, {})
        if row["hits"]:
            row["verdict"] = "reverify"
            names = ", ".join(sorted(row["hits"]))
            row["reason"].append(f"{owner} delta names this struct ({names})")
            if ctx.get("kalloc"):
                row["reason"].append(
                    "and its kalloc descriptor sections resized: "
                    + ", ".join(f"{s} {v.get('prev')}->{v.get('next')}"
                                for s, v in ctx["kalloc"].items()))
        elif ctx.get("code_signal"):
            row["verdict"] = "kext-wide"
            bits = []
            if ctx.get("functions_changed"):
                bits.append(f"functions {ctx['functions'].get('prev')}->"
                            f"{ctx['functions'].get('next')}")
            if ctx.get("kalloc"):
                bits.append("kalloc sections resized")
            if ctx.get("str_added") or ctx.get("str_removed"):
                bits.append(f"{ctx['str_added']}+/{ctx['str_removed']}- strings")
            if ctx.get("same_size"):
                bits.append(f"{len(ctx['same_size'])} same-size changed sections")
            row["reason"].append(f"{owner} changed as a whole ({', '.join(bits)}) "
                                 f"but nothing in the delta names this struct")
        elif ctx and ctx.get("prev_version") != ctx.get("next_version"):
            row["verdict"] = "version"
            row["reason"].append(
                f"{owner} version {ctx.get('prev_version')} -> "
                f"{ctx.get('next_version')}, no other delta")
        rows.append(row)
    order = {"reverify": 0, "kext-wide": 1, "version": 2, "quiet": 3,
             "no-kext-delta": 4}
    rows.sort(key=lambda r: (order.get(r["verdict"], 9), r["struct"]))
    owners = sorted({r["kext"] for r in rows if r["kext"] in kctx})
    return rows, {o: kctx[o] for o in owners}


VERDICT_COLOR = {"reverify": "yellow", "kext-wide": "cyan", "version": "dim",
                 "quiet": "dim", "no-kext-delta": "dim"}


def _hits_lines(row: dict, args) -> list[str]:
    """Evidence lines (sign + string) for a row's struct-specific hits."""
    out = []
    for term, hits in sorted(row["hits"].items()):
        for s in hits["sym_added"][:2]:
            out.append(f"{term} + {s[:96]}")
        for s in hits["sym_removed"][:2]:
            out.append(f"{term} - {s[:96]}")
        for s in hits["added"][:2]:
            out.append(f"{term} + {s[:96]}")
        for s in hits["removed"][:2]:
            out.append(f"{term} - {s[:96]}")
    return out


def render(rows: list[dict], kctx: dict, args, out: ID.Out, ctx: dict) -> int:
    hot = [r for r in rows if r["verdict"] == "reverify"]
    wide = [r for r in rows if r["verdict"] == "kext-wide"]
    if args.json:
        print(json.dumps({"pair": ctx, "kext_context": kctx, "rows": rows,
                          "reverify": len(hot), "kext_wide": len(wide)},
                         indent=2))
        return 0
    print(out.bold(f"offsets drift: {ctx['prev']} -> {ctx['next']}  "
                   f"({ctx['dir']})"))
    print(out.dim(f"  dataset device {ctx['device']}   "
                  f"{len(rows)} struct group(s) in kexploit/offsets.h   "
                  f"{out.yellow(str(len(hot)) + ' reverify')} / "
                  f"{out.cyan(str(len(wide)) + ' kext-wide')}"))
    if hot:
        print()
        print(out.bold("re-verify these first"))
        for r in hot:
            print(f"  {out.yellow('reverify')} {r['struct']:<18} "
                  f"{r['offset_count']:>2} offset(s)  {out.dim(r['kext'])}")
            for reason in r["reason"]:
                print(f"           {out.dim(reason)}")
            for line in _hits_lines(r, args)[: args.max_hits]:
                print(f"           {line}")
            print(out.dim("           offsets: " + ", ".join(r["offsets"])))
    if wide:
        print()
        print(out.bold("kext changed as a whole (no struct-specific evidence)"))
        for r in wide:
            print(f"  {out.cyan('kext-wide')} {r['struct']:<18} "
                  f"{r['offset_count']:>2} offset(s)")
    print()
    print(out.bold("kext-level context"))
    for kext, c in sorted(kctx.items()):
        ver = ""
        if c.get("prev_version") or c.get("next_version"):
            ver = f" {c.get('prev_version')} -> {c.get('next_version')}"
        fn = ""
        if c.get("functions_changed"):
            fn = (f"  functions {c['functions'].get('prev')}->"
                  f"{c['functions'].get('next')}")
        kal = ""
        if c.get("kalloc"):
            kal = "  " + ", ".join(f"{s} {v.get('prev')}->{v.get('next')}"
                                   for s, v in c["kalloc"].items())
        print(f"  {kext}{ver}{fn}{kal}")
        if c.get("same_size"):
            print(out.dim(f"    same-size changed sections: "
                          f"{', '.join(c['same_size'])}"))
        if c.get("str_added") or c.get("str_removed"):
            print(out.dim(f"    {c['str_added']} string(s) added, "
                          f"{c['str_removed']} removed (timestamps filtered)"))
            for s in c.get("str_examples", [])[:3]:
                print(out.dim(f"      + {s[:96]}"))
    return 0


def write_report(rows: list[dict], kctx: dict, ctx: dict, args) -> Path:
    hot = [r for r in rows if r["verdict"] == "reverify"]
    wide = [r for r in rows if r["verdict"] == "kext-wide"]
    quiet = [r for r in rows if r["verdict"] not in ("reverify", "kext-wide")]
    REPORTS = report_dir(getattr(args, "out", None))
    REPORTS.mkdir(parents=True, exist_ok=True)
    stem = f"{ctx['prev']}__{ctx['next']}".replace(" ", "-").replace("/", "_")
    path = REPORTS / f"{stem}.md"
    lines = [
        f"# offsets drift: {ctx['prev']} -> {ctx['next']}",
        "",
        f"- dataset pair: `{ctx['dir']}` (device {ctx['device']}, {ctx['os']})",
        "- source: blacktop/ipsw-diffs, pre-computed `ipsw diff` of the two builds",
        f"- generated: {ctx['generated']} by scripts/offsets_drift.py",
        f"- offsets.h: {ctx['offset_names']} offsets in {ctx['struct_count']} struct groups",
        "- signal, not proof: a hit means RE-VERIFY, not 'the offset moved'",
        "",
        "## re-verify first",
        "",
    ]
    if not hot:
        lines += ["No struct group showed struct-specific evidence in this pair.", ""]
    for r in hot:
        lines.append(f"### `{r['struct']}` - {r['offset_count']} offset(s)")
        lines.append("")
        lines.append(f"- owning kext: `{r['kext']}`")
        for reason in r["reason"]:
            lines.append(f"- {reason}")
        lines.append("")
        lines.append("offsets in this group: "
                     + ", ".join(f"`{o}`" for o in r["offsets"]))
        lines.append("")
        for term, hits in sorted(r["hits"].items()):
            lines.append(f"token `{term}`:")
            lines.append("")
            for s in hits["sym_added"][: args.max_hits]:
                lines.append(f"    + {s}")
            for s in hits["sym_removed"][: args.max_hits]:
                lines.append(f"    - {s}")
            for s in hits["added"][: args.max_hits]:
                lines.append(f"    + {s}")
            for s in hits["removed"][: args.max_hits]:
                lines.append(f"    - {s}")
            lines.append("")
    lines += ["## kext-level context", ""]
    lines.append("Kext-wide deltas: they apply to every struct that kext owns, so "
                 "they are listed once here instead of on each group.")
    lines.append("")
    for kext, c in sorted(kctx.items()):
        bits = []
        if c.get("prev_version") or c.get("next_version"):
            bits.append(f"version {c.get('prev_version')} -> {c.get('next_version')}")
        if c.get("functions_changed"):
            bits.append(f"functions {c['functions'].get('prev')} -> "
                        f"{c['functions'].get('next')}")
        if c.get("kalloc"):
            bits.append("kalloc sections: " + ", ".join(
                f"`{s}` {v.get('prev')} -> {v.get('next')}"
                for s, v in c["kalloc"].items()))
        if c.get("same_size"):
            bits.append("same-size changed sections: "
                        + ", ".join(f"`{s}`" for s in c["same_size"]))
        if c.get("str_added") or c.get("str_removed"):
            bits.append(f"{c['str_added']} strings added / "
                        f"{c['str_removed']} removed (timestamps filtered)")
        if c.get("sym_added") or c.get("sym_removed"):
            bits.append(f"{len(c['sym_added'])} symbols added / "
                        f"{len(c['sym_removed'])} removed")
        lines.append(f"- `{kext}`: " + ("; ".join(bits) if bits else "no signal"))
    lines += ["", "### kext string deltas (evidence, unfiltered by struct)", ""]
    for kext, c in sorted(kctx.items()):
        add_all = c.get("str_added_all", [])
        rem_all = c.get("str_removed_all", [])
        if not add_all and not rem_all:
            continue
        lines.append(f"`{kext}` — {len(add_all)} added / {len(rem_all)} removed")
        lines.append("")
        for s in add_all[: args.max_hits * 6]:
            lines.append(f"    + {s}")
        for s in rem_all[: args.max_hits * 6]:
            lines.append(f"    - {s}")
        if len(add_all) > args.max_hits * 6 or len(rem_all) > args.max_hits * 6:
            lines.append(f"    ... truncated (raise --max-hits); full pair diff: "
                         f"`python3 scripts/ipswdiffs.py kexts {ctx['dir']} "
                         f"--all-strings`")
        lines.append("")
    lines += [
        "",
        "## kext changed as a whole",
        "",
        ", ".join(f"`{r['struct']}` ({r['offset_count']})" for r in wide) or "-",
        "",
        "## quiet groups",
        "",
        ", ".join(f"`{r['struct']}` ({r['verdict']})" for r in quiet) or "-",
        "",
        "## verify with",
        "",
        "- range-fetch the build's kernelcache: `python3 scripts/fetch_kernelcache.py <ipsw-url>`",
        "- poll/fetch/resolve/diff a board: `./W0lfSword kcwatch poll --board t8030`",
        "- zone fields off a kernelcache: `python3 scripts/kc_zone_fields.py <kc>`",
        "- table integrity: `python3 validate_offsets.py` and `python3 -m unittest tests.test_offsets -v`",
        "",
        "## caveats",
        "",
        "- The dataset diffs ONE device (iPhone18,1). Kext-level deltas track the",
        "  build; kernel text layout is per-SoC, so this is a re-verify list, not a",
        "  per-SoC offset diff.",
        "- `Symbols: 0` in these builds means no symbol lists were symbolicated;",
        "  cstring / function-count / kalloc-section deltas are the evidence.",
        "- Build-timestamp strings are filtered (scripts/ipswdiffs.py split_noise).",
        "",
    ]
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="offsets_drift.py", description=__doc__.splitlines()[0],
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("dir", nargs="?", default=None,
                   help="dataset pair dir (see `ipswdiffs index`)")
    p.add_argument("--pair", nargs=2, metavar=("PREV", "NEXT"),
                   help="builds or versions (23G71 23G83 / 26.6 26.6.1)")
    p.add_argument("--os", default="iOS")
    p.add_argument("--structs", default=None,
                   help="comma-separated struct filter (inpcb,socket,vnode)")
    p.add_argument("--cache", default=str(ID.DEFAULT_CACHE))
    p.add_argument("--jobs", type=int, default=8)
    p.add_argument("--max-hits", type=int, default=6)
    p.add_argument("--no-write", action="store_true")
    p.add_argument("--out", default=None,
                   help="report dir (env OFFSETS_DRIFT_DIR, default "
                        "<repo>/.w0lfsword/offsets-drift)")
    p.add_argument("--json", action="store_true")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--fail-on", choices=("never", "strings", "layout"),
                   default="never",
                   help="exit 3 when a group reaches this verdict (CI)")
    args = p.parse_args(argv)

    out = ID.Out(enabled=not args.no_color and not args.json and sys.stdout.isatty())
    ds = ID.Dataset(cache=args.cache, jobs=args.jobs)
    try:
        want = [args.dir] if args.dir else args.pair
        directory, entry = pair_dir_for(ds, want, args.os)
        pair = ID.load_pair(ds, directory)
        want = [s.strip() for s in args.structs.split(",")] if args.structs else None
        rows, kctx = analyse(ds, pair, want, args.jobs)
        ctx = {
            "dir": pair.dir, "prev": entry.prev_build or pair.dir,
            "next": entry.next_build or "", "os": entry.os,
            "device": next((i.split("_")[0] for i in pair.ipsws), "unknown"),
            "generated": __import__("datetime").date.today().isoformat(),
            "offset_names": len(read_offset_names()),
            "struct_count": len(rows),
        }
        if ctx["prev"] and ctx["next"]:
            ctx["prev"] = f"{entry.prev_version or ''} ({entry.prev_build})".strip()
            ctx["next"] = f"{entry.next_version or ''} ({entry.next_build})".strip()
        rc = render(rows, kctx, args, out, ctx)
        if not args.no_write and not args.json:
            path = write_report(rows, kctx, ctx, args)
            print(out.dim(f"  report {path.relative_to(ROOT)}"))
        if args.fail_on != "never":
            racked = (("reverify",) if args.fail_on == "layout"
                      else ("reverify", "kext-wide"))
            if any(r["verdict"] in racked for r in rows):
                return 3
        return rc
    except ID.DatasetError as exc:
        print(f"offsets_drift: {exc}", file=sys.stderr)
        return 2
    except NothingToVerify as exc:
        if args.json:
            print(json.dumps({"pair": args.pair or args.dir, "rows": [],
                              "reverify": 0, "kext_wide": 0, "note": str(exc)},
                             indent=2))
        else:
            print(f"offsets_drift: {exc}")
        return 0


if __name__ == "__main__":
    sys.exit(main())
