#!/usr/bin/env python3
"""ipswdiffs.py — query blacktop/ipsw-diffs without cloning it (3.4 GB repo).

The dataset holds, for every consecutive Apple build pair, a pre-computed
`ipsw diff` in markdown: kernel + kext symbol/section deltas, MachO and dylib
diffs, firmware (im4p/iBoot), entitlements, launchd, feature flags and the
file/removal lists. Everything is fetched per file from raw.githubusercontent
and cached locally — no IPSW download, no `ipsw` binary, no GitHub token.

What this gives the hunt that the local kernelcache tools cannot: a named,
symbolicated diff of *every* build pair (including the ones whose IPSW you
never downloaded), across all binaries, not just the kernelcache.

Layout of a pair directory (all paths are relative links inside its README):

    <dir>/README.md            manifest + kernel/iBoot/WebKit version tables
    <dir>/KEXTS/<bundle>.md    per-kext diff
    <dir>/MACHOS/<group>/...   per-binary diff (group = filesystem|SystemOS|AppOS|ExclaveOS)
    <dir>/DYLIBS/....md        dyld-shared-cache dylib diff
    <dir>/FIRMWARE/...md       firmware image diff
    <dir>/FILES/*.md           added/removed file lists
    <dir>/Entitlements.md      entitlement diff

Subcommands (all take --json for machine output; stdout stays clean):
    index                      every diff pair in the dataset
    resolve A B                find the pair dir for two builds/versions
    info DIR                   pair summary: versions, counts per section
    list DIR [--section S]     manifest entries (targets)
    kexts DIR                  kext deltas: versions, counts, symbols, cstrings
    symbols DIR                symbol adds/removes across the kernel + kexts
    dylibs DIR                 DSC dylib deltas
    firmware DIR               firmware image deltas
    files DIR                  added/removed filesystem paths
    ents DIR                   entitlement changes
    grep PATTERN DIR           search target diffs for a pattern
    sweep DIR --watchlist FILE ranked hit counts for many patterns at once
    show DIR TARGET            print one target's raw diff markdown
    fetch PATH                 raw dataset path -> stdout (e.g. <dir>/KEXTS/x.md)

Options: --cache DIR (env IPSWDIFFS_CACHE; default ~/.cache/ipswdiffs)
         --jobs N  --limit N  --section S  --watchlist FILE  --no-color

Examples:
    python3 scripts/ipswdiffs.py index
    python3 scripts/ipswdiffs.py kexts 26_6_23G71_vs_26_6_1_23G83 --json
    python3 scripts/ipswdiffs.py grep 'object_readonly' \
        26_6_23G71_vs_26_6_1_23G83 --section kernel
    python3 scripts/ipswdiffs.py sweep 26_6_23G71_vs_26_6_1_23G83 \
        --watchlist tools/ipswdiffs.watch.txt

Mirrored byte-for-byte in the ios-bounty-hunt tools/ tree.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

BASE = "https://raw.githubusercontent.com/blacktop/ipsw-diffs/main"
DEFAULT_CACHE = Path(
    os.environ.get("IPSWDIFFS_CACHE") or Path.home() / ".cache" / "ipswdiffs"
)
UA = "w0lfsword-ipswdiffs/1.0 (+local analysis; raw.githubusercontent)"

# Section keys -> which pair-dir subpaths they cover. "kernel" is the
# KEXTS/*.md set (the kernel itself is com.apple.kernel there).
SECTION_DIRS = {
    "kernel": ("KEXTS/",),
    "kexts": ("KEXTS/",),
    "macho": ("MACHOS/",),
    "dylibs": ("DYLIBS/",),
    "firmware": ("FIRMWARE/",),
    "files": ("FILES/",),
    "ents": ("Entitlements.md",),
    "dsc": ("DYLIBS/",),
}
# h2 a section lives under, for pairs that inline diffs in the README instead
# of writing one file per target (older dataset entries).
SECTION_LABELS = {
    "kernel": "kernel", "kexts": "kernel", "firmware": "firmware",
    "macho": "macho", "dylibs": "dsc", "dsc": "dsc", "files": "files",
}
SECTIONS = ("kernel", "kexts", "macho", "dylibs", "firmware", "files", "ents",
            "dsc", "all")
ALL_SECTIONS = ("kernel", "dylibs", "macho", "firmware")

GROUP_KIND = {"🆕": "new", "❌": "removed", "⬆️": "updated", "🔑": "index"}
KIND_MARK = {"new": "+", "removed": "-", "updated": "~", "index": "="}

# Build-time noise: every kext carries the compile timestamp/date, so a
# point release shows "+3str -3str" on nearly every binary without any code
# change. Filtered out by default (--all-strings keeps them), because a delta
# list dominated by "19:46:32" hides the one added ASSERT.
NOISE_RES = (
    re.compile(r"^\d{1,2}:\d{2}:\d{2}$"),
    re.compile(r"^(Mon|Tue|Wed|Thu|Fri|Sat|Sun)[a-z]*,?\s+\w+\s+\d{1,2}\s+\d{4}"),
    re.compile(r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{4}(\s+\d|\s*$)"),
    re.compile(r"^\d{4}[-/]\d{2}[-/]\d{2}([T ]|$)"),
    re.compile(r"^\d{1,2}:\d{2}:\d{2}\s+[A-Z][a-z]{2}\s+\d{1,2}\s+\d{4}$"),
    re.compile(r"^\d+\.\d+(\.\d+)*$"),
    re.compile(r"^(clang|Xcode|Apple LLVM)\b", re.I),
    re.compile(r"^Copyright \(c\)\s", re.I),
)
# A date/time appearing INSIDE a longer string ("... built 09:47:08 Aug  6
# 2026\n") — only used to recognise added/removed pairs that differ by nothing
# but the build stamp, so plain numeric constant changes stay visible.
DATEISH_RE = re.compile(
    r"\d{1,2}:\d{2}:\d{2}"
    r"|[A-Z][a-z]{2}\s+\d{1,2}\s+\d{4}"
    r"|\d{4}[-/]\d{2}[-/]\d{2}"
    r"|\bbuilt\s+\d"
)
DIGITS_RE = re.compile(r"\d+")
MONTHS_RE = re.compile(r"\b(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\b")
TZ_RE = re.compile(r"\b(P[DS]T|M[DS]T|C[DS]T|E[DS]T|UTC|GMT)\b")
WS_RE = re.compile(r"[ \t]+")


def is_noise(text: str) -> bool:
    return any(r.match(text) for r in NOISE_RES)


def _normalize(text: str) -> str:
    """Collapse everything that moves between two builds of the same source.

    Digits, month/timezone names and space runs (a C strftime %e pads the day:
    "Aug  6" vs "Jul 11"), so a format string carrying "built 09:47:08 Aug  6
    2026" matches its "built 14:47:32 Jul 11 2026" counterpart — otherwise
    every logging kext reads as a code change.
    """
    text = DIGITS_RE.sub("#", text)
    text = MONTHS_RE.sub("MMM", text)
    text = TZ_RE.sub("TZ", text)
    return WS_RE.sub(" ", text)


def split_noise(added: list[str], removed: list[str]) -> tuple[
        list[str], list[str], list[str], list[str]]:
    """(added_signal, removed_signal, added_noise, removed_noise).

    Two passes: strings that are *only* a build stamp, then added/removed pairs
    that differ by nothing but a build stamp inside a longer format string
    ("... built 09:47:08 Aug  6 2026"). Both would otherwise read as a code
    change on almost every binary in a point release.
    """
    an = [s for s in added if is_noise(s)]
    rn = [s for s in removed if is_noise(s)]
    asig = [s for s in added if not is_noise(s)]
    rsig = [s for s in removed if not is_noise(s)]

    removed_norm: dict[str, list[str]] = {}
    for s in rsig:
        removed_norm.setdefault(_normalize(s), []).append(s)
    keep_added = []
    for s in asig:
        if DATEISH_RE.search(s):
            twin = removed_norm.get(_normalize(s))
            if twin:
                an.append(s)
                rn.append(twin.pop(0))
                continue
        keep_added.append(s)
    asig = keep_added
    dropped = set(rn)
    rsig = [s for s in rsig if s not in dropped]
    return asig, rsig, an, rn


COUNT_KEYS = ("Functions", "Symbols", "CStrings")
SEC_RE = re.compile(r"^([ +-])\s+(__[A-Za-z0-9_.]+):\s+(0x[0-9a-f]+)\s*$")
COUNT_RE = re.compile(r"^([ +-])\s+(Functions|Symbols|CStrings):\s+(\d+)\s*$")
VERSION_RE = re.compile(r"^([ +-])([0-9][0-9A-Za-z.]*)\s*$")
SYMBOL_RE = re.compile(r"^([+-])\s(_[A-Za-z0-9_.$@]+)\s*$")
CSTRING_RE = re.compile(r"^([+-])\s(\".*\")\s*$")
LINK_RE = re.compile(r"^- \[(.+?)\]\((.+?)\)\s*$")
INLINE_NAME_RE = re.compile(r"^>\s+`(.+?)`\s*$")
HEAD_RE = re.compile(r"^(#{2,4})\s+(.*?)\s*$")


class DatasetError(RuntimeError):
    """Fetch or parse failure the caller must see (never silently empty)."""


# --------------------------------------------------------------------------- #
# fetch + cache
# --------------------------------------------------------------------------- #
class Dataset:
    def __init__(self, base: str = BASE, cache: Path = DEFAULT_CACHE,
                 jobs: int = 8, timeout: int = 30, progress: bool = False):
        self.base = base.rstrip("/")
        self.cache = Path(cache)
        self.jobs = jobs
        self.timeout = timeout
        self.progress = progress
        self._mem: dict[str, str] = {}

    def cache_path(self, rel: str) -> Path:
        return self.cache / rel

    def fetch(self, rel: str) -> str:
        """Fetch a dataset-relative path, cache it, return its text."""
        text = self.try_fetch(rel)
        if text is None:
            raise DatasetError(
                f"404 for {rel} — not in the dataset (check the dir name with "
                f"`index`; paths are case-sensitive)"
            )
        return text

    def try_fetch(self, rel: str) -> str | None:
        """Fetch, or return None when the path does not exist in the dataset."""
        rel = rel.lstrip("/")
        if rel in self._mem:
            return self._mem[rel]
        local = self.cache_path(rel)
        if local.is_file():
            try:
                text = local.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                raise DatasetError(f"cache read failed for {local}: {exc}") from exc
            self._mem[rel] = text
            return text
        url = f"{self.base}/{rel}"
        last = None
        for attempt in range(3):
            try:
                req = urllib.request.Request(url, headers={"User-Agent": UA})
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    text = resp.read().decode("utf-8", errors="replace")
                local.parent.mkdir(parents=True, exist_ok=True)
                tmp = local.with_suffix(local.suffix + ".tmp")
                tmp.write_text(text, encoding="utf-8")
                tmp.replace(local)
                self._mem[rel] = text
                return text
            except urllib.error.HTTPError as exc:
                if exc.code == 404:
                    return None
                last = exc
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                last = exc
            if attempt < 2:
                time.sleep(1.0 + attempt)
        raise DatasetError(f"fetch failed for {rel}: {last}")

    def fetch_many(self, rels: list[str]) -> dict[str, str | None]:
        """Fetch many paths concurrently; per-path failures land as None."""
        out: dict[str, str | None] = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.jobs) as pool:
            futs = {pool.submit(self.try_fetch, r): r for r in rels}
            for i, fut in enumerate(concurrent.futures.as_completed(futs), 1):
                rel = futs[fut]
                try:
                    out[rel] = fut.result()
                except DatasetError:
                    out[rel] = None
                if self.progress and i % 25 == 0:
                    print(f"  fetched {i}/{len(rels)}", file=sys.stderr)
        return out


# --------------------------------------------------------------------------- #
# index
# --------------------------------------------------------------------------- #
@dataclass
class Entry:
    os: str
    section: str
    label: str
    dir: str
    prev_version: str = ""
    prev_build: str = ""
    next_version: str = ""
    next_build: str = ""

    def as_dict(self) -> dict:
        return {
            "os": self.os, "section": self.section, "label": self.label,
            "dir": self.dir, "prev_version": self.prev_version,
            "prev_build": self.prev_build, "next_version": self.next_version,
            "next_build": self.next_build,
        }

    def keys(self) -> set[str]:
        vals = {self.dir, self.label, self.prev_build, self.next_build,
                self.prev_version, self.next_version,
                f"{self.prev_build}->{self.next_build}",
                f"{self.prev_version}->{self.next_version}"}
        return {v.lower().strip() for v in vals if v}


PAIR_RE = re.compile(r"^(.*?)\s*\(([0-9A-Za-z]+)\)\s*\.vs\s*(.*?)\s*\(([0-9A-Za-z]+)\)\s*$")


BUILD_RE = re.compile(r"[0-9]{2}[A-Z][0-9]{2,6}[a-z]?(?![0-9A-Za-z])")


def _builds_from_dir(dirname: str) -> tuple[str, str]:
    """Fallback for labels the strict pattern cannot read (`... **OTAs**`).

    The directory name is what the dataset actually uses, so derive the builds
    from it: `23D8133__iPhone17,1__vs_23D771330a__iPhone17,1`.
    """
    if not re.search(r"_+vs_+", dirname):
        return "", ""
    left, right = re.split(r"_+vs_+", dirname, maxsplit=1)
    lm = BUILD_RE.search(left)
    rm = BUILD_RE.search(right)
    return (lm.group(0) if lm else ""), (rm.group(0) if rm else "")


def parse_index(text: str) -> list[Entry]:
    """Parse the dataset root README (its quick-nav + per-OS sections)."""
    entries: list[Entry] = []
    section = os_name = ""
    for line in text.splitlines():
        m = re.match(r"^###\s+(.+?)\s*$", line)
        if m:
            section = m.group(1)
            os_name = section.split()[0] if section.split() else ""
            continue
        m = LINK_RE.match(line)
        if not m or not m.group(2).endswith("/README.md"):
            continue
        label, link = m.group(1), m.group(2)
        dirpath = link[: -len("/README.md")]
        pm = PAIR_RE.match(label)
        e = Entry(os=os_name or "?", section=section, label=label, dir=dirpath)
        if pm:
            e.prev_version, e.prev_build = pm.group(1).strip(), pm.group(2)
            e.next_version, e.next_build = pm.group(3).strip(), pm.group(4)
        else:
            e.prev_build, e.next_build = _builds_from_dir(dirpath)
        entries.append(e)
    return entries


def resolve_pair(entries: list[Entry], a: str, b: str | None = None) -> list[Entry]:
    """Match a pair by build numbers, versions, or the directory name."""
    if b is None:
        want = a.lower().strip()
        return [e for e in entries if want in e.keys()]
    wa, wb = a.lower().strip(), b.lower().strip()
    hits = []
    for e in entries:
        first = {e.prev_build.lower(), e.prev_version.lower()}
        second = {e.next_build.lower(), e.next_version.lower()}
        if (wa in first and wb in second) or (wa in second and wb in first):
            hits.append(e)
    return hits


# --------------------------------------------------------------------------- #
# pair manifest
# --------------------------------------------------------------------------- #
@dataclass
class ManifestEntry:
    section: str
    sub: str
    group: str
    label: str
    link: str
    kind: str = "updated"

    def as_dict(self) -> dict:
        return {"section": self.section, "sub": self.sub, "group": self.group,
                "label": self.label, "link": self.link, "kind": self.kind}


@dataclass
class Pair:
    dir: str
    label: str = ""
    readme: str = ""
    ipsws: list[str] = field(default_factory=list)
    tables: dict[str, list[list[str]]] = field(default_factory=dict)
    entries: list[ManifestEntry] = field(default_factory=list)
    # Older dataset pairs inline the kernel/kext diffs in the README instead of
    # writing KEXTS/<name>.md, so those targets carry link "inline:<name>" and
    # their text lives here.
    inline: dict[str, str] = field(default_factory=dict)

    def targets(self, section: str | None = None,
                kind: str | None = None) -> list[ManifestEntry]:
        out = [e for e in self.entries if not e.link.endswith("README.md")]
        if section:
            keys = SECTION_DIRS.get(section, (section,))
            label = SECTION_LABELS.get(section)
            out = [e for e in out
                   if any(e.link.startswith(k) for k in keys)
                   or (label is not None and e.link.startswith("inline:")
                       and e.section.lower().startswith(label))]
        if kind:
            out = [e for e in out if e.kind == kind]
        return out

    def rel_path(self, link: str) -> str:
        return f"{self.dir}/{link}"


def parse_pair(directory: str, readme: str) -> Pair:
    """Walk the pair README: headings give context, links give the targets."""
    p = Pair(dir=directory, readme=readme)
    first = readme.splitlines()[0] if readme else ""
    m = re.match(r"^#\s+(.+?)\s*$", first)
    if m:
        p.label = m.group(1)
    section = sub = group = ""
    table_name = ""
    pending_inline: str | None = None
    pending_kind = "updated"
    inline_lines: list[str] = []
    in_inline_fence = False
    for line in readme.splitlines():
        if in_inline_fence:
            if line.strip() == "```":
                in_inline_fence = False
                if pending_inline:
                    p.inline[pending_inline] = ("```diff\n"
                                                + "\n".join(inline_lines) + "\n```\n")
                    p.entries.append(ManifestEntry(
                        section, sub, group, pending_inline,
                        f"inline:{pending_inline}", pending_kind))
                pending_inline, inline_lines = None, []
                continue
            inline_lines.append(line)
            continue
        hm = HEAD_RE.match(line)
        if hm:
            level, title = len(hm.group(1)), hm.group(2)
            if level == 2:
                section, sub, group = title, "", ""
                table_name = title
            elif level == 3:
                sub, group = title, ""
                table_name = title
            else:
                group = title
                table_name = ""
            continue
        bm = INLINE_NAME_RE.match(line)
        if bm:
            pending_inline = bm.group(1)
            pending_kind = "updated"
            for mark, k in GROUP_KIND.items():
                if group.startswith(mark) or (not group and sub.startswith(mark)):
                    pending_kind = k
                    break
            continue
        if pending_inline and line.strip().startswith("```diff"):
            in_inline_fence = True
            continue
        lm = LINK_RE.match(line)
        if lm:
            label, link = lm.group(1), lm.group(2)
            if link.endswith("README.md"):
                continue
            kind = "updated"
            for mark, k in GROUP_KIND.items():
                if group.startswith(mark) or (not group and sub.startswith(mark)):
                    kind = k
                    break
            if group and group.startswith("filesystem"):
                kind = "new" if sub.startswith("🆕") else (
                    "removed" if sub.startswith("❌") else kind)
            p.entries.append(ManifestEntry(section, sub, group, label, link, kind))
            continue
        if line.startswith("|") and table_name:
            cells = [c.strip() for c in line.strip("|").split("|")]
            if all(set(c) <= set(":- ") for c in cells):
                continue
            p.tables.setdefault(table_name, []).append(cells)
            continue
        if line.startswith("- `") and line.endswith("`"):
            p.ipsws.append(line[3:-1])
    # section titles repeat across OS containers ("Kexts" under Kernel); keep
    # the h2 as the section key and let `sub` carry the detail.
    for e in p.entries:
        if e.section.lower() == "kernel" and e.sub.lower() == "kexts":
            e.section = "Kernel"
    return p


# --------------------------------------------------------------------------- #
# target diffs
# --------------------------------------------------------------------------- #
@dataclass
class TargetDiff:
    name: str
    path: str
    version: dict[str, str] = field(default_factory=dict)
    sections: dict[str, dict[str, str]] = field(default_factory=dict)
    counts: dict[str, dict[str, int]] = field(default_factory=dict)
    symbols: dict[str, list[str]] = field(default_factory=dict)
    cstrings: dict[str, list[str]] = field(default_factory=dict)
    same_size: list[str] = field(default_factory=list)
    raw: str = ""
    kind: str = "diff"

    def as_dict(self) -> dict:
        return {"name": self.name, "path": self.path, "kind": self.kind,
                "version": self.version, "sections": self.sections,
                "counts": self.counts, "symbols": self.symbols,
                "cstrings": self.cstrings, "same_size": self.same_size}


def parse_target(name: str, path: str, text: str) -> TargetDiff:
    """Parse one per-target diff file (fenced ```diff block)."""
    td = TargetDiff(name=name, path=path, raw=text)
    # `### Sections with Same Size but Changed Content` sits OUTSIDE the fenced
    # block (it is a note about the binary, not a line of the diff), so scan the
    # whole file for it.
    for sm in re.finditer(r"^- `(__[A-Za-z0-9_.]+)`\s*$", text, re.M):
        td.same_size.append(sm.group(1))
    m = re.search(r"```diff\n(.*?)```", text, re.S)
    if not m:
        td.kind = "list"
        return td
    body = m.group(1)
    for line in body.splitlines():
        sm = SEC_RE.match(line)
        if sm:
            key, val, mark = sm.group(2), sm.group(3), sm.group(1)
            slot = td.sections.setdefault(key, {})
            if mark == "+":
                slot["next"] = val
            elif mark == "-":
                slot["prev"] = val
            else:  # unchanged: the dataset prints it once, unprefixed
                slot["prev"] = slot["next"] = val
            continue
        cm = COUNT_RE.match(line)
        if cm:
            slot = td.counts.setdefault(cm.group(2).lower(), {})
            val = int(cm.group(3))
            if cm.group(1) == "+":
                slot["next"] = val
            elif cm.group(1) == "-":
                slot["prev"] = val
            else:
                slot["prev"] = slot["next"] = val
            continue
        # The bundle version is the first line(s) of the block, before the
        # section dump; both sides are needed, so accept a second match.
        vm = VERSION_RE.match(line) if not td.sections else None
        if vm and not (td.version.get("prev") and td.version.get("next")):
            side = "prev" if vm.group(1) in "- " else "next"
            td.version[side] = vm.group(2)
            if vm.group(1) == " ":
                td.version["prev"] = td.version["next"] = vm.group(2)
            continue
        sym = SYMBOL_RE.match(line)
        if sym:
            side = "added" if sym.group(1) == "+" else "removed"
            td.symbols.setdefault(side, []).append(sym.group(2))
            continue
        cstr = CSTRING_RE.match(line)
        if cstr:
            side = "added" if cstr.group(1) == "+" else "removed"
            td.cstrings.setdefault(side, []).append(cstr.group(2).strip('"'))
            continue
    return td


# --------------------------------------------------------------------------- #
# rendering helpers
# --------------------------------------------------------------------------- #
class Out:
    """Colour is applied at the print site only; --json bypasses it entirely."""

    def __init__(self, enabled: bool = True):
        self.enabled = enabled

    def c(self, s: str, code: str) -> str:
        return f"\033[{code}m{s}\033[0m" if self.enabled else s

    def dim(self, s):    return self.c(s, "2")
    def bold(self, s):   return self.c(s, "1")
    def green(self, s):  return self.c(s, "32")
    def red(self, s):    return self.c(s, "31")
    def yellow(self, s): return self.c(s, "33")
    def cyan(self, s):   return self.c(s, "36")


def emit(payload: dict, out: Out, human) -> int:
    """--json prints nothing else on stdout. Ever."""
    if payload.get("__json__"):
        print(json.dumps(payload["data"], indent=2, sort_keys=False))
        return 0
    return human(out)


# --------------------------------------------------------------------------- #
# subcommands
# --------------------------------------------------------------------------- #
def cmd_index(ds: Dataset, args, out: Out) -> int:
    entries = parse_index(ds.fetch("README.md"))
    if args.json:
        print(json.dumps([e.as_dict() for e in entries], indent=2))
        return 0
    if not entries:
        raise DatasetError("index parse produced 0 pairs — dataset layout changed?")
    by_os: dict[str, list[Entry]] = {}
    for e in entries:
        by_os.setdefault(e.os, []).append(e)
    print(out.bold(f"ipsw-diffs: {len(entries)} build pairs"))
    print(out.dim(f"  cache {ds.cache}   base {ds.base}"))
    width = max((len(e.dir) for e in entries), default=44)
    for osname, lst in by_os.items():
        print()
        print(out.bold(f"{osname} ({len(lst)})"))
        for e in lst:
            print(f"  {e.dir:<{width}} {e.prev_build:>10} -> {e.next_build:<10} "
                  f"{out.dim(e.section)}")
    return 0


def load_pair(ds: Dataset, directory: str) -> Pair:
    text = ds.fetch(f"{directory}/README.md")
    p = parse_pair(directory, text)
    if not p.entries:
        raise DatasetError(
            f"{directory}: no targets parsed — is this a pair dir? "
            f"(`index` lists them; note the links are case-sensitive)"
        )
    return p


def _pair_and_entry(ds: Dataset, args) -> tuple[Pair, Entry]:
    entries = parse_index(ds.fetch("README.md"))
    want = getattr(args, "pair", None)
    if want:
        if len(want) == 1:
            directory = want[0]
            entry = next((e for e in entries if e.dir == directory), None)
            if entry is None:
                raise DatasetError(f"no pair dir {directory!r}; run `index`")
            return load_pair(ds, directory), entry
        hits = resolve_pair(entries, want[0], want[1])
        if not hits:
            raise DatasetError(
                f"no pair matches {want[0]!r} -> {want[1]!r}; run `index` and "
                f"pass either the dir name or the two builds (e.g. 23G71 23G83)"
            )
        if len(hits) > 1:
            names = ", ".join(h.dir for h in hits)
            raise DatasetError(f"{len(hits)} pairs match: {names} — use the dir")
        return load_pair(ds, hits[0].dir), hits[0]
    directory = args.dir
    if not directory:
        raise DatasetError("give a pair dir (see `index`) or --pair PREV NEXT")
    entry = next((e for e in entries if e.dir == directory), None)
    if entry is None:
        entry = Entry(os=args.dir.split("_", 1)[0] or "?", section="?",
                      label=directory, dir=directory)
    return load_pair(ds, directory), entry


def cmd_info(ds: Dataset, args, out: Out) -> int:
    pair, entry = _pair_and_entry(ds, args)
    counts: dict[str, dict[str, int]] = {}
    for e in pair.entries:
        key = e.section or "?"
        slot = counts.setdefault(key, {"new": 0, "removed": 0, "updated": 0,
                                       "total": 0, "index": 0})
        slot[e.kind] = slot.get(e.kind, 0) + 1
        slot["total"] += 1
    data = {
        "dir": pair.dir, "label": pair.label, "os": entry.os,
        "prev_version": entry.prev_version, "prev_build": entry.prev_build,
        "next_version": entry.next_version, "next_build": entry.next_build,
        "ipsws": pair.ipsws, "tables": pair.tables, "sections": counts,
        "target_count": len(pair.targets()),
    }
    if args.json:
        print(json.dumps(data, indent=2))
        return 0
    print(out.bold(f"{pair.label or pair.dir}"))
    print(f"  dir      {pair.dir}")
    if pair.ipsws:
        for i in pair.ipsws:
            print(out.dim(f"  ipsw     {i}"))
    for tname in ("Version", "iBoot", "WebKit"):
        rows = pair.tables.get(tname)
        if not rows:
            continue
        print()
        print(out.cyan(f"{tname}"))
        for row in rows:
            print("  " + "  ".join(f"{c:<28}" for c in row).rstrip())
    print()
    print(out.cyan("sections"))
    for name, slot in sorted(counts.items()):
        print(f"  {name:<16} total={slot['total']:<5} "
              f"{out.green('+' + str(slot.get('new', 0)))} "
              f"{out.red('-' + str(slot.get('removed', 0)))} "
              f"{out.yellow('~' + str(slot.get('updated', 0)))}")
    return 0


def cmd_list(ds: Dataset, args, out: Out) -> int:
    pair, _ = _pair_and_entry(ds, args)
    ents = pair.targets(args.section, args.kind)
    if args.limit:
        ents = ents[: args.limit]
    if args.json:
        print(json.dumps([e.as_dict() for e in ents], indent=2))
        return 0
    for e in ents:
        print(f"{KIND_MARK.get(e.kind, '?')} {e.label:<40} {out.dim(e.link)}")
    print(out.dim(f"{len(ents)} target(s)") + (
        out.dim("  (raise --limit to see more)") if args.limit else ""))
    return 0


def pair_diffs(ds: Dataset, pair: Pair, section: str | None = None,
               kind: str | None = None, jobs: int = 8,
               progress: bool = False) -> list[TargetDiff]:
    ents = pair.targets(section, kind)
    out: list[TargetDiff] = []
    remote = [(e, pair.rel_path(e.link)) for e in ents
              if not e.link.startswith("inline:")]
    texts = (Dataset(base=ds.base, cache=ds.cache, jobs=jobs,
                     progress=progress).fetch_many([r for _e, r in remote])
             if remote else {})
    fetched = {e.link: texts.get(r) for e, r in remote}
    for e in ents:
        if e.link.startswith("inline:"):
            text = pair.inline.get(e.label)
        else:
            text = fetched.get(e.link)
        if text is None:
            out.append(TargetDiff(name=e.label, path=e.link, kind="missing"))
            continue
        out.append(parse_target(e.label, e.link, text))
    return out


def cmd_kexts(ds: Dataset, args, out: Out) -> int:
    pair, _ = _pair_and_entry(ds, args)
    diffs = pair_diffs(ds, pair, "kernel", None, jobs=args.jobs,
                       progress=not args.json and args.progress)
    rows = []
    for td in diffs:
        raw_add = td.cstrings.get("added", [])
        raw_del = td.cstrings.get("removed", [])
        cadd, cdel, cadd_noise, cdel_noise = split_noise(raw_add, raw_del)
        if args.all_strings:
            cadd, cdel = raw_add, raw_del
            cadd_noise, cdel_noise = [], []
        kt = td.sections.get("__DATA_CONST.__kalloc_type", {})
        kv = td.sections.get("__DATA_CONST.__kalloc_var", {})
        kt_changed = bool(kt) and kt.get("prev") != kt.get("next")
        kv_changed = bool(kv) and kv.get("prev") != kv.get("next")
        fn = td.counts.get("functions", {})
        rec = {
            "kext": td.name, "path": td.path, "kind": td.kind,
            "prev": td.version.get("prev", ""), "next": td.version.get("next", ""),
            "version_changed": bool(td.version.get("prev", "")
                                    and td.version.get("prev") != td.version.get("next")),
            "functions": fn,
            "functions_changed": bool(fn) and fn.get("prev") != fn.get("next"),
            "kalloc_type": kt, "kalloc_var": kv,
            "kalloc_type_changed": kt_changed, "kalloc_var_changed": kv_changed,
            "same_size_changed": td.same_size,
            "sym_added": td.symbols.get("added", []),
            "sym_removed": td.symbols.get("removed", []),
            "cstr_added": cadd, "cstr_removed": cdel,
            "cstr_added_noise": len(cadd_noise), "cstr_removed_noise": len(cdel_noise),
        }
        rec["signal"] = bool(rec["sym_added"] or rec["sym_removed"] or cadd or cdel
                             or kt_changed or kv_changed or td.same_size
                             or rec["functions_changed"])
        rec["changed"] = rec["signal"] or rec["version_changed"] or bool(
            raw_add or raw_del)
        if args.grep:
            rx = re.compile(args.grep, re.I)
            rec["changed"] = rec["changed"] or bool(rx.search(td.raw))
        rows.append(rec)
    rows.sort(key=lambda r: (not r["signal"], not r["changed"], r["kext"]))
    if args.changed_only:
        rows = [r for r in rows if r["changed"]]
    if args.limit:
        rows = rows[: args.limit]
    signals = [r for r in rows if r["signal"]]
    if args.json:
        print(json.dumps({"dir": pair.dir, "kexts": rows,
                          "signal_count": len(signals),
                          "noise_filtered": not args.all_strings}, indent=2))
        return 0
    print(out.bold(f"{pair.dir}: {len(rows)} kext(s), "
                   f"{len(signals)} with code-change signals"))
    if not args.all_strings:
        print(out.dim("  build-timestamp strings filtered; --all-strings to keep"))
    print(out.dim("  ! = code signal (symbols/sections/strings), ~ = version or "
                  "timestamp only"))
    for r in rows:
        prev, nxt = r["prev"], r["next"]
        if prev and nxt:
            v = f"{prev} -> {nxt}" if prev != nxt else f"{prev}"
        elif prev or nxt:
            v = f"{prev or nxt} (one side only)"
        else:
            v = "(no version line)"
        if len(v) > 40:
            v = v[:37] + "..."
        flags = ""
        if r["sym_added"]:
            flags += out.green(f" +{len(r['sym_added'])}sym")
        if r["sym_removed"]:
            flags += out.red(f" -{len(r['sym_removed'])}sym")
        if r["cstr_added"]:
            flags += out.green(f" +{len(r['cstr_added'])}str")
        if r["cstr_removed"]:
            flags += out.red(f" -{len(r['cstr_removed'])}str")
        if r["kalloc_type_changed"]:
            flags += out.yellow(" kalloc_type"
                                f" {r['kalloc_type'].get('prev')}->{r['kalloc_type'].get('next')}")
        if r["kalloc_var_changed"]:
            flags += out.yellow(" kalloc_var")
        if r["functions_changed"]:
            flags += out.dim(f" functions {r['functions'].get('prev')}->"
                             f"{r['functions'].get('next')}")
        if r["same_size_changed"]:
            flags += out.yellow(f" same-size-changed({len(r['same_size_changed'])})")
        mark = out.yellow("!") if r["signal"] else ("~" if r["changed"] else " ")
        print(f"{mark} {r['kext']:<56} {v}{flags}")
        for s in r["sym_added"][: args.max_hits]:
            print(out.green(f"      + {s}"))
        for s in r["sym_removed"][: args.max_hits]:
            print(out.red(f"      - {s}"))
        for s in r["cstr_added"][: args.max_hits]:
            print(out.green(f"      + {s}"))
        for s in r["cstr_removed"][: args.max_hits]:
            print(out.red(f"      - {s}"))
    return 0


def cmd_symbols(ds: Dataset, args, out: Out) -> int:
    pair, _ = _pair_and_entry(ds, args)
    diffs = pair_diffs(ds, pair, "kernel", None, jobs=args.jobs,
                          progress=not args.json and args.progress)
    data = {}
    for td in diffs:
        if not (td.symbols.get("added") or td.symbols.get("removed")):
            continue
        data[td.name] = {"added": td.symbols.get("added", []),
                         "removed": td.symbols.get("removed", [])}
    if args.json:
        print(json.dumps({"dir": pair.dir, "symbols": data}, indent=2))
        return 0
    if not data:
        print(out.dim(
            f"{pair.dir}: no symbol lists in this pair — the dataset records "
            f"`Symbols: 0` for these builds (no symbolicator signatures for "
            f"this version). Use kexts/cstrings + `files` instead."))
        return 0
    for kext, slot in sorted(data.items()):
        print(out.bold(kext))
        for s in slot["added"]:
            print(out.green(f"  + {s}"))
        for s in slot["removed"]:
            print(out.red(f"  - {s}"))
    return 0


def _section_picker(ds: Dataset, pair: Pair, args, out: Out,
                    want_sections: list[str]) -> list[ManifestEntry]:
    ents: list[ManifestEntry] = []
    seen = set()
    for s in want_sections:
        for e in pair.targets(s, args.kind):
            if e.link in seen:
                continue
            seen.add(e.link)
            ents.append(e)
    if args.limit:
        ents = ents[: args.limit]
    return ents


def cmd_section(ds: Dataset, args, out: Out, sections: list[str]) -> int:
    """dylibs / firmware / files / ents: fetch the section's targets and report."""
    pair, _ = _pair_and_entry(ds, args)
    if sections == ["files"]:
        return _cmd_files(ds, pair, args, out)
    if sections == ["ents"]:
        return _cmd_ents(ds, pair, args, out)
    ents = _section_picker(ds, pair, args, out, sections)
    diffs = _diff_for_pair_by_entries(ds, pair, ents, args)
    all_strings = getattr(args, "all_strings", False)
    rows = []
    for d in diffs:
        raw_add = d.cstrings.get("added", [])
        raw_del = d.cstrings.get("removed", [])
        cadd, cdel, cadd_noise, cdel_noise = split_noise(raw_add, raw_del)
        if all_strings:
            cadd, cdel = raw_add, raw_del
        rows.append({"label": d.name, "path": d.path, "kind": d.kind,
                     "version": d.version,
                     "sym_added": d.symbols.get("added", []),
                     "sym_removed": d.symbols.get("removed", []),
                     "cstr_added": cadd, "cstr_removed": cdel,
                     "noise": len(cadd_noise) + len(cdel_noise)})
    if args.changed_only:
        rows = [r for r in rows if r["sym_added"] or r["sym_removed"]
                or r["cstr_added"] or r["cstr_removed"]]
    if args.grep:
        rx = re.compile(args.grep, re.I)
        rows = [r for r, d in zip(rows, diffs) if rx.search(d.raw)]
    rows.sort(key=lambda r: (not (r["sym_added"] or r["sym_removed"]
                                  or r["cstr_added"] or r["cstr_removed"]),
                             r["label"]))
    if args.json:
        print(json.dumps({"dir": pair.dir, "section": sections, "targets": rows},
                         indent=2))
        return 0
    print(out.bold(f"{pair.dir}: {len(rows)} target(s) in {'/'.join(sections)}"))
    if not all_strings:
        print(out.dim("  build-timestamp strings filtered; --all-strings to keep"))
    for r in rows:
        bits = []
        if r["sym_added"]:
            bits.append(out.green(f"+{len(r['sym_added'])}sym"))
        if r["sym_removed"]:
            bits.append(out.red(f"-{len(r['sym_removed'])}sym"))
        if r["cstr_added"]:
            bits.append(out.green(f"+{len(r['cstr_added'])}str"))
        if r["cstr_removed"]:
            bits.append(out.red(f"-{len(r['cstr_removed'])}str"))
        if r["noise"]:
            bits.append(out.dim(f"({r['noise']} timestamp)"))
        v = (f"{r['version'].get('prev','')} -> {r['version'].get('next','')}"
             if r["version"].get("prev", "") != r["version"].get("next", "")
             else "")
        print(f"  {r['label']:<48} {v:<28} {' '.join(bits)}")
        for s in (r["cstr_added"] or [])[: args.max_hits]:
            print(out.green(f"      + {s}"))
        for s in (r["cstr_removed"] or [])[: args.max_hits]:
            print(out.red(f"      - {s}"))
    return 0


def _diff_for_pair_by_entries(ds: Dataset, pair: Pair, ents: list[ManifestEntry],
                              args) -> list[TargetDiff]:
    out = []
    remote = [(e, pair.rel_path(e.link)) for e in ents
              if not e.link.startswith("inline:")]
    texts = (Dataset(base=ds.base, cache=ds.cache, jobs=args.jobs,
                     progress=not args.json and args.progress)
             .fetch_many([r for _e, r in remote]) if remote else {})
    fetched = {e.link: texts.get(r) for e, r in remote}
    for e in ents:
        text = (pair.inline.get(e.label) if e.link.startswith("inline:")
                else fetched.get(e.link))
        out.append(parse_target(e.label, e.link, text) if text is not None
                   else TargetDiff(name=e.label, path=e.link, kind="missing"))
    return out


def _cmd_files(ds: Dataset, pair: Pair, args, out: Out) -> int:
    ents = pair.targets("files")
    rels = [pair.rel_path(e.link) for e in ents]
    texts = ds.fetch_many(rels) if rels else {}
    data = {}
    for e, rel in zip(ents, rels):
        text = texts.get(rel)
        if text is None:
            continue
        paths = [l[2:].strip().strip("`") for l in text.splitlines()
                 if l.startswith("- ")]
        key = " ".join(x for x in (e.sub, e.group) if x).strip() or e.label
        data[key] = paths
    if args.json:
        print(json.dumps({"dir": pair.dir, "files": data}, indent=2))
        return 0
    if not data:
        print(out.dim(f"{pair.dir}: no file lists in this pair"))
        return 0
    for label, paths in data.items():
        print(out.bold(label) + out.dim(f"  ({len(paths)})"))
        for p in paths[: args.max_hits or 40]:
            print(f"  {p}")
        if args.max_hits and len(paths) > args.max_hits:
            print(out.dim(f"  ... {len(paths) - args.max_hits} more"))
    return 0


def _cmd_ents(ds: Dataset, pair: Pair, args, out: Out) -> int:
    """Entitlements.md is one file holding many per-binary diff blocks."""
    rel = pair.rel_path("Entitlements.md")
    text = ds.try_fetch(rel)
    if text is None:
        print(out.dim(f"{pair.dir}: no Entitlements.md"))
        return 0
    blocks = []
    cur = {"name": "", "path": ""}
    for line in text.splitlines():
        hm = re.match(r"^###\s+(.+?)\s*$", line)
        if hm:
            cur = {"name": hm.group(1), "path": cur.get("path", "")}
            blocks.append(cur)
            continue
        pm = re.match(r"^>\s+`(.+?)`\s*$", line)
        if pm:
            if blocks:
                blocks[-1]["path"] = pm.group(1)
            continue
        if line.startswith("+") or line.startswith("-"):
            if not blocks:
                continue
            blocks[-1].setdefault("lines", []).append(line)
    for b in blocks:
        keys = {"added": [], "removed": []}
        for line in b.get("lines", []):
            km = re.search(r"<key>([^<]+)</key>", line)
            if not km:
                continue
            keys["added" if line.startswith("+") else "removed"].append(km.group(1))
        b["added_keys"] = keys["added"]
        b["removed_keys"] = keys["removed"]
    # `### AppOS` / `### filesystem` are container headings, not binaries.
    blocks = [b for b in blocks if b.get("path") or b["added_keys"]
              or b["removed_keys"]]
    if args.kind == "new":
        blocks = [b for b in blocks if b["added_keys"]]
    elif args.kind == "removed":
        blocks = [b for b in blocks if b["removed_keys"]]
    elif args.kind == "updated":
        blocks = [b for b in blocks if b["added_keys"] or b["removed_keys"]]
    if args.grep:
        rx = re.compile(args.grep, re.I)
        blocks = [b for b in blocks
                  if rx.search(" ".join(b["added_keys"] + b["removed_keys"]))]
    total_add = sum(len(b["added_keys"]) for b in blocks)
    total_del = sum(len(b["removed_keys"]) for b in blocks)
    if args.json:
        print(json.dumps({"dir": pair.dir, "path": rel, "binaries": len(blocks),
                          "entitlements_added": total_add,
                          "entitlements_removed": total_del,
                          "blocks": blocks}, indent=2))
        return 0
    print(out.bold(f"{rel}: {len(blocks)} binar(y|ies) with entitlement deltas, "
                   f"{out.green('+' + str(total_add))} {out.red('-' + str(total_del))} keys"))
    for b in blocks[: args.limit or len(blocks)]:
        print(f"  {b['name']}")
        print(out.dim(f"    {b['path']}"))
        for k in b["added_keys"][: args.max_hits]:
            print(out.green(f"      + {k}"))
        for k in b["removed_keys"][: args.max_hits]:
            print(out.red(f"      - {k}"))
        if not b["added_keys"] and not b["removed_keys"] and b.get("lines"):
            print(out.dim("      (non-key changes only)"))
    return 0


def _sections_for(arg: str | None, default: list[str]) -> list[str]:
    if not arg:
        return list(default)
    if arg == "all":
        return list(ALL_SECTIONS)
    return [arg]


def cmd_grep(ds: Dataset, args, out: Out) -> int:
    pair, _ = _pair_and_entry(ds, args)
    sections = _sections_for(args.section, ["kernel", "dylibs", "macho"])
    ents = _section_picker(ds, pair, args, out, sections)
    rx = re.compile(args.pattern, re.I if not args.case else 0)
    diffs = _diff_for_pair_by_entries(ds, pair, ents, args)
    hits = []
    for d in diffs:
        lines = [l for l in d.raw.splitlines() if rx.search(l)]
        if not lines:
            continue
        hits.append({"label": d.name, "path": d.path, "lines": lines})
    if args.json:
        print(json.dumps({"dir": pair.dir, "pattern": args.pattern,
                          "sections": sections, "hits": hits}, indent=2))
        return 0
    if not hits:
        print(out.dim(f"no hits for /{args.pattern}/ in {'/'.join(sections)} "
                      f"({len(ents)} target(s) searched, dir {pair.dir})"))
        return 1
    print(out.bold(f"/{args.pattern}/ — {len(hits)} target(s) "
                   f"of {len(ents)} searched in {pair.dir}"))
    for h in hits:
        print(out.cyan(h["label"]))
        for l in h["lines"][: args.max_hits or 2]:
            print("  " + (out.green(l) if l.startswith("+") else
                          out.red(l) if l.startswith("-") else l))
    return 0


def load_watchlist(path: str) -> list[str]:
    terms = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        terms.append(line)
    if not terms:
        raise DatasetError(f"watchlist {path} has no patterns")
    return terms


def cmd_sweep(ds: Dataset, args, out: Out) -> int:
    """Ranked hit counts for a whole watchlist against one build pair."""
    pair, _ = _pair_and_entry(ds, args)
    if not args.watchlist:
        raise DatasetError("sweep needs --watchlist FILE (one regex per line)")
    terms = load_watchlist(args.watchlist)
    sections = _sections_for(args.section, ["kernel", "dylibs"])
    ents = _section_picker(ds, pair, args, out, sections)
    diffs = _diff_for_pair_by_entries(ds, pair, ents, args)
    results = []
    for term in terms:
        rx = re.compile(term, re.I if not args.case else 0)
        per_target: dict[str, list[str]] = {}
        for d in diffs:
            lines = [l for l in d.raw.splitlines() if rx.search(l)]
            if lines:
                per_target[d.name] = lines
        if not per_target:
            results.append({"term": term, "targets": 0, "lines": 0, "hits": {}})
            continue
        results.append({
            "term": term, "targets": len(per_target),
            "lines": sum(len(v) for v in per_target.values()),
            "hits": {k: v[: args.max_hits or 3] for k, v in per_target.items()},
        })
    results.sort(key=lambda r: (-r["lines"], r["term"]))
    data = {"dir": pair.dir, "sections": sections,
            "targets_searched": len(diffs),
            "watchlist": args.watchlist, "results": results}
    if args.json:
        print(json.dumps(data, indent=2))
        return 0
    print(out.bold(f"sweep {pair.dir}  ({len(diffs)} targets, "
                   f"{' / '.join(sections)})"))
    print(out.dim(f"  watchlist {args.watchlist} ({len(terms)} patterns)"))
    for r in results:
        if not r["lines"]:
            print(out.dim(f"  {r['term']:<40} 0"))
            continue
        print(f"{out.yellow('*')} {r['term']:<40} {r['lines']:>4} line(s) in "
              f"{r['targets']} target(s)")
        for tname, lines in list(r["hits"].items())[: 3]:
            print(out.dim(f"    {tname}"))
            for l in lines:
                print("      " + (out.green(l) if l.startswith("+") else
                                  out.red(l) if l.startswith("-") else l))
    return 0


def cmd_show(ds: Dataset, args, out: Out) -> int:
    pair, _ = _pair_and_entry(ds, args)
    want = args.target.lower()
    match = None
    for e in pair.targets(args.section):
        if want == e.link.lower() or want == e.label.lower():
            match = e
            break
    if match is None:
        cands = [e for e in pair.targets(args.section) if want in e.label.lower()
                 or want in e.link.lower()]
        if not cands:
            raise DatasetError(f"{pair.dir}: no target matching {args.target!r} "
                               f"(try `list {pair.dir}`)")
        if len(cands) > 1 and not args.first:
            print(out.dim("several targets match:"))
            for c in cands[:20]:
                print(f"  {c.label}  {out.dim(c.link)}")
            return 1
        match = cands[0]
    if match.link.startswith("inline:"):
        text = pair.inline.get(match.label)
        if text is None:
            raise DatasetError(f"{pair.dir}: inline diff for {match.label!r} lost")
    else:
        text = ds.fetch(pair.rel_path(match.link))
    if args.json:
        print(json.dumps(parse_target(match.label, match.link, text).as_dict(),
                         indent=2))
        return 0
    print(text)
    return 0


def cmd_fetch(ds: Dataset, args, out: Out) -> int:
    text = ds.fetch(args.path)
    if args.json:
        print(json.dumps({"path": args.path, "bytes": len(text)}, indent=2))
        return 0
    print(text)
    return 0


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ipswdiffs.py", description=__doc__.splitlines()[0],
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--cache", default=str(DEFAULT_CACHE),
                   help="cache dir (env IPSWDIFFS_CACHE), default %(default)s")
    p.add_argument("--jobs", type=int, default=8, help="parallel fetches")
    p.add_argument("--json", action="store_true", help="machine output on stdout")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--progress", action="store_true",
                   help="progress on stderr (never with --json)")

    # The same globals are accepted AFTER the subcommand, which is how people
    # actually type them (`kexts <dir> --json`). SUPPRESS keeps the subparser
    # from overwriting a value already given before the subcommand.
    gp = argparse.ArgumentParser(add_help=False)
    gp.add_argument("--cache", default=argparse.SUPPRESS)
    gp.add_argument("--jobs", type=int, default=argparse.SUPPRESS)
    gp.add_argument("--json", action="store_true", default=argparse.SUPPRESS)
    gp.add_argument("--no-color", action="store_true", default=argparse.SUPPRESS)
    gp.add_argument("--progress", action="store_true", default=argparse.SUPPRESS)

    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp, with_dir=True, with_pair=False) -> argparse.ArgumentParser:
        sp.add_argument("--section", choices=SECTIONS, default=None)
        sp.add_argument("--kind", choices=("new", "removed", "updated"),
                        default=None)
        sp.add_argument("--limit", type=int, default=0)
        sp.add_argument("--max-hits", type=int, default=6)
        sp.add_argument("--grep", default=None)
        sp.add_argument("--case", action="store_true")
        if with_dir:
            sp.add_argument("dir", nargs="?", default=None)
        sp.add_argument("--pair", nargs="*", default=None, metavar="BUILD",
                        help="two builds/versions instead of a dir")
        return sp

    def add(name: str, help_: str, with_dir: bool = True,
            **kw) -> argparse.ArgumentParser:
        return common(sub.add_parser(name, help=help_, parents=[gp], **kw),
                      with_dir=with_dir)

    add("index", "every diff pair in the dataset")
    sp = sub.add_parser("resolve", help="find the pair dir for two builds",
                        parents=[gp])
    sp.add_argument("a"); sp.add_argument("b", nargs="?")
    add("info", "pair summary")
    add("list", "manifest entries")
    sp = add("kexts", "kext deltas")
    sp.add_argument("--changed-only", action="store_true")
    sp.add_argument("--all-strings", action="store_true",
                    help="keep build-timestamp strings (filtered by default)")
    add("symbols", "kernel/kext symbol deltas")
    for name in ("dylibs", "firmware"):
        sp = add(name, f"{name} deltas")
        sp.add_argument("--changed-only", action="store_true")
        sp.add_argument("--all-strings", action="store_true")
    add("files", "added/removed files")
    add("ents", "entitlement diff")
    sp = add("grep", "search target diffs", with_dir=False)
    sp.add_argument("pattern")                      # grep PATTERN DIR
    sp.add_argument("dir", nargs="?", default=None)
    sp = add("sweep", "ranked multi-pattern sweep")
    sp.add_argument("--watchlist", default=None)
    sp = add("show", "print one target's diff")
    sp.add_argument("target", nargs="?", default=None)
    sp.add_argument("--first", action="store_true")
    sp = sub.add_parser("fetch", help="raw dataset path -> stdout", parents=[gp])
    sp.add_argument("path")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    out = Out(enabled=not args.no_color and not args.json and sys.stdout.isatty())
    ds = Dataset(cache=args.cache, jobs=args.jobs, progress=args.progress)
    try:
        if args.cmd == "index":
            return cmd_index(ds, args, out)
        if args.cmd == "resolve":
            entries = parse_index(ds.fetch("README.md"))
            hits = resolve_pair(entries, args.a, args.b)
            if args.json:
                print(json.dumps([e.as_dict() for e in hits], indent=2))
                return 0 if hits else 1
            for e in hits:
                print(f"{e.dir}  {e.prev_build} -> {e.next_build}  ({e.label})")
            if not hits:
                print(out.dim(f"no pair matches {args.a} {args.b or ''}; "
                              f"run `index`"), file=sys.stderr)
                return 1
            return 0
        if args.cmd == "info":
            return cmd_info(ds, args, out)
        if args.cmd == "list":
            return cmd_list(ds, args, out)
        if args.cmd == "kexts":
            return cmd_kexts(ds, args, out)
        if args.cmd == "symbols":
            return cmd_symbols(ds, args, out)
        if args.cmd == "dylibs":
            return cmd_section(ds, args, out, ["dylibs"])
        if args.cmd == "firmware":
            return cmd_section(ds, args, out, ["firmware"])
        if args.cmd == "files":
            return cmd_section(ds, args, out, ["files"])
        if args.cmd == "ents":
            return cmd_section(ds, args, out, ["ents"])
        if args.cmd == "grep":
            return cmd_grep(ds, args, out)
        if args.cmd == "sweep":
            return cmd_sweep(ds, args, out)
        if args.cmd == "show":
            return cmd_show(ds, args, out)
        if args.cmd == "fetch":
            return cmd_fetch(ds, args, out)
    except DatasetError as exc:
        print(f"ipswdiffs: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130
    return 2


if __name__ == "__main__":
    sys.exit(main())
