#!/usr/bin/env python3
"""Host-only check for the two halves of the 2026-09-11 bug list that no kernel
code change can settle on this host, and that therefore had no artifact at all
before this script existed:

  BUG.1 (option 2: "probe a field with no concurrent reader ... never the icmp6
  filter pointer the kernel dereferences on the next packet")
      The shipped choice is `inp_depend6.inp6_chksum` (the qword at filt+8). What
      makes it safe is a property of the WHOLE shipped process, not of one line:
      nothing in the engine, the tweak or the app ever SENDS or RECEIVES on that
      socket, so no kernel path consumes the number the probe writes. That is
      checkable statically, and it is checked here - a `send()` added anywhere in
      the compiled sources fails this script.

  BUG.2 (REMAINING: "the scan writes randomMarker into EVERY page of every search
  mapping (~30 MB mapped and dirtied per pass), and the initial spray holds ~22.5k
  sockets ... those two are what the compressor swaps out, which is where the
  1.07 GB/18 min disk-write report comes from. Options: allocate/scan/free the
  mappings one at a time ... and/or limit the marker writes to the pages the walk
  actually reads.")
      That option is NOT implemented - deliberately: it changes a kernel path
      whose only verification is a device run. So instead of a note, the arithmetic
      is now PINNED: this script parses the real constants out of
      kexploit/kexploit_opa334.m, prints the bytes/pages/sockets each cycle maps
      and dirties, and fails if any of them grows. The device-day figure (1073.75
      MB dirtied in 1083 s) is the measurement; this is the regression guard on the
      side that can be checked without a phone.

      One correction that falls out of the parse: the item's "~30 MB mapped and
      dirtied per pass" does not match the source. With the Jetsam scaling a 3 GB
      SE2 gets `(3GB / 8) / 4096` = 98304 pages = 384 MB per cycle as 12 x 32 MB
      mappings - the engine's own comment on the allocate-failure path says
      "up to 12 x 32MB per cycle". The checker prints the table for every RAM
      class so the next device day can be compared against the real numbers.

  DISK BUDGET (the axis the whole bug list was reported on: 1073.75 MB dirtied in
  1083 s against the 1 GB/day limit iOS enforces per app)
      Both halves of the app that can dirty file-backed memory are counted here
      and pinned against that limit: the log sink's fsync (bounded by the BUG.6
      rate window - 3001 calls for a 600 s run) and the scan's per-page marker
      writes (384 MB per cycle x 7 cycles x 3 attempts = 8064 MB per run on the
      3 GB class, i.e. ~7.9x the limit). A constant change on either side fails the
      check, so the ratio cannot drift quietly. It is a regression guard, not a
      claim that the app fits the budget: the scan half does not fit, and the
      printed table says so instead of rounding it away.

Usage:
    python3 scripts/check_pressure_budget.py [--root .] [--wolfterm ../W0lfTerm]
    python3 scripts/check_pressure_budget.py --selftest

Exit 0 = every check passed (and, in selftest mode, every mutation was caught).
"""

import os
import re
import shutil
import sys
import tempfile

ENGINE_FILES = [
    "kexploit/kexploit_opa334.m",
    "kexploit/kexploit_opa334.h",
    # the log sink's rate window (BUG.6): the other half of the disk accounting
    "utils/tweak_log_policy.h",
    "scripts/build_libengine.sh",
]
APP_FILES = [
    "term_bridge.m",
    "TerminalViewController.m",
    "term_settings.m",
]

PAGE_SIZE = 0x1000

CHECKS = []
RESULTS = []


def check(name):
    def deco(fn):
        CHECKS.append((name, fn))
        return fn
    return deco


def report(ok, name, detail=""):
    RESULTS.append((bool(ok), name, detail))
    print("  %s %s%s" % ("ok  " if ok else "FAIL", name, (" - " + detail) if detail and not ok else ""))


def read(root, rel):
    try:
        with open(os.path.join(root, rel), "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


def strip_comments(text):
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    out = []
    for line in text.splitlines():
        cut = line.find("//")
        if cut >= 0 and line.count('"', 0, cut) % 2 == 0:
            line = line[:cut]
        out.append(line)
    return "\n".join(out)


def block(text, marker, open_ch="{"):
    """Body of the first block that starts at/after `marker` (brace counting)."""
    idx = text.find(marker)
    if idx < 0:
        return None
    depth = 0
    started = False
    for i in range(idx, len(text)):
        if text[i] == open_ch:
            depth += 1
            started = True
        elif text[i] == "}":
            depth -= 1
            if started and depth == 0:
                return text[idx:i + 1]
    return None


class Src:
    def __init__(self, root, wolfterm):
        self.root = root
        self.wolfterm = wolfterm
        self.engine = {rel: (read(root, rel) or "") for rel in ENGINE_FILES}
        self.app = {rel: (read(wolfterm, rel) or "") for rel in APP_FILES}
        self.missing = ([rel for rel in ENGINE_FILES if not read(root, rel)]
                        + [rel for rel in APP_FILES if not read(wolfterm, rel)])
        self.k = self.engine["kexploit/kexploit_opa334.m"]
        self.kh = self.engine["kexploit/kexploit_opa334.h"]
        self.policy_h = self.engine["utils/tweak_log_policy.h"]
        self.libe = self.engine["scripts/build_libengine.sh"]
        self.bridge = self.app["term_bridge.m"]

    def archive_sources(self):
        m = re.search(r'SOURCES="(.*?)"', self.libe, re.S)
        if not m:
            return None
        return [t for t in m.group(1).replace("\\\n", " ").split() if t]


def all_present(src):
    if src.missing:
        report(False, "every source this check reads exists", "missing: %s" % ", ".join(src.missing))
        return False
    report(True, "every source this check reads exists", "%d engine + %d app file(s)" % (len(ENGINE_FILES), len(APP_FILES)))
    return True


# ---------------------------------------------------------------------------
# the constants, parsed out of the engine (nothing here is copied by hand)
# ---------------------------------------------------------------------------
def parse_constants(src):
    k = src.k
    got = {}
    m = re.search(r"totalSearchMappingPagesNum = isA18Device \? \(([^)]*)\) : \(([^)]*)\);", k)
    got["pages_a18_expr"], got["pages_expr"] = (m.group(1), m.group(2)) if m else (None, None)
    m = re.search(r"if \(!isA18Device && physmem && physmem < ([\dULL \*]+)\)", k)
    got["scale_gate_expr"] = m.group(1).strip() if m else None
    m = re.search(r"uint64_t scaled = \(physmem / (\d+)\) / PAGE_SIZE;", k)
    got["scale_divisor"] = int(m.group(1)) if m else None
    m = re.search(r"uint64_t floor = \(physmem < ([\dULL \*]+)\) \? (0x[0-9a-fA-F]+) : (0x[0-9a-fA-F]+);", k)
    if m:
        got["small_ram_gate_expr"], got["floor_small"], got["floor_big"] = m.group(1).strip(), m.group(2), m.group(3)
    m = re.search(r"uint64_t searchMappingSize = isA18Device \? \(([^)]*)\) : \(([^)]*)\);", k)
    got["size_a18_expr"], got["size_expr"] = (m.group(1), m.group(2)) if m else (None, None)
    m = re.search(r"mach_vm_size_t searchMappingSize = (0x[0-9a-fA-F]+)ULL \* PAGE_SIZE;", k)
    got["pe_v2_size_expr"] = m.group(1) if m else None
    m = re.search(r"#define OPEN_MAX (\d+)", k)
    got["open_max"] = int(m.group(1)) if m else None
    m = re.search(r"int maxfiles = OPEN_MAX \* (\d+);", k)
    got["maxfiles_mult"] = int(m.group(1)) if m else None
    m = re.search(r"int leeway = (\d+) \* (\d+);", k)
    got["leeway"] = (int(m.group(1)) * int(m.group(2))) if m else None
    m = re.search(r"if \(cycle > (\d+)\)", k)
    got["max_cycles"] = int(m.group(1)) if m else None
    return got


def eval_expr(expr):
    """Evaluate a small C integer expression of the forms used in the file
    ((0x1000 * 0x10), (physmem / 8), (0x2000 * PAGE_SIZE), 8ULL * 1024 * 1024 * 1024)."""
    if expr is None:
        return None
    e = expr.replace("ULL", "").replace("PAGE_SIZE", str(PAGE_SIZE))
    e = e.replace("physmem", "0")
    if not re.fullmatch(r"[0-9a-fA-FxX\s\*\+\-/]+", e):
        return None
    try:
        return int(eval(e, {"__builtins__": {}}, {}))
    except Exception:
        return None


def derive(c, physmem_bytes):
    """The pages / mapping size / mapping count pe_v1 ends up with, exactly as the
    source computes them."""
    pages = eval_expr(c.get("pages_expr"))
    size = eval_expr(c.get("size_expr"))
    if pages is None or size in (None, 0):
        return None
    gate_expr, divisor = c.get("scale_gate_expr"), c.get("scale_divisor")
    if gate_expr and divisor:
        gate = eval_expr(gate_expr)
        if gate is not None and physmem_bytes and physmem_bytes < gate:
            scaled = (physmem_bytes // divisor) // PAGE_SIZE
            small_gate = eval_expr(c.get("small_ram_gate_expr"))
            if small_gate is not None and physmem_bytes < small_gate:
                floor = eval_expr(c.get("floor_small"))
            else:
                floor = eval_expr(c.get("floor_big"))
            if floor is not None and scaled < floor:
                scaled = floor
            pages = scaled
    total = pages * PAGE_SIZE
    return {"pages": pages, "total_bytes": total, "mapping_bytes": size, "mappings": total // size}


# 3 GB = the SE2/iPhone12,8 class the 2026-09-11 report came from; 4/6 GB = the
# other A13-A15 classes; 8 GB = past the scaling gate (the default applies).
# A18-class devices take the other branch of both ternaries.
GB = 1024 * 1024 * 1024
PINNED = [
    ("3 GB", 3 * GB, {"pages": 98304, "total_bytes": 402653184, "mapping_bytes": 0x2000000, "mappings": 12}),
    ("4 GB", 4 * GB, {"pages": 131072, "total_bytes": 536870912, "mapping_bytes": 0x2000000, "mappings": 16}),
    ("6 GB", 6 * GB, {"pages": 196608, "total_bytes": 805306368, "mapping_bytes": 0x2000000, "mappings": 24}),
    ("8 GB", 8 * GB, {"pages": 65536, "total_bytes": 268435456, "mapping_bytes": 0x2000000, "mappings": 8}),
]


@check("BUG.2 pressure: every page of every search mapping is still marked")
def c_marker_covers_every_page(src):
    k = strip_comments(src.k)
    # 2 expected: pe_v1's mapping loop and pe_v2's single-mapping walk. ONE pattern
    # (not two alternates) so a mutation that removes one loop really drops the count.
    loops = re.findall(
        r"for \((?:int|uint64_t) k = 0; k < searchMappingSize; k \+= PAGE_SIZE\) \{\s*\n"
        r"\s*\*\(uint64_t \*\)\(searchMappingAddress \+ k\) = randomMarker;", k)
    ok = len(loops) == 2
    report(ok, "BUG.2 pressure: every page of every search mapping is still marked",
           "per-page marker loops found: %d (2 expected: pe_v1 and pe_v2)" % len(loops))
    return ok


@check("BUG.2 pressure: the mapping arithmetic is pinned (a constant change fails here)")
def c_mapping_arithmetic(src):
    c = parse_constants(src)
    rows = []
    ok = True
    print("       pressure report - pe_v1's search space, as the source computes it:")
    for label, physmem, want in PINNED:
        got = derive(c, physmem)
        rows.append("%s: %s (want %s)" % (label, got, want))
        if got != want:
            ok = False
        if got:
            print("         %-5s %7d page(s)  %6.0f MB total  %2d x %5.1f MB mapping(s)"
                  % (label, got["pages"], got["total_bytes"] / 1048576.0,
                     got["mappings"], got["mapping_bytes"] / 1048576.0))
    a18_pages = eval_expr(c.get("pages_a18_expr"))
    a18_size = eval_expr(c.get("size_a18_expr"))
    if a18_pages is None or a18_size in (None, 0):
        report(False, "BUG.2 pressure: the mapping arithmetic is pinned (a constant change fails here)",
               "the A18 branch of the page/size ternaries could not be parsed")
        return False
    a18 = {"pages": a18_pages, "mapping_bytes": a18_size}
    a18["total_bytes"] = a18["pages"] * PAGE_SIZE
    a18["mappings"] = a18["total_bytes"] // a18["mapping_bytes"]
    if a18 != {"pages": 256, "mapping_bytes": 0x10000, "total_bytes": 1048576, "mappings": 16}:
        ok = False
        rows.append("A18: %s (want pages 256, 64 KB mappings, 16 of them)" % a18)
    report(ok, "BUG.2 pressure: the mapping arithmetic is pinned (a constant change fails here)",
           "; ".join(rows))
    return ok


@check("BUG.2 pressure: the up-front spray bound is pinned")
def c_spray_bound(src):
    c = parse_constants(src)
    n = None
    if c["maxfiles_mult"] and c["open_max"] and c["leeway"] is not None:
        n = c["open_max"] * c["maxfiles_mult"] - c["leeway"]
    ok = n == 22528
    report(ok, "BUG.2 pressure: the up-front spray bound is pinned",
           "derived socket bound: %s (want 22528 = 10240*3 - 4096*2)" % n)
    return ok


@check("BUG.2 pressure: the per-cycle release funnel is still what bounds the peak")
def c_cycle_funnel(src):
    k = strip_comments(src.k)
    # the allocate-failure path inside the mapping loop must hand this cycle's
    # mappings to the funnel instead of leaking them. The window is bounded (900
    # chars) so a funnel call further down the function cannot satisfy the check.
    m = re.search(r"mach_vm_allocate failed!!!.{0,900}?pe_v1_release_cycle\(searchMappings, searchMappingSize,", k, re.S)
    funnels = len(re.findall(r"pe_v1_release_cycle\(", k))
    cycles = re.search(r"if \(cycle > (\d+)\)", k)
    ok = bool(m) and funnels >= 6 and bool(cycles)
    report(ok, "BUG.2 pressure: the per-cycle release funnel is still what bounds the peak",
           "allocate-failure path goes to the funnel: %s; funnel call sites in pe_v1: %d; cycle cap: %s"
           % (bool(m), funnels, cycles.group(1) if cycles else "?"))
    return ok


# ---------------------------------------------------------------------------
# the disk-write budget: the axis the 2026-09-11 report was measured on
# ---------------------------------------------------------------------------
# `W0lfTerm.diskwrites_resource-*.ips` on the SE read 1073.75 MB of file-backed
# memory dirtied in 1083 s, against the 1 GB/day limit iOS enforces per app. Two
# halves of this app can dirty file-backed pages, and both are countable from the
# shipped sources:
#   * the log sink's fsync, bounded by the rate gate's window (BUG.6 host test);
#   * the scan, which writes a marker into EVERY page of EVERY search mapping on
#     every cycle - 384 MB per cycle on the 3 GB class, re-dirtied each cycle and
#     each attempt (BUG.2's remaining half, pinned two checks up).
# This check does that accounting against the limit and fails if any parsed
# constant moves, so the ratio cannot drift unnoticed. It is a regression guard,
# NOT a claim that the app fits the budget - the scan half does not, and that is
# printed rather than rounded away. What the host cannot do: turn one fsync into
# a byte count (the flushed bytes are the log file's own dirty pages) or split
# the report's bytes between the two halves; both stay device measurements.
DISK_LIMIT_BYTES = 1024 * 1024 * 1024            # the 1 GB/day limit iOS reports
DEVICE_DAY_BYTES = int(1073.75 * 1024 * 1024)    # the SE report: 1073.75 MB ...
DEVICE_DAY_SECONDS = 1083                        # ... dirtied in 1083 s (18 min)
DISK_PINNED = {
    "fsync_window_ms": 200,              # tweak_log_policy.h: the BUG.6 window
    "budget_default_s": 600,             # the run length the accounting uses
    "budget_max_s": 1800,                # the clamp the app cannot exceed
    "app_attempts": 3,                   # term_bridge.m: attempts per run
    "engine_cycles": 7,                  # engine: cycles per attempt (cycle > 6)
    "dirty_bytes_per_cycle": 402653184,  # 3 GB class: 98304 pages re-marked
}


def parse_disk_constants(src):
    got = {}
    # comment-stripped: the tree documents the OLD values in prose ("the old
    # hard-coded `#define EXPLOIT_SCAN_BUDGET_SEC 120` lived here"), and a parse
    # that reads the comment instead of the code would pin the bug, not the fix.
    k = strip_comments(src.k)
    m = re.search(r"#define\s+TWEAK_LOG_FSYNC_MIN_INTERVAL_MS\s+(\d+)", src.policy_h)
    got["fsync_window_ms"] = int(m.group(1)) if m else None
    m = re.search(r"^#define\s+EXPLOIT_SCAN_BUDGET_SEC\s+(\d+)", k, re.M)
    got["budget_default_s"] = int(m.group(1)) if m else None
    m = re.search(r"#define\s+KEXPLOIT_SCAN_BUDGET_MAX\s+(\d+)", src.kh)
    got["budget_max_s"] = int(m.group(1)) if m else None
    m = re.search(r"while\s*\(\s*attempt\s*<\s*(\d+)\s*&&", src.bridge)
    got["app_attempts"] = int(m.group(1)) if m else None
    m = re.search(r"if\s*\(cycle\s*>\s*(\d+)\)", k)
    got["engine_cycles"] = (int(m.group(1)) + 1) if m else None
    return got


@check("BUG.5/BUG.6 disk budget: the write accounting is pinned against the 1 GB/day limit")
def c_disk_budget_accounting(src):
    c = parse_disk_constants(src)
    se = derive(parse_constants(src), 3 * GB)     # the class the report came from
    c["dirty_bytes_per_cycle"] = se["total_bytes"] if se else None
    bad = ["%s=%s (want %s)" % (k, c.get(k), want) for k, want in DISK_PINNED.items()
           if c.get(k) != want]
    ok = not bad
    per_cycle, cycles, attempts = c["dirty_bytes_per_cycle"], c["engine_cycles"], c["app_attempts"]
    if per_cycle is not None and cycles is not None and attempts is not None:
        per_attempt = per_cycle * cycles
        per_run = per_attempt * attempts
        print("       disk-write accounting (the report: 1073.75 MB in 1083 s, limit 1 GB/day):")
        print("         scan:  %.0f MB per cycle x %d cycle(s) x %d attempt(s) = %.0f MB dirtied "
              "per run (%.2fx the limit)" % (per_cycle / 1048576.0, cycles, attempts,
                                             per_run / 1048576.0, per_run / float(DISK_LIMIT_BYTES)))
        if c["fsync_window_ms"]:
            grants = int(c["budget_default_s"] * 1000 / c["fsync_window_ms"]) + 1
            print("         log:   %d s run, one fsync per %d ms = at most %d fsync(s) "
                  "(bytes per fsync are the log file's dirty pages - a device measurement)"
                  % (c["budget_default_s"], c["fsync_window_ms"], grants))
        print("         => the scan's per-page marker writes are the half over the limit; this round "
              "bounds the LOG half only (BUG.6), unchanged for the scan (BUG.2 residual)")
    report(ok, "BUG.5/BUG.6 disk budget: the write accounting is pinned against the 1 GB/day limit",
           "; ".join(bad))
    return ok


@check("BUG.1 probe field: nothing in the shipped code consumes the probed qword")
def c_no_consumer(src):
    files = src.archive_sources()
    if files is None:
        report(False, "BUG.1 probe field: nothing in the shipped code consumes the probed qword",
               "scripts/build_libengine.sh has no SOURCES= list")
        return False
    # headers come along: the fsync/probe fields live in .h files that the compiled
    # sources include, so scan the archive sources plus every local header they pull
    # in, plus the app's own sources.
    seeds = list(files) + list(APP_FILES)
    seen, frontier = [], list(seeds)
    for _ in range(3):
        nxt = []
        for rel in frontier:
            rel = os.path.normpath(rel)
            if rel in seen:
                continue
            text = read(src.root, rel)
            base = src.root
            if text is None:
                text = read(src.wolfterm, rel)
                base = src.wolfterm
            if text is None:
                continue
            seen.append(rel)
            for inc in re.findall(r'^\s*#\s*(?:include|import)\s+"([^"]+)"', text, re.M):
                nxt.append(os.path.normpath(os.path.join(os.path.dirname(rel), inc)))
                nxt.append(os.path.normpath(inc))
        frontier = nxt
    bad = []
    for rel in seen:
        text = read(src.root, rel)
        if text is None:
            text = read(src.wolfterm, rel)
        if text is None:
            continue
        code = strip_comments(text)
        for fn in ("send", "sendto", "recv", "recvfrom", "sendmsg", "recvmsg"):
            if re.search(r"(?<![_A-Za-z0-9])%s\s*\(" % fn, code):
                bad.append("%s:%s()" % (rel, fn))
    preserved = "off_inpcb_inp_depend6_inp6_chksum" in src.k or "chksumFieldOff" in src.k
    ok = not bad and preserved and "filtOffset + 8" in src.k
    report(ok, "BUG.1 probe field: nothing in the shipped code consumes the probed qword",
           "send/recv call sites among %d scanned file(s): %s; probe preserves the chksum qword: %s"
           % (len(seen), ", ".join(bad) if bad else "none", preserved))
    return ok


@check("BUG.1 probe field: the probe body does not touch the icmp6 filter pointer")
def c_probe_avoids_filter_pointer(src):
    k = strip_comments(src.k)
    body = block(k, "find_and_corrupt_socket_probe(")
    if body is None:
        report(False, "BUG.1 probe field: the probe body does not touch the icmp6 filter pointer",
               "find_and_corrupt_socket_probe() not found")
        return False
    # the probe may READ the filter pointer's field to derive the window (filt+8)
    # but must never WRITE a value at the icmp6filt field itself; the one deliberate
    # icmp6filt write is the krw primitive inside find_and_corrupt_socket(), which is
    # the corruption the probe is verifying.
    writes = re.findall(r"kwrite\w*\([^;]*inp6_icmp6filt", body) + re.findall(r"inp6_icmp6filt\w*\s*=", body)
    # what makes the probed field inert is that it IS the chksum qword (filt+8), not
    # the filter pointer at filt: the save line has to say so.
    saves_chksum = re.search(r"g_test_filt8_orig\s*=\s*\*\(uint64_t \*\)\(\(uintptr_t\)readBuffer \+ pcbStartOffset \+ filtOffset \+ 8\);", body)
    chksum_preserve = bool(saves_chksum) and "inp6_chksum" in body
    clamped_putback = "probe_kwrite_inpcb_qword" in body or "kwrite_zone_element_qword" in body
    ok = not writes and chksum_preserve and clamped_putback
    report(ok, "BUG.1 probe field: the probe body does not touch the icmp6 filter pointer",
           "writes to the icmp6filt field in the probe body: %s; saves the chksum qword (filt+8): %s; put-back is clamped: %s"
           % (writes if writes else "none", chksum_preserve, clamped_putback))
    return ok


# ---------------------------------------------------------------------------
# selftest
# ---------------------------------------------------------------------------
def _mutate(text, old, new, count=1):
    if old not in text:
        return None
    return text.replace(old, new, count)


def selftest(root, wolfterm):
    mutations = []

    def mut_more_pages(text):
        return _mutate(text, "isA18Device ? (0x10 * 0x10) : (0x1000 * 0x10);",
                             "isA18Device ? (0x10 * 0x10) : (0x4000 * 0x10);")

    def mut_smaller_mappings(text):
        return _mutate(text, "uint64_t searchMappingSize = isA18Device ? (0x10 * PAGE_SIZE) : (0x2000 * PAGE_SIZE);",
                             "uint64_t searchMappingSize = isA18Device ? (0x10 * PAGE_SIZE) : (0x4000 * PAGE_SIZE);")

    def mut_skip_marker(text):
        return _mutate(text,
                       "            for (int k = 0; k < searchMappingSize; k += PAGE_SIZE) {\n"
                       "                *(uint64_t *)(searchMappingAddress + k) = randomMarker;\n"
                       "            }",
                       "            *(uint64_t *)searchMappingAddress = randomMarker;   // mutation: one page only")

    def mut_bigger_spray(text):
        return _mutate(text, "#define OPEN_MAX 10240", "#define OPEN_MAX 16384")

    def mut_add_send(text):
        return _mutate(text, "int pe_v1(void) {",
                             "int pe_v1(void) {\n    send(0, 0, 0, 0);   // mutation: a consumer of the probed field")

    def mut_probe_saves_the_filter_pointer(text):
        # the BUG.1 mistake itself: preserving the qword at filt instead of the
        # inert chksum qword at filt+8
        return _mutate(text,
                       "        g_test_filt8_orig = *(uint64_t *)((uintptr_t)readBuffer + pcbStartOffset + filtOffset + 8);",
                       "        g_test_filt8_orig = *(uint64_t *)((uintptr_t)readBuffer + pcbStartOffset + filtOffset);   // mutation: the filter pointer, not the chksum")

    def mut_funnel_dropped(text):
        # only the allocate-failure path inside pe_v1's mapping loop
        return _mutate(text,
                       "                pe_v1_release_cycle(searchMappings, searchMappingSize, wiredMapping, wiredMappingSize, true);\n"
                       "                free(readBuffer);",
                       "                /* mutation: the mapping-allocate failure path leaks this cycle */\n"
                       "                free(readBuffer);")

    def mut_fsync_window_20ms(text):
        # the disk accounting's log half: a 20 ms window means 10x the fsyncs
        return _mutate(text, "#define TWEAK_LOG_FSYNC_MIN_INTERVAL_MS 200",
                             "#define TWEAK_LOG_FSYNC_MIN_INTERVAL_MS 20")

    def mut_app_attempts_5(text):
        # the disk accounting's scan half: one more attempt multiplies the dirtied
        # bytes by the attempt count
        return _mutate(text, "while (attempt < 3 && !exploit_is_done())",
                             "while (attempt < 5 && !exploit_is_done())")

    mutations = [
        ("the default search-space page count grows 4x", "engine", "kexploit/kexploit_opa334.m", mut_more_pages),
        ("the mapping size changes (a different mapping count)", "engine", "kexploit/kexploit_opa334.m", mut_smaller_mappings),
        ("the marker write covers one page instead of every page", "engine", "kexploit/kexploit_opa334.m", mut_skip_marker),
        ("the log sink's fsync window shrinks to 20 ms", "engine", "utils/tweak_log_policy.h", mut_fsync_window_20ms),
        ("the app's retry cap grows from 3 to 5 attempts", "app", "term_bridge.m", mut_app_attempts_5),
        ("the up-front spray bound grows", "engine", "kexploit/kexploit_opa334.m", mut_bigger_spray),
        ("a send() appears in the compiled sources", "engine", "kexploit/kexploit_opa334.m", mut_add_send),
        ("the probe preserves the filter pointer instead of the chksum qword", "engine", "kexploit/kexploit_opa334.m", mut_probe_saves_the_filter_pointer),
        ("the mapping-allocate failure path stops calling the funnel", "engine", "kexploit/kexploit_opa334.m", mut_funnel_dropped),
    ]

    tmp = tempfile.mkdtemp(prefix="pressure_budget_selftest_")
    failures = 0
    try:
        for name, kind, rel, mutator in mutations:
            root_tmp = os.path.join(tmp, "root")
            app_tmp = os.path.join(tmp, "app")
            for base, files in ((root_tmp, ENGINE_FILES), (app_tmp, APP_FILES)):
                for f in files:
                    dst = os.path.join(base, f)
                    os.makedirs(os.path.dirname(dst), exist_ok=True)
                    shutil.copyfile(os.path.join(root if base == root_tmp else wolfterm, f), dst)
            # the mutation targets a file the checks read; if it is not in the list
            # yet, copy it in too (the checks read it through the archive list)
            target = os.path.join(root_tmp if kind == "engine" else app_tmp, rel)
            if not os.path.exists(target):
                os.makedirs(os.path.dirname(target), exist_ok=True)
                shutil.copyfile(os.path.join(root if kind == "engine" else wolfterm, rel), target)
            with open(target, "r", encoding="utf-8", errors="replace") as fh:
                original = fh.read()
            mutated = mutator(original)
            if mutated is None or mutated == original:
                print("  FAIL mutation %r could not be applied (anchor missing)" % name)
                failures += 1
                continue
            with open(target, "w", encoding="utf-8") as fh:
                fh.write(mutated)
            caught = run_checks(root_tmp, app_tmp, quiet=True)
            if caught:
                print("  ok   mutation caught: %s" % name)
            else:
                print("  FAIL mutation NOT caught: %s" % name)
                failures += 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print("\nselftest: %s" % ("all mutations caught" if failures == 0 else "%d mutation(s) not caught" % failures))
    return 1 if failures else 0


# ---------------------------------------------------------------------------
# runner
# ---------------------------------------------------------------------------
def run_checks(root, wolfterm, quiet=False):
    del RESULTS[:]
    src = Src(root, wolfterm)
    if not all_present(src):
        return ["<sources missing>"]
    print_reports = not quiet
    if quiet:
        # keep stdout tidy during the selftest: the same report() print is fine,
        # the other lints do the same.
        pass
    failed = []
    for name, fn in CHECKS:
        try:
            ok = fn(src)
        except Exception as exc:
            report(False, name, "check raised %r" % (exc,))
            ok = False
        if not ok:
            failed.append(name)
    if print_reports:
        print("\n%d check(s) passed, %d failed" % (len(RESULTS) - len(failed), len(failed)))
    return failed


def main(argv):
    root = os.getcwd()
    wolfterm = os.path.join(os.path.dirname(root), "W0lfTerm")
    selftest_mode = False
    args = argv[1:]
    while args:
        a = args.pop(0)
        if a == "--root":
            root = os.path.abspath(args.pop(0))
        elif a == "--wolfterm":
            wolfterm = os.path.abspath(args.pop(0))
        elif a == "--selftest":
            selftest_mode = True
        else:
            print("unknown argument: %s" % a)
            return 2
    if not os.path.isdir(wolfterm):
        print("no W0lfTerm tree at %s (pass --wolfterm)" % wolfterm)
        return 1

    print("BUG.1 probe field + BUG.2 pressure-source check (host only)")
    print("  engine root: %s" % root)
    print("  app root:    %s\n" % wolfterm)

    failed = run_checks(root, wolfterm)
    rc = 1 if failed else 0

    if selftest_mode:
        print("\nselftest (mutating temp copies):")
        rc |= selftest(root, wolfterm)

    if rc == 0:
        print("\nPRESSURE_BUDGET LINT PASS")
    else:
        print("\nPRESSURE_BUDGET LINT FAIL")
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv))
