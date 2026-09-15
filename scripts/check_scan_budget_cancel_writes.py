#!/usr/bin/env python3
"""Host-only lint for W0lfSword BUG.3 + BUG.5 + BUG.4 + BUG.6 (2026-09-11 device day).

The four items share one property: each is only real if it holds END TO END.
A settable budget nobody pushes into the engine, a "measured" counter nothing
increments, a CANCEL button whose cancel path leaks, a rate-limited sink that
still fsyncs per line - each of those looks fine in a diff and fails on the
device. So every check here reads the shipped sources of both trees and asserts
the wire, not the wording:

  BUG.3  the scan budget is settable (engine setter + clamp + all scan loops
         reading it) and the DEFAULT both trees ship is the one that fits the
         measured walk (600 s), not the 120 s that stopped a quarter of the way
         in; the app pushes its SET row value into the engine at load and on
         every change, and the boot banner reads the value back from the ENGINE.

  BUG.5  "no kernel writes" is backed by a counter: the single write primitive
         (early_kwrite32bytes) increments it on success and the refusal counter
         on failure, the clamped block writer attributes its writes, the engine
         resets per attempt and prints the measured total, and the app logs the
         same numbers - no log or UI string claims "zero writes" without them.

  BUG.4  the app has a visible CANCEL (a control with the word on it, on exactly
         while a run is in flight) that reaches the engine's stop flag, and both
         cancel-capable engine loops release the search mapping AND the socket
         spray on the -7 path - the leak the device day found.

  BUG.6  the disk-write budget: the log sink's fsync (added for panic forensics)
         is paid at most once per 200 ms through ONE process-wide gate, the gate
         is a compiled, host-tested policy shipped by both builds, and no other
         fsync-per-line sink exists in the code the two trees compile - the
         fsync-per-line version dirtied ~1.07 GB in 18 minutes on the SE against
         the 1 GB/day limit iOS reports.

Usage:
    python3 scripts/check_scan_budget_cancel_writes.py [--root .] [--wolfterm ../W0lfTerm]
    python3 scripts/check_scan_budget_cancel_writes.py --selftest

--selftest mutates TEMP COPIES of these sources in the ways that would silently
break each contract and requires the lint to fail on every one of them. A lint
whose checks cannot fail is worse than no lint.

Exit 0 = every check passed (and, in selftest mode, every mutation was caught).
"""

import os
import re
import shutil
import sys
import tempfile

# ---------------------------------------------------------------------------
# sources this lint reads (relative to each repo root)
# ---------------------------------------------------------------------------
ENGINE_FILES = [
    "kexploit/kexploit_opa334.m",
    "kexploit/kexploit_opa334.h",
    "kexploit/krw.m",
    "kexploit/kwrite_counter.c",
    "kexploit/kwrite_counter.h",
    # BUG.6: the log sink and the rate gate it consults, plus the two build
    # lists and the host test that keep the gate in the shipped archive.
    "utils/tweak_log.h",
    "utils/tweak_log.m",
    "utils/tweak_log_policy.c",
    "utils/tweak_log_policy.h",
    "scripts/build_libengine.sh",
    "scripts/run_tweak_log_throttle_host_test.sh",
    "tests/tweak_log_throttle_host_test.c",
    "Makefile",
]
APP_FILES = [
    "term_settings.m",
    "term_settings.h",
    "term_bridge.m",
    "SettingsViewController.m",
    "TerminalViewController.m",
]

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
    path = os.path.join(root, rel)
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


def strip_comments(text):
    """Drop // and /* */ comments so a comment ABOUT a bad string is not read as
    the bad string (the tree documents the old wording on purpose)."""
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    out = []
    for line in text.splitlines():
        cut = line.find("//")
        if cut >= 0 and line.count('"', 0, cut) % 2 == 0:
            line = line[:cut]
        out.append(line)
    return "\n".join(out)


def drop_block(text, marker):
    """Remove the block starting at the line containing `marker` through its
    matching closing brace (no nesting expected in the blocks this lint mutates)."""
    idx = text.find(marker)
    if idx < 0:
        return None
    depth = 0
    started = False
    for i in range(idx, len(text)):
        if text[i] == "{":
            depth += 1
            started = True
        elif text[i] == "}":
            depth -= 1
            if started and depth == 0:
                return text[:idx] + text[i + 1:]
    return None


# ===========================================================================
# context: files resolved once, so every check reads the same bytes
# ===========================================================================
class Src:
    def __init__(self, root, wolfterm):
        self.root = root
        self.wolfterm = wolfterm
        self.engine = {rel: (read(root, rel) or "") for rel in ENGINE_FILES}
        self.app = {rel: (read(wolfterm, rel) or "") for rel in APP_FILES}
        self.engine_missing = [rel for rel in ENGINE_FILES if not read(root, rel)]
        self.app_missing = [rel for rel in APP_FILES if not read(wolfterm, rel)]
        self.e_m = self.engine["kexploit/kexploit_opa334.m"]
        self.e_h = self.engine["kexploit/kexploit_opa334.h"]
        self.krw_m = self.engine["kexploit/krw.m"]
        self.wc_c = self.engine["kexploit/kwrite_counter.c"]
        self.wc_h = self.engine["kexploit/kwrite_counter.h"]
        self.tl_h = self.engine["utils/tweak_log.h"]
        self.tl_m = self.engine["utils/tweak_log.m"]
        self.tlp_c = self.engine["utils/tweak_log_policy.c"]
        self.tlp_h = self.engine["utils/tweak_log_policy.h"]
        self.libe = self.engine["scripts/build_libengine.sh"]
        self.tl_run = self.engine["scripts/run_tweak_log_throttle_host_test.sh"]
        self.tl_test = self.engine["tests/tweak_log_throttle_host_test.c"]
        self.tweak_mk = self.engine["Makefile"]
        self.s_m = self.app["term_settings.m"]
        self.b_m = self.app["term_bridge.m"]
        self.svc_m = self.app["SettingsViewController.m"]
        self.vc_m = self.app["TerminalViewController.m"]


def all_sources_present(src):
    missing = src.engine_missing + src.app_missing
    report(not missing, "every source this lint reads exists",
           "missing: " + ", ".join(missing))
    return not missing


# ===========================================================================
# BUG.3 - the budget, end to end
# ===========================================================================
@check("BUG.3 engine: the default budget is the one that fits the walk (600 s)")
def c_budget_engine_default(src):
    code = strip_comments(src.e_m)     # the tree documents the old 120 s default in a comment
    defs = re.findall(r"#define\s+EXPLOIT_SCAN_BUDGET_SEC\s+(\d+)", code)
    if not defs:
        report(False, "BUG.3 engine: the default budget is the one that fits the walk (600 s)",
               "no EXPLOIT_SCAN_BUDGET_SEC definition")
        return False
    value = int(defs[0])
    ok = value == 600 and len(defs) == 1
    report(ok, "BUG.3 engine: the default budget is the one that fits the walk (600 s)",
           "found %r (definitions: %d); the 120 s default is the 24%%-in-120s behaviour"
           % (defs, len(defs)))
    return ok


@check("BUG.3 engine: the budget is settable and clamped, and every scan/spray loop reads it")
def c_budget_engine_wiring(src):
    ok_setter = bool(re.search(r"void\s+kexploit_set_scan_budget\s*\(\s*int\s+seconds\s*\)", src.e_m))
    ok_clamp = "KEXPLOIT_SCAN_BUDGET_MIN" in src.e_m and "KEXPLOIT_SCAN_BUDGET_MAX" in src.e_m
    ok_getter = bool(re.search(r"int\s+kexploit_scan_budget\s*\(\s*void\s*\)", src.e_m))
    ok_header = ("kexploit_set_scan_budget" in src.e_h and "kexploit_scan_budget" in src.e_h
                 and "KEXPLOIT_SCAN_BUDGET_MIN" in src.e_h and "KEXPLOIT_SCAN_BUDGET_MAX" in src.e_h)
    reads = len(re.findall(r"SCAN_BUDGET_SEC\(\)", src.e_m))
    stops = len(re.findall(r"kexploit_stop_requested\(\)", src.e_m)) + 1  # + the read race's direct atomic load
    ok = ok_setter and ok_clamp and ok_getter and ok_header and reads >= 4 and stops >= 6
    report(ok, "BUG.3 engine: the budget is settable and clamped, and every scan/spray loop reads it",
           "setter=%s clamp=%s getter=%s header=%s SCAN_BUDGET_SEC() uses=%d stop sites=%d (need the walks, the spray, both batches and the read race)"
           % (ok_setter, ok_clamp, ok_getter, ok_header, reads, stops))
    return ok


@check("BUG.3 engine: the cancel/budget check sits INSIDE each walk, not after it")
def c_budget_inside_walks(src):
    # pe_v1 and pe_v2 both walk `while (seekingOffset + pcSize <= searchMappingSize)`.
    # If the stop check moved out of the loop, a CANCEL would still visit every
    # remaining offset - the minute of pointless work the device day reported.
    windows = []
    marker = "while (seekingOffset + pcSize <= searchMappingSize)"
    start = 0
    while True:
        idx = src.e_m.find(marker, start)
        if idx < 0:
            break
        end = src.e_m.find("seekingOffset += PAGE_SIZE", idx)
        windows.append(src.e_m[idx:end] if end > 0 else "")
        start = idx + 1
    ok = len(windows) >= 2 and all("kexploit_stop_requested()" in w and "SCAN_BUDGET_SEC()" in w
                                   for w in windows)
    report(ok, "BUG.3 engine: the cancel/budget check sits INSIDE each walk, not after it",
           "found %d walk(s); each has the check: %s"
           % (len(windows), [("kexploit_stop_requested()" in w and "SCAN_BUDGET_SEC()" in w) for w in windows]))
    return ok


@check("BUG.4 engine: the socket spray honours a CANCEL (it is the longest pre-walk cost)")
def c_cancel_spray(src):
    # The up-front spray opens up to ~28k sockets; a cancel that only landed in
    # the walk still paid for all of it (wakeups/CPU, SG.10).
    upfront = _block_contains(src.e_m, "for (unsigned socketCount = 0; socketCount < (maxfiles - leeway);",
                              "kexploit_stop_requested()")
    mid = _block_contains(src.e_m, "for (uint64_t sc = 0; sc < midSprayBatch; sc++) {",
                          "kexploit_stop_requested()")
    batch = _block_contains(src.e_m, "for (uint64_t sc = 0; sc < maxSocketsCount / splitCount; sc++) {",
                            "kexploit_stop_requested()")
    cycle_top = _block_contains(src.e_m, "while (true) {\n        // BUG.4 (2026-09-11 device day)",
                                "return -7;")
    ok = upfront and mid and batch and cycle_top
    report(ok, "BUG.4 engine: the socket spray honours a CANCEL (it is the longest pre-walk cost)",
           "up-front spray=%s mid-scan batch=%s pe_v2 batch=%s cycle-top returns -7=%s"
           % (upfront, mid, batch, cycle_top))
    return ok


@check("BUG.3 app: the default budget matches the engine default and is pushed in at load")
def c_budget_app_default(src):
    m = re.search(r"static\s+int\s+g_scanBudget\s*=\s*(\d+)\s*;", src.s_m)
    app_default = int(m.group(1)) if m else None
    options = re.search(r"kScanBudgetSecs\[\]\s*=\s*\{([^}]*)\}", src.s_m)
    opts = [int(x) for x in re.findall(r"\d+", options.group(1))] if options else []
    engine = re.search(r"#define\s+EXPLOIT_SCAN_BUDGET_SEC\s+(\d+)", strip_comments(src.e_m))
    engine_default = int(engine.group(1)) if engine else None
    pushed = "kexploit_set_scan_budget(g_scanBudget)" in src.s_m
    ok = (app_default == 600 and engine_default == 600
          and app_default in opts and app_default == max(opts) if opts else False) and pushed
    report(ok, "BUG.3 app: the default budget matches the engine default and is pushed in at load",
           "app default=%r options=%r engine default=%r push-at-load=%s"
           % (app_default, opts, engine_default, pushed))
    return ok


@check("BUG.3 app: a SET row exists, persists, and pushes every change into the engine")
def c_budget_app_row(src):
    row = "Scan budget" in src.svc_m
    seg = "scanBudgetSeg" in src.svc_m and "scanBudgetChanged:" in src.svc_m
    setter = bool(re.search(r"\+\s*\(void\)\s*setScanBudget:\(int\)seconds", src.s_m))
    live = "kexploit_set_scan_budget(seconds)" in src.s_m          # live: next run uses it
    persist = "setInteger:(NSInteger)g_scanBudget forKey:K_BUDG" in src.s_m
    ok = row and seg and setter and live and persist
    report(ok, "BUG.3 app: a SET row exists, persists, and pushes every change into the engine",
           "row=%s segmented=%s setter=%s pushes-live=%s persists=%s"
           % (row, seg, setter, live, persist))
    return ok


@check("BUG.3 app: the boot banner reads the budget back from the ENGINE")
def c_budget_banner(src):
    ok = "kexploit_scan_budget()" in src.b_m
    report(ok, "BUG.3 app: the boot banner reads the budget back from the ENGINE",
           "term_bridge.m does not log kexploit_scan_budget()")
    return ok


# ===========================================================================
# BUG.5 - measured writes instead of a claim
# ===========================================================================
@check("BUG.5 counter: the module exists and exposes the measured getters")
def c_counter_module(src):
    api = ["kwrite_count_reset", "kwrite_count_emit", "kwrite_count_failed",
           "kwrite_count_total", "kwrite_count_bytes", "kwrite_count_failed_total",
           "kwrite_src_push", "kwrite_src_pop", "kwrite_src_current"]
    missing_h = [n for n in api if n not in src.wc_h]
    missing_c = [n for n in api if n not in src.wc_c]
    ok = not missing_h and not missing_c
    report(ok, "BUG.5 counter: the module exists and exposes the measured getters",
           "missing in .h: %r; missing in .c: %r" % (missing_h, missing_c))
    return ok


@check("BUG.5 counter: the ONE write primitive counts both outcomes")
def c_counter_primitive(src):
    # early_kwrite32bytes is the only call that emits kernel bytes.
    idx = src.e_m.find("void early_kwrite32bytes(")
    body = src.e_m[idx:src.e_m.find("\nvoid early_kwrite64(", idx)] if idx >= 0 else ""
    emit = "kwrite_count_emit(" in body
    failed = "kwrite_count_failed(" in body
    ok = bool(body) and emit and failed
    report(ok, "BUG.5 counter: the ONE write primitive counts both outcomes",
           "early_kwrite32bytes counts writes=%s refusals=%s" % (emit, failed))
    return ok


@check("BUG.5 counter: each entry point attributes its writes to its own route")
def c_counter_routes(src):
    krw64 = "KWRITE_SRC_KRW64" in src.e_m and "kwrite_src_push(KWRITE_SRC_KRW64)" in src.e_m
    zone = "kwrite_src_push(KWRITE_SRC_ZONE)" in src.krw_m
    ok = krw64 and zone
    report(ok, "BUG.5 counter: each entry point attributes its writes to its own route",
           "early_kwrite64 pushes its route=%s; krw_zone_write_block pushes its route=%s" % (krw64, zone))
    return ok


@check("BUG.5 engine: the counters reset per attempt, are exported, and are printed")
def c_counter_engine(src):
    reset_attempt = "kwrite_count_reset();" in src.e_m
    exported = ("uint64_t kexploit_scan_writes(void)" in src.e_m
                and "uint64_t kexploit_scan_write_bytes(void)" in src.e_m
                and "kexploit_scan_writes" in src.e_h and "kexploit_scan_write_bytes" in src.e_h)
    summary_fn = "static void kexploit_log_scan_writes(" in src.e_m
    printed = src.e_m.count("kexploit_log_scan_writes(") >= 3   # definition + teardown + staged -5
    ok = reset_attempt and exported and summary_fn and printed
    report(ok, "BUG.5 engine: the counters reset per attempt, are exported, and are printed",
           "reset=%s exported=%s summary=%s print-sites=%d"
           % (reset_attempt, exported, summary_fn, src.e_m.count("kexploit_log_scan_writes(")))
    return ok


@check("BUG.5 app: the run log carries the measured number, not the claim")
def c_counter_app(src):
    reads = "kexploit_scan_writes()" in src.b_m and "kexploit_scan_write_bytes()" in src.b_m
    helper = "static void term_log_write_count(" in src.b_m
    # The number has to be logged on the paths a user actually sees: right after
    # each engine attempt, on a cancel before the first attempt, and after the
    # escape phase (which writes too).
    after_attempt = src.b_m.find("kret = kexploit_opa334();")
    attempt_logged = after_attempt >= 0 and "term_log_write_count(" in src.b_m[after_attempt:after_attempt + 700]
    cancel_logged = 'term_log_write_count("before attempt' in src.b_m
    run_logged = 'term_log_write_count("this run (scan + escape)")' in src.b_m
    ok = reads and helper and attempt_logged and cancel_logged and run_logged
    report(ok, "BUG.5 app: the run log carries the measured number, not the claim",
           "reads the engine counter=%s helper=%s per-attempt log=%s cancel log=%s run log=%s"
           % (reads, helper, attempt_logged, cancel_logged, run_logged))
    return ok


@check("BUG.5: no shipped log/UI string claims 'zero writes' any more")
def c_no_zero_writes_claim(src):
    offenders = []
    for rel, text in list(src.engine.items()) + list(src.app.items()):
        if rel.startswith("__"):
            continue
        if not rel.endswith((".m", ".h", ".c")):
            continue
        code = strip_comments(text)
        for needle in ("zero writes", "zero kernel writes", "no kernel writes so far"):
            if needle in code:
                offenders.append("%s: %r" % (rel, needle))
    ok = not offenders
    report(ok, "BUG.5: no shipped log/UI string claims 'zero writes' any more",
           "still claiming: " + "; ".join(offenders))
    return ok


# ===========================================================================
# BUG.4 - the visible CANCEL and its release path
# ===========================================================================
@check("BUG.4 app: a visible CANCEL control that is on only while a run is in flight")
def c_cancel_control(src):
    control = "UIControl *dot = [[UIControl alloc]" in src.vc_m
    action = "action:@selector(dotTapped:)" in src.vc_m
    label = 'text = @"cancel"' in src.vc_m
    in_state1 = _block_contains(src.vc_m, "if (state == 1) {", "cancelLabel.alpha = 1.0")
    off_otherwise = "self.cancelLabel.alpha = 0.0;" in src.vc_m
    geometry = "TERM_CANCEL_CONTROL_W" in src.vc_m and "TERM_CANCEL_LABEL_W" in src.vc_m
    ok = control and action and label and in_state1 and off_otherwise and geometry
    report(ok, "BUG.4 app: a visible CANCEL control that is on only while a run is in flight",
           "control=%s action=%s word=%s shown-when-running=%s hidden-otherwise=%s geometry=%s"
           % (control, action, label, in_state1, off_otherwise, geometry))
    return ok


def _block_contains(text, marker, needle):
    """True when `needle` occurs inside the block opened by `marker`."""
    idx = text.find(marker)
    if idx < 0:
        return False
    depth = 0
    started = False
    for i in range(idx, len(text)):
        if text[i] == "{":
            depth += 1
            started = True
        elif text[i] == "}":
            depth -= 1
            if started and depth == 0:
                return needle in text[idx:i]
    return False


@check("BUG.4 app: the tap reaches the engine stop flag through the one bridge")
def c_cancel_bridge(src):
    tapped = _block_contains(src.vc_m, "- (void)dotTapped:", "term_bridge_cancel()")
    guard = _block_contains(src.b_m, "void term_bridge_cancel(void) {", "kexploit_request_stop()")
    running = "atomic_load(&g_exploitRunning)" in src.b_m
    ok = tapped and guard and running
    report(ok, "BUG.4 app: the tap reaches the engine stop flag through the one bridge",
           "dotTapped calls the bridge=%s bridge sets the engine flag=%s guards on g_exploitRunning=%s"
           % (tapped, guard, running))
    return ok


@check("BUG.4 app: the run loop treats -7 as cancelled and STOPS (no retry)")
def c_cancel_app_loop(src):
    body = _block_text(src.b_m, "if (kret == -7) {")
    stops = bool(body) and "return;" in body and "atomic_store(&g_exploitRunning, 0)" in body
    report(stops, "BUG.4 app: the run loop treats -7 as cancelled and STOPS (no retry)",
           "the -7 block does not clear g_exploitRunning and return")
    return stops


def _block_text(text, marker):
    idx = text.find(marker)
    if idx < 0:
        return ""
    depth = 0
    started = False
    for i in range(idx, len(text)):
        if text[i] == "{":
            depth += 1
            started = True
        elif text[i] == "}":
            depth -= 1
            if started and depth == 0:
                return text[idx:i + 1]
    return ""


@check("BUG.4 engine pe_v1: the -7 cancel exit releases the spray AND the mappings")
def c_cancel_pev1_release(src):
    funnel_body = _block_text(src.e_m, "static void pe_v1_release_cycle(")
    sockets = "sockets_release(socketPorts, socketPcbIds);" in funnel_body
    munlock = "surface_munlock(address, searchMappingSize)" in funnel_body
    dealloc = "mach_vm_deallocate(mach_task_self(), address, searchMappingSize)" in funnel_body
    # the funnel call must run before the `if (testResult) { ... return testResult; }`
    funnel_call = src.e_m.find("pe_v1_release_cycle(searchMappings, searchMappingSize, wiredMapping, wiredMappingSize,\n                            (testResult != 0) || success);")
    testresult_return = src.e_m.find("return testResult;   // -2 readonly-done / -3 writetest-done")
    ordered = funnel_call >= 0 and testresult_return > funnel_call
    ok = sockets and munlock and dealloc and ordered
    report(ok, "BUG.4 engine pe_v1: the -7 cancel exit releases the spray AND the mappings",
           "funnel releases sockets=%s munlocks=%s deallocates=%s (call before the testResult return=%s)"
           % (sockets, munlock, dealloc, ordered))
    return ok


@check("BUG.4 engine pe_v1: every -7 exit goes through the funnel (no cancel exit leaks)")
def c_cancel_pev1_all_exits(src):
    # Structural, not per-call-site. The leak this bug is about is ONE cancel exit
    # that returned with the search mapping still mapped and ~22k sockets still
    # open, so reading the funnel's own body (the check above) is not enough: a
    # NEW exit that skips it is exactly how this comes back. Every `return -7;`
    # inside pe_v1's body must be preceded by the funnel call and its
    # gencnt-tracker release, the walk's cancel must be the `break` that flows
    # into the terminal funnel call, and that call must deallocate the wired
    # mapping for a -7 (the `(testResult != 0) || success` argument).
    code = strip_comments(src.e_m)
    body = _block_text(code, "int pe_v1(void) {")
    if not body:
        report(False, "BUG.4 engine pe_v1: every -7 exit goes through the funnel (no cancel exit leaks)",
               "pe_v1() body not found")
        return False

    def guarded(r):
        window = body[max(0, r - 300):r]
        return ("pe_v1_release_cycle(" in window
                and "release_gencnt_tracker(targetInpGencntList" in window)

    returns = [m.start() for m in re.finditer(r"return -7;", body)]
    unguarded = len([r for r in returns if not guarded(r)])
    walk_break = bool(re.search(r"testResult = -7;\s*break;", body))
    terminal = "(testResult != 0) || success" in body
    ok = len(returns) >= 1 and unguarded == 0 and walk_break and terminal
    report(ok, "BUG.4 engine pe_v1: every -7 exit goes through the funnel (no cancel exit leaks)",
           "pe_v1 return -7 sites=%d unguarded=%d walk cancel is a break=%s terminal funnel flag=%s"
           % (len(returns), unguarded, walk_break, terminal))
    return ok


@check("BUG.4 engine pe_v2: the aborted (-7) path frees the mapping, the object and the spray")
def c_cancel_pev2_release(src):
    idx = src.e_m.find("if (aborted) break;")
    if idx < 0:
        report(False, "BUG.4 engine pe_v2: the aborted (-7) path frees the mapping, the object and the spray",
               "no `if (aborted) break;` in pe_v2")
        return False
    window = src.e_m[max(0, idx - 1500):idx]
    obj = "release_memory_object(memoryObject" in window
    sockets = "sockets_release(socketPorts, socketPcbIds)" in window
    munlock = "surface_munlock(searchMappingAddress, searchMappingSize)" in window
    dealloc = "mach_vm_deallocate(mach_task_self(), searchMappingAddress, searchMappingSize)" in window
    ok = obj and sockets and munlock and dealloc
    report(ok, "BUG.4 engine pe_v2: the aborted (-7) path frees the mapping, the object and the spray",
           "object=%s sockets=%s munlock=%s deallocate=%s" % (obj, sockets, munlock, dealloc))
    return ok


@check("BUG.4 engine: both cancel paths reach the app as -7 (cancelled, not failed)")
def c_cancel_engine_rc(src):
    code = strip_comments(src.e_m)
    # pe_v1's walk sets testResult = -7 and kexploit_opa334() maps it to -7.
    pev1_sets = "testResult = -7;" in code
    pv1_maps = bool(re.search(r"if \(pv == -7\) \{[^}]*return -7;", code, re.S))
    # pe_v2 is void and its FAILURE exits return bare, so its stop travels out
    # through a flag the A18 caller reads. Checking only that the word "aborted"
    # exists (what this check used to do) passed while an A18 run kept going after
    # a cancel: pe_v2 stopped its walk, then the run fell through into the krw tail
    # and the app never saw a "cancelled" result.
    pev2_sets = "g_peV2Aborted = true;" in code
    a18 = re.search(r"pe_v2\(\);\s*if \(g_peV2Aborted\) \{.{0,600}?return -7;", code, re.S)
    a18_maps = bool(a18) and "kexploit_attempt_teardown" in a18.group(0)
    ok = pev1_sets and pv1_maps and pev2_sets and a18_maps
    report(ok, "BUG.4 engine: both cancel paths reach the app as -7 (cancelled, not failed)",
           "pe_v1 sets -7=%s pe_v1 maps it=%s pe_v2 records the stop=%s A18 caller maps it + tears down=%s"
           % (pev1_sets, pv1_maps, pev2_sets, a18_maps))
    return ok


# ===========================================================================
# BUG.6 - the disk-write budget: the fsync rate gate
# ===========================================================================
def _archive_sources(root):
    """The file list the engine archive is built from (scripts/build_libengine.sh
    SOURCES="..."), i.e. the code that lands in libw0lfengine.a and therefore in
    the app. Parsed instead of hard-coded so a new source cannot slip past the
    'who else fsyncs?' check below."""
    text = read(root, "scripts/build_libengine.sh") or ""
    m = re.search(r'SOURCES="(.*?)"', text, re.S)
    if not m:
        return None
    raw = m.group(1).replace("\\\n", " ")
    return [tok for tok in raw.split() if tok]


@check("BUG.6 throttle: the log sink fsyncs only through the rate gate")
def c_throttle_sink_gated(src):
    code = strip_comments(src.tl_h)
    idx = code.find("fsync(fileno(df))")
    if idx < 0:
        report(False, "BUG.6 throttle: the log sink fsyncs only through the rate gate",
               "no fsync(fileno(df)) call in utils/tweak_log.h at all")
        return False
    window = code[max(0, idx - 320):idx]
    hook = "tweak_log_hook_installed()" in window
    gated = "tweak_log_fsync_due_now()" in window
    # the gate has to be in the SAME condition, not just nearby: an `if (gate) {}`
    # followed by an ungated fsync would pass a "somewhere above" test.
    # ([^{}]* and not [^)]*: the condition contains calls of its own.)
    same_cond = re.search(r"if\s*\([^{}]*tweak_log_fsync_due_now\(\)[^{}]*\)\s*\{", window) is not None
    declared = "int tweak_log_fsync_due_now(void);" in code
    ok = hook and gated and same_cond and declared
    report(ok, "BUG.6 throttle: the log sink fsyncs only through the rate gate",
           "hook gate=%s rate gate=%s same condition=%s declared=%s" % (hook, gated, same_cond, declared))
    return ok


@check("BUG.6 throttle: one process-wide gate, not one per translation unit")
def c_throttle_single_gate(src):
    code = strip_comments(src.tl_m)
    # TweakLog() is a static function in the header, so a gate declared THERE
    # would exist once per file that logs - each with its own 200 ms window.
    per_tu = "static tweak_log_fsync_gate" in strip_comments(src.tl_h)
    defs = len(re.findall(r"static\s+tweak_log_fsync_gate\s+\w+", code))
    defines_now = re.search(r"int\s+tweak_log_fsync_due_now\s*\(\s*void\s*\)\s*\{", code) is not None
    uses_that_gate = re.search(r"tweak_log_fsync_due\s*\(\s*&g_fsyncGate\s*,", code) is not None
    monotonic = "CLOCK_MONOTONIC" in code
    ok = (not per_tu) and defs == 1 and defines_now and uses_that_gate and monotonic
    report(ok, "BUG.6 throttle: one process-wide gate, not one per translation unit",
           "gate in header=%s gate definitions in tweak_log.m=%d defines_now=%s calls it=%s monotonic=%s"
           % (per_tu, defs, defines_now, uses_that_gate, monotonic))
    return ok


@check("BUG.6 throttle: the gate is a compiled, host-tested policy in both builds")
def c_throttle_policy_shipped(src):
    pol_h = strip_comments(src.tlp_h)
    pol_c = strip_comments(src.tlp_c)
    window_const = re.search(r"#define\s+TWEAK_LOG_FSYNC_MIN_INTERVAL_MS\s+200\b", pol_h) is not None
    decision = ("tweak_log_fsync_due" in pol_c
                and "gate->suppressed++" in pol_c
                and "gate->granted++" in pol_c
                and "return 0;" in pol_c)
    in_archive = "utils/tweak_log_policy.c" in (src.libe or "")
    in_tweak = "utils/tweak_log_policy.c" in (src.tweak_mk or "")
    in_test = ("utils/tweak_log_policy.c" in (src.tl_run or "")
               and "tests/tweak_log_throttle_host_test.c" in (src.tl_run or ""))
    test_asserts = ("granted + r.suppressed == r.lines" in src.tl_test
                    or "granted + b.suppressed == b.lines" in src.tl_test)
    test_boundary = "199 * MS" in src.tl_test and "200 * MS" in src.tl_test
    test_not_vacuous = "run_burst_unthrottled" in src.tl_test
    ok = (window_const and decision and in_archive and in_tweak and in_test
          and test_asserts and test_boundary and test_not_vacuous)
    report(ok, "BUG.6 throttle: the gate is a compiled, host-tested policy in both builds",
           "200 ms=%s decision=%s archive=%s tweak=%s host test compiles it=%s counter arithmetic=%s "
           "window edge=%s non-vacuous=%s"
           % (window_const, decision, in_archive, in_tweak, in_test, test_asserts,
              test_boundary, test_not_vacuous))
    return ok


def _file_text(src, rel):
    """Text of a repo-relative path, engine tree first, then the app tree."""
    for base in (src.root, src.wolfterm):
        text = read(base, rel)
        if text is not None:
            return text
    return None


def _reachable_sources(src, seeds, depth=3):
    """seeds plus the LOCAL headers they pull in (quoted #include/#import, tried
    relative to the including file and to the repo root).

    Why not just the SOURCES= list: the sink's fsync lives in utils/tweak_log.h,
    which is not in the archive's file list - only the .m that includes it is.
    A check that reads the SOURCES list alone would answer "which files does the
    app compile" with a list that cannot contain the fsync it is looking for."""
    out = []
    frontier = list(seeds)
    for _ in range(depth + 1):
        nxt = []
        for rel in frontier:
            rel = os.path.normpath(rel)
            if rel in out:
                continue
            text = _file_text(src, rel)
            if text is None:
                continue
            out.append(rel)
            for inc in re.findall(r'^\s*#\s*(?:include|import)\s+"([^"]+)"', text, re.M):
                nxt.append(os.path.normpath(os.path.join(os.path.dirname(rel), inc)))
                nxt.append(os.path.normpath(inc))
        frontier = nxt
    return out


@check("BUG.6 throttle: no other fsync-per-line sink in the shipped code")
def c_throttle_no_other_fsync(src):
    files = _archive_sources(src.root)
    if files is None:
        report(False, "BUG.6 throttle: no other fsync-per-line sink in the shipped code",
               "scripts/build_libengine.sh has no SOURCES= list to parse")
        return False
    candidates = list(files)
    for name in sorted(os.listdir(src.wolfterm)):
        if name.endswith((".m", ".c")):
            candidates.append(name)
    scanned = _reachable_sources(src, candidates)
    hits = []
    for rel in scanned:
        text = _file_text(src, rel)
        if text is None:
            continue
        if re.search(r"(?<![_A-Za-z])fsync\s*\(", strip_comments(text)):
            hits.append(rel)
    ok = hits == ["utils/tweak_log.h"]
    report(ok, "BUG.6 throttle: no other fsync-per-line sink in the shipped code",
           "%d file(s) scanned (archive sources + their local headers + the app sources); fsync call sites: %s"
           % (len(scanned), ", ".join(hits) if hits else "none"))
    return ok


# ===========================================================================
# selftest: every mutation above must be caught
# ===========================================================================
def _mutate(text, old, new, count=1):
    if old not in text:
        return None
    return text.replace(old, new, count)


def _mutate_all(text, old, new):
    if old not in text:
        return None
    return text.replace(old, new)


def selftest(root, wolfterm):
    """Each entry: (name, file-kind, relative path, mutator). The mutator returns
    the mutated text, or None when the anchor is not found (which is itself a
    selftest failure: the lint would not be checking what we think)."""
    mutations = []

    def mut_engine_budget_120(text):
        return _mutate(text, "#define EXPLOIT_SCAN_BUDGET_SEC 600", "#define EXPLOIT_SCAN_BUDGET_SEC 120")

    def mut_app_budget_120(text):
        return _mutate(text, "static int g_scanBudget = 600;", "static int g_scanBudget = 120;")

    def mut_app_no_push(text):
        return _mutate(text, "    kexploit_set_scan_budget(g_scanBudget);\n\n    // Push package",
                             "\n    // Push package")

    def mut_no_emit_count(text):
        return _mutate(text, "    kwrite_count_emit(kwrite_src_current(), EARLY_KRW_LENGTH);",
                             "    /* counting removed by the selftest */")

    def mut_zone_no_route(text):
        return _mutate(text, "    kwrite_src_t prevSrc = kwrite_src_push(KWRITE_SRC_ZONE);",
                             "    /* route push removed by the selftest */")

    def mut_no_engine_summary(text):
        return drop_block(text, "static void kexploit_log_scan_writes(const char *where) {")

    def mut_no_app_writes_log(text):
        return _mutate(text, "            term_log_write_count(\"this attempt (scan + probe)\");",
                             "            /* app write log removed by the selftest */")

    def mut_no_cancel_word(text):
        return _mutate_all(text, "        self.cancelLabel.alpha = 1.0;\n", "")

    def mut_no_cancel_stop(text):
        return _mutate(text, "        kexploit_request_stop();", "        /* stop flag removed by the selftest */")

    def mut_no_pe_v1_funnel_call(text):
        return _mutate(text,
                       "        pe_v1_release_cycle(searchMappings, searchMappingSize, wiredMapping, wiredMappingSize,\n                            (testResult != 0) || success);",
                       "        /* funnel call removed by the selftest */")

    def mut_no_pe_v1_cancel_release(text):
        # The exact regression BUG.4 is about: a cancel exit that returns with
        # the search mapping mapped and the spray still open.
        return _mutate(text,
                       "            pe_v1_release_cycle(nil, searchMappingSize, wiredMapping, wiredMappingSize, true);\n"
                       "            free(readBuffer);\n"
                       "            free(writeBuffer);\n"
                       "            release_gencnt_tracker(targetInpGencntList, \"pe_v1\");\n"
                       "            return -7;",
                       "            return -7;")

    def mut_no_funnel_sockets(text):
        return _mutate(text, "    sockets_release(socketPorts, socketPcbIds);\n    while (searchMappings.lastObject)",
                             "    while (searchMappings.lastObject)")

    def mut_no_pe_v2_munlock(text):
        return _mutate(text, "        surface_munlock(searchMappingAddress, searchMappingSize);\n        kr = mach_vm_deallocate(mach_task_self(), searchMappingAddress, searchMappingSize);",
                             "        kr = mach_vm_deallocate(mach_task_self(), searchMappingAddress, searchMappingSize);")

    def mut_app_retries_after_cancel(text):
        return _mutate(text, "            if (kret == -7) {", "            if (false && kret == -7) {")

    def mut_spray_ignores_cancel(text):
        return _mutate(text,
                       "            // BUG.4: a CANCEL stops the SPRAY too - this loop opens up to ~28k\n"
                       "            // sockets and used to run to the end of the file table even after a\n"
                       "            // cancel (it was the longest thing a cancelled run still paid for).\n"
                       "            if (kexploit_stop_requested()) {",
                       "            if (false) {")

    def mut_a18_ignores_cancel(text):
        return _mutate(text, "        if (g_peV2Aborted) {", "        if (false) {")

    def mut_sink_fsyncs_every_line(text):
        # The BUG.6 regression itself: the rate gate dropped from the condition,
        # so the sink is back to one fsync per line (what dirtied 1.07 GB in
        # 18 minutes on the SE).
        return _mutate(text,
                       "if (tweak_log_hook_installed() && tweak_log_fsync_due_now()) {",
                       "if (tweak_log_hook_installed()) {")

    def mut_gate_per_translation_unit(text):
        return _mutate(text,
                       "int tweak_log_fsync_due_now(void);",
                       "static tweak_log_fsync_gate g_perTuGate;   // mutation: per-TU gate\nint tweak_log_fsync_due_now(void);")

    def mut_policy_not_in_archive(text):
        return _mutate(text,
                       "utils/tweak_log.m utils/tweak_log_policy.c \\",
                       "utils/tweak_log.m \\")

    def mut_interval_zero(text):
        return _mutate(text,
                       "#define TWEAK_LOG_FSYNC_MIN_INTERVAL_MS 200",
                       "#define TWEAK_LOG_FSYNC_MIN_INTERVAL_MS 0")

    def mut_app_adds_a_bare_fsync(text):
        return _mutate(text,
                       "    TweakLog(\"[w0lf] cancel requested - the scan will stop at its next check\");",
                       "    fsync(0);   // mutation: an ungated sink in the app\n"
                       "    TweakLog(\"[w0lf] cancel requested - the scan will stop at its next check\");")

    mutations = [
        ("engine budget default back to 120", "engine", "kexploit/kexploit_opa334.m", mut_engine_budget_120),
        ("app budget default back to 120", "app", "term_settings.m", mut_app_budget_120),
        ("app stops pushing the budget into the engine", "app", "term_settings.m", mut_app_no_push),
        ("the write primitive stops counting emits", "engine", "kexploit/kexploit_opa334.m", mut_no_emit_count),
        ("the clamped writer stops attributing its route", "engine", "kexploit/krw.m", mut_zone_no_route),
        ("the engine's measured summary is gone", "engine", "kexploit/kexploit_opa334.m", mut_no_engine_summary),
        ("the app stops logging the measured number", "app", "term_bridge.m", mut_no_app_writes_log),
        ("the cancel word is never shown", "app", "TerminalViewController.m", mut_no_cancel_word),
        ("the bridge stops setting the stop flag", "app", "term_bridge.m", mut_no_cancel_stop),
        ("pe_v1 stops calling its release funnel", "engine", "kexploit/kexploit_opa334.m", mut_no_pe_v1_funnel_call),
        ("pe_v1's cancel exit returns without the funnel", "engine", "kexploit/kexploit_opa334.m", mut_no_pe_v1_cancel_release),
        ("the funnel stops releasing the spray", "engine", "kexploit/kexploit_opa334.m", mut_no_funnel_sockets),
        ("pe_v2's cancel path stops munlocking the mapping", "engine", "kexploit/kexploit_opa334.m", mut_no_pe_v2_munlock),
        ("the app retries on -7 after a cancel", "app", "term_bridge.m", mut_app_retries_after_cancel),
        ("the up-front spray ignores a cancel", "engine", "kexploit/kexploit_opa334.m", mut_spray_ignores_cancel),
        ("the A18 caller ignores pe_v2's cancel", "engine", "kexploit/kexploit_opa334.m", mut_a18_ignores_cancel),
        ("the log sink fsyncs every line again (no rate gate)", "engine", "utils/tweak_log.h", mut_sink_fsyncs_every_line),
        ("the rate gate moves into the per-TU header", "engine", "utils/tweak_log.h", mut_gate_per_translation_unit),
        ("the throttle policy drops out of the engine archive", "engine", "scripts/build_libengine.sh", mut_policy_not_in_archive),
        ("the rate window is 0 ms (grants every line)", "engine", "utils/tweak_log_policy.h", mut_interval_zero),
        ("the app grows a second, ungated fsync sink", "app", "term_bridge.m", mut_app_adds_a_bare_fsync),
    ]

    tmp = tempfile.mkdtemp(prefix="bug345_lint_selftest_")
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

            target = os.path.join(root_tmp if kind == "engine" else app_tmp, rel)
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


# ===========================================================================
# runner
# ===========================================================================
def run_checks(root, wolfterm, quiet=False):
    del RESULTS[:]
    src = Src(root, wolfterm)
    failed_names = []
    if not all_sources_present(src):
        return ["<sources missing>"]
    for name, fn in CHECKS:
        try:
            ok = fn(src)
        except Exception as exc:      # a check that crashes is a failing check
            report(False, name, "check raised %r" % (exc,))
            ok = False
        if not ok:
            failed_names.append(name)
    if not quiet:
        passed = len(RESULTS) - len(failed_names)
        print("\n%d check(s) passed, %d failed" % (passed, len(failed_names)))
    return failed_names


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

    print("BUG.3 + BUG.5 + BUG.4 + BUG.6 end-to-end lint")
    print("  engine root: %s" % root)
    print("  app root:    %s\n" % wolfterm)

    failed = run_checks(root, wolfterm)
    rc = 1 if failed else 0

    if selftest_mode:
        print("\nselftest (mutating temp copies):")
        rc |= selftest(root, wolfterm)

    if rc == 0:
        print("\nSCAN_BUDGET_CANCEL_WRITES LINT PASS")
    else:
        print("\nSCAN_BUDGET_CANCEL_WRITES LINT FAIL")
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv))
