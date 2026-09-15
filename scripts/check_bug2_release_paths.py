#!/usr/bin/env python3
"""BUG.2 release-path lint (host only, no device, no build).

Encodes the invariants of the 0.12 / BUG.2 audit of pe_v1 + pe_v2 in
kexploit/kexploit_opa334.m so a later edit cannot silently add an exit that
walks away with the socket spray, a search mapping, an mlock'd surface, the
memory object or the wired pages.

What it is: a source-level lint over the two function bodies. It proves the
shape of the release funnel (every exit is preceded by a release call) and that
the one-release-site rules hold. It does NOT prove kernel behaviour and does not
replace a device run.

Usage: python3 scripts/check_bug2_release_paths.py   (exit 0 = all checks pass)
       python3 scripts/check_bug2_release_paths.py --selftest
       (--selftest mutates TEMP COPIES of the engine source and of
        kexploit/probe_restore_policy.c (BUG.1 step 1) - no repo file is written
        - and requires the lint to FAIL on each mutation, so the checks above
        cannot silently become vacuous. exit 0 = every mutation was caught.)
"""
import re
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "kexploit" / "kexploit_opa334.m"
# BUG.1 step 1 (same file family): the restore contract the engine and the host
# test both compile - the file that decides whether a corrupted live inpcb is put
# back, and through which fds.
SRC_POLICY = Path(__file__).resolve().parent.parent / "kexploit" / "probe_restore_policy.c"
# BUG.1 step 3b: the clamp itself (the file the host test also drives) and the one
# other caller that writes through it, so "no unclamped write into a live object"
# stays true for the whole tree and not just for the probe.
SRC_WRITER = Path(__file__).resolve().parent.parent / "kexploit" / "krw_zone_write.c"
SRC_SANDBOX = Path(__file__).resolve().parent.parent / "kexploit" / "sandbox.m"


EXIT = re.compile(r"\breturn\b|FAILURE_V?\(|\bFAILURE\(")
LOOKBACK = 20  # lines before an exit in which its release call must appear
# The funnel call every exit of the function must be preceded by.
FUNNEL = {"pe_v1": "pe_v1_release_cycle(", "pe_v2": "wired_pages_cleanup("}
# Exits that legitimately walk away holding NOTHING, identified by the log line
# of the branch they sit in (verified by hand in the audit). Each of these fires
# before any of the audited resources exists:
#   pe_v1/pe_v2 "calloc failed for the OOB buffers" - the two OOB buffers are all
#     that could be held, and the exit frees them.
#   pe_v2 "All allocation sizes failed" - every wired-page attempt already
#     released its own pages; the wiredAddrs tracker does not exist yet.
# Anything else must show the funnel in its lookback window: a bare
# free(readBuffer) is NOT accepted as a release.
PREFLIGHT = {
    "pe_v1": ("calloc failed for the OOB buffers",),
    "pe_v2": ("calloc failed for the OOB buffers", "All allocation sizes failed"),
}

# surface_mlock(expr, ...) -> how that mapping gets its surface_munlock. The
# wired pages of pe_v2 are mlock'd by address but released by value through the
# wiredAddrs tracking array (wired_pages_cleanup) or inline on the branch that
# finds a page, which is why the expression cannot be matched textually.
MLOCK_RELEASE = {
    "wiredMapping": r"surface_munlock\(wiredMapping",
    "searchMappingAddress": r"surface_munlock\(searchMappingAddress",
    "wiredAddr": r"surface_munlock\(addr\.unsignedLongLongValue",
    "wiredPage": r"surface_munlock\(wiredPage",
    "addr.unsignedLongLongValue": r"surface_munlock\(addr\.unsignedLongLongValue",
}
# (nothing to allowlist: RULES above covers the exits that legitimately hold
# nothing - they are the ones that fire before the function's first resource.)

failures, passes = [], []


def report(ok, name, detail):
    (passes if ok else failures).append(name)
    print(("PASS  " if ok else "FAIL  ") + name + "  " + detail)


def strip_comments(text):
    """Remove //-comments (outside string literals) so prose cannot trip a check."""
    out = []
    for line in text.split("\n"):
        i, in_str, cut = 0, None, None
        while i < len(line):
            c = line[i]
            if in_str:
                if c == "\\":
                    i += 2
                    continue
                if c == in_str:
                    in_str = None
            elif c in "\"'":
                in_str = c
            elif c == "/" and i + 1 < len(line) and line[i + 1] == "/":
                cut = i
                break
            i += 1
        out.append(line[:cut] if cut is not None else line)
    return "\n".join(out)


def body(text, header):
    start = text.index(header)
    i = text.index("{", start)
    depth, j = 0, i
    while j < len(text):
        if text[j] == "{":
            depth += 1
        elif text[j] == "}":
            depth -= 1
            if depth == 0:
                break
        j += 1
    return text[:start].count("\n"), text[i : j + 1]


def bare_mo_dealloc_outside_helper(text):
    """The ONLY legal bare memory-object deallocates are the two inside
    release_memory_object (the call plus its one bounded retry). Anything else
    is a release site that bypasses the funnel."""
    needle = "mach_port_deallocate(mach_task_self(), memoryObject)"
    total = text.count(needle)
    _, helper = body(text, "static kern_return_t release_memory_object(")
    inside = helper.count(needle)
    return total == 2 and inside == 2


# ---------------------------------------------------------------------------
# Round 3 of the same task: the reviewer pointed out that the first pass
# DOCUMENTED three leaks (pe_init retry, the early-return teardown, the MRC
# tracker arrays) instead of fixing them. These checks cover the fixes, which is
# what makes them stay fixed.
# ---------------------------------------------------------------------------
TEARDOWN = "kexploit_attempt_teardown();"


def section_exits(body_text, offset):
    """Every function-level exit in source order, paired with the code between the
    PREVIOUS exit and this one. That straight-line section is the exit's own path,
    so it is where the exit's own releases have to appear."""
    lines = body_text.split("\n")
    out, prev = [], 0
    for i, line in enumerate(lines):
        code = line.strip()
        if not code or code.startswith("//") or not EXIT.search(code):
            continue
        out.append((offset + i + 1, code, "\n".join(lines[prev:i])))
        prev = i + 1
    return out


def brace_depths(lines):
    depths, depth = [], 0
    for line in lines:
        depths.append(depth)
        depth += line.count("{") - line.count("}")
    return depths


def block_scopes(lines, exit_idx, depths):
    """The text that sits DIRECTLY in each block enclosing the exit, before the
    exit, innermost block first.

    Used for the one-shot teardown, which a later exit on the same straight-line
    path (the kernel-base-scan failure and the final success return, both reached
    through the tail) legitimately relies on. A release placed in a SIBLING branch
    of an enclosing block is not in any of these windows - which is the point: an
    exit may only be covered by a release on its own path.
    """
    scopes, level = [], depths[exit_idx]
    while level >= 1:
        start = exit_idx - 1
        while start >= 0 and not (depths[start] == level - 1 and "{" in lines[start]):
            start -= 1
        if start < 0:
            break
        scopes.append("\n".join(l for i, l in enumerate(lines[start + 1:exit_idx], start=start + 1)
                                if depths[i] == level))
        level -= 1
    return scopes


def round3(text):
    print()
    print("round 3 — the three leaks the first pass left 'documented, not fixed':")

    # 1. kexploit_opa334(): every exit that has run pe_init() tears the attempt
    #    down (free thread stopped + joined, target fds closed); the two exits
    #    before pe_init() must not, because nothing is allocated there yet.
    offset, body_text = body(text, "int kexploit_opa334(void) {")
    init_line = None
    at = body_text.find("pe_init();")
    if at != -1:
        init_line = offset + body_text[:at].count("\n") + 1
    missing, extra, traced = [], [], []
    klines = body_text.split("\n")
    kdepths = brace_depths(klines)
    for line_no, code, _section in [e for e in section_exits(body_text, offset)]:
        idx = line_no - offset - 1
        scopes = block_scopes(klines, idx, kdepths)
        has = any(TEARDOWN in s for s in scopes)
        after_init = init_line is not None and line_no > init_line
        traced.append((line_no, code, "teardown" if has else "pre-init (holds nothing)"))
        if after_init and not has:
            missing.append((line_no, code))
        if not after_init and has:
            extra.append((line_no, code))
    report(
        not missing and not extra,
        "kexploit_opa334: every exit after pe_init() runs the attempt teardown",
        f"{len(traced)} exit(s) traced (pe_init at src line {init_line}), "
        f"without teardown: {missing if missing else 'none'}, "
        f"unexpected: {extra if extra else 'none'}",
    )
    for line_no, code, rel in traced:
        print(f"        kexploit_opa334 src line {line_no}: {code}   <- {rel}")

    # 2. the spray-tracking pair (socketPorts / socketPcbIds) is released on every
    #    pe_v1 exit (through the funnel) and on every pe_v2 exit (explicitly).
    _, funnel = body(text, "static void pe_v1_release_cycle(")
    report("tracker_arrays_release();" in funnel,
           "pe_v1: the single exit funnel releases the spray-tracking pair",
           "tracker_arrays_release() " +
           ("found in pe_v1_release_cycle" if "tracker_arrays_release();" in funnel
            else "MISSING from pe_v1_release_cycle"))
    off, pv2 = body(text, "void pe_v2(void) {")
    bad, checked = [], 0
    for line_no, code, section in section_exits(pv2, off):
        checked += 1
        if "tracker_arrays_release();" not in section:
            bad.append((line_no, code))
    report(not bad,
           "pe_v2: every exit releases the spray-tracking pair",
           f"{checked} exit(s) checked, missing: {bad if bad else 'none'}")

    # 3. the per-call gencnt tracker is released on every TERMINAL exit of both
    #    (the exits that fire before it exists are named).
    exempt = {
        "pe_v1": ("calloc failed for the OOB buffers",),
        "pe_v2": ("calloc failed for the OOB buffers", "All allocation sizes failed"),
    }
    for name, header in (("pe_v1", "int pe_v1(void) {"), ("pe_v2", "void pe_v2(void) {")):
        off, body_text2 = body(text, header)
        bad, checked = [], 0
        for line_no, code, section in section_exits(body_text2, off):
            if any(marker in section for marker in exempt[name]):
                continue
            checked += 1
            if "release_gencnt_tracker(" not in section:
                bad.append((line_no, code))
        report(not bad, f"{name}: every terminal exit releases the gencnt tracker",
               f"{checked} exit(s) checked, missing: {bad if bad else 'none'}")

    # 4. the pair is only ever created inside tracker_arrays_reset() - a bare
    #    `[NSMutableArray new]` at a re-creation site is how the leak came back.
    creations = re.findall(r"\bsocket(?:Ports|PcbIds) = \[NSMutableArray", text)
    _, reset_body = body(text, "static void tracker_arrays_reset(void) {")
    in_helper = reset_body.count("[NSMutableArray")
    report(len(creations) == 2 and in_helper == 2,
           "the spray trackers are only created inside tracker_arrays_reset()",
           f"{len(creations)} creation site(s) in the file, {in_helper} inside the helper")

    # 5. a retry releases the previous attempt's OOB mapping before replacing it.
    _, iprw = body(text, "void initialize_physical_read_write(")
    ok = ("release_physical_mapping();" in iprw and
          iprw.index("release_physical_mapping();") < iprw.index("create_physically_contiguous_mapping("))
    report(ok,
           "initialize_physical_read_write: the previous OOB mapping is released first",
           "release_physical_mapping() " +
           ("precedes the new mapping" if ok else "MISSING before create_physically_contiguous_mapping()"))

    # 6. one free thread per process: pe_init guards the create, the teardown
    #    clears the flag, and every wait in free_thread honours the stop flag (5
    #    = four waits + the post-wait break).
    _, init_body = body(text, "void pe_init(void) {")
    _, teardown = body(text, "static void kexploit_attempt_teardown(void) {")
    _, ft = body(text, "void *free_thread(void *arg) {")
    report("if (g_freeThreadLive)" in init_body and "pthread_create(" in init_body
           and "g_freeThreadLive = true;" in init_body,
           "pe_init: the free thread is created only when none is live",
           "guard/create/set " + ("present" if "g_freeThreadLive = true;" in init_body else "MISSING"))
    report("g_freeThreadLive = false;" in teardown and "pthread_join(" in teardown
           and "g_freeThreadStop, 1, __ATOMIC_RELEASE" in teardown,
           "teardown: sets the stop flag, joins the thread, clears the live flag",
           "stop/join/clear " + ("present" if "g_freeThreadLive = false;" in teardown else "MISSING"))
    waits = ft.count("g_freeThreadStop")
    report(waits >= 5, "free_thread: every wait can be broken by the stop flag",
           f"{waits} stop-flag check(s) in free_thread (want 5)")

    # 7. one [cleanup] log line per release, so a device log shows each item.
    for shape in [
        ("log line: teardown (free thread)", r"KPRINTF\(\"\[cleanup\] kexploit: free thread stopped \+ joined"),
        ("log line: teardown (target fds)", r"KPRINTF\(\"\[cleanup\] kexploit: target fds closed"),
        ("log line: spray tracker pair", r"KPRINTF\(\"\[cleanup\] spray tracking arrays released"),
        ("log line: gencnt tracker", r"KPRINTF\(\"\[cleanup\] %s: gencnt tracker released"),
        ("log line: previous OOB mapping", r"KPRINTF\(\"\[cleanup\] physical mapping"),
    ]:
        name, pattern = shape
        hit = bool(re.search(pattern, text))
        report(hit, name, "pattern " + ("found" if hit else "MISSING"))


# ---------------------------------------------------------------------------
# BUG.1 step 1 (same day, SE panic): the staged write probe's restore contract.
# The engine and the host test compile the SAME kexploit/probe_restore_policy.c,
# so these checks pin the shape of the fix: which exits restore (all but the
# promotion - the default must be fail-safe), which fds may be used (the spray
# tracking array, else the promotion's fds stamped for THIS corruption, else a
# loud failure), and that neither side re-invents an enumeration of exit codes.
# ---------------------------------------------------------------------------
def bug1_restore(text, policy):
    print()
    print("BUG.1 step 1 - the staged write probe's unconditional restore:")

    _, wrapper = body(text, "int find_and_corrupt_socket(")
    ok = ("probe_exit_action_for(rc) == PROBE_ACTION_RESTORE" in wrapper
          and "restore_corrupted_socket();" in wrapper)
    report(ok, "find_and_corrupt_socket: the exit is classified, then restored",
           "policy call + restore " + ("present" if ok else "MISSING from the wrapper"))

    _, restore = body(text, "static bool restore_corrupted_socket(void) {")
    ok = "probe_restore_fd_source(" in restore
    report(ok, "the restore asks the policy which fds it may write through",
           "probe_restore_fd_source() " + ("in restore_corrupted_socket" if ok else "MISSING"))
    ok = ("PROBE_FD_SOURCE_UNREACHABLE" in restore and "return false;" in restore
          and "PROBE_FD_SOURCE_PROMOTION_FDS" in restore)
    report(ok, "the restore handles all three fd sources (array / promotion fds / loud failure)",
           "unreachable-returns-false + promotion-fd branch " + ("present" if ok else "MISSING"))

    _, live = body(text, "static bool probe_fds_are_live_for(int controlSocketIdx) {")
    ok = ("g_probe_fds_idx == controlSocketIdx" in live
          and "g_probe_fds_gen == g_probe_save_gen" in live)
    report(ok, "the live-fd test requires the socket index AND the save generation",
           "stamp checks " + ("present" if ok else "MISSING (a pair from an earlier save would be used)"))

    _, openfds = body(text, "static void open_probe_socket_fds(int controlSocketIdx) {")
    ok = ("g_probe_fds_gen = g_probe_save_gen;" in openfds
          and "int newControl = fileport_makefd" in openfds)
    report(ok, "open_probe_socket_fds opens into locals and stamps only a successful pair",
           "commit-on-success + generation stamp " + ("present" if ok else "MISSING"))
    report("g_probe_save_gen++;" in text, "the save site bumps the corruption generation",
           "stamp " + ("found" if "g_probe_save_gen++;" in text else "MISSING"))

    _, pv1 = body(text, "int pe_v1(void) {")
    ok = "g_test_mo = MACH_PORT_NULL;" in pv1
    report(ok, "the restore's OOB verify context is cleared when its memory object is released",
           "clear after release_memory_object " + ("present" if ok else "MISSING"))

    # the policy source itself: the fail-safe default is the whole point
    handoffs = policy.count("return PROBE_ACTION_HAND_OFF;")
    default = re.search(r"if \(probeRc == PROBE_EXIT_PROMOTED\) \{[\s\S]*?"
                        r"return PROBE_ACTION_HAND_OFF;[\s\S]*?\}\s*\n\s*"
                        r"return PROBE_ACTION_RESTORE;", policy)
    report(handoffs == 1 and default is not None,
           "probe_exit_action_for: exactly one hand-off, and the default is RESTORE",
           f"{handoffs} hand-off return(s), fail-safe default "
           + ("present" if default else "MISSING (an unseen exit code would not restore)"))
    fallback = "if (promotionPairLive) return PROBE_FD_SOURCE_PROMOTION_FDS;" in policy
    report(fallback, "probe_restore_fd_source: the promotion-fd fallback is the array-gone case",
           "fallback " + ("present" if fallback else "MISSING (the staged -5 restore would write nothing)"))


# ---------------------------------------------------------------------------
# BUG.1 step 3b (2026-09-11 SE panic): the clamp must actually COVER the probe.
# Step 3 clamped kwrite_zone_element, but the probe wrote with early_kwrite64 -
# an unclamped 32-byte RMW at whatever address it had produced (0.13's BUG.7).
# These checks pin both halves: the writer refuses every undeclared call (the SE
# write was an exact multiple of 0x20, so the old shifted-tail rule never saw
# it), and no caller in the probe/escape path writes through the unclamped path.
# ---------------------------------------------------------------------------
def bug1_step3b(text, writer, sandbox):
    print()
    print("BUG.1 step 3b - the clamp covers the probe, and nothing is written undeclared:")

    # 1. the bound check refuses a write with no declared object (default deny)
    deny = re.search(r"if \(!haveObj\) \{[\s\S]{0,400}?KRW_ZONE_REFUSE_UNDECLARED", writer)
    report(deny is not None,
           "the writer's bound check refuses a call with no object declared",
           "default-deny branch " + ("present" if deny else "MISSING (an undeclared write would be emitted unproven)"))
    plan_before_emit = (deny is not None and "while (off < len) {" in writer and
                        deny.start() < writer.index("while (off < len) {"))
    report(plan_before_emit,
           "the whole range is proved before the emit loop",
           "planning pass precedes the first block " + ("yes" if plan_before_emit else "NO"))

    # 2. the qword path the probe uses is clamped too
    qword = re.search(r"krw_zone_verdict krw_zone_write_qword\([^)]*\)\s*\{[\s\S]*?\n\}", writer)
    qword_body = qword.group(0) if qword else ""
    ok = ("if (!haveObj) {" in qword_body and "KRW_ZONE_REFUSE_UNDECLARED" in qword_body and
          "blockStart + KRW_ZONE_BLOCK_LEN > objBase + objSize" in qword_body)
    report(ok, "the qword writer refuses an undeclared or out-of-window block",
           "guards " + ("present" if ok else "MISSING from krw_zone_write_qword"))
    aligned = "krw_zone_block_align_down(dst)" in qword_body
    report(aligned, "the qword writer patches the 0x20-aligned block, not 32 bytes at dst",
           "aligned block " + ("used" if aligned else "MISSING (an unaligned RMW can straddle two blocks)"))

    # 3. the probe: every write it makes goes through the clamped helper
    _, probe = body(text, "static int find_and_corrupt_socket_probe(")
    ok = "early_kwrite64(" not in probe and "early_kwrite32bytes(" not in probe
    report(ok, "find_and_corrupt_socket_probe holds no unclamped write",
           "early_kwrite64/32bytes " + ("absent" if ok else "PRESENT in the probe"))
    ok = probe.count("probe_kwrite_inpcb_qword(") >= 2
    report(ok, "the probe's marker write and its own restore both use the clamped helper",
           f"{probe.count('probe_kwrite_inpcb_qword(')} clamped call(s) in the probe")

    # 4. the restore: both put-back writes go through the clamped helper
    _, restore = body(text, "static bool restore_corrupted_socket(void) {")
    ok = "early_kwrite64(" not in restore and "early_kwrite32bytes(" not in restore
    report(ok, "restore_corrupted_socket holds no unclamped write",
           "early_kwrite64/32bytes " + ("absent" if ok else "PRESENT (the put-back would bypass the clamp)"))
    ok = (restore.count("probe_kwrite_inpcb_qword(") >= 2 and
          "if (!wrote8 || !wrote0)" in restore)
    report(ok, "the restore's put-back uses the clamped helper and handles a refusal",
           f"{restore.count('probe_kwrite_inpcb_qword(')} clamped call(s) + refusal branch in the restore")

    # 5. the other write into a live inpcb in the escape path is clamped as well
    _, leak = body(text, "void krw_sockets_leak_forever(void) {")
    ok = "kwrite_zone_element_qword(" in leak and "KRW_ZONE_OK" in leak
    report(ok, "krw_sockets_leak_forever's inpcb write is clamped too",
           "clamped " + ("yes" if ok else "NO (it still writes through early_kwrite64)"))

    # 6. the window the probe declares is derived, not guessed
    _, window = body(text, "static uint64_t probe_inpcb_window_size(void)")
    ok = ("g_test_filt_offset" in window and "krw_zone_window_for_field_end(" in window)
    report(ok, "probe_inpcb_window_size derives the window from the probed field offset",
           "derivation " + ("present" if ok else "MISSING (a hardcoded size would be a guess)"))
    ok = "off_inpcb_inp_depend6_inp6_chksum" in text.split("probe_inpcb_window_size_for_offsets")[1][:400]
    report(ok, "the offsets-table window uses the inp6_chksum field the table pins",
           "offset constant " + ("used" if ok else "MISSING"))

    # 7. the one caller outside the probe that used the undeclared form declares now
    bare = re.search(r"(?<!_)\bkwrite_zone_element\(", sandbox)
    report(bare is None and "kwrite_zone_element_declared(" in sandbox,
           "sandbox.m declares the object instead of calling the undeclared writer",
           "bare call " + ("absent" if bare is None else "PRESENT at char %d" % bare.start()) +
           ", declared call " + ("present" if "kwrite_zone_element_declared(" in sandbox else "MISSING"))
    ok = "KRW_ZONE_OK" in sandbox and "sizeof(struct extension_class_node)" in sandbox
    report(ok, "sandbox.m states the struct it knows and checks the verdict",
           "struct size + verdict check " + ("present" if ok else "MISSING"))


MUTATIONS = [
    ("pe_v1 loses its release funnel before the -4 exit",
     SRC.name,
     lambda s: re.sub(r"pe_v1_release_cycle\(nil, searchMappingSize, wiredMapping, "
                      r"wiredMappingSize, true\);\n(\s*)free\(readBuffer\);",
                      r"free(readBuffer);", s, count=1)),
    ("pe_v1's -4 exit loses the attempt teardown",
     SRC.name,
     lambda s: s.replace("            KPRINTF(\"[-] race rejected on this device — vm_map kr=4 "
                         "on every attempt, technique cannot run here\\n\");\n"
                         "            kexploit_attempt_teardown();   // BUG.2 round 3: this exit used to skip it\n",
                         "            KPRINTF(\"[-] race rejected on this device — vm_map kr=4 "
                         "on every attempt, technique cannot run here\\n\");\n")),
    ("a pe_v1 cycle goes back to a bare [NSMutableArray new] tracker pair",
     SRC.name,
     lambda s: s.replace("        tracker_arrays_reset();\n        unsigned socketPortsCount = 0;\n#define OPEN_MAX",
                         "        socketPorts = [NSMutableArray new];\n        socketPcbIds = [NSMutableArray new];\n"
                         "        unsigned socketPortsCount = 0;\n#define OPEN_MAX")),
    ("initialize_physical_read_write forgets the previous OOB mapping",
     SRC.name,
     lambda s: s.replace("    release_physical_mapping();\n    pcSize = contiguous_mapping_size;",
                         "    pcSize = contiguous_mapping_size;")),
    ("the teardown stops breaking free_thread's first wait",
     SRC.name,
     # The first wait is on freeThreadStart. Since the T18 yield change both
     # waits end in `pthread_yield_np();` instead of a bare `;`, so the mutation
     # drops the stop-flag half of the condition rather than rewriting the body
     # (a mutation that does not apply is a mutation the lint was never tested
     # against - the selftest reports it as MISSED, which is what this pattern
     # did between the T18 edit and this fix).
     lambda s: s.replace("    while (__atomic_load_n(&freeThreadStart, __ATOMIC_ACQUIRE) == 0 &&\n"
                         "           __atomic_load_n(&g_freeThreadStop, __ATOMIC_ACQUIRE) == 0)\n"
                         "        pthread_yield_np();",
                         "    while (__atomic_load_n(&freeThreadStart, __ATOMIC_ACQUIRE) == 0)\n"
                         "        pthread_yield_np();")),
    ("a release site bypasses release_memory_object",
     SRC.name,
     lambda s: s.replace('kr = release_memory_object(memoryObject, "pe_v1");',
                         "kr = mach_port_deallocate(mach_task_self(), memoryObject);")),
    ("pe_v2's tail stops releasing its wiredAddrs tracker",
     SRC.name,
     lambda s: re.sub(r"\[wiredAddrs release\];   // BUG\.2 audit: same MRC tracker[^\n]*\n[^\n]*\n",
                      "", s, count=1)),
    # --- BUG.1 step 1 (the restore contract) -------------------------------
    ("the probe's exit funnel enumerates rc != KERN_SUCCESS again instead of the policy",
     SRC.name,
     lambda s: s.replace("if (probe_exit_action_for(rc) == PROBE_ACTION_RESTORE) {",
                         "if (rc != KERN_SUCCESS) {")),
    ("the restore stops asking the policy which fds it may write through",
     SRC.name,
     lambda s: s.replace("probe_fd_source fdSource = probe_restore_fd_source(trackingArrayHoldsPair, promotionPairLive);",
                         "probe_fd_source fdSource = PROBE_FD_SOURCE_FILEPORTS;")),
    ("the promotion's fds are accepted without the save-generation check",
     SRC.name,
     lambda s: s.replace("           g_probe_fds_idx == controlSocketIdx &&\n"
                         "           g_probe_fds_gen == g_probe_save_gen;",
                         "           g_probe_fds_idx == controlSocketIdx;")),
    ("the restore's OOB verify context is not cleared when its port is released",
     SRC.name,
     lambda s: s.replace("            g_test_mo = MACH_PORT_NULL;\n            if (kr != KERN_SUCCESS) {",
                         "            if (kr != KERN_SUCCESS) {")),
    ("the policy hands every exit over instead of restoring by default",
     SRC_POLICY.name,
     lambda s: s.replace("    return PROBE_ACTION_RESTORE;\n}", "    return PROBE_ACTION_HAND_OFF;\n}")),
    ("the policy drops the promotion-fd fallback (the staged -5 restore)",
     SRC_POLICY.name,
     lambda s: s.replace("    if (promotionPairLive) return PROBE_FD_SOURCE_PROMOTION_FDS;",
                         "    /* fallback removed */")),
    # --- BUG.1 step 3b (the clamp must cover the probe) --------------------
    ("the restore goes back to the unclamped early_kwrite64 put-back",
     SRC.name,
     lambda s: s.replace("        bool wrote8 = probe_kwrite_inpcb_qword(pcb + g_test_filt_offset + 8, g_test_filt8_orig,",
                         "        early_kwrite64(pcb + g_test_filt_offset + 8, g_test_filt8_orig);\n"
                         "        bool wrote8 = probe_kwrite_inpcb_qword(pcb + g_test_filt_offset + 8, g_test_filt8_orig,")),
    ("the probe's marker round trip goes back to the unclamped early_kwrite64",
     SRC.name,
     lambda s: s.replace("        bool markerWrote = probe_kwrite_inpcb_qword(chksumAddr, chksumMarker,",
                         "        early_kwrite64(chksumAddr, chksumMarker);\n"
                         "        bool markerWrote = probe_kwrite_inpcb_qword(chksumAddr, chksumMarker,")),
    ("the qword writer stops refusing an undeclared call",
     SRC_WRITER.name,
     lambda s: s.replace("    if (!haveObj) {\n        krw_zone_log_refusal(KRW_ZONE_REFUSE_UNDECLARED, dst, sizeof(uint64_t),",
                         "    if (false) {\n        krw_zone_log_refusal(KRW_ZONE_REFUSE_UNDECLARED, dst, sizeof(uint64_t),")),
    ("the bound check stops refusing a call with no object declared",
     SRC_WRITER.name,
     lambda s: s.replace("    if (!haveObj) {\n        // Default deny.", "    if (false) {\n        // Default deny.")),
    ("the qword writer RMWs 32 bytes at dst instead of the aligned block",
     SRC_WRITER.name,
     lambda s: s.replace("    uint64_t blockStart = krw_zone_block_align_down(dst);",
                         "    uint64_t blockStart = dst;")),
    ("sandbox.m calls the undeclared writer again",
     SRC_SANDBOX.name,
     lambda s: s.replace("kwrite_zone_element_declared(ext_class_node_kptr, cn_buf, 0x20,",
                         "kwrite_zone_element(ext_class_node_kptr, cn_buf, 0x20) /* declared:")),
]


def selftest():
    """Prove the checks bite: mutate a temp copy, require the lint to fail."""
    import shutil
    import subprocess
    import tempfile

    rc = 0
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        (tmp / "scripts").mkdir()
        (tmp / "kexploit").mkdir()
        shutil.copy(Path(__file__), tmp / "scripts" / Path(__file__).name)
        lint = str(tmp / "scripts" / Path(__file__).name)
        cmd = [sys.executable, lint]
        # every source the lint reads must exist in the temp tree, because the
        # mutations touch more than one of them (BUG.1 step 1 added the policy,
        # step 3b the writer and sandbox.m).
        originals = {p.name: p.read_text() for p in (SRC, SRC_POLICY, SRC_WRITER, SRC_SANDBOX)}
        for name, content in originals.items():
            (tmp / "kexploit" / name).write_text(content)

        p = subprocess.run(cmd, capture_output=True, text=True)
        baseline = p.returncode == 0
        print(("PASS  " if baseline else "FAIL  ") + "selftest baseline: the lint passes on the unmutated source")
        rc |= 0 if baseline else 1

        for label, filename, mutate in MUTATIONS:
            original = originals[filename]
            target = tmp / "kexploit" / filename
            mutated = mutate(original)
            if mutated == original:
                print(f"FAIL  selftest mutation did not apply: {label}")
                rc = 1
                continue
            target.write_text(mutated)
            q = subprocess.run(cmd, capture_output=True, text=True)
            bit = q.returncode != 0
            detail = ""
            if bit:
                detail = " first check that failed: " + next(
                    l.strip() for l in q.stdout.splitlines() if l.startswith("FAIL"))
            print(("PASS  " if bit else "FAIL  ")
                  + f"selftest: the lint rejects - {label}" + detail)
            rc |= 0 if bit else 1
            target.write_text(original)
    print()
    print("selftest: " + ("all mutations caught" if rc == 0 else "SOME MUTATIONS WERE MISSED"))
    return rc


def main():
    raw = SRC.read_text()
    line_of_brace = raw.count("\n", 0, raw.index("int pe_v1(void) {")) + 1
    text = strip_comments(raw)
    policy = strip_comments(SRC_POLICY.read_text())
    writer = strip_comments(SRC_WRITER.read_text())
    sandbox = strip_comments(SRC_SANDBOX.read_text())
    regions = {}
    for header, name in (("int pe_v1(void) {", "pe_v1"), ("void pe_v2(void) {", "pe_v2")):
        offset, body_text = body(text, header)
        regions[name] = (offset, body_text)

    # 1. every function-level exit of pe_v1/pe_v2 releases the audited resources
    for name, (offset, body_text) in regions.items():
        lines = body_text.split("\n")
        funnel = FUNNEL[name]
        found, bad = [], []
        for i, line in enumerate(lines):
            code = line.strip()
            if not code or code.startswith("//") or not EXIT.search(code):
                continue
            window = "\n".join(lines[max(0, i - LOOKBACK) : i])
            if funnel in window:
                found.append((offset + i + 1, code, funnel))
            elif any(marker in window for marker in PREFLIGHT[name]):
                found.append((offset + i + 1, code, "holds nothing (branch marker matched)"))
            else:
                bad.append((offset + i + 1, code))
        report(
            not bad,
            f"{name}: every exit is preceded by {funnel}",
            f"{len(found)} exit(s) traced, unreleased: {bad if bad else 'none'}",
        )
        for line_no, code, rel in found:
            print(f"        {name} src line {line_no}: {code}   <- {rel}")

    # 2. pe_v1 has exactly one release site per resource: no direct deallocate or
    #    sockets_release in the function body (it all goes through the funnel).
    pv1 = regions["pe_v1"][1]
    direct = [l.strip() for l in pv1.split("\n")
              if re.search(r"sockets_release\(|mach_vm_deallocate\(|surface_munlock\(", l)]
    report(
        not direct,
        "pe_v1: the release funnel is the only release site",
        f"{len(direct)} direct sockets_release/deallocate/munlock call(s) in the body",
    )

    # 3. every surface_mlock() CALL is accounted for by a surface_munlock()
    #    (the declaration `void surface_mlock(uint64_t address, ...)` is not a call)
    mlocks = [m.strip() for m in re.findall(
        r"(?<![A-Za-z_>])surface_mlock\(\s*((?!uint64_t|mach_vm_|void)[^,;]+),", text)]
    unaccounted = []
    for expr in mlocks:
        pattern = MLOCK_RELEASE.get(expr)
        if pattern is None or not re.search(pattern, text):
            unaccounted.append(expr)
    report(
        not unaccounted,
        "every surface_mlock() expression has a documented surface_munlock() path",
        f"{len(mlocks)} mlock site(s) {mlocks}, unaccounted: {unaccounted if unaccounted else 'none'}",
    )

    # 4. the release funnel and its per-release log lines are present
    shapes = [
        ("pe_v1 funnel empties the mapping array before releasing",
         r"while \(searchMappings\.lastObject\) \{\s*\n\s*mach_vm_address_t address = searchMappings\.lastObject[\s\S]{0,200}?\[searchMappings removeLastObject\];\s*\n\s*surface_munlock\(address,"),
        ("pe_v2: the found wired page is munlocked before its deallocate",
         r"surface_munlock\(wiredPage, wiredEntrySize\);\s*\n\s*kr = mach_vm_deallocate\(mach_task_self\(\), wiredPage,"),
        ("pe_v2: the walk's search mapping is munlocked before its deallocate",
         r"surface_munlock\(searchMappingAddress, searchMappingSize\);\s*\n\s*kr = mach_vm_deallocate\(mach_task_self\(\), searchMappingAddress,"),
        # BUG.2 audit round 2: the wiredAddrs tracker is an owned (MRC) object
        # with up to 4MB of backing store. It must be released on all four exit
        # shapes: the allocFailed retry, the two FAILURE(0) exits and the tail.
        ("pe_v2: the wiredAddrs tracker is released on all four exit shapes",
         r"\[wiredAddrs release\];[\s\S]*\[wiredAddrs release\];[\s\S]*"
         r"\[wiredAddrs release\];[\s\S]*\[wiredAddrs release\];"),
        ("pe_v2: the tail cleans the wired pages up before releasing the tracker",
         None, lambda t: bool(re.search(
             r"wired_pages_cleanup\(wiredAddrs, wiredEntrySize\);\s*// A3\.5\s*\n\s*"
             r"printf\(\"\[\+\] pe_v2: Done[^\n]*\n\s*\[wiredAddrs release\];", raw))),
        # A real search: the earlier negative-lookahead version of this check
        # matched any line that did NOT contain the string, i.e. it could never
        # fail. This one fails as soon as a release site bypasses the helper.
        ("no bare memory-object deallocate outside release_memory_object",
         None, bare_mo_dealloc_outside_helper),
        ("release_memory_object is used by pe_v1 and pe_v2",
         r"release_memory_object\(memoryObject, \"pe_v1\"\)[\s\S]*release_memory_object\(memoryObject, \"pe_v2\"\)"),
        ("pe_v1: A18 wired mapping is only deallocated on a terminal exit",
         r"pe_v1_release_cycle\(searchMappings, searchMappingSize, wiredMapping, wiredMappingSize,\s*\n\s*\(testResult != 0\) \|\| success\);"),
        ("log line: socket spray release",
         r"KPRINTF\(\"\[cleanup\] sockets_release: %lu sprayed socket fileports released"),
        ("log line: wired page release",
         r"KPRINTF\(\"\[cleanup\] wired_pages_cleanup: %lu wired page"),
        ("log line: memory object release",
         r"KPRINTF\(\"\[cleanup\] %s: memory object %#x released \(kr=%d\)"),
        ("log line: pe_v1 search mapping release",
         r"KPRINTF\(\"\[cleanup\] pe_v1: search mapping %#llx munlocked \+ deallocated"),
        ("log line: pe_v1 wired mapping release",
         r"KPRINTF\(\"\[cleanup\] pe_v1: wired mapping %#llx munlocked"),
        ("log line: pe_v2 search mapping release",
         r"KPRINTF\(\"\[cleanup\] pe_v2: search mapping %#llx munlocked \+ deallocated"),
        ("log line: pe_v2 found wired page release",
         r"KPRINTF\(\"\[cleanup\] pe_v2: found wired page %#llx munlocked \+ deallocated"),
    ]
    for shape in shapes:
        name = shape[0]
        if len(shape) == 2:
            hit = bool(re.search(shape[1], text, re.M))
            detail = "pattern " + ("found" if hit else "MISSING")
        else:
            # (name, None, predicate) - a real assertion instead of a pattern
            hit = bool(shape[2](text))
            detail = "assertion " + ("holds" if hit else "VIOLATED")
        report(hit, name, detail)

    round3(text)
    bug1_restore(text, policy)
    bug1_step3b(text, writer, sandbox)

    print()
    print(f"{len(passes)} check(s) passed, {len(failures)} failed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(selftest() if "--selftest" in sys.argv[1:] else main())
