#!/usr/bin/env python3
"""Task 17 (re-run): assert every count the two bug lists quote against the
captured output of THIS tree.

Why this exists: the roadmaps quote numbers (``checks=116``, ``checks=56``,
``checks=53``, ``checks=108``, ``25 check(s) passed``, ``16/21 ok, 0 drift``,
``41/65/95`` for old revisions ...). A number in a doc is a claim; a number next
to a log that really prints it is evidence. This script is the mechanical link
between the two: each row below names a bug item, the capture file, and the
exact line that must be in it. It prints PASS/FAIL per claim with the quoted
line and the file's sha256, and exits non-zero if any claim is unbacked.

It runs nothing: it reads the capture in this directory. The captures come from
the three authorized host harnesses via ``capture.sh`` (see COMMANDS.txt and
RC.txt); the historical revisions come from ``replay_revisions.sh``.

Host only. Reads files, writes nothing.

    python3 docs/verification/2026-09-11-0.12/t17/verify_bug_claims.py
"""

import hashlib
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SUITE = os.path.join(HERE, "suite_logs", "w0lf_host_verification")

# (bug, what it is, file, line that must be present verbatim)
CLAIMS = [
    # --- BUG.1 step 1: every exit restores, and the put-back can write ---
    ("BUG.1 step 1", "the restore policy host test passes",
     "probe_restore_e2e.log", "checks=56 failures=0"),
    ("BUG.1 step 1", "its verdict line",
     "probe_restore_e2e.log", "PROBE_RESTORE_E2E_HOST_TEST PASS"),
    ("BUG.1 step 1", "exit -1 (write-verify exhaustion) restores",
     "probe_restore_e2e.log", "exit -1 (write-verify exhaustion) restores"),
    ("BUG.1 step 1", "exit -7 (cancel) restores instead of promoting",
     "probe_restore_e2e.log", "cancel (-7) restores (it is not the promotion)"),
    ("BUG.1 step 1", "the restore still writes after the release funnel",
     "probe_restore_e2e.log",
     "cancel after the release funnel: the saved values still go back"),
    ("BUG.1 step 1", "with no usable fd pair the restore writes NOTHING",
     "probe_restore_e2e.log",
     "cancel with no usable fd pair: the restore writes NOTHING "
     "(no write through a foreign socket)"),
    ("BUG.1 step 1", "the saved values are read back, not assumed",
     "probe_restore_e2e.log",
     "... and the saved values are back in the object (read back, not assumed)"),
    ("BUG.1 step 1", "no put-back block leaves the declared inpcb window",
     "probe_restore_e2e.log",
     "... and not one of them left the declared inpcb window"),
    ("BUG.1 step 1", "the policy selftest catches its mutations",
     "probe_restore_e2e_self.log", "selftest: all mutations caught"),
    # --- BUG.1 step 2: the probe field has no concurrent reader ---
    ("BUG.1 step 2", "nothing consumes the probed qword",
     "pressure_budget.log",
     "ok   BUG.1 probe field: nothing in the shipped code consumes the probed qword"),
    ("BUG.1 step 2", "the probe body does not touch the icmp6 filter pointer",
     "pressure_budget.log",
     "ok   BUG.1 probe field: the probe body does not touch the icmp6 filter pointer"),
    ("BUG.1 step 2", "the field check lives in the 8-check pressure lint",
     "pressure_budget.log", "8 check(s) passed, 0 failed"),
    # --- BUG.1 step 3 / 3b: the 32-byte block writer decides before it writes ---
    ("BUG.1 step 3", "the writer harness count of THIS tree",
     "krw_zone_write.log", "checks=116 failures=0"),
    ("BUG.1 step 3", "its verdict line",
     "krw_zone_write.log", "KRW_ZONE_WRITE_HOST_TEST PASS"),
    ("BUG.1 step 3", "the SE write itself is refused",
     "krw_zone_write.log", "SE write (0x50 into a 0x60 object) is refused"),
    ("BUG.1 step 3", "a refusal emits no block (no half-applied write)",
     "krw_zone_write.log", "refused write emits no block (no half-applied write)"),
    ("BUG.1 step 3", "a refusal changes no kernel byte",
     "krw_zone_write.log", "refused write changed no kernel byte"),
    ("BUG.1 step 3b", "a shifted tail without a declared object is refused",
     "krw_zone_write.log", "shifted tail without a declared object is refused"),
    ("BUG.1 step 3", "a write that fits its declared object still lands",
     "krw_zone_write.log",
     "len 0x40 (multiple of 0x20) inside a declared object is written"),
    # --- BUG.3: the scan budget (and where the check sits) ---
    ("BUG.3 engine", "the default budget fits the walk (600 s)",
     "scan_budget_cancel.log",
     "ok   BUG.3 engine: the default budget is the one that fits the walk (600 s)"),
    ("BUG.3 engine", "every scan/spray loop reads it",
     "scan_budget_cancel.log",
     "ok   BUG.3 engine: the budget is settable and clamped, and every scan/spray loop reads it"),
    ("BUG.3 engine", "the check sits INSIDE each walk",
     "scan_budget_cancel.log",
     "ok   BUG.3 engine: the cancel/budget check sits INSIDE each walk, not after it"),
    ("BUG.3 app", "the default matches the engine and is pushed in at load",
     "scan_budget_cancel.log",
     "ok   BUG.3 app: the default budget matches the engine default and is pushed in at load"),
    ("BUG.3 app", "a SET row persists and pushes every change",
     "scan_budget_cancel.log",
     "ok   BUG.3 app: a SET row exists, persists, and pushes every change into the engine"),
    ("BUG.3 app", "the boot banner reads the budget back from the ENGINE",
     "scan_budget_cancel.log",
     "ok   BUG.3 app: the boot banner reads the budget back from the ENGINE"),
    # --- BUG.4: the visible CANCEL, end to end ---
    ("BUG.4 engine", "the socket spray honours a CANCEL",
     "scan_budget_cancel.log",
     "ok   BUG.4 engine: the socket spray honours a CANCEL (it is the longest pre-walk cost)"),
    ("BUG.4 app", "the control is on only while a run is in flight",
     "scan_budget_cancel.log",
     "ok   BUG.4 app: a visible CANCEL control that is on only while a run is in flight"),
    ("BUG.4 app", "the tap reaches the engine stop flag through the one bridge",
     "scan_budget_cancel.log",
     "ok   BUG.4 app: the tap reaches the engine stop flag through the one bridge"),
    ("BUG.4 app", "the run loop treats -7 as cancelled and STOPS",
     "scan_budget_cancel.log",
     "ok   BUG.4 app: the run loop treats -7 as cancelled and STOPS (no retry)"),
    ("BUG.4 engine pe_v1", "the -7 exit releases the spray AND the mappings",
     "scan_budget_cancel.log",
     "ok   BUG.4 engine pe_v1: the -7 cancel exit releases the spray AND the mappings"),
    ("BUG.4 engine pe_v1", "every -7 exit goes through the funnel",
     "scan_budget_cancel.log",
     "ok   BUG.4 engine pe_v1: every -7 exit goes through the funnel (no cancel exit leaks)"),
    ("BUG.4 engine pe_v2", "the aborted path frees mapping, object and spray",
     "scan_budget_cancel.log",
     "ok   BUG.4 engine pe_v2: the aborted (-7) path frees the mapping, the object and the spray"),
    ("BUG.4 engine", "both cancel paths reach the app as -7",
     "scan_budget_cancel.log",
     "ok   BUG.4 engine: both cancel paths reach the app as -7 (cancelled, not failed)"),
    ("BUG.4 app build", "the linked binary defines the cancel control's callee",
     "app_static_symbols.log", "T _kexploit_request_stop"),
    ("BUG.4 app build", "the linked binary defines the pe_v2 abort flag",
     "app_static_symbols.log", "b _g_peV2Aborted"),
    ("BUG.4 app build", "the `cancel` label is in the shipped binary",
     "app_static_symbols.log", "cancel                             19"),
    # --- BUG.5: the measured write counter ---
    ("BUG.5", "the counter host test passes",
     "kwrite_counter.log", "checks=53 failures=0"),
    ("BUG.5", "its verdict line",
     "kwrite_counter.log", "KWRITE_COUNTER_HOST_TEST PASS"),
    ("BUG.5 engine", "the write primitive counts both outcomes",
     "scan_budget_cancel.log",
     "ok   BUG.5 counter: the ONE write primitive counts both outcomes"),
    ("BUG.5 app", "the run log carries the measured number, not the claim",
     "scan_budget_cancel.log",
     "ok   BUG.5 app: the run log carries the measured number, not the claim"),
    ("BUG.5", "no shipped log/UI string claims 'zero writes'",
     "scan_budget_cancel.log",
     "ok   BUG.5: no shipped log/UI string claims 'zero writes' any more"),
    ("BUG.5 app build", "`zero kernel writes` is gone from the binary",
     "app_static_symbols.log", "zero kernel writes                 0"),
    # --- BUG.6 (disk-write throttle; the fsync half of the 1 GB/day axis) ---
    ("BUG.6", "the throttle host test passes",
     "tweak_log_throttle.log", "checks=30 failures=0"),
    ("BUG.6", "one process-wide gate, not one per translation unit",
     "scan_budget_cancel.log",
     "ok   BUG.6 throttle: one process-wide gate, not one per translation unit"),
    ("BUG.6", "the gate is a compiled, host-tested policy in both builds",
     "scan_budget_cancel.log",
     "ok   BUG.6 throttle: the gate is a compiled, host-tested policy in both builds"),
    ("BUG.6", "the 600 s run stays inside the advertised 3001 fsync bound",
     "tweak_log_throttle.log",
     "ok   600 s run: within the advertised bound of 3001 fsyncs"),
    ("BUG.6", "the lint's own count of THIS tree",
     "scan_budget_cancel.log", "25 check(s) passed, 0 failed"),
    ("BUG.6", "the lint's selftest catches every mutation",
     "scan_budget_cancel_self.log", "selftest: all mutations caught"),
]

# (bug, what, file, line, sha256 the capture must have - the anchors the docs quote)
ANCHORS = [
    ("BUG.1 step 3", "krw_zone_write.log", "krw_zone_write.log",
     "1386b0b6e393b4923dc3ad9cd69547b8e9471e78f2c904688b5a09cc3b0ea5be"),
    ("BUG.1 step 1", "probe_restore_e2e.log", "probe_restore_e2e.log",
     "62f760e7402071fcb823a7ec5191904e098ac6b520907ef13135ba6fa729cf4b"),
    ("BUG.5", "kwrite_counter.log", "kwrite_counter.log",
     "1dc9c1d4b0e35b86e23667ff627e4b57bb7f6ec8385e622fc78c585dd6424e63"),
]

# numbers that may NEVER be read as "this tree": they belong to an older revision
HISTORICAL = [
    ("the clamp-only KRW harness at HEAD (e51b172)", "revisions/krw_head/build_and_run.log",
     "checks=41 failures=0"),
    ("the route-A TRM harness (8e97aa7)", "revisions/trm_routea/build_and_run.log",
     "checks=65 failures=0"),
    ("the TRM.2 harness (dfe75f2)", "revisions/trm_trm2/build_and_run.log",
     "checks=95 failures=0"),
]


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def read(path):
    try:
        return open(path, encoding="utf-8", errors="replace").read()
    except OSError:
        return None


def main():
    ok = bad = 0
    print("T17 re-run: every claim of the open-bug lists against the capture in")
    print("docs/verification/2026-09-11-0.12/t17/ (host only; no device command)\n")

    for bug, what, name, needle in CLAIMS:
        path = os.path.join(SUITE, name)
        body = read(path)
        if body is None:
            path = os.path.join(HERE, name)
            body = read(path)
        if body is None:
            print("BAD  %-16s %-58s missing file %s" % (bug, what, name))
            bad += 1
            continue
        if needle in body:
            print("ok   %-16s %-58s %s" % (bug, what, name))
            ok += 1
        else:
            print("BAD  %-16s %-58s not in %s" % (bug, what, name))
            print("     wanted: %s" % needle)
            bad += 1

    print("\n-- anchors: the capture files the docs hash --")
    for bug, what, name, want in ANCHORS:
        path = os.path.join(HERE, name)
        got = sha256(path) if os.path.exists(path) else "missing"
        if got == want:
            print("ok   %-16s %-58s %s" % (bug, what, got[:16] + "..."))
            ok += 1
        else:
            print("BAD  %-16s %-58s sha256=%s" % (bug, what, got))
            print("     want: %s" % want)
            bad += 1

    print("\n-- HISTORICAL: reproduced from git, never a count of this tree --")
    for what, rel, needle in HISTORICAL:
        path = os.path.join(HERE, rel)
        body = read(path)
        if body is not None and needle in body:
            print("ok   %-51s %s -> %s" % (what[:51], rel, needle))
            ok += 1
        else:
            print("BAD  %-51s %s does not print %s" % (what[:51], rel, needle))
            bad += 1

    print("\n-- suite + capture integrity --")
    checks = [
        ("suite, plain: 16 ok, 0 drift", "host_verification.log",
         "host verification: 16 ok, 0 drift"),
        ("suite, --with-builds: 21 ok, 0 drift", "host_verification_builds.log",
         "host verification: 21 ok, 0 drift"),
        ("TRM shell harness, THIS tree: 108", "trm_shell_host_test.log",
         "checks=108 failures=0"),
        # Re-pinned 2026-09-15: the T18 yield edit changed the engine's code size,
        # so the archive and the linked binary hash differently while the symbol
        # set and every check count stay the same (see the note in
        # scripts/check_host_verification.sh).
        ("engine archive hash as the suite pins it", "host_verification_builds.log",
         "32f6af7e665ab15d"),
        ("linked app binary hash as the suite pins it", "host_verification_builds.log",
         "167faf5da4919ab5"),
        ("every cited evidence path resolves", "capture_path_check.log",
         "re:capture path check: \\d+ ok, 0 bad"),
    ]
    for what, name, needle in checks:
        path = os.path.join(HERE, name)
        body = read(path)
        # a "re:" needle is a regex, so the row does not pin a count that grows
        # every time a doc cites one more evidence path
        hit = body is not None and (
            re.search(needle[3:], body) is not None if needle.startswith("re:")
            else needle in body)
        if hit:
            print("ok   %-51s %s" % (what, name))
            ok += 1
        else:
            print("BAD  %-51s not in %s" % (what, name))
            bad += 1

    rc = read(os.path.join(HERE, "RC.txt")) or ""
    for name in ("krw_zone_write", "kwrite_counter", "host_verification",
                 "host_verification_builds"):
        line = "%s 0" % name
        if line in rc:
            print("ok   %-51s RC.txt" % ("rc=0: " + name))
            ok += 1
        else:
            print("BAD  %-51s no 'rc=0' in RC.txt" % name)
            bad += 1

    print("\nclaim check: %d ok, %d bad" % (ok, bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
