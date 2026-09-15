#!/usr/bin/env python3
"""
probe_restore_e2e_selftest.py - prove the BUG.1 end-to-end host test bites.

`tests/probe_restore_e2e_host_test.c` prints PASS for the clamp (steps 3/3b) and
the staged write probe's restore path (step 1). A green run only means something
if the harness would go red when the fix is removed, so this script mutates TEMP
COPIES of the two engine sources the harness compiles and requires the built
harness to FAIL on each mutation. No repo file is written and nothing is
committed.

The mutations are the four regressions the item is about:

  1. the clamp's block-end refusal removed        -> the put-back block leaves
                                                     the declared window again
  2. the writer's default deny removed            -> an unproven qword is emitted
  3. the cancel/budget exit handed off           -> a cancelled probe walks away
                                                     from a corrupted live inpcb
  4. the promotion-fd fallback removed           -> the staged exit can write
                                                     nothing back (BUG.1 itself)

Usage: python3 scripts/probe_restore_e2e_selftest.py   (exit 0 = all caught)
"""
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TEST = ROOT / "tests" / "probe_restore_e2e_host_test.c"
KEXPLOIT = ROOT / "kexploit"
SOURCES = ("krw_zone_write.c", "probe_restore_policy.c")
HEADERS = ("krw_zone_write.h", "probe_restore_policy.h")

MUTATIONS = [
    ("the clamp's block-end refusal removed (krw_zone_write_qword)", "krw_zone_write.c",
     lambda s: s.replace(
         "    if (blockStart + KRW_ZONE_BLOCK_LEN > objBase + objSize) {",
         "    if (0) {", 1)),

    ("the writer's default deny removed (an undeclared qword is emitted)", "krw_zone_write.c",
     lambda s: s.replace(
         "    if (!haveObj) {\n        krw_zone_log_refusal(KRW_ZONE_REFUSE_UNDECLARED",
         "    if (0) {\n        krw_zone_log_refusal(KRW_ZONE_REFUSE_UNDECLARED", 1)),

    ("the cancel/budget exit handed off instead of restored", "probe_restore_policy.c",
     lambda s: s.replace(
         "    return PROBE_ACTION_RESTORE;\n}\n\nprobe_fd_source",
         "    return (probeRc == -7) ? PROBE_ACTION_HAND_OFF : PROBE_ACTION_RESTORE;"
         "\n}\n\nprobe_fd_source", 1)),

    ("the promotion-fd fallback removed (the staged exit writes nothing back)",
     "probe_restore_policy.c",
     lambda s: s.replace(
         "    if (promotionPairLive) return PROBE_FD_SOURCE_PROMOTION_FDS;",
         "    (void)promotionPairLive;", 1)),
]


def build_and_run(cc, workdir, out):
    """Compile the harness against the sources in `workdir`; return (rc, stdout)."""
    cmd = [
        cc, "-std=gnu99", "-Wall", "-Wextra", "-Wno-unused-parameter",
        f"-I{ROOT}",
        "-o", str(out),
        str(TEST),
        str(workdir / SOURCES[0]),
        str(workdir / SOURCES[1]),
    ]
    p = subprocess.run(cmd, capture_output=True, text=True)
    if p.returncode != 0:
        return p.returncode, "compile failed:\n" + p.stdout + p.stderr
    q = subprocess.run([str(out)], capture_output=True, text=True)
    return q.returncode, q.stdout + q.stderr


def selftest():
    cc = os.environ.get("CC", "cc")
    if shutil.which(cc) is None:
        print(f"selftest: {cc} not found - cannot build the harness")
        return 2

    rc = 0
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        originals = {name: (KEXPLOIT / name).read_text() for name in SOURCES + HEADERS}
        for name, content in originals.items():
            (tmp / name).write_text(content)

        out = tmp / "probe_restore_e2e_host_test"
        got_rc, out_text = build_and_run(cc, tmp, out)
        baseline = got_rc == 0 and "PROBE_RESTORE_E2E_HOST_TEST PASS" in out_text
        print(("PASS  " if baseline else "FAIL  ")
              + "selftest baseline: the harness passes on the unmutated sources")
        if not baseline:
            print(out_text)
        rc |= 0 if baseline else 1

        for label, filename, mutate in MUTATIONS:
            original = originals[filename]
            mutated = mutate(original)
            if mutated == original:
                print(f"FAIL  selftest mutation did not apply: {label}")
                rc = 1
                continue
            (tmp / filename).write_text(mutated)
            got_rc, out_text = build_and_run(cc, tmp, out)
            caught = got_rc != 0
            detail = ""
            if caught:
                first = next((l.strip() for l in out_text.splitlines()
                              if l.strip().startswith("FAIL")), "non-zero exit")
                detail = f" first failure: {first}"
            print(("PASS  " if caught else "FAIL  ")
                  + f"selftest: the harness rejects - {label}" + detail)
            if not caught:
                print(out_text)
            rc |= 0 if caught else 1
            (tmp / filename).write_text(original)

    print()
    print("selftest: " + ("all mutations caught" if rc == 0 else "SOME MUTATIONS WERE MISSED"))
    return rc


def main():
    if "--selftest" not in sys.argv[1:]:
        print("probe_restore_e2e_selftest.py - run with --selftest")
        return 0
    return selftest()


if __name__ == "__main__":
    sys.exit(main())
