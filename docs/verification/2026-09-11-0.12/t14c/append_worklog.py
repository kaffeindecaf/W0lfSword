#!/usr/bin/env python3
"""Build the T14c WORKLOG entry from the captured logs, then append it.

Every command line and every chunk of output in the entry is read straight out
of the captured log files, so the entry cannot drift from what actually ran.
"""
import os
import subprocess
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = "/home/kaffein/Desktop/W0lfSword"
TERM = "/home/kaffein/Desktop/W0lfTerm"
WORKLOG = os.path.join(ROOT, "docs/WORKLOG.md")

# (name, cwd label, verbatim command) - in the order they were run
JOBS = [
    ("e1_krw_zone_write", "$ROOT",
     "bash scripts/run_krw_zone_write_host_test.sh"),
    ("e2_kwrite_counter", "$ROOT",
     "bash scripts/run_kwrite_counter_host_test.sh"),
    ("e3_probe_restore_e2e", "$ROOT",
     "bash scripts/run_probe_restore_e2e_host_test.sh"),
    ("e3b_probe_restore_selftest", "$ROOT",
     "python3 scripts/probe_restore_e2e_selftest.py --selftest"),
    ("e7_tweak_log_throttle", "$ROOT",
     "bash scripts/run_tweak_log_throttle_host_test.sh"),
    ("e8_trm_shell", "$ROOT",
     "bash scripts/run_trm_host_test.sh"),
    ("e5_scan_budget_cancel", "$ROOT",
     "python3 scripts/check_scan_budget_cancel_writes.py"),
    ("e5b_scan_budget_cancel_self", "$ROOT",
     "python3 scripts/check_scan_budget_cancel_writes.py --selftest"),
    ("e6_pressure_budget", "$ROOT",
     "python3 scripts/check_pressure_budget.py"),
    ("e6b_pressure_budget_selftest", "$ROOT",
     "python3 scripts/check_pressure_budget.py --selftest"),
    ("e4_bug2_release_paths", "$ROOT",
     "python3 scripts/check_bug2_release_paths.py"),
    ("e4b_bug2_release_paths_self", "$ROOT",
     "python3 scripts/check_bug2_release_paths.py --selftest"),
    ("py_compile", "$ROOT",
     "python3 -m py_compile scripts/check_scan_budget_cancel_writes.py "
     "scripts/check_bug2_release_paths.py scripts/check_pressure_budget.py "
     "scripts/probe_restore_e2e_selftest.py"),
    ("bash_syntax", "$ROOT",
     "bash -n scripts/run_krw_zone_write_host_test.sh "
     "scripts/run_probe_restore_e2e_host_test.sh "
     "scripts/run_kwrite_counter_host_test.sh "
     "scripts/run_tweak_log_throttle_host_test.sh scripts/build_libengine.sh "
     "scripts/regression.sh"),
    ("e9_engine_lib_build", "$ROOT", "make THEOS=$HOME/theos libengine"),
    ("e9b_engine_lib_archive_hash", "$ROOT",
     "sha256sum .theos/libengine/libw0lfengine.a"),
    ("e9c_app_ipa_build", "$TERM_SRC", "bash scripts/build_ipa.sh sideload 0.20"),
    ("e9d_app_binary_hash", "$TERM_SRC",
     "sha256sum dist/Payload/W0lfTerm.app/W0lfTerm"),
    ("e9e_app_ipa_hash", "$TERM_SRC",
     "sha256sum dist/W0lfTerm-0.20-sideload.ipa"),
    ("e11_host_suite_with_builds", "$ROOT",
     "bash scripts/check_host_verification.sh --with-builds"),
]

FULL_EMBED_MAX = 8000      # logs this size or smaller are embedded whole
TAIL_LINES = 40            # bigger ones: the tail that carries the verdict


def read(name):
    p = os.path.join(HERE, name + ".log")
    return open(p, encoding="utf-8", errors="replace").read()


def rc_of(name):
    for line in open(os.path.join(HERE, "RC.txt"), encoding="utf-8"):
        if line.startswith(name + " rc="):
            return line.strip().split("rc=")[1]
    return "?"


def block(name, cwd, cmd):
    text = read(name).rstrip("\n")
    rc = rc_of(name)
    out = ["", "### %s" % name, "", "```", "cd %s" % cwd, "$ %s" % cmd, "```", ""]
    lines = text.split("\n")
    if len(text.encode()) <= FULL_EMBED_MAX:
        out += ["exit %s - full output:" % rc, "", "```", text, "```"]
    else:
        out += ["exit %s - verdict tail (the complete %d-line log is "
                "`docs/verification/2026-09-11-0.12/t14c/%s.log`):"
                % (rc, len(lines), name), "", "```",
                "\n".join(lines[-TAIL_LINES:]), "```"]
    return "\n".join(out)


stamp = time.strftime("%Y-%m-%d %H:%M %z")
entry = []
entry.append("")
entry.append("")
entry.append("## T14c - every T14 host command re-run from the working tree, "
             "with its output")
entry.append("")
entry.append("Task 14/14 closing pass, %s. Same scope as `T14b` and the same "
             "constraint set, but this" % stamp)
entry.append("time the per-command output is embedded below *from the captured "
             "log files*, not summarised.")
entry.append("")
entry.append("Nothing in the engine, the app or the CLI changed in this pass: "
             "the three deliverables")
entry.append("(settable scan budget, a CANCEL that releases the leaked search "
             "mapping and drains the")
entry.append("socket spray, the measured write count in place of the "
             "\"zero writes\" claim) are the")
entry.append("ones tasks 10-13 landed, and this pass is the re-run that proves "
             "they still hold on this")
entry.append("working tree. The only files added are under "
             "`docs/verification/2026-09-11-0.12/t14c/`")
entry.append("and this entry.")
entry.append("")
entry.append("### Command table (cwd `/home/kaffein/Desktop/W0lfSword` unless "
             "noted; `$TERM_SRC` = `/home/kaffein/Desktop/W0lfTerm`)")
entry.append("")
entry.append("| # | command | what it is |")
entry.append("| - | ------- | ---------- |")
desc = {
    "e1_krw_zone_write": "KRW: the 32-byte block writer's object clamp + the "
                         "unconditional-restore policy (BUG.1)",
    "e2_kwrite_counter": "KRW: the write counter (BUG.5), counted outcomes per "
                         "route",
    "e3_probe_restore_e2e": "KRW: the probe's save/corrupt/exit/put-back "
                            "sequence end to end (BUG.1)",
    "e3b_probe_restore_selftest": "the same harness's own selftest",
    "e7_tweak_log_throttle": "KRW: the fsync rate gate (BUG.6), simulated clock",
    "e8_trm_shell": "TRM: the route-A in-process shell host suite",
    "e5_scan_budget_cancel": "end-to-end source lint for BUG.3/BUG.4/BUG.5/BUG.6",
    "e5b_scan_budget_cancel_self": "that lint's mutation selftest",
    "e6_pressure_budget": "BUG.1 probe field + BUG.2 pressure + the disk-write "
                          "accounting vs 1 GB/day",
    "e6b_pressure_budget_selftest": "that check's mutation selftest",
    "e4_bug2_release_paths": "the release-path lint (BUG.2 / BUG.1 step 3b)",
    "e4b_bug2_release_paths_self": "that lint's mutation selftest",
    "py_compile": "the four Python checks compile",
    "bash_syntax": "the six harness scripts parse",
    "e9_engine_lib_build": "W0lfTerm's engine archive, built from THIS tree",
    "e9b_engine_lib_archive_hash": "its hash",
    "e9c_app_ipa_build": "the W0lfTerm ipa (sideload 0.20)",
    "e9d_app_binary_hash": "the linked app binary's hash",
    "e9e_app_ipa_hash": "the ipa's hash (zip mtimes - not byte-stable, see below)",
    "e11_host_suite_with_builds": "the hash-pinned suite: all of the above that "
                                  "regression.sh owns, plus both builds",
}
for name, cwd, cmd in JOBS:
    entry.append("| | `%s` | %s |" % (cmd, desc[name]))
entry.append("")
entry.append("### The exit codes, as captured (`t14c/RC.txt`)")
entry.append("")
entry.append("```")
entry.append(open(os.path.join(HERE, "RC.txt"), encoding="utf-8").read().rstrip("\n"))
entry.append("```")
entry.append("")
entry.append("Every command exited 0. The three non-zero-free rows in "
             "`regression.sh`'s own list")
entry.append("(`rm a non-empty dir`, `kread 0x0`, the gated `fetch`) are "
             "assertions inside the TRM")
entry.append("harness, not failures - it counts them as `ok`.")
entry.append("")
entry.append("### Per-command output")
for name, cwd, cmd in JOBS:
    entry.append(block(name, cwd, cmd))

entry.append("")
entry.append("### The app side, from the linked binary (E10)")
entry.append("")
entry.append("Host-only static read of the 0.20 Mach-O the E9c build produced "
             "(`llvm-nm-19`,")
entry.append("`strings -a`, `llvm-objdump-19 -d --macho --symbolize-operands`):")
entry.append("")
entry.append("```")
entry.append(open(os.path.join(HERE, "e10_symbols_strings.log"), encoding="utf-8").read().rstrip("\n"))
entry.append("")
entry.append(open(os.path.join(HERE, "e10c_app_call_edges.log"), encoding="utf-8").read().rstrip("\n"))
entry.append("```")
entry.append("")
entry.append("`zero kernel writes` occurs 0 times in the shipped binary; "
             "`no kernel writes` (the")
entry.append("measured phrasing, `... no kernel writes (engine-counted per "
             "run)`) occurs 5 times, and")
entry.append("`engine-counted` twice. The only `zero kernel writes` strings "
             "left in either tree are")
entry.append("comments describing this bug plus the lint's own needle list "
             "(`check_scan_budget_cancel_writes.py:371`).")
entry.append("")
entry.append("### Build artifacts and hashes this pass produced")
entry.append("")
entry.append("```")
man = open(os.path.join(HERE, "MANIFEST.txt"), encoding="utf-8").read()
start = man.index("build artifacts this pass produced")
entry.append(man[start:man.index("tool versions:")].rstrip("\n"))
entry.append("```")
entry.append("")
entry.append("`engine archive` and `app binary` are byte-identical to the "
             "hashes pinned in")
entry.append("`scripts/check_host_verification.sh` (263ae60d.../2922ebb3...), "
             "which is what E11 confirms.")
entry.append("The ipa is not byte-stable - it is a zip carrying mtimes - which "
             "is why the pinned suite")
entry.append("compares the *build log* in canon mode and hashes the binary "
             "instead.")
entry.append("")
entry.append("### Evidence directory")
entry.append("")
entry.append("`docs/verification/2026-09-11-0.12/t14c/` - the 20 logs above, "
             "`RC.txt`, `COMMANDS.txt`,")
entry.append("`capture.sh` (the re-runnable capture), `extract_edges.py`, "
             "`write_manifest.py` and")
entry.append("`MANIFEST.txt` with a sha256 + byte size for every one of them.")
entry.append("Re-run the capture with:")
entry.append("")
entry.append("```")
entry.append("bash docs/verification/2026-09-11-0.12/t14c/capture.sh")
entry.append("```")
entry.append("")
entry.append("### HARD RULE compliance (this pass)")
entry.append("")
entry.append("- HARD RULE 1 (no exploit, no device command): every command "
             "above is host `cc`/`clang`,")
entry.append("  `python3`, `bash`, `make` for the Theos cross-compile, or a "
             "read of a built Mach-O. No")
entry.append("  `idevice*`, no `ssh`, no `usbmuxd`, no exploit, no device "
             "addressed or attached.")
entry.append("- HARD RULE 2 (no git write command): no `git add`/`commit`/"
             "`push`/`checkout`/`reset`/`stash`;")
entry.append("  read-only `git status` only.")
entry.append("- HARD RULE 3 (no file deletion): nothing deleted.")
entry.append("- Working tree only: this pass added "
             "`docs/verification/2026-09-11-0.12/t14c/` and this entry; no "
             "engine, CLI or app source was touched.")
entry.append("")
entry.append("### What this pass does NOT cover (plainly)")
entry.append("")
entry.append("- No device run, so every item stays \"NOT device-verified\": "
             "tapping `cancel` mid-run and")
entry.append("  watching the `[cleanup]` lines, the SE banner reading `600` "
             "back from the engine, and the")
entry.append("  `-7` reaching the app are device-day checks.")
entry.append("- The disk accounting is a SOURCE arithmetic guard, not a "
             "measurement: 8064 MB dirtied per")
entry.append("  run on the 3 GB class against the 1 GB/day limit. The scan "
             "half is still over the limit;")
entry.append("  the check makes the ratio impossible to move unnoticed, it "
             "does not fix it.")
entry.append("- The settable budget is wired engine -> W0lfTerm app only. A grep "
             "for `budget`/`timeout`/")
entry.append("  `cancel` in the W0lfSword bash CLI (`W0lfSword`) returns "
             "nothing: that CLI builds, installs and")
entry.append("  monitors, it does not run the scan loops in-process, so there "
             "is no flag for it to pass.")
entry.append("  The engine API it would call is exported and host-tested "
             "(`kexploit_set_scan_budget`,")
entry.append("  `kexploit_scan_budget` - both `T` in the linked app binary).")
entry.append("- `[TermSettings scanBudget]` (the getter) is in the source and "
             "the settings row, but has no")
entry.append("  `bl` edge of its own: it returns the file-static `g_scanBudget`. "
             "The two edges that matter")
entry.append("  (`load` -> `kexploit_set_scan_budget`, `setScanBudget:` -> the "
             "same) are in the disassembly")
entry.append("  above.")

with open(WORKLOG, "a", encoding="utf-8") as f:
    f.write("\n".join(entry) + "\n")

print("appended %d lines to %s" % (len(entry), WORKLOG))
print("new size: %d bytes" % os.path.getsize(WORKLOG))
