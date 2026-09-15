#!/usr/bin/env python3
"""T15 manifest: sha256 + byte size of every evidence file this BUG.1 closing
pass produced, the hash of the archive it rebuilt from the working tree, and the
determinism check (the two unsuffixed logs are a first run of the same two
commands that capture.sh re-ran as s1_*; identical hashes mean the results are
reproducible, not a single lucky run).

    python3 docs/verification/2026-09-11-0.12/t15/write_manifest.py
"""
import hashlib
import os
import platform
import subprocess
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SWORD = "/home/kaffein/Desktop/W0lfSword"


def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


lines = []
lines.append("docs/verification/2026-09-11-0.12/t15 - manifest (sha256, bytes, name)")
lines.append("generated %s on %s" % (time.strftime("%Y-%m-%dT%H:%M:%S%z"), platform.platform()))
lines.append("scope: T15 BUG.1 (zone-bound write fix) closing verification - the three "
             "sub-steps, host only")
lines.append("(no device, no device command, no exploit run, no git write)")
lines.append("")
rows = []
for name in sorted(os.listdir(HERE)):
    if name in ("MANIFEST.txt",):
        continue
    p = os.path.join(HERE, name)
    if os.path.isfile(p):
        rows.append((sha(p), os.path.getsize(p), name))
for h, s, n in rows:
    lines.append("%s  %9d  %s" % (h, s, n))

lines.append("")
lines.append("determinism: the same command run twice, byte-identical output")
for first, second in (("krw_zone_write_host_test", "s1_krw_zone_write_host_test"),
                      ("probe_restore_e2e_host_test", "s1_probe_restore_e2e"),
                      ("probe_restore_e2e_selftest", "s1_probe_restore_e2e_selftest"),
                      ("pressure_budget", "s2_pressure_budget"),
                      ("pressure_budget_selftest", "s2_pressure_budget_selftest"),
                      ("bug2_release_paths", "s1_bug2_release_paths"),
                      ("bug2_release_paths_selftest", "s1_bug2_release_paths_selftest")):
    a = sha(os.path.join(HERE, first + ".log"))
    b = sha(os.path.join(HERE, second + ".log"))
    lines.append("  %s  %s.log == %s.log" % ("IDENTICAL" if a == b else "DIFFERS  ", first, second))

lines.append("")
lines.append("independent check written for this pass (not a re-run of the project harness):")
sweep = os.path.join(HERE, "s3b_independent_clamp_sweep.log")
if os.path.isfile(sweep):
    for line in open(sweep).read().splitlines()[-4:]:
        if line.strip():
            lines.append("  " + line.strip())
    lines.append("  source: independent_clamp_sweep.c (this directory), linked against")
    lines.append("  kexploit/krw_zone_write.c - the shipped clamp, a monitor this file owns.")

lines.append("")
lines.append("build artifact this pass produced (hashed on disk):")
for label, p in (("engine archive", os.path.join(SWORD, ".theos/libengine/libw0lfengine.a")),):
    lines.append("  %s  %s  %s" % (sha(p), label, p))
lines.append("  (pinned by scripts/check_host_verification.sh: "
             "263ae60d49fd0c1557ac8d26f365b6d9d4c8475387ab45451306da31167f9661)")

lines.append("")
lines.append("tool versions:")
for cmd in (["cc", "--version"], ["python3", "--version"], ["llvm-nm-19", "--version"], ["make", "--version"]):
    try:
        out = subprocess.run(cmd, capture_output=True, text=True).stdout.splitlines()
        lines.append("  %-12s %s" % (cmd[0], out[0] if out else ""))
    except OSError as e:
        lines.append("  %-12s (unavailable: %s)" % (cmd[0], e))

with open(os.path.join(HERE, "MANIFEST.txt"), "w") as fh:
    fh.write("\n".join(lines) + "\n")
print("\n".join(lines))
