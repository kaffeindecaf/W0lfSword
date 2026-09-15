#!/usr/bin/env python3
"""Write MANIFEST.txt for the t14_verify evidence directory: sha256 + bytes per
artifact, plus the two build hashes and the tool versions the run used."""
import hashlib
import os
import platform
import subprocess
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SKIP = {"MANIFEST.txt"}
out = []
out.append("docs/verification/2026-09-11-0.12/t14_verify - manifest (sha256, bytes, path)")
out.append("generated %s on %s" % (time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                                   platform.platform()))
out.append("scope: independent re-run of the T14 host suites (no device, no exploit)")
out.append("")

names = sorted(n for n in os.listdir(HERE) if n not in SKIP)
for n in names:
    p = os.path.join(HERE, n)
    h = hashlib.sha256(open(p, "rb").read()).hexdigest()
    out.append("%s %10d  %s" % (h, os.path.getsize(p), n))

out.append("")
out.append("build artifacts this run produced (hashed on disk):")
for label, p in (
    ("engine archive", "/home/kaffein/Desktop/W0lfSword/.theos/libengine/libw0lfengine.a"),
    ("app binary", "/home/kaffein/Desktop/W0lfTerm/dist/Payload/W0lfTerm.app/W0lfTerm"),
    ("app ipa", "/home/kaffein/Desktop/W0lfTerm/dist/W0lfTerm-0.20-sideload.ipa"),
):
    if os.path.exists(p):
        h = hashlib.sha256(open(p, "rb").read()).hexdigest()
        out.append("  %s %s  %s" % (h, label, p))

out.append("")
out.append("tool versions:")
for cmd in (["cc", "--version"], ["python3", "--version"], ["llvm-nm-19", "--version"],
            ["clang", "--version"]):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True)
        first = (r.stdout or r.stderr).strip().splitlines()[0] if (r.stdout or r.stderr) else "?"
    except OSError as e:
        first = "unavailable: %s" % e
    out.append("  %-22s %s" % (cmd[0], first))

open(os.path.join(HERE, "MANIFEST.txt"), "w", encoding="utf-8").write("\n".join(out) + "\n")
print("\n".join(out))
