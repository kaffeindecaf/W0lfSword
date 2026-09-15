#!/usr/bin/env python3
"""T14c manifest: sha256 + byte size of every evidence file this pass produced,
plus the hashes of the two build artifacts it produced from the working tree."""
import hashlib
import os
import platform
import subprocess
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SWORD = "/home/kaffein/Desktop/W0lfSword"
TERM = "/home/kaffein/Desktop/W0lfTerm"


def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


lines = []
lines.append("docs/verification/2026-09-11-0.12/t14c - manifest (sha256, bytes, name)")
lines.append("generated %s on %s" % (
    time.strftime("%Y-%m-%dT%H:%M:%S%z"), platform.platform()))
lines.append("scope: T14c re-run of the KRW / TRM / W0lfTerm host suites from the "
             "working tree (no device, no exploit, no git write)")
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
lines.append("build artifacts this pass produced (hashed on disk):")
for label, p in (
    ("engine archive", os.path.join(SWORD, ".theos/libengine/libw0lfengine.a")),
    ("app binary", os.path.join(TERM, "dist/Payload/W0lfTerm.app/W0lfTerm")),
    ("app ipa (zip mtimes, not byte-stable)", os.path.join(TERM, "dist/W0lfTerm-0.20-sideload.ipa")),
):
    lines.append("  %s  %s  %s" % (sha(p), label, p))

lines.append("")
lines.append("tool versions:")
for cmd in (["cc", "--version"], ["python3", "--version"], ["llvm-nm-19", "--version"], ["clang", "--version"]):
    try:
        out = subprocess.run(cmd, capture_output=True, text=True).stdout.splitlines()
        lines.append("  %-12s %s" % (cmd[0], out[0] if out else ""))
    except OSError as e:
        lines.append("  %-12s (unavailable: %s)" % (cmd[0], e))

open(os.path.join(HERE, "MANIFEST.txt"), "w").write("\n".join(lines) + "\n")
print("\n".join(lines))
