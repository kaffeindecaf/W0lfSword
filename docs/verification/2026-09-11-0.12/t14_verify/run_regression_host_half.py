#!/usr/bin/env python3
"""Build and run regression.sh's host half (lines 1-139: shell/python syntax, offset
tables, chain grid, the BUG.1 and BUG.3/BUG.4/BUG.5/BUG.6 host sections). The "Live
device smoke" section (line 158+) is excluded by construction, and so is "Build"
(make package) - neither is part of the host bug-list verification."""
import subprocess
import sys

src = open("scripts/regression.sh", encoding="utf-8").read().splitlines(True)
host = [l for l in src[:139] if not l.startswith('cd "$(dirname')]
host.append('\nprintf \'Regression (host half, device section excluded): %d passed, %d failed\\n\' "$PASS" "$FAIL"\n')
host.append('[ "$FAIL" -eq 0 ]\n')
tmp = "/tmp/regression_host_half.sh"
open(tmp, "w", encoding="utf-8").write("".join(host))
print("wrote %s (%d lines, from regression.sh lines 1-139; device section 158-171 excluded)" % (tmp, len(host)))
r = subprocess.run(["bash", tmp], cwd=".", capture_output=True, text=True)
sys.stdout.write(r.stdout)
sys.stderr.write(r.stderr)
print("exit=%d" % r.returncode)
sys.exit(r.returncode)
