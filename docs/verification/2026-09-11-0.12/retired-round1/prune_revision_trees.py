#!/usr/bin/env python3
"""Task 17 housekeeping: keep the replay evidence, drop the 58 MB of extracted
source trees from the repo.

The revision replay (`replay_revisions.sh`) exports a whole git tree per commit
to run the old harness. What matters as evidence is the log it printed - the
extracted copy is regenerable from the commit hash, so it is MOVED out of the
workspace (not deleted) to $TMPDIR/w0lf_t17_revisions/.

Host only; touches nothing outside docs/verification/2026-09-11-0.12/t17/ and
the temp dir.
"""
import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REV = os.path.join(HERE, "revisions")
KEEP = {"COMMANDS.txt", "RC.txt", "build_and_run.log", "build_and_run.log.keep"}
DEST = os.path.join(
    os.environ.get("TMPDIR", "/tmp").rstrip("/"), "w0lf_t17_revisions"
)

moved = 0
for label in sorted(os.listdir(REV)):
    src = os.path.join(REV, label)
    if not os.path.isdir(src):
        continue
    out = os.path.join(DEST, label)
    os.makedirs(out, exist_ok=True)
    for name in sorted(os.listdir(src)):
        if name in KEEP:
            continue
        shutil.move(os.path.join(src, name), os.path.join(out, name))
        moved += 1
    with open(os.path.join(src, "TREE-MOVED-OUT.txt"), "w") as fh:
        fh.write(
            "The extracted source tree of this revision is not kept in the "
            "repo (58 MB for four revisions).\n"
            "Regenerate it with: bash replay_revisions.sh\n"
            "  (git archive <commit> | tar -x into $TMPDIR/w0lf_t17_revisions)\n"
            "commit: %s\n"
            % open(os.path.join(src, "COMMANDS.txt")).read().splitlines()[1]
        )
    print("kept  %-12s %s" % (label, sorted(KEEP & set(os.listdir(src)))))
print("moved %d entries to %s" % (moved, DEST))
sys.exit(0)
