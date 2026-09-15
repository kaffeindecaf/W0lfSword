#!/usr/bin/env python3
"""T17 second pass: rewrite the round-1 TREE-MOVED-OUT.txt notes so they describe
where the replayed trees actually live now (in the repo).

Reads each revision's COMMANDS.txt for the commit, the paths exported and the
tree digest. Host only; writes only inside revisions/*/.

    python3 docs/verification/2026-09-11-0.12/t17/fix_tree_notes.py
"""
import os

REV = os.path.join(os.path.dirname(os.path.abspath(__file__)), "revisions")

NOTE = """CORRECTED (T17 second pass) - the tree of this revision IS in the repo:
  revisions/{label}/tree   (sparse export, {nfiles} files, sha256 {digest})
  paths exported: {paths}
  commit: {commit}

This note used to say the extracted source tree was moved OUT of the repo to a
temp directory, because a whole-repo export of this revision is ~15 MB. That made
the capture depend on a path outside the repo, and a capture that stops resolving
once that directory is cleared is not evidence. The second pass re-exported every
replayed revision SPARSE - only the paths that revision's host harness compiles,
~0.6 MB each - into revisions/{label}/tree/, and nothing in this capture
references the old temp copy any more.

Superseded by: revisions/{label}/COMMANDS.txt (tree path + digest) and
../../retired-round1/README.md (why the round-1 layout was replaced).
"""


def main():
    for label in sorted(os.listdir(REV)):
        d = os.path.join(REV, label)
        cmds = os.path.join(d, "COMMANDS.txt")
        if not os.path.isdir(d) or not os.path.exists(cmds):
            continue
        fields = {}
        for line in open(cmds, encoding="utf-8"):
            for key in ("commit:", "paths exported:", "tree sha256", "tree files:"):
                if line.startswith(key):
                    fields[key.rstrip(":")] = line.split(":", 1)[1].strip()
        body = NOTE.format(
            label=label,
            nfiles=fields.get("tree files", "?"),
            digest=fields.get("tree sha256", "?"),
            paths=fields.get("paths exported", "?"),
            commit=fields.get("commit", "?"),
        )
        note = os.path.join(d, "TREE-MOVED-OUT.txt")
        open(note, "w", encoding="utf-8").write(body)
        print("rewrote %s" % os.path.relpath(note))


if __name__ == "__main__":
    main()
