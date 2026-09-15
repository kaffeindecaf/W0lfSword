# retired-round1 - artifacts of the first T17 pass, kept but out of the capture

T17 was run twice. The first pass (`docs/verification/2026-09-11-0.12/t17/`,
still the live capture directory) produced two things the second pass had to
undo, and the files themselves are kept here rather than deleted:

- `prune_revision_trees.py` - housekeeping that MOVED the extracted
  source trees of the four replayed revisions out of the repo (a whole-repo
  export per revision is ~15 MB). That is what made the first-pass capture
  depend on a directory outside the repo, and a capture that stops resolving
  when the temp dir is cleared is not evidence. The second pass replaced it:
  `t17/replay_revisions.sh` now exports each revision SPARSE, only the paths
  that harness compiles (~0.6 MB each), directly into
  `t17/revisions/<label>/tree/`, so the trees ship with the capture.
- `TREE-MOVED-OUT.txt` (one per replayed revision, still in place under
  `t17/revisions/<label>/`) said the same thing; those files were rewritten in
  place to point at the in-repo tree.

Nothing here is referenced by the current capture. `t17/check_capture_paths.py`
is the check that keeps it that way: it fails if anything under `t17/` still
points at a temp-dir tree, and if any evidence path a roadmap, the README or the
worklog cites does not resolve.

Host only; no device command; nothing committed.
