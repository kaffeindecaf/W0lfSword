#!/usr/bin/env bash
# Task 17 (re-run) - replay an OLD revision of a host harness from git, without
# touching the working tree (git archive only - no checkout, no reset, no stash,
# no commit).
#
#   bash docs/verification/2026-09-11-0.12/t17/replay_revisions.sh
#
# WHY THIS IS IN THE EVIDENCE SET: the roadmaps quote check counts from passes
# whose logs were never kept (41 for the KRW writer harness; 65 / 95 / 108 for
# the TRM shell harness). Those counts cannot be confirmed or withdrawn from the
# CURRENT tree - only by running the revision that produced them. This script is
# that run, host only (cc + a host test binary; no device command anywhere).
# It is NOT one of the three authorized re-run commands: those cover the current
# tree, and each of their captures is in the parent directory. Everything below
# is a historical-revision reproduction, and the reconciliation table
# (../CLAIMS-RECONCILED.md) marks those numbers HISTORICAL, never current.
#
# SELF-CONTAINED: each replayed tree is exported SPARSE (only the paths that
# harness compiles) into revisions/<label>/tree/, so the capture does not depend
# on $TMPDIR surviving - an earlier pass exported the four whole-repo trees
# (~58 MB) into the temp dir and left the capture pointing at files that were
# gone. trees/ total ~2.6 MB here.
#
# Host only. No device command. Writes only under this directory.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SW="$(cd "$HERE/../../../.." && pwd)"
KEEP="$HERE/revisions"

# the include closure of both host harnesses: trm_shell_host_test.c pulls
# terminal/*.h + utils/tweak_log.h, terminal/trm_shell.c pulls kexploit/*.h,
# utils/state.h and the repo-root sandbox_escape.h; krw needs kexploit/ only.
PATHS_TRM="tests terminal utils kexploit sandbox_escape.h"
PATHS_KRW="tests kexploit"

digest() {  # digest <dir> - sha256 over the sorted per-file hashes
    ( cd "$1" && find . -type f ! -name '*.pyc' -print0 | sort -z \
        | xargs -0 sha256sum | sha256sum | cut -d' ' -f1 )
}

# replay <label> <commit> <pathspec> <what>
replay() {
    local label="$1" commit="$2" paths="$3" what="$4"
    local dir="$KEEP/$label/tree" out="$KEEP/$label"
    local sha
    sha=$(git -C "$SW" rev-parse --short "$commit" 2>/dev/null) || { echo "$label: no such commit $commit"; return 1; }
    mkdir -p "$dir"
    # the paths that revision needs, exported from the git object store (never
    # checked out into the working tree)
    ( cd "$SW" && git archive "$commit" -- $paths ) | tar -x -C "$dir" || return 1
    # shellcheck disable=SC2086  # word-split pathspec is the point
    ( cd "$dir" && eval "$what" ) >"$out/build_and_run.log" 2>&1
    local rc=$?
    printf '%s %s\n' "$label" "$rc" >"$out/RC.txt"
    {
        echo "# $label"
        echo "commit: $(git -C "$SW" log -1 --pretty='%H %s' "$commit")"
        echo "paths exported: $paths"
        echo "tree: revisions/$label/tree (sparse export of that commit, in-repo)"
        echo "tree sha256 (sorted per-file hashes): $(digest "$dir")"
        echo "tree files: $(find "$dir" -type f | wc -l)"
        echo "command (cwd = revisions/$label/tree):"
        echo "  $what"
    } >"$out/COMMANDS.txt"
    printf '%-14s %s rc=%s -> %s\n' "$label" "$sha" "$rc" \
        "$(grep -hE 'checks=[0-9]+ failures=[0-9]+' "$out/build_and_run.log" | tail -1)"
}

# The TRM shell harness at three revisions: route A (the "65" claim),
# TRM.2 (the "95" claim), TRM.1/tab completion (the "108" claim).
TRM_CMD='cc -std=gnu99 -Wall -Wno-unused-parameter -Wno-unused-function -Wno-sign-compare -I. -Itests/hostshim -o trm_test tests/trm_shell_host_test.c terminal/trm_shell.c terminal/trm_common.c -lpthread && ./trm_test'
replay trm_routea 8e97aa7 "$PATHS_TRM" "$TRM_CMD"
replay trm_trm2   dfe75f2 "$PATHS_TRM" "$TRM_CMD"
replay trm_trm1   979b8df "$PATHS_TRM" "$TRM_CMD"

# The KRW writer clamp harness as committed (the "41 checks" claim). HEAD is
# 979b8df/e51b172: the committed harness is the clamp-only revision, the
# 116-check one lives only in the working tree.
replay krw_head HEAD "$PATHS_KRW" \
    'cc -std=gnu99 -Wall -Wextra -Wno-unused-parameter -I. -o krw_test tests/krw_zone_write_host_test.c kexploit/krw_zone_write.c && ./krw_test'

echo
echo "logs + sparse trees kept in: $KEEP/<label>/{build_and_run.log,RC.txt,COMMANDS.txt,tree/}"
