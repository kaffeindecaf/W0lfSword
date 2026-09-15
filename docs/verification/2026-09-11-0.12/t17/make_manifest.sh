#!/usr/bin/env bash
# Task 17: pin the capture to the exact tree it was taken from.
# Host-only; issues no device command; writes only inside this directory.
#
#   bash docs/verification/2026-09-11-0.12/t17/make_manifest.sh
#
# Run order for a full reproduction (each host-only, none of them a device
# command, nothing committed):
#   1. bash capture.sh                          (the three authorized harnesses)
#   2. WITH_BUILDS=1 bash capture.sh            (adds the Theos cross-builds)
#   3. bash replay_revisions.sh                 (historical revisions, from git)
#   4. python3 check_capture_paths.py           (every cited path resolves)
#   5. bash make_manifest.sh                    (this file: hashes everything)
#
# Writes next to this script:
#   changed_files.txt      `git status --porcelain` of the tree the capture is from
#   tree_state.txt         HEAD, branch, date, dirty-entry count
#   changed_file_stats.txt `git diff --stat` + one line per untracked file
#   changed_files.sha256   sha256 of every changed/untracked file (pins content)
#   inputs.sha256          sha256 of the sources the host harnesses compile
#   MANIFEST.txt           sha256 + size of every capture file in this dir
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SW="$(cd "$HERE/../../../.." && pwd)"
cd "$SW" || exit 1

git status --porcelain >"$HERE/changed_files.txt"

{
    echo "repo:       $SW"
    echo "captured:   $(date -u +%Y-%m-%dT%H:%M:%SZ) (UTC) / $(date '+%Y-%m-%d %H:%M:%S %z')"
    echo "branch:     $(git branch --show-current)"
    echo "HEAD:       $(git rev-parse HEAD)"
    echo "HEAD subject: $(git log -1 --pretty=%s)"
    echo "dirty:      $(git status --porcelain | wc -l) entries (see changed_files.txt)"
} >"$HERE/tree_state.txt"

{
    echo "== git diff --stat (tracked, uncommitted) =="
    git diff --stat
    echo
    echo "== untracked files (deleted: none - this task deletes nothing) =="
    git ls-files --others --exclude-standard
} >"$HERE/changed_file_stats.txt"

# every tracked-modified or untracked file, hashed
{
    git diff --name-only
    git ls-files --others --exclude-standard
} | sort -u | while read -r f; do
    [ -f "$f" ] && sha256sum "$f"
done >"$HERE/changed_files.sha256"

# the app tree the capture also reads (its ROADMAP carries the 0.6 side of the
# bug list, and the suite reads the binary it links)
TERM="${W0LF_TERM:-$HOME/Desktop/W0lfTerm}"
{
    echo "repo: $TERM"
    echo "HEAD: $(git -C "$TERM" rev-parse HEAD 2>/dev/null)"
    echo
    echo "== git status --porcelain =="
    git -C "$TERM" status --porcelain 2>/dev/null
    echo
    echo "== sha256 of the changed app file + the linked binary =="
    sha256sum "$TERM/ROADMAP.md" 2>/dev/null
    sha256sum "$TERM/dist/Payload/W0lfTerm.app/W0lfTerm" 2>/dev/null
} >"$HERE/w0lfterm_changed_files.txt"

# the sources the host harnesses compile: if these move, the capture is void
sha256sum \
    kexploit/krw_zone_write.c kexploit/krw_zone_write.h \
    kexploit/probe_restore_policy.c kexploit/probe_restore_policy.h \
    kexploit/kwrite_counter.c kexploit/kwrite_counter.h \
    tests/krw_zone_write_host_test.c tests/probe_restore_e2e_host_test.c \
    tests/kwrite_counter_host_test.c tests/trm_shell_host_test.c \
    terminal/trm_shell.c \
    scripts/run_krw_zone_write_host_test.sh scripts/run_kwrite_counter_host_test.sh \
    scripts/run_probe_restore_e2e_host_test.sh scripts/run_trm_host_test.sh \
    scripts/check_host_verification.sh \
    >"$HERE/inputs.sha256" 2>/dev/null

{
    echo "capture files in $(basename "$HERE")/ (sha256, bytes, name)"
    find "$HERE" -type f ! -name MANIFEST.txt ! -name '*.pyc' -print0 \
        | sort -z | xargs -0 sha256sum | while read -r h p; do
            printf '%s  %8d  %s\n' "$h" "$(wc -c <"$p")" "${p#"$HERE"/}"
        done
} >"$HERE/MANIFEST.txt"

echo "wrote changed_files.txt, tree_state.txt, changed_file_stats.txt, changed_files.sha256, inputs.sha256, MANIFEST.txt"
echo
sed -n '1,8p' "$HERE/tree_state.txt"
echo
echo "MANIFEST.txt: $(wc -l <"$HERE/MANIFEST.txt") lines"
