#!/usr/bin/env bash
# Re-run the host-side verification harnesses for the 2026-09-11 device-day bug
# list (ROADMAP section 0.12 here, section 0.6 in W0lfTerm) and compare each run
# with the exit status and output hash recorded in docs/WORKLOG.md.
#
# Why this exists: the worklog is the evidence that the BUG.1/BUG.3/BUG.4/BUG.5
# fixes hold on this host. A hash in a worklog is only worth something if the
# next person can reproduce it, so this script reruns every logged command and
# reports PASS (rc and hash both match) or DRIFT (paste the new hash into the
# worklog only after understanding WHY it moved - a changed check count is a
# code change, not a flake).
#
# Every command here is host-only: it compiles C with the host cc, runs a Python
# source lint, or runs the Theos cross-build. It touches no device and issues no
# device command (the "Live device smoke" section of scripts/regression.sh is
# deliberately NOT part of this file - it ssh's to .w0lfsword/active_device).
#
#   bash scripts/check_host_verification.sh
#   bash scripts/check_host_verification.sh --with-builds
#   W0LF_TERM=/path/to/W0lfTerm bash scripts/check_host_verification.sh --with-builds
#
# --with-builds adds the cross-builds (make libengine, the W0lfTerm ipa build and
# the static check on the linked binary); they are host-only too, just slower.
#
# Pins re-taken 2026-09-15 (six entries, all from one cause and one harness bug):
#
#   * the T18 yield edit in kexploit/kexploit_opa334.m (both free-thread waits
#     end in `pthread_yield_np();` instead of a bare `;`) landed AFTER the last
#     capture, so every derived artifact moved: the engine archive
#     (`engine_lib_archive`), the linked W0lfTerm binary (`app_binary`) and the
#     addresses in `app_static_symbols`; its `nm` symbol set and the string
#     counts are UNCHANGED - only the addresses shifted by the new code size.
#   * `bug2_release_paths` prints the src line number of each traced exit, and
#     the same edit moved them (1975 vs 1984); the check count is unchanged at
#     56, 0 failed.
#   * `bug2_release_paths_self` was FAILING (rc=1, "SOME MUTATIONS WERE
#     MISSED"): one mutation still targeted the pre-yield `while (...) ;` shape,
#     so it never applied and the rule it guards was untested. The mutation now
#     drops the stop-flag half of free_thread's first wait; the selftest is
#     "all mutations caught" again.
#   * `trm_shell_host_test` drifted for a reason that had nothing to do with the
#     tests: its own stdout was fully buffered when redirected, so a `df` child
#     spawned by the selftest path wrote into the middle of a parent line and
#     the interleave moved between runs. tests/trm_shell_host_test.c now line-
#     buffers stdout, and the canon hash is byte-stable over repeated runs.
#
# Pins re-taken 2026-09-20 (W0lfTerm ANIM.1/ANIM.2/ANIM.3, six entries): the
# app-side launch work moved the app and everything derived from it, and one new
# entry joined the suite.
#
#   * `scan_budget_cancel` (25 -> 30 checks) and `scan_budget_cancel_self`
#     (21 -> 31 mutations): the lint gained the ANIM app checks (one caret gate,
#     the art-then-banner order, the line fade and its cadence bound, the build
#     wiring) and a mutation each for the ways those can rot - a text path that
#     forgets the caret gate, a launch path that boots the banner directly, a
#     boot paced by a literal instead of term_anim.c, an art line rule that
#     drifts from the host test, the art dropping out of the resource list, a
#     fade range left pointing into text a trim moved, a fade duration that is a
#     literal, the fade cap ignored, the art fading line by line again, and a
#     fade longer than the log hook's batch cadence.
#   * `term_anim_host_test` is new: the app's term_anim.c (caret blink rule, boot
#     budget arithmetic, the line-fade rule and its frame count) driven on the
#     host, 36 checks. It reads the art from THIS tree, which is the file the
#     W0lfTerm Makefile copies into the bundle, so the sequence it prices is the
#     sequence the device draws.
#   * `app_ipa_build` moved because the app rebuilt (new source file, new
#     resource, version label 0.20 -> 0.21), and `app_binary` with it
#     (396151837a0e... -> e06e5674... -> 214fd5c0... -> 725384bd..., the ANIM.5
#     build). The canon log hash has not moved since the first 0.21 build: the
#     file list and the version label are what it sees, and neither changed.
#   * the ANIM.5 pass (transitions: `clear` scrolls, a theme cross-fade, the
#     settings slide) moved the two lint hashes again - 30 -> 31 checks,
#     31 -> 36 mutations (a `clear` that ignores Reduce Motion, output wiped by
#     the scroll it landed during, a cross-fade per settings tick, the sheet
#     losing its slide, a dismissal that animates under Reduce Motion) - and the
#     harness to 36 checks. `app_static_symbols` grew the ANIM.5 symbols
#     (_term_should_animate, _term_settings_slide, _term_clear_scroll_ms,
#     _term_theme_crossfade_ms).
#   * `app_static_symbols` grew the term_anim symbols, the two new selector
#     strings and the bundled-art comparison (`cmp` against
#     scripts/wolf_art.txt here - a drift between the shipped art and the tested
#     art now fails the entry rather than passing quietly).
#
# Re-pin only with a reason like the above: a count that changes is a code
# change, not a flake.
set -uo pipefail

cd "$(dirname "$0")/.." || exit 1
ROOT="$PWD"
TERM_SRC="${W0LF_TERM:-$HOME/Desktop/W0lfTerm}"
OUT="${TMPDIR:-/tmp}/w0lf_host_verification"
mkdir -p "$OUT"

WITH_BUILDS=0
[ "${1:-}" = "--with-builds" ] && WITH_BUILDS=1

PASS=0
FAIL=0

# Output lines that are inherently different on every run, masked before hashing
# in "canon" mode: the trm_shell harness runs real commands and prints the live
# system state (date, df, loadavg, its own pid and its random temp dir), and the
# Theos build prints its parallel compile order plus the zip's mtimes.
CANON_SED='
  s#/tmp/trm_shell_test_[A-Za-z0-9]+#/tmp/trm_shell_test_TMPDIR#g
  s/pid=[0-9]+ ppid=[0-9]+/pid=N ppid=N/
  s#\| \[sh\] [0-9]{4}-[0-9]{2}-[0-9]{2} [0-9:]{8} [+-][0-9]{4}#| [sh] DATE#
  s#\| \[sh\] load +[0-9.]+ [0-9.]+ [0-9.]+#| [sh] loadavg N N N#
  s#total=[0-9]+MB free=[0-9]+MB avail=[0-9]+MB#total=NMB free=NMB avail=NMB#
  s/[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}/DATE TIME/g'

# check <name> <cwd> <expected-rc> <expected-hash> <raw|canon> <command>
check() {
    local name="$1" dir="$2" erc="$3" ehash="$4" mode="$5" cmd="$6"
    local log="$OUT/$name.log"
    ( cd "$dir" && eval "$cmd" ) >"$log" 2>&1
    local rc=$?
    local got
    if [ "$mode" = canon ]; then
        got=$(sed -E "$CANON_SED" "$log" | sort | sha256sum | cut -d' ' -f1)
    else
        got=$(sha256sum <"$log" | cut -d' ' -f1)
    fi
    if [ "$rc" = "$erc" ] && [ "$got" = "$ehash" ]; then
        printf 'ok   %-34s rc=%s %s (%s)\n' "$name" "$rc" "${got:0:16}..." "$(wc -c <"$log") bytes"
        PASS=$((PASS + 1))
    else
        printf 'BAD  %-34s rc=%s (want %s) sha256=%s\n' "$name" "$rc" "$erc" "$got"
        printf '     want %s\n     log %s\n' "$ehash" "$log"
        FAIL=$((FAIL + 1))
    fi
}

echo "host verification suite - cwd=$ROOT"
echo "raw logs: $OUT"
echo

# --- the three named harnesses (ROADMAP 0.12 BUG.1 / BUG.3 / BUG.5) ---
check krw_zone_write         "$ROOT" 0 1386b0b6e393b4923dc3ad9cd69547b8e9471e78f2c904688b5a09cc3b0ea5be raw \
    'bash scripts/run_krw_zone_write_host_test.sh'
# BUG.7: the window the clamp is given is the kalloc bucket read out of the zone
# (pcb -> inpcbinfo.ipi_zone -> z_elem_size), including the refusal verdict for an
# object whose bucket contradicts the field table. Same decision file the engine
# archive compiles (kexploit/krw_zone_size.c).
check krw_zone_size          "$ROOT" 0 5d1e08cffa5f28acedeec7fadd7e567a5493b8a8c75b1ccbeb2ded3715627725 raw \
    'bash scripts/run_krw_zone_size_host_test.sh'
# BUG.1 end to end: the same two files, driven through the probe's
# save -> corrupt -> exit -> put-back sequence (the 32-byte overrun injected,
# then the -1 and -7 exits), plus its own selftest on temp copies.
check probe_restore_e2e      "$ROOT" 0 62f760e7402071fcb823a7ec5191904e098ac6b520907ef13135ba6fa729cf4b raw \
    'bash scripts/run_probe_restore_e2e_host_test.sh'
check probe_restore_e2e_self "$ROOT" 0 97e2173af1a31a7e57ebcfb20289a524b99f1b74723faee2507578c38840a935 raw \
    'python3 scripts/probe_restore_e2e_selftest.py --selftest'
check kwrite_counter         "$ROOT" 0 1dc9c1d4b0e35b86e23667ff627e4b57bb7f6ec8385e622fc78c585dd6424e63 raw \
    'bash scripts/run_kwrite_counter_host_test.sh'
# BUG.6: the disk-write throttle (the fsync rate gate), counted with a simulated
# clock. Its source (utils/tweak_log_policy.c) is the one the engine archive and
# the tweak build ship, so a drift between tested and shipped fails at entry 12f.
check tweak_log_throttle     "$ROOT" 0 d59cd9fd7d8be99c390a569e1c7430af0b37a8023433fc4beaf5806b530653ab raw \
    'bash scripts/run_tweak_log_throttle_host_test.sh'
check scan_budget_cancel     "$ROOT" 0 10ea294ebad7da40895743c79dc01205dfae68bf2733c28aecb7f182a677b4cd raw \
    'python3 scripts/check_scan_budget_cancel_writes.py'
check scan_budget_cancel_self "$ROOT" 0 ddd180c1285b4e7c98abd84070ec5baa97e0649c3a7815ff386af4a22521327e raw \
    'python3 scripts/check_scan_budget_cancel_writes.py --selftest'
# ANIM.1 / ANIM.3: the launch animations' decisions (term_anim.c) - the caret
# blink rule and the boot sequence's budget arithmetic. The app compiles the same
# file (app entry term_anim.c in the W0lfTerm Makefile) and the harness reads the
# art from this tree, which is the art the Makefile copies into the bundle, so
# the sequence the test prices is the sequence the device draws.
check term_anim_host_test    "$ROOT" 0 1681da1cdb64330efdd51236453a1110b2273e7f84289fbf48e76eec43cfcf07 raw \
    'bash "$TERM_SRC/scripts/run_term_anim_host_test.sh"'

# --- the rest of regression.sh's host half (run directly, never the whole file) ---
# re-pinned 2026-09-18 (BUG.7): the lint gained six zone-window checks and four
# mutations for them (the bucket read delegated to the tested chain, the injected
# reader, the field-span floor, the refused-window branch), so both hashes moved:
# 55 checks / 19 mutations before, 61 / 23 after.
check bug2_release_paths     "$ROOT" 0 68e092eb5bd3c215350d03f93f1912f527fdaf1b767566753aad0ed668f19161 raw \
    'python3 scripts/check_bug2_release_paths.py'
check bug2_release_paths_self "$ROOT" 0 eb73de27dd79cb551dbf3ad4e4748390ed7fc934dae667d6af00aaab2e6a9b4f raw \
    'python3 scripts/check_bug2_release_paths.py --selftest'
check test_offsets           "$ROOT" 0 eead34fbfc466f966c32ceb1d2e43f1312400ccf97fa2894239a85550f47857d raw \
    'python3 scripts/test_offsets.py'
# re-pinned 2026-09-11 (T14): check_pressure_budget.py gained its 8th check (the
# disk-write accounting against the 1 GB/day limit) and two selftest mutations, so
# both hashes moved. 7 checks / 7 mutations before, 8 / 9 after.
check pressure_budget        "$ROOT" 0 91bd530e7bf386a527b9d56e01bae5812821c5a281315bd6ffd4c3ac3c29d549 raw \
    'python3 scripts/check_pressure_budget.py'
check pressure_budget_self   "$ROOT" 0 98be7a751526bbd282f158c2d0522a78acedb4f8f8797d2f7f78217b534fe9ad raw \
    'python3 scripts/check_pressure_budget.py --selftest'
check test_chain_select      "$ROOT" 0 9a596a45ef210f9b0238c8c2fc595887a88b66e8b260818a02798e2d2092fbc6 raw \
    'bash scripts/test_chain_select.sh'
# The trm_shell harness is the one host check whose raw output cannot be byte
# stable (it prints live df/date/loadavg/pid): rc + canonical hash instead.
check trm_shell_host_test    "$ROOT" 0 89e5f65f65e23cc4ad9b9b499bf30e5c4de0c2af32b1c2cdbe33eee87af8fc6e canon \
    'bash scripts/run_trm_host_test.sh'
check py_compile             "$ROOT" 0 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 raw \
    'python3 -m py_compile scripts/check_scan_budget_cancel_writes.py scripts/check_bug2_release_paths.py scripts/check_pressure_budget.py scripts/probe_restore_e2e_selftest.py'
check bash_syntax            "$ROOT" 0 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 raw \
    'bash -n scripts/run_krw_zone_write_host_test.sh scripts/run_probe_restore_e2e_host_test.sh scripts/run_kwrite_counter_host_test.sh scripts/run_tweak_log_throttle_host_test.sh scripts/build_libengine.sh scripts/regression.sh "$TERM_SRC/scripts/run_term_anim_host_test.sh" "$TERM_SRC/scripts/build_ipa.sh"'

if [ "$WITH_BUILDS" = 1 ]; then
    echo
    [ -d "$TERM_SRC" ] || { echo "BAD  W0lfTerm tree not found at $TERM_SRC (set W0LF_TERM)"; FAIL=$((FAIL + 1)); }
    if [ -d "$TERM_SRC" ]; then
        # 1) engine archive: the host-tested C files are in it, so a drift
        #    between the tested sources and the shipped ones fails here.
        #    Re-pinned 2026-09-18 (BUG.7): the engine gained the zone-bucket read
        #    (kexploit/krw_zone_size.c is a new archive member and
        #    kexploit_opa334.m now delegates its chain to it), so the build log
        #    (804K/52 objects -> 808K/53 objects), the archive and the linked app
        #    all moved. The archive was rebuilt with a 0-byte build log (zero
        #    warnings, zero errors) and llvm-nm shows the archive defines
        #    _krw_zone_bucket_for_pcb while kexploit_opa334.o references it.
        # shellcheck disable=SC2016  # eval'd command string: the expansion is the point
        check engine_lib_build "$ROOT" 0 573a137e7bd6f9eb4ab379bfcc6c1ad68ac8a0e152fb042d92b3d037aa0190c2 raw \
            'THEOS=${THEOS:-$HOME/theos} make libengine'
        got_ar=$(sha256sum .theos/libengine/libw0lfengine.a | cut -d' ' -f1)
        if [ "$got_ar" = 9acea9964e08984d43c9805c0d01247c1a55044479674b8620dd8e0129d7b035 ]; then
            printf 'ok   %-34s %s\n' "engine_lib_archive" "${got_ar:0:16}..."
            PASS=$((PASS + 1))
        else
            printf 'BAD  %-34s sha256=%s\n     want %s\n' "engine_lib_archive" "$got_ar" \
                32f6af7e665ab15d58031528d4e9cd912c6ba5b94ee4aab05345fddc44c411e5
            FAIL=$((FAIL + 1))
        fi
        # 2) app build: the log varies only in compile order + zip mtimes (canon
        #    mode); the linked binary is the assertion, so hash it directly.
        check app_ipa_build "$TERM_SRC" 0 81c1969c99ef64565d8373c499af5387f545ee69e6d7df1ceead4ba70525ca29 canon \
            'bash scripts/build_ipa.sh sideload 0.21'
        got_bin=$(sha256sum "$TERM_SRC/dist/Payload/W0lfTerm.app/W0lfTerm" | cut -d' ' -f1)
        # Re-pinned 2026-09-18 (BUG.7): the app links the rebuilt engine archive,
        # so the binary moved with it. Same build (0.20), no source change on the
        # app side.
        if [ "$got_bin" = 725384bdae6e9585af5472739b503cace83f8a5782c8e2e2957062d4442bc01d ]; then
            printf 'ok   %-34s %s\n' "app_binary" "${got_bin:0:16}..."
            PASS=$((PASS + 1))
        else
            printf 'BAD  %-34s sha256=%s\n     want %s\n' "app_binary" "$got_bin" \
                725384bdae6e9585af5472739b503cace83f8a5782c8e2e2957062d4442bc01d
            FAIL=$((FAIL + 1))
        fi
        # 3) the app-side static check (llvm-nm: GNU nm cannot read Mach-O)
        #    Re-pinned 2026-09-18 (BUG.7): the linked binary moved with the engine
        #    archive, and _krw_zone_bucket_for_pcb was added to the nm list so the
        #    shipped app is proved to link the zone-bucket chain the host test
        #    drives - not just to compile it.
        # shellcheck disable=SC2016  # eval'd command string: the expansion is the point
        check app_static_symbols "$TERM_SRC" 0 a6d06dbfdd710c2f2911c3a96a2190c1d613ca44ca7a644b4c37fa3ed2d81a84 raw \
            'BIN=dist/Payload/W0lfTerm.app/W0lfTerm
             { echo "W0lfTerm app-side static check (linked binary produced by the 0.21 rebuild)"
               echo "binary: $BIN"
               echo "sha256: $(sha256sum "$BIN" | cut -d" " -f1)"
               echo
               echo "== nm: cancel/verification symbols =="
               llvm-nm-19 "$BIN" | grep -E " _g_peV2Aborted| _probe_exit_action_for| _kexploit_request_stop| _kexploit_stop_requested| _kwrite_zone_element| _tweak_log_fsync_due| _krw_zone_bucket_for_pcb"
               echo
               echo "== nm: ANIM.1/ANIM.2/ANIM.3 decisions (term_anim.c is inside the app) =="
               llvm-nm-19 "$BIN" | grep -E " _term_caret_blinks| _term_caret_blink_interval| _term_boot_tick| _term_boot_handover| _term_boot_duration_ms| _term_boot_budget_ms| _term_boot_fits| _term_line_fade_ms| _term_line_should_fade| _term_line_fade_frame_rate| _term_clear_scroll_ms| _term_theme_crossfade_ms| _term_settings_slide| _term_should_animate"
               echo
               echo "== strings markers (count) =="
               for m in cancel "pe_v2 scan stopped on request" "no kernel writes" "zero kernel writes" "measured by kwrite_counter" beginBootSequence skipBootSequence wolf_art fadeTick endLineFade; do
                   printf "  %-34s %s\n" "$m" "$(strings -a "$BIN" | grep -cF "$m")"
               done
               echo
               echo "== ANIM.3 bundled art vs the tree the Makefile copies from =="
               shipped_art=$(sha256sum dist/Payload/W0lfTerm.app/wolf_art.txt | cut -d" " -f1)
               source_art=$(sha256sum "$ROOT/scripts/wolf_art.txt" | cut -d" " -f1)
               echo "shipped wolf_art.txt: $shipped_art"
               echo "source  wolf_art.txt: $source_art"
               echo "bundled art is the art this tree tests"
               cmp -s dist/Payload/W0lfTerm.app/wolf_art.txt "$ROOT/scripts/wolf_art.txt" || { echo "DRIFT: the bundled art is not the tested art"; exit 1; } }'
    fi
fi

printf '\nhost verification: %d ok, %d drift\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ] || exit 1
