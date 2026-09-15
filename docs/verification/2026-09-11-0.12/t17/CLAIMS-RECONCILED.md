# T17 (second pass) - host re-run and claim-by-claim reconciliation

Task 17/18 of the 2026-09-11 device-day bug work: W0lfSword `ROADMAP.md` section
`0.12` (`BUG.1`-`BUG.6`) and W0lfTerm `ROADMAP.md` section `0.6`.

**Host only. No device command was issued, no exploit was run, nothing was
committed or checked out.** Every number below is either backed by a file in this
directory or explicitly marked HISTORICAL / WITHDRAWN - there is no third
category, which is what the first pass of this task got wrong.

> Re-run note: the whole capture was re-taken against the current working tree
> after this table was written (see section 7). The three anchor hashes below
> (`1386b0b6...`, `1dc9c1d4...`, `62f760e7...`) came back byte-identical, and
> `verify_bug_claims.py` re-asserts every row of section 3 that names a capture
> file -> `claim check: 64 ok, 0 bad`.

## 0. Scope: what this pass was allowed to run, and what else is in here

Authorized run set (the three the task names, run against the **current working
tree**):

| # | command | what it covers |
|---|---|---|
| 1 | `bash scripts/run_krw_zone_write_host_test.sh` | BUG.1 - the 32-byte block writer's clamp + the staged probe's restore policy |
| 2 | `bash scripts/run_kwrite_counter_host_test.sh` | BUG.5 - the measured kernel-write counter |
| 3 | `bash scripts/check_host_verification.sh` (`--with-builds` too) | BUG.1/3/4/5/6 suite: 16 entries, 21 with the cross-builds |

Entry 3 **is** a suite driver: it runs ten further host harnesses itself
(`probe_restore_e2e`, `trm_shell_host_test`, `tweak_log_throttle`,
`scan_budget_cancel`, `bug2_release_paths`, `pressure_budget`, `test_offsets`,
`test_chain_select`, `py_compile`, `bash_syntax`). Their raw output is evidence
here **because it is the stdout of an authorized command**, captured by the
authorized command, into `suite_logs/w0lf_host_verification/` (one file per
entry) - they are not run as separate entries. The first pass listed them as
extra commands; this pass does not.

The harnesses are **repo scripts invoked as `bash scripts/<name>`, not installed
commands**: `command -v check_host_verification.sh` -> nothing,
`command -v krw_zone_write_host_test` -> nothing (only `git` resolves, `/bin/git`).
That is deliberate - nothing is installed globally and no device binary is
touched.

Two things in this directory are **not** part of the authorized set, and are
labelled as such wherever they are cited:

- `replay_revisions.sh` + `revisions/` - historical-revision reproduction. Three
  numbers in the roadmaps (41, 65, 95) are counts of *older revisions* of a
  harness, and no run of the current tree can confirm or withdraw them. They are
  reproduced from the git object store with `git archive` (no checkout, no reset,
  no stash) and marked HISTORICAL. The replayed tree of each revision is kept
  **inside the repo** (`revisions/<label>/tree/`, sparse: the paths that harness
  compiles, ~0.6 MB each) so the capture depends on nothing outside the repo.
  The first pass exported whole 15 MB trees into a temp directory; that is the
  defect `retired-round1/README.md` records.
- `check_capture_paths.py` - a check **about** the capture: it fails if any
  evidence path cited by a roadmap, the README or the worklog does not resolve,
  and if anything under `t17/` still names a temp-dir tree.

## 1. What ran, and what it printed

`capture.sh` with `WITH_BUILDS=1`, cwd `/home/kaffein/Desktop/W0lfSword`,
exit statuses in `RC.txt`, exact command lines in `COMMANDS.txt`:

```
krw_zone_write                   rc=0 (7492 bytes)
kwrite_counter                   rc=0 (2629 bytes)
host_verification                rc=0 (1461 bytes)
host_verification_builds         rc=0 (1807 bytes)
```

Verdicts, quoted from the raw logs:

```
$ bash scripts/run_krw_zone_write_host_test.sh            # krw_zone_write.log
checks=116 failures=0
KRW_ZONE_WRITE_HOST_TEST PASS

$ bash scripts/run_kwrite_counter_host_test.sh            # kwrite_counter.log
checks=53 failures=0
KWRITE_COUNTER_HOST_TEST PASS

$ bash scripts/check_host_verification.sh                 # host_verification.log
host verification: 16 ok, 0 drift

$ bash scripts/check_host_verification.sh --with-builds   # host_verification_builds.log
ok   engine_lib_build                   rc=0 334a5c211aedbcef... (88 bytes)
ok   engine_lib_archive                 263ae60d49fd0c15...
ok   app_ipa_build                      rc=0 e4f7235f621013d6... (2282 bytes)
ok   app_binary                         2922ebb3c8138e6d...
ok   app_static_symbols                 rc=0 fd7a746a6f461d09... (943 bytes)
host verification: 21 ok, 0 drift
```

Per-entry verdicts out of the suite's own raw logs
(`suite_logs/w0lf_host_verification/`, written by the suite):

| suite entry | verdict | log |
|---|---|---|
| `krw_zone_write` | `checks=116 failures=0` | `krw_zone_write.log` |
| `probe_restore_e2e` | `checks=56 failures=0` | `probe_restore_e2e.log` |
| `probe_restore_e2e_self` | `selftest: all mutations caught` | `probe_restore_e2e_self.log` |
| `kwrite_counter` | `checks=53 failures=0` | `kwrite_counter.log` |
| `tweak_log_throttle` | `checks=30 failures=0` | `tweak_log_throttle.log` |
| `scan_budget_cancel` | `25 check(s) passed, 0 failed` | `scan_budget_cancel.log` |
| `scan_budget_cancel_self` | `selftest: all mutations caught` | `scan_budget_cancel_self.log` |
| `bug2_release_paths` | `56 check(s) passed, 0 failed` | `bug2_release_paths.log` |
| `bug2_release_paths_self` | `selftest: all mutations caught` | `bug2_release_paths_self.log` |
| `pressure_budget` | `8 check(s) passed, 0 failed` | `pressure_budget.log` |
| `pressure_budget_self` | `selftest: all mutations caught` | `pressure_budget_self.log` |
| `test_offsets` / `test_chain_select` / `py_compile` / `bash_syntax` | rc 0 | same names |
| `trm_shell_host_test` | `checks=108 failures=0` | `trm_shell_host_test.log` |
| `engine_lib_build` | `OK: .theos/libengine/libw0lfengine.a` | `engine_lib_build.log` |
| `app_ipa_build` | `OK: dist/W0lfTerm-0.20-sideload.ipa` | `app_ipa_build.log` |
| `app_static_symbols` | symbol/string counts below | `app_static_symbols.log` |

Content hashes of the logs cited most (they are the anchors of the BUG.1/3/4/5
rows below):

```
1386b0b6e393b4923dc3ad9cd69547b8e9471e78f2c904688b5a09cc3b0ea5be  krw_zone_write.log
1dc9c1d4b0e35b86e23667ff627e4b57bb7f6ec8385e622fc78c585dd6424e63  kwrite_counter.log
62f760e7402071fcb823a7ec5191904e098ac6b520907ef13135ba6fa729cf4b  probe_restore_e2e.log
```

Those three are byte-identical to the ones the first pass kept (the harnesses are
deterministic), so this pass confirms them rather than replacing them.

VOLATILE BY DESIGN - two capture files change on every run and are *expected* to
differ from a re-run: `t17/trm_shell_host_test.log` (the TRM harness prints live
`date` / `df` / `loadavg` / its own pid and tempdir) and
`t17/suite_logs_plain/w0lf_host_verification/trm_shell_host_test.log`. Everything
else - including the app-build logs, whose compile order and zip mtimes vary, which
is why the suite hashes them in `canon` mode - is stable, and a fresh re-run of the
three authorized commands diffs clean against the captures in this directory
(checked at freeze time: `krw_zone_write.log`, `kwrite_counter.log` and
`host_verification.log` were byte-identical to the re-run). `MANIFEST.txt` pins the
bytes as captured; re-run `capture.sh` and `make_manifest.sh` together to refresh.
`host_verification.log`, `host_verification_builds.log` and
`trm_shell_host_test.log` are this pass's files; the TRM harness prints live
`date`/`df`/`loadavg`/tempdir, which is why the suite pins its **canonical** hash
`42305c27487f35be...` instead of the raw one.
`trm_shell_host_test.log` and `probe_restore_e2e.log` are copied up from
`suite_logs/w0lf_host_verification/` by `capture.sh` so the README/roadmap
citations do not depend on the suite's internal directory name.

App-side static check, quoted from `suite_logs/w0lf_host_verification/app_static_symbols.log`
(linked binary `dist/Payload/W0lfTerm.app/W0lfTerm`, sha256 `2922ebb3...`):

```
T _kexploit_request_stop        T _kexploit_stop_requested     b _g_peV2Aborted
T _probe_exit_action_for        T _kwrite_zone_element{,_declared,_set_object,...
  cancel                             19
  pe_v2 scan stopped on request      1
  no kernel writes                   5
  zero kernel writes                 0
  measured by kwrite_counter         1
```

## 2. Historical revisions (not the current tree)

`replay_revisions.sh`, exit statuses in `revisions/<label>/RC.txt`:

| label | commit | reprinted |
|---|---|---|
| `trm_routea` | `8e97aa7` (route A shell) | `checks=65 failures=0` |
| `trm_trm2` | `dfe75f2` (TRM.2 redirection) | `checks=95 failures=0` |
| `trm_trm1` | `979b8df` (TRM.1 completion) | `checks=108 failures=0` |
| `krw_head` | `HEAD` = `e51b172` | `checks=41 failures=0` |

Additional second capture of the 41: `head_replay/` (its own sources + built
binary + log, also in-repo).

Two things follow, and they are the opposite of what the first pass asserted:

- **41 is historical.** It is the count of the clamp-only revision of
  `tests/krw_zone_write_host_test.c` **as committed at HEAD**, not of the working
  tree. The working tree prints **116** (captured above). The number 41 is real
  *for that revision*; it must never be read as the current count, and the
  ROADMAP now says so at the point where it quotes it.
- **108 is the current tree's count** and needs no replay: it comes out of the
  authorized suite run on the working tree (`trm_shell_host_test.log`, and the
  `rc=0 ... (15415 bytes)` entry in `host_verification.log`). The `979b8df` replay
  agreeing with it is corroboration, not the source of the claim.
  `git diff --stat HEAD -- tests/trm_shell_host_test.c terminal/` is empty, so the
  harness and shell sources are the committed ones; `utils/tweak_log.h`/`.m` are
  modified in the tree, and both revisions print 108 all the same.

## 3. Claim-by-claim

Statuses: **BACKED** = a file in this directory contains the quoted output or
hash; **CORRECTED** = the claim was rewritten in the doc and now cites a capture
or is marked historical; **WITHDRAWN** = no capture exists and no committed
revision produces it, so the number is gone from the doc.

### W0lfSword `ROADMAP.md` 0.12 - BUG.1 (steps 1, 2, 3, 3b)

| claim | status | evidence / what it is now |
|---|---|---|
| `checks=116 failures=0` / `KRW_ZONE_WRITE_HOST_TEST PASS` | BACKED | `krw_zone_write.log` sha256 `1386b0b6...`; quoted again in `host_verification.log` line 2 |
| `41 checks, 0 failures` | CORRECTED -> HISTORICAL | `revisions/krw_head/build_and_run.log` + `head_replay/build_and_run.log`; the ROADMAP text now says in place that 41 is the committed revision's count and 116 is this tree's |
| `checks=65 failures=0` (BUG.1 step 1) | WITHDRAWN | no capture; no committed revision produces it |
| `43 check(s) passed` (bug2_release_paths) | WITHDRAWN | the lint is untracked (no revision of it exists in git); this pass prints 56, in `suite_logs/w0lf_host_verification/bug2_release_paths.log` |
| `56 check(s) passed, 0 failed` + selftest | BACKED | `suite_logs/w0lf_host_verification/bug2_release_paths{,_self}.log` |
| `checks=56 failures=0` (probe_restore_e2e) | BACKED | `probe_restore_e2e.log` sha256 `62f760e7...` (also a suite entry) |
| step 2 field choice: nothing consumes the probed qword | BACKED | `suite_logs/w0lf_host_verification/pressure_budget.log` lines `ok BUG.1 probe field: nothing in the shipped code consumes the probed qword` / `ok BUG.1 probe field: the probe body does not touch the icmp6 filter pointer` |
| `8 check(s) passed, 0 failed` (pressure_budget) | BACKED | same log; the `7 check(s) passed` / `7/7` the BUG.2 note carried is a T12-dated count (before the disk-budget check was added) and is CORRECTED |
| `16 ok, 0 drift` / `21 ok, 0 drift` (suite) | BACKED | `host_verification.log`, `host_verification_builds.log` |
| archive `263ae60d...`, linked binary `2922ebb3...` | BACKED | `suite_logs/w0lf_host_verification/engine_lib_archive` + `app_binary` entries in `host_verification_builds.log` |

### W0lfSword `ROADMAP.md` 0.12 - BUG.2 (memory pressure)

| claim | status | evidence |
|---|---|---|
| the pressure/mapping table and the spray bound | BACKED | `suite_logs/w0lf_host_verification/pressure_budget.log` (prints `98304 page(s) 384 MB total 12 x 32.0 MB mapping(s)` for the 3 GB class, and `8064 MB dirtied per run (7.88x the limit)`) |
| `7 check(s) passed, 0 failed` | CORRECTED | now 8 (same log); the 7 is dated T12 prose, no retained log |
| release-path audit (every exit funnels, 56 checks) | BACKED | `suite_logs/w0lf_host_verification/bug2_release_paths.log` |
| `~30 MB mapped per pass` | CORRECTED (T12 note kept) | the log's own table: 384 MB per cycle on the SE2 class |

### W0lfSword `ROADMAP.md` 0.12 - BUG.3 (scan budget)

| claim | status | evidence |
|---|---|---|
| `25 check(s) passed, 0 failed`, six BUG.3 lines | BACKED | `suite_logs/w0lf_host_verification/scan_budget_cancel.log` - quoted lines include `ok BUG.3 engine: the default budget is the one that fits the walk (600 s)`, `... every scan/spray loop reads it`, `... sits INSIDE each walk, not after it`, `ok BUG.3 app: the default budget matches the engine default and is pushed in at load`, `ok BUG.3 app: a SET row exists, persists, and pushes every change into the engine`, `ok BUG.3 app: the boot banner reads the budget back from the ENGINE` |
| `--selftest` -> `selftest: all mutations caught` | BACKED | `suite_logs/w0lf_host_verification/scan_budget_cancel_self.log` |
| `21 check(s) passed` (earlier pass) | BACKED | `docs/verification/2026-09-11-0.12/scan_budget_cancel.log`, the first capture of that lint |
| `20 check(s) passed` (T10 pass) | CORRECTED | dated count, no retained log; the reproducible ones are 21 and 25 |
| `8 check(s) passed, 0 failed` (pressure_budget) | BACKED | `suite_logs/w0lf_host_verification/pressure_budget.log` |

### W0lfSword `ROADMAP.md` 0.12 - BUG.4 (visible CANCEL)

| claim | status | evidence |
|---|---|---|
| the cancel checks are green | BACKED | eight `BUG.4` lines in `suite_logs/w0lf_host_verification/scan_budget_cancel.log`: spray honours cancel; visible control only while running; the tap reaches the engine stop flag; the run loop stops on -7; pe_v1 `-7` releases spray + mappings; pe_v1's -7 funnel; pe_v2 aborted path frees mapping/object/spray; both cancel paths reach the app as `-7` |
| "seven cancel checks" | CORRECTED | the log has eight (T16 prose undercounted by one) |
| `cancel` x19, `pe_v2 scan stopped on request` x1 | BACKED | `suite_logs/w0lf_host_verification/app_static_symbols.log` |
| linked binary sha256 `2922ebb3...` | BACKED | rebuilt in this pass, same hash (`app_binary` in `host_verification_builds.log`) |
| `checks=53 failures=0` (kwrite_counter) | BACKED | `kwrite_counter.log` |
| `20 check(s) passed` (twice) | CORRECTED | dated counts -> 21 and 25 |

### W0lfSword `ROADMAP.md` 0.12 - BUG.5 (measured writes)

| claim | status | evidence |
|---|---|---|
| `checks=53 failures=0` / `KWRITE_COUNTER_HOST_TEST PASS` | BACKED | `kwrite_counter.log` sha256 `1dc9c1d4...` |
| no shipped log/UI string claims "zero writes" | BACKED | `scan_budget_cancel.log` line `ok BUG.5: no shipped log/UI string claims 'zero writes' any more` |
| `no kernel writes` x5 / `zero kernel writes` x0 | BACKED | `app_static_symbols.log` |
| `20 check(s) passed` | CORRECTED | dated count -> 25 |

### W0lfSword `ROADMAP.md` 0.12 - BUG.6 (stale host pairing)

| claim | status | evidence |
|---|---|---|
| the throttle is host-tested and is one process-wide gate | BACKED | four `BUG.6` lines in `scan_budget_cancel.log` and `checks=30 failures=0` / `TWEAK_LOG_THROTTLE_HOST_TEST PASS` in `tweak_log_throttle.log` (both from the authorized suite) |
| `references/dead-device-usb-triage.md` exists with the two-error table | BACKED (file check, not a harness) | `test -f references/dead-device-usb-triage.md` -> present |
| the pairing failure itself | NOT host-testable | a host/USB condition; unchanged, device day |

### W0lfTerm `ROADMAP.md` 0.2 / 0.6

| claim | status | evidence |
|---|---|---|
| `TRM.1` "13 new host checks (108 pass, 0 failures)" | BACKED for 108 (this tree) / HISTORICAL for the predecessor | 108: `trm_shell_host_test.log` + the `trm_shell_host_test rc=0` entry in `host_verification.log`; the 13 is the delta from the TRM.2 revision, which reprints `checks=95 failures=0` in `revisions/trm_trm2/` |
| `TRM.2` "13 new host checks (95 pass)" | HISTORICAL, reproduced | `revisions/trm_trm2/build_and_run.log` -> `checks=95 failures=0` |
| route-A block "65/65 pass" + README `65/65` | CORRECTED -> HISTORICAL | `revisions/trm_routea/build_and_run.log` -> `checks=65 failures=0`; both docs now say 65 is that revision's count and the harness on disk prints 108 |
| 0.6 `BUG.1` (cancel): `25 check(s)`, selftest, `cancel` x19, binary sha, `21 ok, 0 drift` | BACKED | `suite_logs/w0lf_host_verification/{scan_budget_cancel,scan_budget_cancel_self,app_static_symbols}.log`, `host_verification_builds.log` |
| 0.6 `BUG.2` (zero writes): `checks=53`, `no kernel writes` 5 / `zero kernel writes` 0, `20 check(s)` | BACKED / CORRECTED | `kwrite_counter.log`, `app_static_symbols.log`; the `20` is dated -> 25 |
| 0.6 `BUG.3` (disk writes): `checks=30`, four BUG.6 checks, `25 check(s)` | BACKED | `tweak_log_throttle.log`, `scan_budget_cancel.log` |
| 0.6 `BUG.4` (caret timer) / `BUG.6` (pairing doc) | documentation/code claims, re-read in place | no count asserted; unchanged |
| 0.6 `BUG.5` (`keyBarSize` caching) | still open `[ ]` | unchanged by this pass; no claim of a fix |

## 4. What this pass corrected in the docs

| file | correction |
|---|---|
| W0lfSword `ROADMAP.md` | BUG.1 step 3: 41 relabelled HISTORICAL with an in-repo capture, 116 stated as this tree's count; BUG.2: `7 check(s) passed` -> 8, dated; BUG.1/3/4/5 capture paths repointed at `suite_logs/w0lf_host_verification/`; the revision trees described as in-repo and sparse |
| W0lfSword `README.md` | TRM counts: 108 is this tree's; `65/65` labelled HISTORICAL with its capture |
| W0lfTerm `ROADMAP.md` | TRM.1: 108 attributed to this tree + the suite capture; 65/95 labelled HISTORICAL with in-repo trees; 0.6 `BUG.1`/`BUG.2` capture paths repointed |
| W0lfSword `docs/WORKLOG.md` | new `T17 (second pass)` section recording this run; the C4 correction note kept |
| this directory | `capture.sh`, `replay_revisions.sh`, `make_manifest.sh` rewritten; `retired-round1/` records what the first pass did that made the capture depend on a temp dir |

`changed_files.txt` is the porcelain list of the tree this capture came from and
`changed_files.sha256` hashes every changed/untracked file, so the docs above can
be read against the exact tree state.

## 5. What is still NOT verified

Every item in both bug sections remains **not device-verified**: this pass touched
no device and ran no exploit. The device halves the roadmaps name - the restore on
the SE, the banner reading 600 back, tap-the-word-mid-run and the `[cleanup]`
lines, the readonly run's counter reading 0 - are unchanged and still wait for a
device day. `readonly` remains the only mode for an unproven device/iOS pair.

## 6. Reproduce

```
bash docs/verification/2026-09-11-0.12/t17/capture.sh
WITH_BUILDS=1 bash docs/verification/2026-09-11-0.12/t17/capture.sh
bash docs/verification/2026-09-11-0.12/t17/replay_revisions.sh
python3 docs/verification/2026-09-11-0.12/t17/check_capture_paths.py
bash docs/verification/2026-09-11-0.12/t17/make_manifest.sh
```

`check_capture_paths.py` must print `capture path check: <N> ok, 0 bad` - the
`N` grows whenever a doc starts citing one more evidence path (73 at the first
run of this pass, 78 after section 7 and the W0lfTerm `BUG.3` note were added),
so the assertion is the `0 bad` half; its raw output is kept as
`t17/capture_path_check.log`. `MANIFEST.txt` hashes every file in this directory.

## 7. Re-run verification (this pass): capture re-taken, every claim re-asserted

After the table above was written, the capture was taken again from the working
tree as it stands, with nothing else changed, to make sure the numbers above are
a property of this tree and not of one lucky run. `tree_state.txt` for the run:

```
repo:       /home/kaffein/Desktop/W0lfSword
branch:     main
HEAD:       e51b1729b14b41097e1f5269b8f3e704b14b763c
HEAD subject: roadmap: 0.13 findings (le_next fix, restore-through-bogus-address, BUG.7 clamp gap, walk pace)
dirty:      38 entries (see changed_files.txt)
```

The `captured:` timestamp line of that file is omitted above; the file itself is
`t17/tree_state.txt`.

Commands re-run (exact lines in `COMMANDS.txt`, exit statuses in `RC.txt`,
all four `rc=0`; every one of them is host-only and none is a device command):

```
bash scripts/run_krw_zone_write_host_test.sh                 -> checks=116 failures=0
bash scripts/run_kwrite_counter_host_test.sh                 -> checks=53 failures=0
bash scripts/check_host_verification.sh                      -> host verification: 16 ok, 0 drift
W0LF_TERM=~/Desktop/W0lfTerm bash scripts/check_host_verification.sh --with-builds
                                                             -> host verification: 21 ok, 0 drift
bash replay_revisions.sh      -> checks=41 (HEAD) / 65 / 95 / 108, all rc=0
python3 check_capture_paths.py -> capture path check: 78 ok, 0 bad
python3 verify_bug_claims.py   -> claim check: 64 ok, 0 bad   (this section's checker)
```

The three anchor hashes came back **byte-identical** to the ones quoted above
(`1386b0b6...` `krw_zone_write.log`, `1dc9c1d4...` `kwrite_counter.log`,
`62f760e7...` `probe_restore_e2e.log`), so the harnesses are deterministic and
sections 1-3 stand unchanged for this tree. Only the two files documented as
volatile-by-design moved: `trm_shell_host_test.log` (live `date`/`df`/`loadavg`/
pid) - whose *canonical* hash is what the suite pins, and the suite reports
`0 drift` for it - and the app-build log, which the suite hashes in `canon` mode.

`verify_bug_claims.py` (new in this pass) is the mechanical form of "each
verified fact is backed by captured output": it holds one row per claim of both
bug lists - `BUG.1` steps 1/2/3/3b, `BUG.3`, `BUG.4`, `BUG.5`, `BUG.6` - each
naming the capture file and the exact line that must be in it, plus the three
anchor sha256 values, the three HISTORICAL revision counts, the two suite
summary lines, `checks=108` and the `rc=0` of all four captured commands. Raw
output: `t17/verify_bug_claims.log`; it exits non-zero if any row is unbacked
(it caught one wrong row while being written - the cancel exit's line is
`cancel (-7) restores (it is not the promotion)`, not the wording first
guessed). Final line of the captured run:

```
claim check: 64 ok, 0 bad
```

Corrections this pass made in the docs (all three were ATTRIBUTION errors left
by the earlier pass - the counts themselves were right):

| file | correction |
|---|---|
| W0lfSword `ROADMAP.md` (TRM route A) | `checks=108` was attributed to the suite command itself; it is the count line of the suite's `trm_shell_host_test` entry, while the suite's own summary is `21 ok, 0 drift` and its entry line is `ok trm_shell_host_test rc=0 42305c27487f35be...` |
| W0lfTerm `ROADMAP.md` (`TRM.1`) | same attribution fix, and "re-ran it (`run_trm_host_test.sh`)" now states that the run is the authorized suite entry whose command is that script |
| W0lfSword `README.md` | the `108` citation now names the entry's raw log (which really contains the count) instead of the suite summary |

New in this pass: the W0lfTerm `0.6` `BUG.3` (disk writes) item had no T17 note
at all - the only item of the two bug lists without one - so it now records the
re-run of its log half
(`t17/suite_logs/w0lf_host_verification/tweak_log_throttle.log` ->
`checks=30 failures=0`, the four `BUG.6` structural checks inside the 25-check
lint) and re-reads the 1 GB/day accounting from the fresh
`t17/suite_logs/w0lf_host_verification/pressure_budget.log`
(`8064 MB dirtied per run (7.88x the limit)`, `at most 3001 fsync(s)`) next to
the device report's own figures.

Nothing about the device status changed: no device command was issued in this
pass either, so every "NOT device-verified" note above is still true.
