# Worklog

Raw evidence for the host-side verification runs that back the 2026-09-11 device-day
bug fixes. One entry per executor task; newest last. Every entry records the exact
command, its working directory, the exit status, and the sha256 of the complete
stdout+stderr. The raw outputs themselves live next to this file under
`docs/verification/<date>-<section>/` (the `*.log` extension is gitignored, so these
files stay local - that is deliberate).

Host: `Linux 7.0.13+parrot7-amd64 x86_64`, `cc (Debian 14.2.0-19) 14.2.0`,
`Python 3.13.5`, `llvm-nm-19` (the GNU `nm` at `/bin/nm` cannot read Mach-O).
No device was attached and no device command was run.

---

## T11 - execute the existing host-side harnesses (ROADMAP 0.12 / 0.6)

First recorded 2026-09-11T23:05+02:00; **re-run and corrected 2026-09-11T23:07-23:12+02:00**
by the verification pass for this task. Scope: run the host harnesses that already
exist, capture their raw output, command, exit status and hash, and make every
recorded hash reproducible. Nothing was committed; no git command other than
read-only `git status` / `git check-ignore` was used.

### HARD RULE compliance

- HARD RULE 1 (no exploit, no device command): every command below either compiles a
  C file with the host `cc` and runs the resulting binary, runs a Python source lint,
  or runs the Theos cross-build. `scripts/regression.sh` was deliberately NOT run as a
  whole: its last section ("Live device smoke", `scripts/regression.sh:111`) reads
  `.w0lfsword/active_device` and would `ssh root@<ip>`; that file currently contains
  `localhost`. Each host check `regression.sh` wraps was run directly instead (same
  commands, same logs).
- HARD RULE 2 (no git commit/push/checkout): no git command other than read-only
  `git status` / `git check-ignore` was used.
- HARD RULE 3 (no file deletion): nothing was deleted. The W0lfTerm build script
  recreates its own `dist/` outputs, as it always does.

### The three named harnesses (ROADMAP 0.12: BUG.1, BUG.3, BUG.5)

| # | command | cwd | exit | sha256 (stdout+stderr) | reproducible? | bytes | raw log |
|---|---------|-----|------|------------------------|---------------|-------|---------|
| 1 | `bash scripts/run_krw_zone_write_host_test.sh` | `/home/kaffein/Desktop/W0lfSword` | 0 | `1386b0b6e393b4923dc3ad9cd69547b8e9471e78f2c904688b5a09cc3b0ea5be` | byte-identical | 7492 | `docs/verification/2026-09-11-0.12/krw_zone_write.log` |
| 2 | `bash scripts/run_kwrite_counter_host_test.sh` | `/home/kaffein/Desktop/W0lfSword` | 0 | `1dc9c1d4b0e35b86e23667ff627e4b57bb7f6ec8385e622fc78c585dd6424e63` | byte-identical | 2629 | `docs/verification/2026-09-11-0.12/kwrite_counter.log` |
| 3 | `python3 scripts/check_scan_budget_cancel_writes.py` | `/home/kaffein/Desktop/W0lfSword` | 0 | `1057dd2deb5ea1079e6cd85b38c1dc4fd6586aea9b7915fdc99405bc2b78cf53` | byte-identical | 1855 | `docs/verification/2026-09-11-0.12/scan_budget_cancel.log` |
| 4 | `python3 scripts/check_scan_budget_cancel_writes.py --selftest` | `/home/kaffein/Desktop/W0lfSword` | 0 | `0ef98157b486fa3cccd79d0ecb74e5062e63a9f697be49e60089f0db54c8cf75` | byte-identical | 30939 | `docs/verification/2026-09-11-0.12/scan_budget_cancel_selftest.log` |

Exit lines (copied verbatim from the logs):

```
$ bash scripts/run_krw_zone_write_host_test.sh
checks=116 failures=0
KRW_ZONE_WRITE_HOST_TEST PASS
(exit 0)

$ bash scripts/run_kwrite_counter_host_test.sh
checks=53 failures=0
KWRITE_COUNTER_HOST_TEST PASS
(exit 0)

$ python3 scripts/check_scan_budget_cancel_writes.py
21 check(s) passed, 0 failed
SCAN_BUDGET_CANCEL_WRITES LINT PASS
(exit 0)

$ python3 scripts/check_scan_budget_cancel_writes.py --selftest
selftest: all mutations caught
SCAN_BUDGET_CANCEL_WRITES LINT PASS
(exit 0)
```

`--selftest` deliberately mutates its own fixtures and prints a `FAIL`ing line per
mutation before reporting `selftest: all mutations caught` (exit 0) - that is the
proof the checks fire, not a real failure. `check_bug2_release_paths.py --selftest`
has the same shape.

### Sibling host checks (the rest of `regression.sh`'s host half)

| # | command | cwd | exit | sha256 (stdout+stderr) | reproducible? | bytes | raw log |
|---|---------|-----|------|------------------------|---------------|-------|---------|
| 5 | `python3 scripts/check_bug2_release_paths.py` | `/home/kaffein/Desktop/W0lfSword` | 0 | `1df3ce4c11439d92bf412a4f411140e20fcb0bc260dd3370cc670413460a171f` | byte-identical | 7170 | `docs/verification/2026-09-11-0.12/check_bug2_release_paths.log` |
| 6 | `python3 scripts/check_bug2_release_paths.py --selftest` | `/home/kaffein/Desktop/W0lfSword` | 0 | `03bc081c48798f73959714628936f48d818d8c7e04c6a8af1a09c250b1a7f612` | byte-identical | 4768 | `docs/verification/2026-09-11-0.12/check_bug2_release_paths_selftest.log` |
| 7 | `python3 scripts/test_offsets.py` | `/home/kaffein/Desktop/W0lfSword` | 0 | `eead34fbfc466f966c32ceb1d2e43f1312400ccf97fa2894239a85550f47857d` | byte-identical | 552 | `docs/verification/2026-09-11-0.12/test_offsets.log` |
| 8 | `bash scripts/test_chain_select.sh` | `/home/kaffein/Desktop/W0lfSword` | 0 | `9a596a45ef210f9b0238c8c2fc595887a88b66e8b260818a02798e2d2092fbc6` | byte-identical | 2129 | `docs/verification/2026-09-11-0.12/test_chain_select.log` |
| 9 | `bash scripts/run_trm_host_test.sh` | `/home/kaffein/Desktop/W0lfSword` | 0 | raw: varies per run (see correction C2); canonical: `42305c27487f35be1e26678529c99383adeaff82ea08ec2de71c6ac867804556` | rc + canonical hash | 15415 | `docs/verification/2026-09-11-0.12/trm_shell_host_test.log` |
| 10 | `python3 -m py_compile scripts/check_scan_budget_cancel_writes.py scripts/check_bug2_release_paths.py` | `/home/kaffein/Desktop/W0lfSword` | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | byte-identical | 0 | `docs/verification/2026-09-11-0.12/py_compile.log` |
| 11 | `bash -n scripts/run_krw_zone_write_host_test.sh scripts/run_kwrite_counter_host_test.sh scripts/build_libengine.sh scripts/regression.sh` | `/home/kaffein/Desktop/W0lfSword` | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | byte-identical | 0 | `docs/verification/2026-09-11-0.12/bash_syntax.log` |

`e3b0c442...` is the sha256 of the empty string - entries 10 and 11 are silent on
success, so exit 0 with 0 bytes is the whole output.

Summary lines: `check_bug2_release_paths.py` -> `56 check(s) passed, 0 failed`;
`test_chain_select.sh` -> `chain selector: 26 passed, 0 failed`; `test_offsets.py` ->
`PASS: thresholds strictly increasing, 4 critical offsets resolved at every threshold,
itk_space matches XPF-verified values`; `run_trm_host_test.sh` -> `checks=108
failures=0` / `TRM_SHELL_HOST_TEST PASS`.

### Build checks

| # | command | cwd | exit | sha256 (stdout+stderr) | reproducible? | bytes | raw log |
|---|---------|-----|------|------------------------|---------------|-------|---------|
| 12 | `THEOS=$HOME/theos make libengine` | `/home/kaffein/Desktop/W0lfSword` | 0 | `26f3293a19e478d4277337d5660db513a8eb9e92e2aeaefee8537cd3287c0952` | byte-identical | 88 | `docs/verification/2026-09-11-0.12/engine_lib_build.log` |
| 13 | `bash scripts/build_ipa.sh sideload 0.20` | `/home/kaffein/Desktop/W0lfTerm` | 0 | raw: varies per run (see correction C3); canonical: `e4f7235f621013d694bcc495ec41d92d733019d2cdd0afe05dadf51fd1778241` | rc + canonical hash | 2282 | `docs/verification/2026-09-11-0.12/app_ipa_build.log` (+ `.rerun.log`) |
| 14 | static check on the linked app binary (see below) | `/home/kaffein/Desktop/W0lfTerm` | 0 | `c675553e0da6653c82f0b6dc48b27cb763ff183eed11afd0be8e6df704f481ad` | byte-identical | 859 | `docs/verification/2026-09-11-0.12/app_static_symbols.log` |

- 12: output is exactly `OK: .theos/libengine/libw0lfengine.a (804K, 51 objects)`;
  `sha256(.theos/libengine/libw0lfengine.a)` =
  `0cf3f46c349c2d5d6eefc087a31e34b0c628bbf9a1971886491694f9e89012ee` (822280 bytes).
  The archive holds **51 objects plus `__.SYMDEF`** (`ar t` prints 52 lines) - the
  count in the message is right. This archive contains the same
  `kexploit/krw_zone_write.c`, `kexploit/probe_restore_policy.c` and
  `kexploit/kwrite_counter.c` that entries 1-2 compile, so a drift between the tested
  sources and the shipped ones fails here.
- 13: `OK: dist/W0lfTerm-0.20-sideload.ipa`, exit 0. The app binary it produced is
  **byte-identical across two consecutive builds** and to the binary the earlier
  session recorded:
  `sha256(dist/Payload/W0lfTerm.app/W0lfTerm)` =
  `5986b31e9f423135e8ce6037aaa6eee7e55209f301819b71fb92302a0254415d` (515376 bytes).
  The `.ipa` container hash is not stable by construction (zip stores mtimes) - the
  linked binary is the assertion.
- 14: exact command (one `{ ... }` block): `sha256sum` of the binary, then
  `llvm-nm-19 "$BIN" | grep -E ' _g_peV2Aborted| _probe_exit_action_for|
  _kexploit_request_stop| _kexploit_stop_requested| _kwrite_zone_element'`, then
  `strings -a "$BIN" | grep -cF` for each marker. Symbols defined in the freshly
  linked binary:

```
00000001000b91cc b _g_peV2Aborted
000000010000d118 T _kexploit_request_stop
000000010000d13c T _kexploit_stop_requested
0000000100017864 T _kwrite_zone_element
00000001000177e0 T _kwrite_zone_element_clear_object
00000001000178a8 T _kwrite_zone_element_declared
00000001000178ec T _kwrite_zone_element_qword
00000001000177b4 T _kwrite_zone_element_set_object
000000010000c2cc T _probe_exit_action_for
```

  Marker counts: `cancel` 19, `pe_v2 scan stopped on request` 1, `no kernel writes` 5
  (the corrected wording), `zero kernel writes` **0**, `measured by kwrite_counter` 1.
  The `zero kernel writes` count of 0 is the BUG.5 claim the lint also asserts.

### Reproducibility suite (new this pass)

`scripts/check_host_verification.sh` re-runs every command above and compares rc and
hash with the table in this worklog, so the evidence is machine-checkable instead of
transcribed. Host-only, same HARD RULE 1 reasoning (no device, no device command).

| # | command | cwd | exit | sha256 (stdout+stderr) | bytes | raw log |
|---|---------|-----|------|------------------------|-------|---------|
| 15 | `bash scripts/check_host_verification.sh` | `/home/kaffein/Desktop/W0lfSword` | 0 | `409a5c8fcb6dad947f4b957ecfb6f2e601c0748e59e63af89f9b89ffdb692c0d` | 989 | `docs/verification/2026-09-11-0.12/suite.log` |
| 16 | `bash scripts/check_host_verification.sh --with-builds` | `/home/kaffein/Desktop/W0lfSword` | 0 | `a4dc89ed3b55d8cb36510b1379eb2d06b83d06441fa125392ed8e380d2f1893a` | 1341 | `docs/verification/2026-09-11-0.12/suite_with_builds.log` |
| 17 | mutation test: same suite with entry 1's expected hash replaced by zeros | `/home/kaffein/Desktop/W0lfSword` | **1** | `388c9632f856e72b6452f046b8bde64a3c492c96c7c2c5debdc49c391178a6cf` | 1168 | `docs/verification/2026-09-11-0.12/suite_mutation_test.log` |

Entry 16 tail: `host verification: 16 ok, 0 drift` (the 11 checks + `engine_lib_build`,
`engine_lib_archive`, `app_ipa_build`, `app_binary`, `app_static_symbols`).
Entry 17 is the proof the suite can fail: with one expected hash corrupted it prints

```
BAD  krw_zone_write                     rc=0 (want 0) sha256=1386b0b6e393b4923dc3ad9cd69547b8e9471e78f2c904688b5a09cc3b0ea5be
     want 0000000000000000000000000000000000000000000000000000000000000000
     log /tmp/w0lf_host_verification/krw_zone_write.log
...
host verification: 10 ok, 1 drift
```

and exits 1. `shellcheck -s bash -e SC2059 scripts/check_host_verification.sh` -> no
output, exit 0; `bash -n` -> exit 0.

### Corrections to the earlier T11 record

- **C1 (command named wrong).** Entry 14 was recorded as `nm ...`; the symbol names
  and addresses in that log can only come from a Mach-O-aware `nm`. Verified: `/bin/nm`
  (GNU binutils) prints `nm: dist/Payload/W0lfTerm.app/W0lfTerm: file format not
  recognized` (exit 1). The command that reproduces the log byte-for-byte is
  `llvm-nm-19` (`/usr/bin/llvm-nm-19`).
- **C2 (hash not reproducible).** Entry 9's raw hash
  `c07fd6251efbcd88d2d78c457fb778d0247e6d333f0e817d80c0b6aeb8c6ce5b` cannot be
  reproduced by construction: the harness prints its random container
  (`/tmp/trm_shell_test_XXXXXX`), `pid`/`ppid`, and the live `date`, `df` and `loadavg`.
  Five fresh runs gave five different raw hashes (`629e6610...`, `9851b64e...`,
  `be1d6c89...`, `ca7e1ec2...`, `9b2da52d...`) and the **same canonical hash**
  `42305c27...` after masking those volatile fields (filter:
  `sed -E 's#/tmp/trm_shell_test_[A-Za-z0-9]+#/tmp/trm_shell_test_TMPDIR#g;
  s/pid=[0-9]+ ppid=[0-9]+/pid=N ppid=N/; s#\| \[sh\] [0-9]{4}-[0-9]{2}-[0-9]{2}
  [0-9:]{8} [+-][0-9]{4}#| [sh] DATE#; s#\| \[sh\] load +[0-9.]+ [0-9.]+ [0-9.]+#|
  [sh] loadavg N N N#;
  s#total=[0-9]+MB free=[0-9]+MB avail=[0-9]+MB#total=NMB free=NMB avail=NMB#' | sort`).
  The canonical hash also matches the log the earlier session wrote, so the run itself
  is the same run - only the raw hash was a one-off. The raw hash of the log now on
  disk (`trm_shell_host_test.log`, written by this pass at 23:07) is
  `c046682ebb27e7afd0f4b0db0d372974710470fc2ba070b4f784ef00299b4262` - recorded for
  traceability, not as a value to re-match.
- **C3 (hash not reproducible).** Entry 13's raw log hash `c55e006e...` is likewise
  one-off: the Theos build's parallel compile order varies and the zip listing carries
  mtimes. Two consecutive builds differed only in those two ways (diff of
  `app_ipa_build.log` vs `app_ipa_build.rerun.log`); the canonical hash
  `e4f7235f...` and the linked binary hash `5986b31e...` matched exactly. The two raw
  hashes on disk are `77889116e539f85bf8e840b62ad9446b7a2beb40bd521fa3ceeda932a6d2f7fb`
  (`app_ipa_build.log`) and
  `a06acfbd51c723199289e4860f16f34127859d585205440487bd053d756f832e`
  (`app_ipa_build.rerun.log`).
- **C4 (stale prose numbers) - FIXED at T17.** This pass recorded them instead of
  fixing them (out of its scope): the ROADMAP 0.12 prose for BUG.1 said the
  zone-writer harness reports `41 checks, 0 failures` while it reports
  `checks=116 failures=0`, and the W0lfTerm 0.6 entry quoted `20 check(s)` for the
  scan lint, which reports 25 (21 at the first capture). T17
  (`docs/verification/2026-09-11-0.12/t17/CLAIMS-RECONCILED.md`) corrected both in
  place and did the rest of the 0.12 / 0.6 prose too: `41` now cites the replay of
  the committed harness revision (`t17/revisions/krw_head/build_and_run.log`,
  `checks=41 failures=0`, so the number is real - it was the revision, not the
  claim, that was stale); the `checks=65 failures=0` and `43 check(s) passed` this
  item's step-1 block quoted are marked WITHDRAWN (no capture, and no committed
  revision of either harness produces them); the `20 check(s)` counts are marked
  as dated with no retained log; and the TRM shell harness's `65/65` is corrected
  to the 108 the harness on disk prints (65 and 95 are real too - the counts of
  the route-A and TRM.2 revisions, replayed in `t17/revisions/`).

### What this evidence does and does not cover

Does: the host-visible halves of BUG.1 (writer clamp + restore policy, 116 checks),
BUG.3 (budget/cancel lint, 21 checks + 15 mutations caught), BUG.4 (cancel propagation
in both walks, 43 engine checks + the app-side link check), BUG.5 (write counting,
53 checks; no shipped string claims "zero writes"), plus the app build linking all of
it into a bit-identical binary.

Does not: any device behaviour. Nothing here was run on a phone, and no device command
was issued. The staged write probe's on-device restore, the panic, the app's cancel
tap and the resource budgets are all still NOT device-verified - that needs the next
device day, and readonly stays the only mode offered on unproven device/iOS pairs.

### T11 re-run (task 11/12) - fresh execution, every hash reproduced byte-for-byte

Re-ran every command in the tables above again in one pass on the same host, window
`2026-09-11T23:12:04+02:00` .. `2026-09-11T23:14:21+02:00`, cwd
`/home/kaffein/Desktop/W0lfSword`. No `sha256` moved: the logs now archived under
`docs/verification/2026-09-11-0.12/` are this run's outputs, and they are byte-identical
to the earlier pass's (same hash, same byte count, one exception noted in C7). The last
command of the window was `bash scripts/check_host_verification.sh` again, after every
edit of this pass, and it printed `11 ok, 0 drift` with the same 989-byte hash
`409a5c8f...` - the tree is where the suite expects it.

The three commands that prove it end to end:

| # | command | cwd | exit | sha256 (stdout+stderr) | bytes | raw log |
|---|---------|-----|------|------------------------|-------|---------|
| 18 | `bash scripts/check_host_verification.sh` (re-run) | `/home/kaffein/Desktop/W0lfSword` | 0 | `409a5c8fcb6dad947f4b957ecfb6f2e601c0748e59e63af89f9b89ffdb692c0d` | 989 | `docs/verification/2026-09-11-0.12/suite.log` |
| 19 | `W0LF_TERM=/home/kaffein/Desktop/W0lfTerm bash scripts/check_host_verification.sh --with-builds` (re-run) | `/home/kaffein/Desktop/W0lfSword` | 0 | `a4dc89ed3b55d8cb36510b1379eb2d06b83d06441fa125392ed8e380d2f1893a` | 1341 | `docs/verification/2026-09-11-0.12/suite_with_builds.log` |
| 20 | mutation test: entry 1's expected hash zeroed in the script, suite run, script put back | `/home/kaffein/Desktop/W0lfSword` | **1** | `388c9632f856e72b6452f046b8bde64a3c492c96c7c2c5debdc49c391178a6cf` | 1168 | `docs/verification/2026-09-11-0.12/suite_mutation_test.log` |

- 18: tail `host verification: 11 ok, 0 drift` (exit 0), same hash as entry 15.
- 19: tail `host verification: 16 ok, 0 drift` (exit 0), same hash as entry 16. It rebuilt
  for real this time: `ls -l --time-style=+%H:%M:%S` right after the run shows
  `dist/Payload/W0lfTerm.app/W0lfTerm`, `dist/W0lfTerm-0.20-sideload.ipa` and
  `.theos/libengine/libw0lfengine.a` all stamped `23:12:38` (suite tail at `23:12:42`), and
  the suite's own artifact checks matched (`0cf3f46c...` archive, `5986b31e...` binary).
  `unzip -l dist/W0lfTerm-0.20-sideload.ipa` -> 4 files, `Payload/W0lfTerm.app/W0lfTerm`
  515376 bytes at `23:12`.
- 20: tail `host verification: 10 ok, 1 drift`, exit 1,
  `BAD krw_zone_write rc=0 (want 0) sha256=1386b0b6... want 0000...`. Reproduces entry 17
  exactly, so the suite is not vacuous. The mutation is reverted immediately:
  `sha256(scripts/check_host_verification.sh)` is
  `d14be9c3692c230f8da1b56f8b5b8d7d1c22564df05a9721278821f9614e66f3` before and after,
  `diff -u` against a pre-mutation copy is empty, `bash -n` exits 0.

#### Corrections and re-checks this pass

- **C5 - `scripts/build_ipa.sh` does exist and does run.** An earlier report called it
  "command not installed"; local evidence contradicts that, so here is the record.
  `ls -l /home/kaffein/Desktop/W0lfTerm/scripts/build_ipa.sh` ->
  `-rw-rw-r-- 1 kaffein kaffein 3855 11. Sep 16:28 scripts/build_ipa.sh`;
  `bash -n scripts/build_ipa.sh` -> exit 0; and run directly this pass, cwd
  `/home/kaffein/Desktop/W0lfTerm`, `bash scripts/build_ipa.sh sideload 0.20` -> exit 0,
  tail `OK: dist/W0lfTerm-0.20-sideload.ipa`, raw log
  `docs/verification/2026-09-11-0.12/app_ipa_build.direct.log` (2282 bytes, sha256
  `6a3492ad2cf1347594eef249a005d6beb95a7facee3df76e11e4368d608c8c09`), canonical hash
  `e4f7235f621013d694bcc495ec41d92d733019d2cdd0afe05dadf51fd1778241` - i.e. byte-for-byte
  the run entry 13 records, two builds later. Its prerequisite is present
  (`/home/kaffein/theos`), and the binary it produced at `23:14:13` is again
  `5986b31e...`. This is the command entry 13 and entry 19 run.
- **C6 - C1 re-confirmed.** `nm dist/Payload/W0lfTerm.app/W0lfTerm` ->
  `nm: ... file format not recognized`, exit 1 (GNU binutils); `llvm-nm-19` on the same
  file lists the symbols. Entry 14's command is `llvm-nm-19`, not GNU `nm`.
- **C7 - C2 re-confirmed, with the exact volatile lines.** Three fresh runs of
  `bash scripts/run_trm_host_test.sh`: raw `33804ac7...`, `b30ea9e2...`, `aa12b560...`;
  canonical `42305c27487f35be1e26678529c99383adeaff82ea08ec2de71c6ac867804556` all three
  times (mask + `sort` + sha256, filter written to `/tmp/canon.sed`). `diff` between two
  runs shows 10 differing lines: 9 carry the random container `/tmp/trm_shell_test_XXXXXX`
  and 1 is `id ... pid=325599 ppid=325598` - exactly the two things the canonical mask
  normalises. `checks=108 failures=0` / `TRM_SHELL_HOST_TEST PASS` in every run. Entry 9's
  policy (rc + canonical hash) is therefore the right one, and entry 9's archived raw hash
  is a one-off as recorded.
- **C8 - archive count and contents.** `ar t .theos/libengine/libw0lfengine.a | wc -l` ->
  52 = 51 objects + `__.SYMDEF` (the message's "51 objects" is right). The archive holds
  `kexploit_krw_zone_write.c.o`, `kexploit_probe_restore_policy.c.o` and
  `kexploit_kwrite_counter.c.o`, i.e. exactly the sources entries 1-2 compile by hand.
- **HARD RULE 1 re-check.** `scripts/regression.sh:111` is `section "Live device smoke"`,
  `:113` reads `.w0lfsword/active_device` (currently `localhost`), `:115` is
  `ssh ... root@$DEV_IP`. That is why `regression.sh` is never run whole - only its host
  checks individually, as above. No exploit and no device command was issued in this pass,
  and no git write command was used (`git status --short` and `git log -1` only, read-only).
  No file in `/home/kaffein/Desktop/W0lfTerm` was edited either: the six files its
  `git status` lists as modified are stamped `22:44:59` .. `23:02:16`, all before this
  window, and the build only wrote `dist/` and `.theos/`, both gitignored
  (`W0lfTerm/.gitignore:2-3`).

#### Method note (why the mutation test runs at the repo root)

`check_scan_budget_cancel_writes.py` derives the app tree as a sibling of its cwd
(`os.path.dirname(root) + "/W0lfTerm"`, `scripts/check_scan_budget_cancel_writes.py:685`),
so a copy of the suite under `/tmp` with no `W0lfTerm` sibling makes that lint exit 1 with
`no W0lfTerm tree at /tmp/W0lfTerm (pass --wolfterm)` - an environment artifact, not a
drift. Two such symlink-farm runs were made while working this out; they are kept in
`/tmp/w0lf_mut_*` (nothing was deleted) and are deliberately not cited as evidence.

---

## T12 - closing BUG.1-BUG.6 with per-item evidence (ROADMAP 0.12 / 0.6)

Recorded 2026-09-11T23:2x+02:00 (task 12/12). Scope: close the six open-bug items
with a verification artifact each, in roadmap order. The BUG.1/3/4/5 code was
already in the tree from the previous tasks; this pass re-ran every harness on the
CURRENT tree, filled the one item that had no artifact at all (the disk-write
throttle, BUG.6), and corrected one claim that turned out not to be backed
(`references/dead-device-usb-triage.md` did not exist).

### What changed in the tree (no device, no git write command)

| # | change | file(s) |
|---|--------|---------|
| 1 | the fsync rate gate extracted from the ObjC-only block of the sink header into a compiled, host-testable policy | `utils/tweak_log_policy.c` / `.h` (new) |
| 2 | the sink consults ONE process-wide gate instead of a per-TU `static struct timespec` | `utils/tweak_log.h`, `utils/tweak_log.m` |
| 3 | the gate is in both build lists, so the tested file is the shipped file | `scripts/build_libengine.sh`, `Makefile` |
| 4 | host test with a simulated clock that counts the grants | `tests/tweak_log_throttle_host_test.c`, `scripts/run_tweak_log_throttle_host_test.sh` (new) |
| 5 | 4 new checks + 5 new selftest mutations (21 total) for the throttle, incl. "no other ungated fsync in the code the app compiles" | `scripts/check_scan_budget_cancel_writes.py` |
| 6 | the throttle harness registered in the standing suites | `scripts/regression.sh`, `scripts/check_host_verification.sh` (3 re-pinned hashes) |
| 7 | the engine-side triage doc the roadmap claimed, created | `references/dead-device-usb-triage.md` (new, 3205 bytes) |
| 8 | per-item closing notes with the evidence below | `ROADMAP.md` (this repo), `W0lfTerm/ROADMAP.md` |

### Command table (cwd `/home/kaffein/Desktop/W0lfSword` unless noted)

| # | command | cwd | exit | sha256 (stdout+stderr) | bytes | log |
|---|---------|-----|------|------------------------|-------|-----|
| 1 | `bash scripts/run_krw_zone_write_host_test.sh` | W0lfSword | 0 | `1386b0b6e393b4923dc3ad9cd69547b8e9471e78f2c904688b5a09cc3b0ea5be` | 7492 | `.../t12/krw_zone_write.log` |
| 2 | `bash scripts/run_kwrite_counter_host_test.sh` | W0lfSword | 0 | `1dc9c1d4b0e35b86e23667ff627e4b57bb7f6ec8385e622fc78c585dd6424e63` | 2629 | `.../t12/kwrite_counter.log` |
| 3 | `bash scripts/run_tweak_log_throttle_host_test.sh` | W0lfSword | 0 | `d59cd9fd7d8be99c390a569e1c7430af0b37a8023433fc4beaf5806b530653ab` | 2873 | `.../t12/tweak_log_throttle.log` |
| 4 | `python3 scripts/check_scan_budget_cancel_writes.py` | W0lfSword | 0 | `4dc5246d0662e7df01b483d7cb9e859244210c7f31cba283198d4c658547790d` | 2161 | `.../t12/scan_budget_cancel.log` |
| 5 | `python3 scripts/check_scan_budget_cancel_writes.py --selftest` | W0lfSword | 0 | `e24a0f3e9a1e9bc7b7be800439e50ab11d7190fa77c7c6858eafa28e5b98a040` | 46714 | `.../t12/scan_budget_cancel_self.log` |
| 6 | `python3 scripts/check_bug2_release_paths.py` | W0lfSword | 0 | `1df3ce4c11439d92bf412a4f411140e20fcb0bc260dd3370cc670413460a171f` | 7170 | `.../t12/bug2_release_paths.log` |
| 7 | `python3 scripts/check_bug2_release_paths.py --selftest` | W0lfSword | 0 | `03bc081c48798f73959714628936f48d818d8c7e04c6a8af1a09c250b1a7f612` | 4768 | `.../t12/bug2_release_paths_self.log` |
| 8 | `python3 scripts/test_offsets.py` | W0lfSword | 0 | `eead34fbfc466f966c32ceb1d2e43f1312400ccf97fa2894239a85550f47857d` | 552 | `.../t12/test_offsets.log` |
| 9 | `bash scripts/test_chain_select.sh` | W0lfSword | 0 | `9a596a45ef210f9b0238c8c2fc595887a88b66e8b260818a02798e2d2092fbc6` | 2129 | `.../t12/test_chain_select.log` |
| 10 | `bash scripts/run_trm_host_test.sh` | W0lfSword | 0 | canonical `42305c27487f35be1e26678529c99383adeaff82ea08ec2de71c6ac867804556` | 15415 | `.../t12/trm_shell_host_test.log` |
| 11 | `python3 -m py_compile scripts/check_scan_budget_cancel_writes.py scripts/check_bug2_release_paths.py` | W0lfSword | 0 | `e3b0c442...` (empty) | 0 | `.../t12/py_compile.log` |
| 12 | `bash -n scripts/run_krw_zone_write_host_test.sh scripts/run_kwrite_counter_host_test.sh scripts/run_tweak_log_throttle_host_test.sh scripts/build_libengine.sh scripts/regression.sh` | W0lfSword | 0 | `e3b0c442...` (empty) | 0 | `.../t12/bash_syntax.log` |
| 13 | `THEOS=$HOME/theos make libengine` | W0lfSword | 0 | `334a5c211aedbcef4436eb7731927659a5bef0f10be980caaf0b44d3b2082668` | 88 | `.../t12/engine_lib_build.log` |
| 14 | `bash scripts/build_ipa.sh sideload 0.20` | W0lfTerm | 0 | canonical `e4f7235f621013d694bcc495ec41d92d733019d2cdd0afe05dadf51fd1778241` | 2282 | `.../t12/app_ipa_build.log` |
| 15 | `bash scripts/check_host_verification.sh --with-builds` | W0lfSword | 0 | `6b80b9b0cb9bae16b2cba5faf90b30aa469e85c96f51c977d6b48d3336dfd855` | 1419 | `.../t12/suite_with_builds.log` |
| 16 | `./W0lfSword audit` | W0lfSword | 0 | `94ec025be0a82401583515eef12eed9bec1404767ab22e639e10f2d90fd32f13` | 1327 | `.../t12/audit.log` |
| 17 | `llvm-objdump-19 -d --macho dist/Payload/W0lfTerm.app/W0lfTerm` (cwd W0lfTerm), then grep the call sites | W0lfTerm | 0 | `c2084cdfe1f782ebf5b328ffb353bfcab2d94dc3ed9b6472a45ffe232f6de275` | 2510338 | `.../t12/app_disassembly.txt` |
| 18 | `THEOS=$HOME/theos make package` (the tweak, not just the archive), then `llvm-nm-19 .theos/obj/debug/arm64/FilzaApplySandboxExt.dylib \| grep tweak_log_fsync_due` | W0lfSword | 0 | log `4a6922246e79f69aa0e6e0ba802ef0ea18dc2035ae7875437d7ce96515361c7e`, dylib sha256 `db57db11bff8a058e78d49715eb7855721a687b9166a002638d860157379fc19` | 2208 | `.../t12/make_package.log` |

Entry 18 is the second half of "the tested file is the shipped file": the Makefile
line this pass edited is only exercised by the tweak build. `make package` -> exit 0,
`dm.pl: building package ... in
./packages/com.kaffeindecaf.w0lfsword_1.5.0-12+debug_iphoneos-arm64.deb` (the only
diagnostics are ld64.lld's two known notes), the build log contains
`==> Compiling utils/tweak_log_policy.c (arm64)…`, and the built dylib defines the
policy:

```
$ llvm-nm-19 .theos/obj/debug/arm64/FilzaApplySandboxExt.dylib | grep tweak_log_fsync_due
000000000003de14 T _tweak_log_fsync_due
000000000003dda8 T _tweak_log_fsync_due_now
```

`.../t12/` = `docs/verification/2026-09-11-0.12/t12/` (the new subdirectory, so the
earlier pass's logs in the parent directory are untouched). `e3b0c442...` is the
sha256 of the empty string.

The call sites entry 17 checks, in the binary entry 14 built (line = the
disassembly file's own addressing, verified by grepping the symbol's function body):

```
-[TerminalViewController dotTapped:]:     (starts 0x100007f24)
100007f3c:  bl  _TermClick
100007f40:  bl  _termHapticLight
100007f44:  bl  _term_bridge_cancel

_term_bridge_cancel:                      (starts 0x10001df4c)
10001df50:  bl  _kexploit_request_stop
10001df5c:  bl  _TweakLog

+[TermSettings setScanBudget:]:           (starts 0x100020ba4)
100020c38:  bl  _kexploit_set_scan_budget
```

so "the button reaches the engine's stop flag" and "the SET row pushes the value
into the engine" are call instructions in the installed artifact, not strings in it.

Exit lines, verbatim:

```
$ bash scripts/run_krw_zone_write_host_test.sh
checks=116 failures=0
KRW_ZONE_WRITE_HOST_TEST PASS

$ bash scripts/run_kwrite_counter_host_test.sh
checks=53 failures=0
KWRITE_COUNTER_HOST_TEST PASS

$ bash scripts/run_tweak_log_throttle_host_test.sh
checks=30 failures=0
TWEAK_LOG_THROTTLE_HOST_TEST PASS

$ python3 scripts/check_scan_budget_cancel_writes.py
25 check(s) passed, 0 failed
SCAN_BUDGET_CANCEL_WRITES LINT PASS

$ python3 scripts/check_scan_budget_cancel_writes.py --selftest
selftest: all mutations caught
SCAN_BUDGET_CANCEL_WRITES LINT PASS            (21 mutations, 5 of them new)

$ python3 scripts/check_bug2_release_paths.py
56 check(s) passed, 0 failed
$ python3 scripts/check_bug2_release_paths.py --selftest
selftest: all mutations caught                 (19 mutations)

$ bash scripts/check_host_verification.sh --with-builds
host verification: 17 ok, 0 drift
```

### Hashes that legitimately moved (and nothing else did)

The worklog's pinned suite caught the change instead of hiding it - `--with-builds`
reported `10 ok, 6 drift` on the first run after the throttle landed, and each of
the six was explained, not excused:

| entry | before | after | why |
|-------|--------|-------|-----|
| `tweak_log_throttle` | (new) | `d59cd9fd...` | the new harness |
| `scan_budget_cancel` | `1057dd2d...` | `4dc5246d...` | 21 -> 25 checks (4 new BUG.6 lines) |
| `scan_budget_cancel_self` | `0ef98157...` | `e24a0f3e...` | 16 -> 21 mutations, each printing a `FAIL` line as designed |
| `engine_lib_build` | `26f3293a...` | `334a5c21...` | `51 objects` -> `52 objects` |
| `engine_lib_archive` | `0cf3f46c...` | `263ae60d...` | same, one more object in the archive |
| `app_binary` | `5986b31e...` | `2922ebb3...` | the app now links `_tweak_log_fsync_due` / `_tweak_log_fsync_due_now` |
| `app_static_symbols` | `c675553e...` | `fd7a746a...` | its command now also greps for the throttle symbols |

Unchanged byte-for-byte (i.e. the BUG.1/3/4/5 fixes did not move): `krw_zone_write`,
`kwrite_counter`, `bug2_release_paths`, `bug2_release_paths_self`, `test_offsets`,
`test_chain_select`, `trm_shell_host_test`, `py_compile`, `bash_syntax`,
`app_ipa_build`.

### The suite can still fail (mutation test, entries 19-20)

| # | command | exit | sha256 | bytes | log |
|---|---------|------|--------|-------|-----|
| 19 | the suite with entry 3's expected hash zeroed | **1** | `c9b96fee2e8d8f54a100dce4f8938baac35c40eecd96ae5e1fecd580f92c51be` | 1250 | `.../t12/suite_mutation_test.log` |
| 20 | `bash scripts/check_host_verification.sh --with-builds` again, after the revert | 0 | `6b80b9b0cb9bae16...` | 1419 | `.../t12/suite_with_builds.log` |

Entry 19 printed

```
BAD  tweak_log_throttle                 rc=0 (want 0) sha256=d59cd9fd7d8be99c390a569e1c7430af0b37a8023433fc4beaf5806b530653ab
host verification: 11 ok, 1 drift
```

- which is also an independent confirmation of the real hash, since the BAD line
  prints what the run actually produced. The mutation is reverted immediately:
  `sha256(scripts/check_host_verification.sh)` is
  `f07be539ae4fb220b788c8fa34a09e5f5e6409318c629a8e2f8994ee36c0cda0` as of entry 20.

### HARD RULE compliance

- HARD RULE 1 (no exploit, no device command): every command above compiles C with
  the host `cc`, runs a Python source lint, or runs the Theos cross-build. `ssh` was
  never called, `scripts/regression.sh` was still never run whole (its "Live device
  smoke" section reads `.w0lfsword/active_device` and would `ssh root@$DEV_IP`), and
  no `idevice*` binary was invoked.
- HARD RULE 2 (no git commit/push/checkout): no git write command was used; the tree
  is left modified on purpose, with the new files untracked.
- HARD RULE 3 (no deletion): nothing was deleted. The new logs went to a NEW
  subdirectory (`docs/verification/2026-09-11-0.12/t12/`) so the earlier pass's logs
  stay where they were.

### What this does and does not cover

Does: the host-visible halves of all six items - BUG.1 (the 0x20 block at +0x50 of a
0x60 object refused, restore policy per exit, 116 + 56 checks), BUG.2 (the leak/cancel
half: per-exit release tracing, 56 + 25 checks), BUG.3 (the budget default and the
app row reaching the engine, 25 checks + a link-level `bl`), BUG.4 (the visible CANCEL
and its release path, 25 checks + the app's `nm`/disassembly + strings), BUG.5 (the
measured write counter and no shipped "zero writes" string, 53 + 25 checks), BUG.6
(the throttle: 30 checks counting the fsyncs, 4 structural checks, 5 mutations, and
the triage document that was missing).

Does not: any device behaviour. Nothing here was run on a phone. The throttled
fsync's BYTES are still unmeasured on the host (the gate bounds the calls, not the
bytes each call flushes), the staged probe's on-device restore is still unconfirmed,
and the memory-pressure half of BUG.2 (dirtying ~30 MB of mappings per pass plus the
~22.5k-socket spray) is still a documented option rather than a patch. Readonly stays
the only mode offered on unproven device/iOS pairs.

---

## T12b - the two halves the critic named as "no artifact attached"

Same day, same session, after the round-1 critique of T12. Two items were marked
done with a note where the task asks for an artifact: BUG.1's option 2 (probe a
field with no concurrent reader) and BUG.2's remaining half (the pressure sources
the item itself says need a technique decision). Both now have a host check, and
one of them produced a correction.

### New: `scripts/check_pressure_budget.py` (7 checks + 7 mutations, selftested)

| # | command | exit | sha256 | bytes | why |
|---|---------|------|--------|-------|-----|
| 21 | `python3 scripts/check_pressure_budget.py` | 0 | `e8b2e91222630ad27d8d079e430d0ee923ede3aa930c91c6e52fa5c88cd488a5` | 1689 | the artifact for BUG.1 option 2 + BUG.2's remaining half |
| 22 | `python3 scripts/check_pressure_budget.py --selftest` | 0 | `7b0311fd7ba89485dc9c5da93da9d843d98c9d2270a5aeaf6baa15b8d68a71ff` | 18482 | proves the 7 checks can fail |

What it checks, all against the shipped sources (never against a copy):

1. `BUG.1 probe field: nothing in the shipped code consumes the probed qword` -
   scans the engine archive's `SOURCES=` list plus every local header they include
   plus the app's sources for `send`/`sendto`/`recv`/`recvfrom`/`sendmsg`/`recvmsg`
   (0 found), and requires the probe to preserve the qword at `filtOffset + 8`.
2. `BUG.1 probe field: the probe body does not touch the icmp6 filter pointer` -
   brace-scopes `find_and_corrupt_socket_probe()` and requires no write to the
   `inp6_icmp6filt` field inside it, the chksum save line (`filt + 8`, not `filt`),
   and a clamped put-back.
3. `BUG.2 pressure: every page of every search mapping is still marked` - both
   per-page marker loops (pe_v1, pe_v2), counted with ONE pattern so removing a loop
   drops the count.
4. `BUG.2 pressure: the mapping arithmetic is pinned` - parses the ternaries, the
   `physmem / 8` scaling and the two floors, then compares the derived
   pages/mapping-count for 3/4/6/8 GB and the A18 branch against pinned values.
5. `BUG.2 pressure: the up-front spray bound is pinned` - derives
   `OPEN_MAX * 3 - 4096 * 2` = 22528 from the source.
6. `BUG.2 pressure: the per-cycle release funnel is still what bounds the peak` -
   bounded window after `mach_vm_allocate failed!!!` (900 chars, so a later funnel
   call cannot satisfy it) plus the cycle cap.
7. `every source this check reads exists`.

Selftest mutations, all seven caught: default page count x4, mapping size changed,
marker write limited to one page, spray bound grown, a `send()` added, the probe
preserving `filt` instead of `filt + 8`, and the allocate-failure path skipping the
funnel. Two of them were NOT caught on the first run and the check was fixed rather
than the mutation weakened (the marker count had matched the same loop twice through
two alternate patterns, and the funnel lookahead was unanchored); one mutation had a
stale anchor and was retargeted at the real save line.

### The correction that fell out of it

The script prints the search-space table the source computes:

```
3 GB    98304 page(s)  384 MB total  12 x  32.0 MB mapping(s)
4 GB   131072 page(s)  512 MB total  16 x  32.0 MB mapping(s)
6 GB   196608 page(s)  768 MB total  24 x  32.0 MB mapping(s)
8 GB    65536 page(s)  256 MB total   8 x  32.0 MB mapping(s)
```

so ROADMAP 0.12 `BUG.2`'s "~30 MB mapped and dirtied per pass" is wrong by an order
of magnitude: the 3 GB SE2 class gets 384 MB per cycle (12 x 32 MB), which is also
what the engine's own comment says on the allocate-failure path. Recorded as a
marked correction inside the item (the original figure is left in place so the wrong
number stays traceable), and `docs/verification/2026-09-11-0.12/t12/BUG-EVIDENCE.md`
carries the table.

### Wiring and re-pins this pass

- `scripts/regression.sh` gained a `check_pressure_budget.py` block in the BUG.1/BUG.2
  host section (host-only, same reasoning as the rest).
- `scripts/check_host_verification.sh` gained the two checks and now compiles the new
  script in its `py_compile` entry; it reported `12 ok, 2 drift` on the first run
  after the addition, and both drifts were the two new entries' own pins (filled in
  with the values printed by that run, `e8b2e912...` / `7b0311fd...`).
- `docs/verification/2026-09-11-0.12/t12/BUG-EVIDENCE.md` is new: per-item quote ->
  change -> one command -> observed output, so each item can be checked on its own.

### HARD RULE compliance (this pass)

No exploit, no device command, no `ssh`, no `idevice*` binary. No git write command.
Nothing deleted: the new logs and the index were added under the existing
`docs/verification/2026-09-11-0.12/t12/` directory.

---

## T13 - BUG.1 end to end: the overrun clamp + the restore path, host-verified

Recorded 2026-09-11T23:36-23:38+02:00 (task 13/14). Scope: close BUG.1 (`W0lfSword`
`ROADMAP.md:450`) with the one artifact it did not yet have - a host test that
INJECTS the 32-byte overrun and then drives the staged write probe's whole
sequence (save -> corrupt -> exit -> put-back) through the clamp, on the two
exits the item names: the error exit (write-verify exhaustion, `-1`) and the
cancel/budget exit (`-7`), including the shape where `pe_v1`'s release funnel has
already emptied the spray tracking array. The three code steps of the item were
already in the tree from the earlier tasks; nothing about the engine changed in
this pass except the tests, the two suite wirings and the checklist note.

The item, quoted (`W0lfSword/ROADMAP.md:450-459`):

> `BUG.1` - **the staged write probe panics the device.** A 32-byte write from
> `early_kwrite32bytes` (via `kwrite_zone_element`'s backward-shifted RMW) lands
> past the end of a kalloc.96 object -> `zalloc.c:1322` zone bound check ->
> panic. ... Fix: (1) restore the saved values unconditionally on every path, not
> only after a successful read-back; (2) probe a field with no concurrent reader
> (`so_usecount` / `inp_depend6_chksum`) or a scratch object we own, never the
> icmp6 filter pointer the kernel dereferences on the next packet; (3) clamp the
> writer so a 32-byte block that is not provably inside the target object is
> refused.

### What changed in the tree (no device, no git write command)

| # | change | file(s) |
|---|--------|---------|
| 1 | the end-to-end host test: the overrun injected, then the probe's save -> corrupt -> exit -> put-back sequence, on the `-1` and `-7` exits | `tests/probe_restore_e2e_host_test.c` (new, 543 lines) |
| 2 | its runner - compiles the REAL `kexploit/krw_zone_write.c` + `kexploit/probe_restore_policy.c`, host `cc` only | `scripts/run_probe_restore_e2e_host_test.sh` (new) |
| 3 | its selftest: four mutations on TEMP COPIES of those two engine sources, each required to make the harness fail (so a green run cannot be vacuous) | `scripts/probe_restore_e2e_selftest.py` (new) |
| 4 | both registered in the standing BUG.1 section (host-only, same shape as the existing entries) | `scripts/regression.sh` |
| 5 | both registered in the host-verification suite, with their output hashes pinned; the new `.py` added to `py_compile`, the new `.sh` to `bash -n` | `scripts/check_host_verification.sh` |
| 6 | the per-item index gains the new one-command artifact for `BUG.1` | `docs/verification/2026-09-11-0.12/t12/BUG-EVIDENCE.md` |
| 7 | a closing note on the item itself (host-verified only, still no device run) | `ROADMAP.md` (this repo) |

What is REAL in the new harness: the clamp (`krw_zone_write.c`, steps 3/3b) and
the restore contract (`probe_restore_policy.c`, step 1) - the two files the engine
archive is built from, compiled here with no stubs. What is the TEST's own model:
the fake kernel window, and `probe_restore_model()`, which is the engine's restore
loop (`kexploit/kexploit_opa334.m:1820-1927`; its write-then-verify loop is
`1873-1917`) reduced to its decisions and its
write order (the `+8` qword first, the filter pointer last). Every decision inside
it comes from the two real files; a refusal or an unreachable fd pair is returned
as a FAILED restore, never as a silent success.

### Command table (cwd `/home/kaffein/Desktop/W0lfSword` unless noted)

`.../t13/` = `docs/verification/2026-09-11-0.12/t13/`. `raw` = the sha256 of the
command's complete stdout+stderr as saved (bytes in the next column).

| # | command | exit | sha256 (stdout+stderr) | bytes | raw log |
|---|---------|------|------------------------|-------|---------|
| 1 | `bash scripts/run_probe_restore_e2e_host_test.sh` | 0 | `62f760e7402071fcb823a7ec5191904e098ac6b520907ef13135ba6fa729cf4b` | 4830 | `.../t13/probe_restore_e2e.log` |
| 2 | `python3 scripts/probe_restore_e2e_selftest.py --selftest` | 0 | `97e2173af1a31a7e57ebcfb20289a524b99f1b74723faee2507578c38840a935` | 852 | `.../t13/probe_restore_e2e_selftest.log` |
| 3 | `bash scripts/run_krw_zone_write_host_test.sh` (the sibling harness, unchanged) | 0 | `1386b0b6e393b4923dc3ad9cd69547b8e9471e78f2c904688b5a09cc3b0ea5be` | 7492 | `.../t13/krw_zone_write.log` |
| 4 | `bash scripts/check_host_verification.sh` | 0 | `e202a8fa8f0822dee82c48bd2b2c4e1a112a24b8c4f84d10f863421ec81338e9` | 1378 | `.../t13/host_suite.log` |
| 5 | `./W0lfSword audit` | 0 | not byte-stable (spinner frames) - see the note below | 1135 | `.../t13/audit.log` |
| 6 | the BUG.1 section of `scripts/regression.sh`, run alone through all three of its paths (in-repo / scripts absent / the two new scripts stubbed to exit 1) | 0, 0, 0 | in-repo `7bf73e02cbb294be85aa3e2fe2f866bbefb24b844dbcbb1c9d5ea0614a7ab26b`, absent `95de928b681c0eb4091f46cccf0b20ade114720dc2d9b9942461efeb784c8569`, failing `f84000b81fb87a6ffc92d44fe50baa4a7a09e122c9bf12c7410a70519038b902` | 665 / 667 / 722 | `.../t13/regression_bug1_section.repo.log`, `.../t13/regression_bug1_section.absent.log`, `.../t13/regression_bug1_section.failing.log` |

`--with-builds` was NOT used for entry 4: it re-runs the Theos cross-builds, which
belong to the scheduler/build task and not to this one; the suite's host half is
what this item's claims rest on. Entry 5's hash moves between runs because the
audit prints a spinner whose frame count varies; the stable part is quoted below.

### Raw command + output, entry 1 (`bash scripts/run_probe_restore_e2e_host_test.sh`)

```
probe_restore_e2e_host_test (BUG.1: the 32-byte overrun clamp + the restore path, end to end)

1. the 32-byte overrun (the SE panic) is injected and refused:
  ok   control: the harness counts a raw 32-byte write at +0x50 of a 0x60 object (the SE overrun)
  ok   injected overrun (0x20 at +0x50 of 0x60) is REFUSED
  ok   the refusal emitted no block and no RMW read
  ok   the refused overrun changed no kernel byte
  ok   the refusal is logged with the block and the object bounds
  ok   the qword shape at the same address is allowed (block +0x40..+0x60)
  ok   it emits the aligned block +0x40..+0x60, wholly inside the 0x60 object
  ok   the first qword past the object end is refused
  ok   and it emits no block either
  ok   and the refusal says the object does not contain the target

2. the probe's save -> corrupt -> exit -> put-back sequence, on ERROR:
  ok     18.x/26.x (filt 0x148, chksum 0x150): the probe's marker write is inside the declared window
  ok     ... and the marker is in the object (the corruption is live)
  ok     exit -1 (write-verify exhaustion) restores
  ok     ... through the spray tracking array (it still holds the pair)
  ok     ... and the saved values are back in the object (read back, not assumed)
  ok     ... both fields byte-identical to the saved values (marker gone)
  ok     ... the put-back emitted exactly the two blocks (one per qword)
  ok     ... and not one of them left the declared inpcb window
  ok     ... the qword before the first put-back field was not touched
  ok     17.0-17.7.x (filt 0x150, chksum 0x158): the probe's marker write is inside the declared window
  ok     ... and the marker is in the object (the corruption is live)
  ok     exit -1 (write-verify exhaustion) restores
  ok     ... through the spray tracking array (it still holds the pair)
  ok     ... and the saved values are back in the object (read back, not assumed)
  ok     ... both fields byte-identical to the saved values (marker gone)
  ok     ... the put-back emitted exactly the two blocks (one per qword)
  ok     ... and not one of them left the declared inpcb window
  ok     ... the qword before the first put-back field was not touched

3. the same sequence on CANCEL (-7), including after the spray array was released:
  ok   cancel (-7) restores (it is not the promotion)
  ok   cancel in the write-verify loop: the pair is re-opened from the array and the values go back
  ok   cancel: both fields are byte-identical to the saved values again
  ok   cancel after the array was released: the promotion's fds are used (not UNREACHABLE)
  ok   cancel after the release funnel: the saved values still go back (BUG.1's 'one exit later')
  ok   cancel with no usable fd pair: the restore writes NOTHING (no write through a foreign socket)
  ok     ... and it reports a FAILED restore, never a silent success
  ok     ... the field is still corrupted, which is what the failure report says

4. the promotion is handed over, not restored:
  ok   the promotion (0) is handed to the caller
  ok     ... and this path issues no put-back at all (the corrupted socket IS the primitive)

5. the clamp covers the restore's own put-back (step 3b):
  ok   the restore is attempted (its fd pair is live) with the kalloc.96 bucket declared
  ok     ... and it is reported as a FAILED restore, never as a written one
  ok     ... not one block was emitted for the put-back (refused, not written unproven)
  ok     ... no kernel byte changed anywhere in the window
  ok     ... and the refusal names the missing declaration
  ok   a window that cuts the put-back's aligned block: refused, no block, no restore claimed
  ok     ... the refusal names the block and the object it would leave
  ok     ... and no kernel byte changed
  ok   the same put-back under the engine's field-derived window does go back
  ok     ... with every block and RMW read inside the declared window

6. the declared window is derived from the field offsets:
  ok   18.x/26.x (filt 0x148, chksum 0x150): the declared window is 0x160 (field end rounded up)
  ok   18.x/26.x (filt 0x148, chksum 0x150): both put-back qwords share one 0x20-aligned block
  ok   18.x/26.x (filt 0x148, chksum 0x150): the declared window contains both put-back qwords
  ok   18.x/26.x (filt 0x148, chksum 0x150): the 32-byte block holding them ends inside the window (no refusal)
  ok   17.0-17.7.x (filt 0x150, chksum 0x158): the declared window is 0x160 (field end rounded up)
  ok   17.0-17.7.x (filt 0x150, chksum 0x158): both put-back qwords share one 0x20-aligned block
  ok   17.0-17.7.x (filt 0x150, chksum 0x158): the declared window contains both put-back qwords
  ok   17.0-17.7.x (filt 0x150, chksum 0x158): the 32-byte block holding them ends inside the window (no refusal)

checks=56 failures=0
PROBE_RESTORE_E2E_HOST_TEST PASS
(exit 0)
```

The first check of block 1 is the detector check: the harness writes the SE's own
out-of-object block straight through the primitive and REQUIRES its counters to
fire, so "the overrun was refused" is a measurement and not an absence of
evidence. The block-1 last checks pin the one asymmetry that is easy to miss: the
32-byte shape at `+0x50` is refused (that is the panic), while the qword shape at
the same address is allowed - its 0x20-ALIGNED block is `+0x40..+0x60`, wholly
inside the object. That is what makes the probe's own put-back at that address
legal after step 3b, and it is why the fix is a block clamp and not a ban on the
address.

### Raw command + output, entry 2 (`python3 scripts/probe_restore_e2e_selftest.py --selftest`)

```
PASS  selftest baseline: the harness passes on the unmutated sources
PASS  selftest: the harness rejects - the clamp's block-end refusal removed (krw_zone_write_qword) first failure: FAIL a window that cuts the put-back's aligned block: refused, no block, no restore claimed
PASS  selftest: the harness rejects - the writer's default deny removed (an undeclared qword is emitted) first failure: FAIL the first qword past the object end is refused
PASS  selftest: the harness rejects - the cancel/budget exit handed off instead of restored first failure: FAIL cancel (-7) restores (it is not the promotion)
PASS  selftest: the harness rejects - the promotion-fd fallback removed (the staged exit writes nothing back) first failure: FAIL cancel after the array was released: the promotion's fds are used (not UNREACHABLE)

selftest: all mutations caught
(exit 0)
```

Each mutation is written to a TEMP COPY (`kexploit/krw_zone_write.c` /
`kexploit/probe_restore_policy.c`); no repo file is modified. The four are the
item's own regressions: the clamp's block-end refusal, the writer's default deny,
the cancel exit no longer restoring, and the promotion-fd fallback that BUG.1's
"one exit later" bug was.

### Raw command + output, entry 6 (the `regression.sh` BUG.1 section, all three paths)

The section hosts five commands (the writer clamp, the end-to-end harness, its
selftest, the release-path lint, the pressure/field-choice lint). Three runs of
it prove that its skip branch and its failure branch are wired to a real result
and not to a tick that is printed regardless:

```
$ D=/tmp/reg_$(date +%s)
$ mkdir -p "$D/absent" "$D/fail/scripts"
$ awk 'NR<=101' scripts/regression.sh \
      | grep -v 'cd "$(dirname "$0")/\.\." || exit 1' > "$D/reg_bug1_section.sh"   # 100 lines, through the BUG.1 section
$ printf '#!/bin/sh\nexit 1\n' > "$D/fail/scripts/run_probe_restore_e2e_host_test.sh"
$ printf '#!/bin/sh\nexit 1\n' > "$D/fail/scripts/probe_restore_e2e_selftest.py"
$ chmod +x "$D"/fail/scripts/*

$ (cd /home/kaffein/Desktop/W0lfSword && bash "$D/reg_bug1_section.sh") > repo.log    2>&1; echo $?   # 0
$ (cd "$D/absent"                   && bash "$D/reg_bug1_section.sh") > absent.log  2>&1; echo $?   # 0
$ (cd "$D/fail"                     && bash "$D/reg_bug1_section.sh") > failing.log 2>&1; echo $?   # 0
```

Raw stdout of the three runs, whole, in order (the `✗` lines for syntax/offsets in
the second and third runs are the section's own probes failing against a tree
that is not there, which is the point of those two runs; ANSI escapes stripped
here, the bytes are in `.../t13/regression_bug1_section.{repo,absent,failing}.log`):

```
$ (cd /home/kaffein/Desktop/W0lfSword && bash "$D/reg_bug1_section.sh")
== Shell syntax ==
  ✓ bash -n on all scripts

== Python syntax ==
  ✓ py_compile on all .py

== Offset table tests (D2.1) ==
  ✓ test_offsets.py

== Chain selector golden grid (AUD.6) ==
  ✓ test_chain_select.sh

== BUG.1 host tests (zone-writer clamp + probe restore policy) ==
  ✓ krw_zone_write_host_test (116 checks)
  ✓ probe_restore_e2e_host_test (56 checks)
  ✓ probe_restore_e2e_selftest.py (4 mutations rejected)
  ✓ check_bug2_release_paths.py (56 checks)
  ✓ check_pressure_budget.py (7 checks)

$ (cd "$D/absent" && bash "$D/reg_bug1_section.sh")
== Shell syntax ==
  ✗ bash -n
...
== BUG.1 host tests (zone-writer clamp + probe restore policy) ==
  run_krw_zone_write_host_test.sh missing — skipping
  run_probe_restore_e2e_host_test.sh missing — skipping
  probe_restore_e2e_selftest.py missing — skipping
  check_bug2_release_paths.py missing — skipping
  check_pressure_budget.py missing — skipping

$ (cd "$D/fail" && bash "$D/reg_bug1_section.sh")
== BUG.1 host tests (zone-writer clamp + probe restore policy) ==
  run_krw_zone_write_host_test.sh missing — skipping
  ✗ run_probe_restore_e2e_host_test.sh — see /tmp/regression_probe_restore.log
  ✗ probe_restore_e2e_selftest.py — see /tmp/regression_probe_restore_self.log
  check_bug2_release_paths.py missing — skipping
  check_pressure_budget.py missing — skipping
```

`...` above stands for the four section blocks that are identical to the first
run's and are only printed as `✗` against an empty tree; the raw files carry them
whole. `$D/reg_bug1_section.sh` is a temp copy of `scripts/regression.sh` lines
1-101 (through the BUG.1 section) with its `cd $(dirname $0)/..` line dropped, so
the caller's cwd decides which tree the section looks at - nothing in the repo was
moved or deleted to produce the "absent" and "failing" rows, and each run's exit
status is the section's own (0: the skip and the failure branches do not set the
temp copy's exit code, they set its printed result). The whole `regression.sh` was
NOT run: its last section reads `.w0lfsword/active_device` and would `ssh` to
whatever it names. Its BUG.1 commands were run directly (entries 1-3 above).

This entry first carried a hand-assembled three-part text under the single name
`regression_bug1_section.log`; it matched no single run of the section (it
predated the check_bug2/pressure_budget entries the section has since grown) and
its hash was therefore not reproducible from the tree. The file now holds the
in-repo run verbatim and the other two paths have their own raw files, each with
the hash in the table above.

### Raw output, entry 4 (`bash scripts/check_host_verification.sh`)

```
host verification suite - cwd=/home/kaffein/Desktop/W0lfSword
raw logs: /tmp/w0lf_host_verification

ok   krw_zone_write                     rc=0 1386b0b6e393b492... (7492 bytes)
ok   probe_restore_e2e                  rc=0 62f760e7402071fc... (4830 bytes)
ok   probe_restore_e2e_self             rc=0 97e2173af1a31a7e... (852 bytes)
ok   kwrite_counter                     rc=0 1dc9c1d4b0e35b86... (2629 bytes)
ok   tweak_log_throttle                 rc=0 d59cd9fd7d8be99c... (2873 bytes)
ok   scan_budget_cancel                 rc=0 4dc5246d0662e7df... (2161 bytes)
ok   scan_budget_cancel_self            rc=0 e24a0f3e9a1e9bc7... (46714 bytes)
ok   bug2_release_paths                 rc=0 1df3ce4c11439d92... (7170 bytes)
ok   bug2_release_paths_self            rc=0 03bc081c48798f73... (4768 bytes)
ok   test_offsets                       rc=0 eead34fbfc466f96... (552 bytes)
ok   pressure_budget                    rc=0 e8b2e91222630ad2... (1086 bytes)
ok   pressure_budget_self               rc=0 7b0311fd7ba89485... (9763 bytes)
ok   test_chain_select                  rc=0 9a596a45ef210f9b... (2129 bytes)
ok   trm_shell_host_test                rc=0 42305c27487f35be... (15415 bytes)
ok   py_compile                         rc=0 e3b0c44298fc1c14... (0 bytes)
ok   bash_syntax                        rc=0 e3b0c44298fc1c14... (0 bytes)

host verification: 16 ok, 0 drift
(exit 0)
```

Every hash in that output was reproduced byte-for-byte on a second run (checked:
`/tmp/suite2.log` and `.../t13/host_suite.log` hash to the same
`e202a8fa8f0822dee82c48bd2b2c4e1a112a24b8c4f84d10f863421ec81338e9`). The two new
entries are the only additions; the fourteen pre-existing pins did not move,
which is the check that this pass added tests without changing shipped code.

### Raw output, entry 5 (`./W0lfSword audit`), stable lines only

```
  ✓ kexploit/kexploit_opa334.m
  ✓ W0lfSword (shellcheck clean)
  ✓ W0lfSword (dead-fn scan: 178 defs, 0 dead)
  ✓ repo scripts (56 shell/python files parse)
  ✓ W0lfSword (CLI consistency: 50 commands, registry = dispatch = menu = help)

  ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓  AUDIT PASSED
(exit 0)
```

The full run's first lines (the "not running as root" hint and the spinner) are in
`.../t13/audit.log`; they are the reason entry 5 has no pinned hash. The audit's
shellcheck step covers the main CLI script only (`-s bash -e SC2059 W0lfSword`);
run by hand over the three scripts this pass touched it reports nothing for the
new runner and one pre-existing SC2012 info at `scripts/regression.sh:152`
(`ls -t packages/*.deb | head -1`), a line this pass did not write.

### What this pass does NOT verify (plainly)

- Nothing on a device. No exploit was run, no `idevice*` binary, no `ssh`. The
  clamp and the restore are verified as code; the SE run that would confirm the
  on-device restore is still the next device day, and `readonly` stays the only
  mode offered on unproven device/iOS pairs.
- The harness drives the two real engine sources, not the engine. The restore
  loop around them (`probe_restore_model()`) is the test's model of
  `kexploit_opa334.m:1820-1927` (its write-then-verify loop at `1873-1917`); if
  that loop is rewritten on device, this file
  has to be re-read against it (`scripts/check_pressure_budget.py` and
  `scripts/check_bug2_release_paths.py` are what read the engine source itself).
- The window the clamp is given is still the inpcb FIELD span, not the kalloc
  bucket size - the residual BUG.7 records in the 0.13 section. The harness pins
  that (block 5: a declaration that is too small is refused, and the field-derived
  one is accepted), it does not close it.

### Re-verification pass (task 13/14, same night, second pass)

Every hash in the table above was reproduced from the tree with the recorded
command, byte for byte, on a second pass. Nothing in `kexploit/` changed in this
pass; the only source edit is a comment in `tests/probe_restore_e2e_host_test.c`.

| # | command re-run | exit | sha256 reproduced | matches the recorded log |
|---|----------------|------|-------------------|--------------------------|
| 1 | `bash scripts/run_probe_restore_e2e_host_test.sh` | 0 | `62f760e7402071fcb823a7ec5191904e098ac6b520907ef13135ba6fa729cf4b` | yes, byte-identical |
| 2 | `python3 scripts/probe_restore_e2e_selftest.py --selftest` | 0 | `97e2173af1a31a7e57ebcfb20289a524b99f1b74723faee2507578c38840a935` | yes, byte-identical |
| 3 | `bash scripts/run_krw_zone_write_host_test.sh` | 0 | `1386b0b6e393b4923dc3ad9cd69547b8e9471e78f2c904688b5a09cc3b0ea5be` | yes, byte-identical |
| 4 | `bash scripts/check_host_verification.sh` | 0 | `e202a8fa8f0822dee82c48bd2b2c4e1a112a24b8c4f84d10f863421ec81338e9` | yes, byte-identical (`16 ok, 0 drift`) |
| 6 | the BUG.1 section, three paths | 0, 0, 0 | `7bf73e02...`, `95de928b...`, `f84000b8...` | yes (the three logs listed in the table) |

Two corrections to the record came out of that pass, both in this file:

1. entry 6's log was a hand-assembled three-part text whose hash did not
   reproduce from any run of the section (the section has since grown the
   `check_bug2_release_paths.py` and `check_pressure_budget.py` entries, which
   that text predated). It is now the in-repo run verbatim, with the "scripts
   absent" and "stubbed to exit 1" paths in their own raw files and their own
   hashes, and the temp-copy line range and commands spelled out in entry 6.
2. the cited engine line range for the modelled restore loop was off by a
   couple of lines: the restore helper is `kexploit_opa334.m:1820-1927` and its
   write-then-verify loop is `1873-1917` (a comment fix - the harness output hash
   is unchanged, as the table above shows).

Still true after this pass, and repeated because it is the item's whole point:
no exploit was run, no `idevice*` binary was invoked, no `ssh`, and no git
command other than read-only `git status` / `git check-ignore`. Nothing was
committed, pushed, checked out or deleted; all changes stay in the working tree.

### Third pass (task 13/14, closing round): every artifact re-run + the engine link check

Same tree, no source edit in this pass (the only write is this record and the new
raw log in `.../t13/engine_link_check.log`). What the pass adds to the record is
the half the earlier passes asserted from prose: that the clamp and the restore
policy are actually IN the linked engine archive, and that all four host
commands still reproduce the pinned bytes.

| # | command (cwd `/home/kaffein/Desktop/W0lfSword`) | exit | sha256 of stdout+stderr | vs. the pinned log in `.../t13/` |
|---|--------------------------------------------------|------|-------------------------|----------------------------------|
| 1 | `bash scripts/run_probe_restore_e2e_host_test.sh` | 0 | `62f760e7402071fcb823a7ec5191904e098ac6b520907ef13135ba6fa729cf4b` | `diff` exit 0 - byte-identical to `probe_restore_e2e.log` |
| 2 | `python3 scripts/probe_restore_e2e_selftest.py --selftest` | 0 | `97e2173af1a31a7e57ebcfb20289a524b99f1b74723faee2507578c38840a935` | `diff` exit 0 - byte-identical to `probe_restore_e2e_selftest.log` |
| 3 | `bash scripts/run_krw_zone_write_host_test.sh` | 0 | `1386b0b6e393b4923dc3ad9cd69547b8e9471e78f2c904688b5a09cc3b0ea5be` | `diff` exit 0 - byte-identical to `krw_zone_write.log` |
| 4 | `bash scripts/check_host_verification.sh` | 0 | `e202a8fa8f0822dee82c48bd2b2c4e1a112a24b8c4f84d10f863421ec81338e9` | `diff` exit 0 - byte-identical to `host_suite.log` (`16 ok, 0 drift`) |
| 5 | `python3 scripts/check_bug2_release_paths.py` | 0 | - | `56 check(s) passed, 0 failed` |
| 6 | `python3 scripts/check_pressure_budget.py` | 0 | - | `7 check(s) passed, 0 failed`, `PRESSURE_BUDGET LINT PASS` |
| 7 | the BUG.1 section, all three paths | 0, 0, 0 | `7bf73e02...`, `95de928b...`, `f84000b8...` | reproduced byte-identically in a fresh `mktemp -d` run (see below) |
| 8 | `THEOS=$HOME/theos make libengine` | 0 | - | `OK: .theos/libengine/libw0lfengine.a (804K, 52 objects)` |

Entry 1's raw output is the block published above in this section
("Raw command + output, entry 1"); the third pass re-produced exactly those
bytes, which is what the `diff` column says, so it is not re-pasted here. Entry 7
was re-run from a fresh temp copy:

```
$ D=$(mktemp -d /tmp/reg_check.XXXXXX); mkdir -p "$D/absent" "$D/fail/scripts"
$ awk 'NR<=101' scripts/regression.sh \
      | grep -v 'cd "$(dirname "$0")/\.\." || exit 1' > "$D/reg_bug1_section.sh"   # 100 lines
$ printf '#!/bin/sh\nexit 1\n' > "$D/fail/scripts/run_probe_restore_e2e_host_test.sh"
$ printf '#!/bin/sh\nexit 1\n' > "$D/fail/scripts/probe_restore_e2e_selftest.py"
$ chmod +x "$D"/fail/scripts/*
$ (cd /home/kaffein/Desktop/W0lfSword && bash "$D/reg_bug1_section.sh") > "$D/repo.log"    2>&1; echo $?   # 0
$ (cd "$D/absent"                   && bash "$D/reg_bug1_section.sh") > "$D/absent.log"  2>&1; echo $?   # 0
$ (cd "$D/fail"                     && bash "$D/reg_bug1_section.sh") > "$D/failing.log" 2>&1; echo $?   # 0
7bf73e02cbb294be85aa3e2fe2f866bbefb24b844dbcbb1c9d5ea0614a7ab26b  "$D/repo.log"
95de928b681c0eb4091f46cccf0b20ade114720dc2d9b9942461efeb784c8569  "$D/absent.log"
f84000b81fb87a6ffc92d44fe50baa4a7a09e122c9bf12c7410a70519038b902  "$D/failing.log"
repo: IDENTICAL   absent: IDENTICAL   failing: IDENTICAL      # diff against .../t13/regression_bug1_section.*.log
```

Entry 8 is the new artifact, `.../t13/engine_link_check.log` (947 bytes, sha256
`419b886fb1c840eb536118dfd3f453226cf51b884297d17a43fa39ecc264f072`), raw:

```
$ THEOS=$HOME/theos make libengine
bash scripts/build_libengine.sh
OK: .theos/libengine/libw0lfengine.a (804K, 52 objects)
exit=0

$ llvm-nm-19 .theos/libengine/libw0lfengine.a | grep -E "krw_zone_write_qword|kwrite_zone_element_qword|probe_exit_action_for|probe_restore_fd_source|krw_zone_window_for_field_end|krw_zone_block_align_down|krw_zone_write\b"
                 U _krw_zone_window_for_field_end
                 U _kwrite_zone_element_qword
                 U _probe_exit_action_for
                 U _probe_restore_fd_source
                 U _krw_zone_write
                 U _krw_zone_write_qword
0000000000000a14 T _kwrite_zone_element_qword
kexploit_krw_zone_write.c.o:
00000000000000cc T _krw_zone_block_align_down
00000000000000e4 T _krw_zone_window_for_field_end
0000000000000338 T _krw_zone_write
000000000000074c T _krw_zone_write_qword
0000000000000000 T _probe_exit_action_for
0000000000000034 T _probe_restore_fd_source
```

Read: the archive DEFINES the clamp (`_krw_zone_write`, `_krw_zone_write_qword`,
`_krw_zone_block_align_down`, `_krw_zone_window_for_field_end`, from
`kexploit_krw_zone_write.c.o`), the engine wrapper (`_kwrite_zone_element_qword`,
`kexploit_krw.m.o`) and the restore policy (`_probe_exit_action_for`,
`_probe_restore_fd_source`, `kexploit_probe_restore_policy.c.o`), and
`kexploit_opa334.o` REFERENCES all of them (`U`). That is the link-level half of
"the probe's restore path is the shipped path", not just a host-test file that
happens to compile.

`/bin/nm` (binutils) cannot read these Mach-O objects (`file format not
recognized`, all 52 of them) - the theos/LLVM `llvm-nm-19` is what reads the
archive; the first attempt at this check printed nothing for that reason, which is
worth recording so the next pass does not read an empty grep as a missing symbol.

HARD-RULE compliance, this pass: no exploit, no `idevice*`, no `ssh`, no device
command of any kind - the four commands are host `cc`/`python3` and a Theos
cross-compile of the library, which touches no device. No `git add`, `commit`,
`push`, `checkout`, `reset` or file deletion; the working tree is as it was plus
this record and one log file.

---

## T14 - BUG.3 / BUG.4 / BUG.5 closed, and the KRW / TRM / W0lfTerm suites re-run from the working tree

2026-09-11T23:44-23:55+02:00. Scope, in the order the task gave it: (1) confirm the three
`BUG.3`-`BUG.5` deliverables are end to end in the working tree - a settable scan budget
(engine `kexploit_scan_budget` / `g_scanBudgetSec` plus the W0lfTerm SET row that consumes
it), a visible CANCEL whose cancel path releases the leaked search mapping and drains the
socket spray, and the "zero writes" claim removed or backed by a write-accounting check tied
to the 1 GB/day limit; (2) actually execute the host KRW, TRM and W0lfTerm build/test suites
from the working tree and record the commands with their full pass/fail output.

The engine and the app were NOT modified in this pass. The sources carrying those three
deliverables still carry the mtimes of the tasks that wrote them (`kexploit_opa334.m`
22:54, `kwrite_counter.c` 22:43, `term_bridge.m` 22:45, `TerminalViewController.m` 22:46,
`SettingsViewController.m` 22:46), and the linked app binary this pass produced is
byte-identical to the T12/T13 one (`sha256 2922ebb3c8138e6dcbd2efb95101afdceb26e409b83f8129d28bdb351eaf14c8`),
which is independent proof that neither tree's ObjC/C sources moved. What this pass adds to
the tree is one check and the record of the run; both are listed next.

### What changed (working tree)

| file | change | sha256 after |
|------|--------|--------------|
| `scripts/check_pressure_budget.py` | 8th check + 2 selftest mutations (details below) | `7e2ff88e8dd1ac9a8024e13b4a06cba76fb8d4d29c3b3458befb6038645e5dcb` |
| `scripts/check_host_verification.sh` | two expected hashes re-pinned (both moved because of the line above) + the comment that says why | `a35fd5f8e6783833d673de6994dc37b109d978a7d840bcb00bcef20090726878` |
| `docs/verification/2026-09-11-0.12/t14/` | raw logs of this pass: 29 files (28 logs + the extraction helper `extract_edges.py`) + `MANIFEST.txt` (sha256 + bytes for each) | see `MANIFEST.txt` |
| `docs/WORKLOG.md` | this entry | - |

Why the new check, i.e. what the task's third clause was missing: the two existing lints
already back the claim from both sides - `run_kwrite_counter_host_test.sh` counts the writes
the one primitive emits (`checks=53`), and the shared lint forbids any shipped string from
claiming "zero writes" - but neither did the arithmetic against the figure the device day was
measured on. The disk axis had a bound for the LOG half (`tweak_log_throttle_host_test.sh`,
`checks=30`, 3001 fsyncs for a 600 s run) and a pinned size for the SCAN half
(`check_pressure_budget.py`'s mapping arithmetic), and nothing put the two next to the
1 GB/day limit. The 8th check does exactly that, from parsed constants only:

    disk-write accounting (the report: 1073.75 MB in 1083 s, limit 1 GB/day):
      scan:  384 MB per cycle x 7 cycle(s) x 3 attempt(s) = 8064 MB dirtied per run (7.88x the limit)
      log:   600 s run, one fsync per 200 ms = at most 3001 fsync(s) (bytes per fsync are the log file's dirty pages - a device measurement)
      => the scan's per-page marker writes are the half over the limit; this round bounds the LOG half only (BUG.6), unchanged for the scan (BUG.2 residual)

It fails if `TWEAK_LOG_FSYNC_MIN_INTERVAL_MS`, `EXPLOIT_SCAN_BUDGET_SEC`,
`KEXPLOIT_SCAN_BUDGET_MAX`, the app's retry cap (`while (attempt < 3 ...)`), the engine's
cycle cap (`if (cycle > 6)`) or the 3 GB-class dirtied-bytes total move, so the ratio cannot
drift quietly; it does NOT claim the app fits the budget (the scan half does not, and the
printed table says so). The parse is comment-stripped on purpose: the first attempt read the
tree's own history comment (`the old hard-coded #define EXPLOIT_SCAN_BUDGET_SEC 120 lived
here`) and pinned 120 s, which is how a lint starts guarding the bug instead of the fix.

### Command table

`.../t14/` = `docs/verification/2026-09-11-0.12/t14/`. `raw` = sha256 of the command's
complete stdout+stderr as saved (bytes in the next column). Every command is host-only.

| # | command | cwd | exit | sha256 (stdout+stderr) | bytes | raw log |
|---|---------|-----|------|------------------------|-------|---------|
| 1 | `bash scripts/check_host_verification.sh --with-builds` | W0lfSword | 0 | `6c784f80e5069a521592ff77e13d354ffb15877a1784e023ce6160ca77069517` | 1731 | `.../t14/host_suite_with_builds.log` |
| 2 | `python3 scripts/check_pressure_budget.py` | W0lfSword | 0 | `91bd530e7bf386a527b9d56e01bae5812821c5a281315bd6ffd4c3ac3c29d549` | 1666 | `.../t14/pressure_budget.log` |
| 3 | `python3 scripts/check_pressure_budget.py --selftest` | W0lfSword | 0 | `98be7a751526bbd282f158c2d0522a78acedb4f8f8797d2f7f78217b534fe9ad` | 17515 | `.../t14/pressure_budget_selftest.log` |
| 4 | `python3 scripts/check_scan_budget_cancel_writes.py` (run by #1; log kept) | W0lfSword | 0 | `4dc5246d0662e7df01b483d7cb9e859244210c7f31cba283198d4c658547790d` | 2161 | `.../t14/suite/scan_budget_cancel.log` |
| 5 | `bash scripts/run_trm_host_test.sh` (run by #1; the TRM suite) | W0lfSword | 0 | `5e4d4909a97a0b40209d447d3fafa0dc5e8851fe510d120d579271ea4026aebb` | 15415 | `.../t14/suite/trm_shell_host_test.log` |
| 6 | the host half of `scripts/regression.sh` (lines 1-139, device section excluded, verdict tail appended) | W0lfSword | 0 | `956d4644791930e717857ab3d501ab3c18a3918264600cd3c42bc0f5e22e9023` | 1027 | `.../t14/regression_host_section.log` |
| 7 | `REBUILD_ENGINE=1 bash scripts/build_ipa.sh sideload 0.20` (engine archive rebuilt from the tree, then the app) | W0lfTerm | 0 | `6067fe89e5050ba8a64ea08beba7adf4368a82d6289db8dff2e73659e4dd714a` | 2308 | `.../t14/app_ipa_build_rebuild_engine.log` |
| 8 | `llvm-objdump-19 -d --macho dist/Payload/W0lfTerm.app/W0lfTerm` | W0lfTerm | 0 | `c2084cdfe1f782ebf5b328ffb353bfcab2d94dc3ed9b6472a45ffe232f6de275` | 2510338 | `.../t14/app_disassembly.txt` |
| 9 | the call-edge extraction over #8 (script preserved at `.../t14/extract_edges.py`, 4 named bodies) | W0lfSword | 0 | `4441c08397497f1877e4f48c544c96edba0db6a93f4dda3e700722ec43dfc825` | 1673 | `.../t14/w0lfterm_call_edges.log` |
| 10 | `llvm-nm-19` + `strings -a` on the built app binary | W0lfSword | 0 | `dafcd6f587e8cf5a32a163e36ab2a789aed7b05c7d4a9f5fbfe9533fec2c5fa0` | 1583 | `.../t14/w0lfterm_strings_and_symbols.log` |
| 11 | the TRM pass/fail lines extracted from #5 | W0lfSword | 0 | `ca98783ca85689e76c6cf26677282ece4c458a2de4f35aa3f39ee748859e5acd` | 4347 | `.../t14/trm_passfail.txt` |

Entry 6 is the T13 technique reused: `regression.sh` was NOT run whole (its last section
reads `.w0lfsword/active_device` and would `ssh root@<ip>` - the HARD RULE forbids that), so
lines 1-139 were extracted to a temp script with the `cd` line stripped, plus two appended
lines (`printf ... "$PASS" "$FAIL"` and `[ "$FAIL" -eq 0 ]`) so the log carries a verdict and
the exit status is that verdict, not the last `ok` helper's. Entry 7 rebuilds the engine
archive from the tree on purpose: without `REBUILD_ENGINE=1` the app build reuses whatever
`.theos/libengine/libw0lfengine.a` is lying around, which would prove the app links an
archive, not that it links THIS tree.

### Raw output, entry 1 (`bash scripts/check_host_verification.sh --with-builds`)

```
host verification suite - cwd=/home/kaffein/Desktop/W0lfSword
raw logs: /tmp/w0lf_host_verification

ok   krw_zone_write                     rc=0 1386b0b6e393b492... (7492 bytes)
ok   probe_restore_e2e                  rc=0 62f760e7402071fc... (4830 bytes)
ok   probe_restore_e2e_self             rc=0 97e2173af1a31a7e... (852 bytes)
ok   kwrite_counter                     rc=0 1dc9c1d4b0e35b86... (2629 bytes)
ok   tweak_log_throttle                 rc=0 d59cd9fd7d8be99c... (2873 bytes)
ok   scan_budget_cancel                 rc=0 4dc5246d0662e7df... (2161 bytes)
ok   scan_budget_cancel_self            rc=0 e24a0f3e9a1e9bc7... (46714 bytes)
ok   bug2_release_paths                 rc=0 1df3ce4c11439d92... (7170 bytes)
ok   bug2_release_paths_self            rc=0 03bc081c48798f73... (4768 bytes)
ok   test_offsets                       rc=0 eead34fbfc466f96... (552 bytes)
ok   pressure_budget                    rc=0 91bd530e7bf386a5... (1666 bytes)
ok   pressure_budget_self               rc=0 98be7a751526bbd2... (17515 bytes)
ok   test_chain_select                  rc=0 9a596a45ef210f9b... (2129 bytes)
ok   trm_shell_host_test                rc=0 42305c27487f35be... (15415 bytes)
ok   py_compile                         rc=0 e3b0c44298fc1c14... (0 bytes)
ok   bash_syntax                        rc=0 e3b0c44298fc1c14... (0 bytes)

ok   engine_lib_build                   rc=0 334a5c211aedbcef... (88 bytes)
ok   engine_lib_archive                 263ae60d49fd0c15...
ok   app_ipa_build                      rc=0 e4f7235f621013d6... (2282 bytes)
ok   app_binary                         2922ebb3c8138e6d...
ok   app_static_symbols                 rc=0 fd7a746a6f461d09... (943 bytes)

host verification: 21 ok, 0 drift
```

This is the run that shows the suite is not just green but RE-PRODUCIBLE: every hash in it
matches the one pinned in `check_host_verification.sh`, including the two this pass moved
(entries 11 and 12 → the re-pin above). `trm_shell_host_test` prints as `ok` here but its
hash is a CANONICALIZED one (live date/df/loadavg/pid masked) - the raw log for entry 5 is
the un-canonicalized run of the same command.

The per-check counts behind entries 1-5, from their own logs, are:
`krw_zone_write` 116 checks / 0 failures (`KRW_ZONE_WRITE_HOST_TEST PASS`),
`probe_restore_e2e` 56 / 0 (`PROBE_RESTORE_E2E_HOST_TEST PASS`),
`kwrite_counter` 53 / 0 (`KWRITE_COUNTER_HOST_TEST PASS`),
`tweak_log_throttle` 30 / 0 (`TWEAK_LOG_THROTTLE_HOST_TEST PASS`),
`scan_budget_cancel` 25 checks / 0 failed (`SCAN_BUDGET_CANCEL_WRITES LINT PASS`),
`trm_shell_host_test` `checks=108 failures=0` (`TRM_SHELL_HOST_TEST PASS`),
`bug2_release_paths` 56 checks / 0 failed, `pressure_budget` 8 checks / 0 failed
(`PRESSURE_BUDGET LINT PASS`), `test_chain_select` `26 passed, 0 failed`, and
`test_offsets` prints no per-check counter - its verdict line is
`PASS: thresholds strictly increasing, 4 critical offsets resolved at every threshold,
itk_space matches XPF-verified values` over its 8 version blocks.

### Raw output, entry 2 (the new check, in place)

```
BUG.1 probe field + BUG.2 pressure-source check (host only)
  engine root: /home/kaffein/Desktop/W0lfSword
  app root:    /home/kaffein/Desktop/W0lfTerm

  ok   every source this check reads exists
  ok   BUG.2 pressure: every page of every search mapping is still marked
       pressure report - pe_v1's search space, as the source computes it:
         3 GB    98304 page(s)     384 MB total  12 x  32.0 MB mapping(s)
         4 GB   131072 page(s)     512 MB total  16 x  32.0 MB mapping(s)
         6 GB   196608 page(s)     768 MB total  24 x  32.0 MB mapping(s)
         8 GB    65536 page(s)     256 MB total   8 x  32.0 MB mapping(s)
  ok   BUG.2 pressure: the mapping arithmetic is pinned (a constant change fails here)
  ok   BUG.2 pressure: the up-front spray bound is pinned
  ok   BUG.2 pressure: the per-cycle release funnel is still what bounds the peak
       disk-write accounting (the report: 1073.75 MB in 1083 s, limit 1 GB/day):
         scan:  384 MB per cycle x 7 cycle(s) x 3 attempt(s) = 8064 MB dirtied per run (7.88x the limit)
         log:   600 s run, one fsync per 200 ms = at most 3001 fsync(s) (bytes per fsync are the log file's dirty pages - a device measurement)
         => the scan's per-page marker writes are the half over the limit; this round bounds the LOG half only (BUG.6), unchanged for the scan (BUG.2 residual)
  ok   BUG.5/BUG.6 disk budget: the write accounting is pinned against the 1 GB/day limit
  ok   BUG.1 probe field: nothing in the shipped code consumes the probed qword
  ok   BUG.1 probe field: the probe body does not touch the icmp6 filter pointer

8 check(s) passed, 0 failed

PRESSURE_BUDGET LINT PASS
```

Entry 3 (the selftest, `--selftest`, temp copies of both trees' sources) reports
`selftest: all mutations caught` with 9 `ok mutation caught:` lines - the two new ones being
`the log sink's fsync window shrinks to 20 ms` and `the app's retry cap grows from 3 to 5
attempts`, i.e. one mutation per half of the accounting, so the check is provably not
vacuous on either side.

### Raw output, entry 4 (the BUG.3/BUG.4/BUG.5/BUG.6 end-to-end lint)

```
BUG.3 + BUG.5 + BUG.4 + BUG.6 end-to-end lint
  engine root: /home/kaffein/Desktop/W0lfSword
  app root:    /home/kaffein/Desktop/W0lfTerm

  ok   every source this lint reads exists
  ok   BUG.3 engine: the default budget is the one that fits the walk (600 s)
  ok   BUG.3 engine: the budget is settable and clamped, and every scan/spray loop reads it
  ok   BUG.3 engine: the cancel/budget check sits INSIDE each walk, not after it
  ok   BUG.4 engine: the socket spray honours a CANCEL (it is the longest pre-walk cost)
  ok   BUG.3 app: the default budget matches the engine default and is pushed in at load
  ok   BUG.3 app: a SET row exists, persists, and pushes every change into the engine
  ok   BUG.3 app: the boot banner reads the budget back from the ENGINE
  ok   BUG.5 counter: the module exists and exposes the measured getters
  ok   BUG.5 counter: the ONE write primitive counts both outcomes
  ok   BUG.5 counter: each entry point attributes its writes to its own route
  ok   BUG.5 engine: the counters reset per attempt, are exported, and are printed
  ok   BUG.5 app: the run log carries the measured number, not the claim
  ok   BUG.5: no shipped log/UI string claims 'zero writes' any more
  ok   BUG.4 app: a visible CANCEL control that is on only while a run is in flight
  ok   BUG.4 app: the tap reaches the engine stop flag through the one bridge
  ok   BUG.4 app: the run loop treats -7 as cancelled and STOPS (no retry)
  ok   BUG.4 engine pe_v1: the -7 cancel exit releases the spray AND the mappings
  ok   BUG.4 engine pe_v1: every -7 exit goes through the funnel (no cancel exit leaks)
  ok   BUG.4 engine pe_v2: the aborted (-7) path frees the mapping, the object and the spray
  ok   BUG.4 engine: both cancel paths reach the app as -7 (cancelled, not failed)
  ok   BUG.6 throttle: the log sink fsyncs only through the rate gate
  ok   BUG.6 throttle: one process-wide gate, not one per translation unit
  ok   BUG.6 throttle: the gate is a compiled, host-tested policy in both builds
  ok   BUG.6 throttle: no other fsync-per-line sink in the shipped code

25 check(s) passed, 0 failed

SCAN_BUDGET_CANCEL_WRITES LINT PASS
```

That lint is source-level, so it says the WIRE is there, not that the built artifact carries
it. That is what entries 8-10 are for, and they answer in call instructions rather than in
symbol names.

### Raw output, entry 9 (the app's own call edges, from the linked binary)

```
W0lfTerm 0.20 app binary - the app's own call edges into the engine (link-level proof, not symbol existence)
binary: /home/kaffein/Desktop/W0lfTerm/dist/Payload/W0lfTerm.app/W0lfTerm
sha256: 2922ebb3c8138e6dcbd2efb95101afdceb26e409b83f8129d28bdb351eaf14c8
source : llvm-objdump-19 -d --macho <binary> (full dump: app_disassembly.txt, 2510338 bytes)
extract: python3 /tmp/extract_edges.py <dump> <label...>   (bl targets inside each named body)

=== -[TerminalViewController dotTapped:]:
    0b 66 00 94 bl _TermClick
    05 00 00 94 bl _termHapticLight
    f9 57 00 94 bl _term_bridge_cancel

=== _term_bridge_cancel:
    01 00 00 14 b 0x10001df50
    c1 bc ff 97 bl _kexploit_request_stop
    09 00 00 94 bl _TweakLog
    05 00 00 14 b 0x10001df74
    05 00 00 94 bl _TweakLog
    01 00 00 14 b 0x10001df74

=== +[TermSettings setScanBudget:]:
    01 00 00 14 b 0x100020bc8
    01 00 00 14 b 0x100020bd8
    01 00 00 14 b 0x100020bf8
    01 00 00 14 b 0x100020c04
    01 00 00 14 b 0x100020c08
    ed ff ff 17 b 0x100020bc8
    01 00 00 14 b 0x100020c24
    0d 00 00 14 b 0x100020c58
    69 b1 ff 97 bl _kexploit_set_scan_budget
    01 00 00 14 b 0x100020c58

=== -[SettingsViewController scanBudgetChanged:]:
    32 eb ff 97 bl _TermClick
    68 ff ff 97 bl _termHapticSelect
    76 df ff 97 bl _term_bridge_apply_settings

== the budget selector the change handler sends (the row -> TermSettings edge) ==
29857:100020d74:	01 7d 40 f9	ldr	x1, [x8, #0xf8] ; Objc selector ref: scanBudgetSeconds:
35913:100026ae0:	01 f5 42 f9	ldr	x1, [x8, #0x5e8] ; Objc selector ref: scanBudgetSeconds:
35920:100026afc:	01 f9 42 f9	ldr	x1, [x8, #0x5f0] ; Objc selector ref: setScanBudget:

```

Read: the cancel word's control calls `term_bridge_cancel`, which calls
`_kexploit_request_stop` (the engine's stop flag); the SET row's change handler sends
`scanBudgetSeconds:`/`setScanBudget:`, and `+[TermSettings setScanBudget:]` ends in
`bl _kexploit_set_scan_budget`, i.e. the UI's setter and the engine's setter are the same
call in the artifact a device would install. `_kexploit_request_stop`'s own body has no `bl`
(it is an atomic store), which is why it appears with an empty call list.

### Raw output, entry 10 (the claims, checked in the binary)

```
W0lfTerm 0.20 binary - the claims the UI makes, checked in the artifact
binary sha256: 2922ebb3c8138e6dcbd2efb95101afdceb26e409b83f8129d28bdb351eaf14c8

== llvm-nm: engine functions DEFINED in the app (T = defined text symbol) ==
000000010000d298 T _kexploit_clear_stop
000000010000d254 T _kexploit_request_stop
000000010000d238 T _kexploit_scan_budget
000000010000d1b4 T _kexploit_scan_write_bytes
000000010000d1c8 T _kexploit_scan_write_failures
000000010000d1a0 T _kexploit_scan_writes
000000010000d1dc T _kexploit_set_scan_budget
000000010000d278 T _kexploit_stop_requested
00000001000179b8 T _kwrite_zone_element_qword
000000010000c408 T _probe_exit_action_for
000000010000afec T _tweak_log_fsync_due
000000010000b3d4 T _tweak_log_fsync_due_now

== strings: the wording claims (BUG.5) ==
  no kernel writes                         5
  zero kernel writes                       0
  zero writes                              0
  measured by kwrite_counter               1
  cancel                                   19
  pe_v2 scan stopped on request            1

== the measured-write lines the app prints (BUG.5: a number, not a sentence) ==
[w0lf] kernel writes %s: %llu write(s) / %llu byte(s) (engine-counted, reset per attempt; refused: %llu) - BUG.5
scan + validate offsets, no kernel writes (engine-counted per run). still pegs a core + dirties ~1 GB of file-backed memory (SG.10)
[SCAN] kernel writes issued %s: %llu write(s), %llu byte(s) [measured by kwrite_counter, BUG.5]
 no corruption performed, stopping (kernel writes measured: %llu write(s) / %llu byte(s), BUG.5)
```

### Raw output, entry 7 (the app + engine build from the tree, `REBUILD_ENGINE=1`)

```
== 1/6 engine lib ==
OK: .theos/libengine/libw0lfengine.a (804K, 52 objects)
  built: .theos/obj/debug/W0lfTerm.app
OK: dist/W0lfTerm-0.20-sideload.ipa
```

followed by the archive and the binary hashed on disk after the build:

```
263ae60d49fd0c1557ac8d26f365b6d9d4c8475387ab45451306da31167f9661  /home/kaffein/Desktop/W0lfSword/.theos/libengine/libw0lfengine.a
2922ebb3c8138e6dcbd2efb95101afdceb26e409b83f8129d28bdb351eaf14c8  dist/Payload/W0lfTerm.app/W0lfTerm
```

Both are the values the suite pins, so the archive the app links is the archive this tree
builds, and the app that comes out is the same one the T12/T13 passes hashed.

### Raw output, entry 6 (`regression.sh`'s host half) and entry 11 (the TRM list)

Entry 6, complete:

```
== Shell syntax ==
  ✓ bash -n on all scripts

== Python syntax ==
  ✓ py_compile on all .py

== Offset table tests (D2.1) ==
  ✓ test_offsets.py

== Chain selector golden grid (AUD.6) ==
  ✓ test_chain_select.sh

== BUG.1 host tests (zone-writer clamp + probe restore policy) ==
  ✓ krw_zone_write_host_test (116 checks)
  ✓ probe_restore_e2e_host_test (56 checks)
  ✓ probe_restore_e2e_selftest.py (4 mutations rejected)
  ✓ check_bug2_release_paths.py (56 checks)
  ✓ check_pressure_budget.py (8 checks)

== BUG.3 + BUG.5 + BUG.4 + BUG.6 host tests (scan budget, measured writes, CANCEL, disk-write throttle) ==
  ✓ kwrite_counter_host_test (53 checks)
  ✓ tweak_log_throttle_host_test (30 checks)
  ✓ check_scan_budget_cancel_writes.py (25 checks)

Regression (host half, device section excluded): 12 passed, 0 failed
```

Entry 11 is the TRM suite's 108 `ok` lines in order (`.../t14/trm_passfail.txt`, 4347
bytes). The tail of it, verbatim:

```
[8] redirection (TRM.2)
  ok   reports 'written to' after a redirect
  ok   the payload landed in the file
  ok   >> added the second line
  ok   >> did not truncate (2 lines)
  ok   plain > truncates back to 1 line
  ok   the truncated content is gone
  ok   the redirected payload did not print to the terminal
  ok   and it is in the file
  ok   an unwritable target fails
  ok   the failure is still reported in the terminal
  ok   a missing path after '>' is refused
  ok   '>' inside a word is not a redirect
  ok   normal commands are unaffected
[9] completion (TRM.1)
  ok   a command name completes and gains a space
  ok   gated command names complete too
  ok   kwrite8/16/32/64 are all candidates
  ok   an ambiguous token with no common prefix is left alone
  ok   the candidate list names them
  ok   no candidate stays silent
  ok   path completion appends the rest of the name
  ok   three entries share the prefix
  ok   an already-complete common prefix reports no change
  ok   a directory candidate gets a trailing slash
  ok   a non-path command gets no path candidates
  ok   an unmatched path stays silent
  ok   an empty line completes to nothing
checks=108 failures=0
TRM_SHELL_HOST_TEST PASS
```

The other seven TRM sections (parser/dispatch, filesystem, cd/path resolution, gating,
kernel+probe commands, packages, the selftest path) are in the same file in order, all `ok`.

### Per-item map (what evidence now backs each item)

| item | what was asked | evidence |
|------|----------------|----------|
| W0lfSword `BUG.3` / W0lfTerm `BUG.3` (scan budget) | settable end to end: engine `kexploit_scan_budget` / `g_scanBudgetSec`, app SET row consuming it | lint checks `BUG.3 engine: ...` (4) and `BUG.3 app: ...` (3), all `ok`; the link edge `+[TermSettings setScanBudget:] -> bl _kexploit_set_scan_budget` in the built binary; `_kexploit_scan_budget` / `_kexploit_set_scan_budget` defined (`T`) in it |
| W0lfSword `BUG.4` / W0lfTerm `BUG.1` (CANCEL) | visible cancel that releases the leaked search mapping and drains the socket spray on the cancel path | lint checks `BUG.4 app: a visible CANCEL control ...`, `the tap reaches the engine stop flag ...`, `the run loop treats -7 as cancelled and STOPS`, `pe_v1: the -7 cancel exit releases the spray AND the mappings`, `pe_v1: every -7 exit goes through the funnel`, `pe_v2: the aborted (-7) path frees the mapping, the object and the spray`, `both cancel paths reach the app as -7`, `the socket spray honours a CANCEL` - all `ok`; the link edges `-[TerminalViewController dotTapped:] -> bl _term_bridge_cancel -> bl _kexploit_request_stop` |
| W0lfSword `BUG.5` / W0lfTerm `BUG.2` (the "zero writes" claim) | remove it or back it with a write-accounting check tied to the 1 GB/day limit | lint check `BUG.5: no shipped log/UI string claims 'zero writes' any more` = `ok`; `kwrite_counter` 53/0 in the host test; `no kernel writes`=5 / `zero kernel writes`=0 / `zero writes`=0 in the built binary; the measured-write log format strings present; and the NEW 8th pressure-budget check, which prints 8064 MB dirtied per run (7.88x the 1 GB/day limit) next to 3001 fsyncs for the log half |

### HARD RULE compliance (this pass)

- HARD RULE 1 (no exploit, no device command): every command above is host `cc`/`python3`/`bash`,
  a Theos cross-compile, or a read of a built Mach-O. `scripts/regression.sh` was not run whole
  and its device section was excluded by construction (entry 6). No `idevice*`, no `ssh`, no
  `usbmuxd`, no exploit, no device attached or addressed.
- HARD RULE 2 (no git write command): no `git add`/`commit`/`push`/`checkout`/`reset`/`stash`.
  Read-only `git status`/`git log` only.
- HARD RULE 3 (no file deletion): nothing deleted. The W0lfTerm build script rewrote its own
  `dist/` and `.theos/` outputs, which it does on every run.
- Working tree only: the changes are the two scripts, the `.../t14/` evidence directory and
  this entry.

### What this pass does NOT cover (plainly)

- No device run: the SE device half is unchanged and every item above stays "NOT
  device-verified". Nothing here was executed against a phone, and no panic log was read.
- The disk accounting is a SOURCE arithmetic guard, not a measurement: it prints what the
  parsed constants imply (8064 MB dirtied per run on the 3 GB class). How many bytes one
  fsync actually flushes is the log file's own dirty pages, and the split of the device's
  1073.75 MB between the log half and the scan half stays a device measurement
  (`W0lfTerm.diskwrites_resource-*.ips`). The scan half is still over the limit and this pass
  does not change that; it makes the ratio impossible to move unnoticed.
- The `-7` cancel reaching the app, the banner reading 600 back on the SE, and the CANCEL
  being tappable mid-run are the device-day checks this pass cannot do.
- The re-pin in `check_host_verification.sh` means earlier entries in this file quote the
  PRE-T14 `pressure_budget` hashes (`e8b2e912...`, `7b0311fd...`) and the pre-T14 check count
  (7 checks / 7 mutations). Those are history, not drift; entry 1 above is the current pair.

## T14b - the T14 set re-run from the working tree, every command and its full output

2026-09-11T23:55-23:58+02:00. Same scope as T14, done as an independent pass: (1) confirm the
three named deliverables are in the tree end to end - the settable scan budget (engine
`kexploit_scan_budget` / `g_scanBudgetSec`, app SET row consuming it), the visible CANCEL whose
cancel path releases the leaked search mapping and drains the socket spray, and the "zero
writes" claim backed by write accounting tied to the 1 GB/day limit; (2) run the host KRW, TRM
and W0lfTerm suites from the working tree and record the commands with their complete
pass/fail output. Nothing in either tree was edited except this file and the new evidence
directory below: the sources carrying the fixes still have the mtimes of the tasks that wrote
them (`kexploit_opa334.m` 22:54, `kwrite_counter.c` 22:43, `term_bridge.m` 22:45,
`TerminalViewController.m` 22:46, `SettingsViewController.m` 22:46), and the app build
reproduced the T12/T13/T14 binary byte for byte (`sha256 2922ebb3...`).

`.../t14b/` = `docs/verification/2026-09-11-0.12/t14_verify/`. `raw` = sha256 of that
command's complete stdout+stderr as saved.

| # | command | cwd | exit | sha256 (stdout+stderr) | bytes | raw log |
|---|---------|-----|------|------------------------|-------|---------|
| E1 | `bash scripts/run_krw_zone_write_host_test.sh` | W0lfSword | 0 | `1386b0b6e393b492...` | 7492 | `.../t14b/e1_krw_zone_write.log` |
| E2 | `bash scripts/run_kwrite_counter_host_test.sh` | W0lfSword | 0 | `1dc9c1d4b0e35b86...` | 2629 | `.../t14b/e2_kwrite_counter.log` |
| E3 | `bash scripts/run_probe_restore_e2e_host_test.sh` | W0lfSword | 0 | `62f760e7402071fc...` | 4830 | `.../t14b/e3_probe_restore_e2e.log` |
| E3b | `python3 scripts/probe_restore_e2e_selftest.py --selftest` | W0lfSword | 0 | `97e2173af1a31a7e...` | 852 | `.../t14b/e3b_probe_restore_selftest.log` |
| E4 | `python3 scripts/check_bug2_release_paths.py` | W0lfSword | 0 | `1df3ce4c11439d92...` | 7170 | `.../t14b/e4_bug2_release_paths.log` |
| E4b | `python3 scripts/check_bug2_release_paths.py --selftest` | W0lfSword | 0 | `03bc081c48798f73...` | 4768 | `.../t14b/e4b_bug2_selftest.log` |
| E5 | `python3 scripts/check_scan_budget_cancel_writes.py` | W0lfSword | 0 | `4dc5246d0662e7df...` | 2161 | `.../t14b/e5_scan_budget_cancel.log` |
| E5b | `python3 scripts/check_scan_budget_cancel_writes.py --selftest` | W0lfSword | 0 | `e24a0f3e9a1e9bc7...` | 46714 | `.../t14b/e5b_scan_budget_cancel_selftest.log` |
| E6 | `python3 scripts/check_pressure_budget.py` | W0lfSword | 0 | `91bd530e7bf386a5...` | 1666 | `.../t14b/e6_pressure_budget.log` |
| E6b | `python3 scripts/check_pressure_budget.py --selftest` | W0lfSword | 0 | `98be7a751526bbd2...` | 17515 | `.../t14b/e6b_pressure_budget_selftest.log` |
| E7 | `bash scripts/run_tweak_log_throttle_host_test.sh` | W0lfSword | 0 | `d59cd9fd7d8be99c...` | 2873 | `.../t14b/e7_tweak_log_throttle.log` |
| E8 | `bash scripts/run_trm_host_test.sh` (TRM suite) | W0lfSword | 0 | `feb41a586ba75bf7...` raw / `42305c27487f35be...` canonical | 15415 | `.../t14b/e8_trm_shell_host_test.log` |
| E9 | `REBUILD_ENGINE=1 bash scripts/build_ipa.sh sideload 0.20` | W0lfTerm | 0 | `4d8afa713bb5b381...` | 2308 | `.../t14b/e9_app_ipa_build_rebuild_engine.log` |
| E10 | `llvm-nm-19` + `strings -a` on the built app binary | W0lfTerm | 0 | `5a4214afe0b49de7...` | 3528 | `.../t14b/e10_binary_symbols_and_strings.log` |
| E10b | `llvm-objdump-19 -d --macho <app binary>` | W0lfTerm | 0 | `c2084cdfe1f782eb...` | 2510338 | `.../t14b/e10b_app_disassembly.txt` |
| E10c | the call-edge extraction over E10b (`extract_edges.py`, copied next to it) | W0lfTerm | 0 | `5a4509918891eae1...` | 1717 | `.../t14b/e10c_app_call_edges.log` |
| E11 | `bash scripts/check_host_verification.sh --with-builds` | W0lfSword | 0 | `6c784f80e5069a52...` | 1731 | `.../t14b/e11_host_suite_with_builds.log` |
| E12 | `python3 docs/verification/2026-09-11-0.12/t14_verify/run_regression_host_half.py` (regression.sh lines 1-139, device section excluded) | W0lfSword | 0 | `927307f099b405d5...` | 1145 | `.../t14b/e12_regression_host_half.log` |

`MANIFEST.txt` in the same directory carries sha256 + bytes for all 21 files it lists (18 raw
logs/dumps plus `extract_edges.py`, `run_regression_host_half.py`, `write_manifest.py`) plus the
three build outputs and the tool versions (`cc 14.2.0`, `clang 19.1.7`, `python3 3.13.5`,
`llvm-nm-19`). E8 is the one raw log that cannot be byte-stable (the TRM harness runs real
commands and prints the live date, `df`, loadavg and its own pid/random temp dir), so it is
pinned by `check_host_verification.sh` as a CANONICALIZED hash; that canonicalization
reproduces the pin exactly:

```
$ sed -E "$CANON_SED" e8_trm_shell_host_test.log | sort | sha256sum
42305c27487f35be1e26678529c99383adeaff82ea08ec2de71c6ac867804556
pinned in check_host_verification.sh:  42305c27487f35be1e26678529c99383adeaff82ea08ec2de71c6ac867804556
```

Every other hash above is byte-for-byte the value the T14 entry recorded - so the T14 numbers
were not a one-off and the suite is reproducible, not merely green once.

### Raw output, E11 (the hash-pinned suite, builds included)

```
host verification suite - cwd=/home/kaffein/Desktop/W0lfSword
raw logs: /tmp/w0lf_host_verification

ok   krw_zone_write                     rc=0 1386b0b6e393b492... (7492 bytes)
ok   probe_restore_e2e                  rc=0 62f760e7402071fc... (4830 bytes)
ok   probe_restore_e2e_self             rc=0 97e2173af1a31a7e... (852 bytes)
ok   kwrite_counter                     rc=0 1dc9c1d4b0e35b86... (2629 bytes)
ok   tweak_log_throttle                 rc=0 d59cd9fd7d8be99c... (2873 bytes)
ok   scan_budget_cancel                 rc=0 4dc5246d0662e7df... (2161 bytes)
ok   scan_budget_cancel_self            rc=0 e24a0f3e9a1e9bc7... (46714 bytes)
ok   bug2_release_paths                 rc=0 1df3ce4c11439d92... (7170 bytes)
ok   bug2_release_paths_self            rc=0 03bc081c48798f73... (4768 bytes)
ok   test_offsets                       rc=0 eead34fbfc466f96... (552 bytes)
ok   pressure_budget                    rc=0 91bd530e7bf386a5... (1666 bytes)
ok   pressure_budget_self               rc=0 98be7a751526bbd2... (17515 bytes)
ok   test_chain_select                  rc=0 9a596a45ef210f9b... (2129 bytes)
ok   trm_shell_host_test                rc=0 42305c27487f35be... (15415 bytes)
ok   py_compile                         rc=0 e3b0c44298fc1c14... (0 bytes)
ok   bash_syntax                        rc=0 e3b0c44298fc1c14... (0 bytes)

ok   engine_lib_build                   rc=0 334a5c211aedbcef... (88 bytes)
ok   engine_lib_archive                 263ae60d49fd0c15...
ok   app_ipa_build                      rc=0 e4f7235f621013d6... (2282 bytes)
ok   app_binary                         2922ebb3c8138e6d...
ok   app_static_symbols                 rc=0 fd7a746a6f461d09... (943 bytes)

host verification: 21 ok, 0 drift
```

### Raw output, E5 (the BUG.3/BUG.4/BUG.5/BUG.6 end-to-end lint) and E12 (regression host half)

E5, complete (25/25; the cancel/budget/write-accounting rows are the deliverable checks):

```
BUG.3 + BUG.5 + BUG.4 + BUG.6 end-to-end lint
  engine root: /home/kaffein/Desktop/W0lfSword
  app root:    /home/kaffein/Desktop/W0lfTerm

  ok   BUG.3 engine: the default budget is the one that fits the walk (600 s)
  ok   BUG.3 engine: the budget is settable and clamped, and every scan/spray loop reads it
  ok   BUG.3 engine: the cancel/budget check sits INSIDE each walk, not after it
  ok   BUG.4 engine: the socket spray honours a CANCEL (it is the longest pre-walk cost)
  ok   BUG.3 app: the default budget matches the engine default and is pushed in at load
  ok   BUG.3 app: a SET row exists, persists, and pushes every change into the engine
  ok   BUG.3 app: the boot banner reads the budget back from the ENGINE
  ok   BUG.5 counter: the module exists and exposes the measured getters
  ok   BUG.5 counter: the ONE write primitive counts both outcomes
  ok   BUG.5 counter: each entry point attributes its writes to its own route
  ok   BUG.5 engine: the counters reset per attempt, are exported, and are printed
  ok   BUG.5 app: the run log carries the measured number, not the claim
  ok   BUG.5: no shipped log/UI string claims 'zero writes' any more
  ok   BUG.4 app: a visible CANCEL control that is on only while a run is in flight
  ok   BUG.4 app: the tap reaches the engine stop flag through the one bridge
  ok   BUG.4 app: the run loop treats -7 as cancelled and STOPS (no retry)
  ok   BUG.4 engine pe_v1: the -7 cancel exit releases the spray AND the mappings
  ok   BUG.4 engine pe_v1: every -7 exit goes through the funnel (no cancel exit leaks)
  ok   BUG.4 engine pe_v2: the aborted (-7) path frees the mapping, the object and the spray
  ok   BUG.4 engine: both cancel paths reach the app as -7 (cancelled, not failed)
  ok   BUG.6 throttle: the log sink fsyncs only through the rate gate
  ok   BUG.6 throttle: one process-wide gate, not one per translation unit
  ok   BUG.6 throttle: the gate is a compiled, host-tested policy in both builds
  ok   BUG.6 throttle: no other fsync-per-line sink in the shipped code

25 check(s) passed, 0 failed

SCAN_BUDGET_CANCEL_WRITES LINT PASS
```

E12, complete (the regression script's host half; the `Live device smoke` section at line 158
does `ssh root@<ip>` and the `Build` section runs `make package`, so both are excluded from
this pass by construction - that is what the wrapper script documents):

```
wrote /tmp/regression_host_half.sh (140 lines, from regression.sh lines 1-139; device section 158-171 excluded)

== Shell syntax ==
  ✓ bash -n on all scripts

== Python syntax ==
  ✓ py_compile on all .py

== Offset table tests (D2.1) ==
  ✓ test_offsets.py

== Chain selector golden grid (AUD.6) ==
  ✓ test_chain_select.sh

== BUG.1 host tests (zone-writer clamp + probe restore policy) ==
  ✓ krw_zone_write_host_test (116 checks)
  ✓ probe_restore_e2e_host_test (56 checks)
  ✓ probe_restore_e2e_selftest.py (4 mutations rejected)
  ✓ check_bug2_release_paths.py (56 checks)
  ✓ check_pressure_budget.py (8 checks)

== BUG.3 + BUG.5 + BUG.4 + BUG.6 host tests (scan budget, measured writes, CANCEL, disk-write throttle) ==
  ✓ kwrite_counter_host_test (53 checks)
  ✓ tweak_log_throttle_host_test (30 checks)
  ✓ check_scan_budget_cancel_writes.py (25 checks)
Regression (host half, device section excluded): 12 passed, 0 failed
exit=0
```

Per-harness verdict lines from E1-E8's own logs: `checks=116 failures=0` /
`KRW_ZONE_WRITE_HOST_TEST PASS` (E1), `checks=53 failures=0` /
`KWRITE_COUNTER_HOST_TEST PASS` (E2), `checks=56 failures=0` /
`PROBE_RESTORE_E2E_HOST_TEST PASS` (E3), `selftest: all mutations caught` (E3b, 4 mutations),
`56 check(s) passed, 0 failed` + `selftest: all mutations caught` (E4/E4b, 19 mutations), `25 check(s) passed,
0 failed` + `selftest: all mutations caught` (E5/E5b, 21 mutations), `8 check(s) passed, 0
failed` + `selftest: all mutations caught` (E6/E6b, 9 mutations), `checks=30 failures=0` /
`TWEAK_LOG_THROTTLE_HOST_TEST PASS` (E7), `checks=108 failures=0` / `TRM_SHELL_HOST_TEST PASS`
(E8).

E6's 8th check is the one my task's third clause asked for - the write accounting next to the
1 GB/day limit, printed rather than asserted:

```
  ok   BUG.5/BUG.6 disk budget: the write accounting is pinned against the 1 GB/day limit
       disk-write accounting (the report: 1073.75 MB in 1083 s, limit 1 GB/day):
         scan:  384 MB per cycle x 7 cycle(s) x 3 attempt(s) = 8064 MB dirtied per run (7.88x the limit)
         log:   600 s run, one fsync per 200 ms = at most 3001 fsync(s) (bytes per fsync are the log file's dirty pages - a device measurement)
         => the scan's per-page marker writes are the half over the limit; this round bounds the LOG half only (BUG.6), unchanged for the scan (BUG.2 residual)
```

### Raw output, E9 (both halves built from THIS tree) and E10c (the app's call edges)

E9, complete:

```
== 1/6 engine lib ==
bash scripts/build_libengine.sh
OK: .theos/libengine/libw0lfengine.a (804K, 52 objects)
== 2/6 theos build ==
> Making all for application W0lfTerm…
==> Compiling main.m (arm64)…
==> Compiling term_settings.m (arm64)…
==> Compiling /home/kaffein/Desktop/W0lfSword/terminal/trm_common.c (arm64)…
==> Compiling /home/kaffein/Desktop/W0lfSword/terminal/trm_probe.c (arm64)…
==> Compiling engine_stubs.m (arm64)…
==> Compiling term_bridge.m (arm64)…
==> Compiling /home/kaffein/Desktop/W0lfSword/terminal/trm_shell.c (arm64)…
==> Compiling AppDelegate.m (arm64)…
==> Compiling TerminalViewController.m (arm64)…
==> Compiling SettingsViewController.m (arm64)…
==> Linking application W0lfTerm (arm64)…
ld64.lld: warning: Option `-ios_version_min' is not yet implemented. Stay tuned...
ld64.lld: warning: Option `-multiply_defined' is obsolete. Please modernize your usage.
==> Signing W0lfTerm…
  built: .theos/obj/debug/W0lfTerm.app
== 3/6 entitlements (sideload) ==
== 4/6 assemble Payload/W0lfTerm.app + sign ==
== 5/6 package .ipa ==
== 6/6 verify ==
Archive:  dist/W0lfTerm-0.20-sideload.ipa
  Length      Date    Time    Name
---------  ---------- -----   ----
        0  2026-09-11 23:56   Payload/
        0  2026-09-11 23:56   Payload/W0lfTerm.app/
     1459  2026-09-11 23:56   Payload/W0lfTerm.app/Info.plist
  code signature:
Identifier=W0lfTerm
CodeDirectory v=20400 size=4321 flags=0x0(none) hashes=125+7 location=embedded
  entitlements:
<key>get-task-allow</key>
<true/>
  markers:
    [boot] W0lfTerm              1
    terminal/exec probe          1
    route A in-process shell     1
  substrate-free: 0 hits (want 0)
  fixups: LC_DYLD_INFO_ONLY=1 LC_DYLD_CHAINED_FIXUPS=0 (chained must be 0 for sideload re-signers)

OK: dist/W0lfTerm-0.20-sideload.ipa
```

hashed on disk right after that build:

```
263ae60d49fd0c1557ac8d26f365b6d9d4c8475387ab45451306da31167f9661  .theos/libengine/libw0lfengine.a
2922ebb3c8138e6dcbd2efb95101afdceb26e409b83f8129d28bdb351eaf14c8  dist/Payload/W0lfTerm.app/W0lfTerm
```

The ipa itself is NOT byte-stable (its zip carries build mtimes; this run produced
`92554bb4cbf24e041ade454caa5b1323d17b24b4315f56cf4799b7bf691a0c31`, 158820 bytes) - the
stable artifacts are the archive and the linked binary, which is why the suite pins those two
and the canonicalized build log.

E10c, complete - the cancel and budget wires are call instructions in the artifact a device
would install, not symbol names:

```
W0lfTerm 0.20 app binary - the app's own call edges into the engine (link-level, not symbol existence)
binary: /home/kaffein/Desktop/W0lfTerm/dist/Payload/W0lfTerm.app/W0lfTerm
sha256: 2922ebb3c8138e6dcbd2efb95101afdceb26e409b83f8129d28bdb351eaf14c8
source: llvm-objdump-19 -d --macho <binary>  (full dump: e10b_app_disassembly.txt, 2510338 bytes)
extract: python3 extract_edges.py <dump> <exact label line>

=== -[TerminalViewController dotTapped:]:
    0b 66 00 94 bl _TermClick
    05 00 00 94 bl _termHapticLight
    f9 57 00 94 bl _term_bridge_cancel

=== _term_bridge_cancel:
    01 00 00 14 b 0x10001df50
    c1 bc ff 97 bl _kexploit_request_stop
    09 00 00 94 bl _TweakLog
    05 00 00 14 b 0x10001df74
    05 00 00 94 bl _TweakLog
    01 00 00 14 b 0x10001df74

=== +[TermSettings setScanBudget:]:
    01 00 00 14 b 0x100020bc8
    ...
    69 b1 ff 97 bl _kexploit_set_scan_budget

=== -[SettingsViewController scanBudgetChanged:]:
    32 eb ff 97 bl _TermClick
    68 ff ff 97 bl _termHapticSelect
    76 df ff 97 bl _term_bridge_apply_settings

== the budget selector the change handler sends ==
29736:+[TermSettings setScanBudget:]:
29792:+[TermSettings scanBudgetSeconds:]:
29857:100020d74: 01 7d 40 f9  ldr x1, [x8, #0xf8] ; Objc selector ref: scanBudgetSeconds:
35920:100026afc: 01 f9 42 f9  ldr x1, [x8, #0x5f0] ; Objc selector ref: setScanBudget:
```

One trap worth writing down: `extract_edges.py` matches a label line EXACTLY, and the
disassembly labels carry a trailing colon (`_term_bridge_cancel:`), so passing
`_term_bridge_cancel` reports `NOT FOUND` for every label while the dump is perfectly
readable - the label list has to include the colon.

E10, the claims themselves read out of the same binary:

```
binary sha256: 2922ebb3c8138e6dcbd2efb95101afdceb26e409b83f8129d28bdb351eaf14c8
== llvm-nm-19: engine functions DEFINED in the app (T = defined text) ==
000000010000d254 T _kexploit_request_stop
000000010000d238 T _kexploit_scan_budget
000000010000d1a0 T _kexploit_scan_writes
000000010000d1b4 T _kexploit_scan_write_bytes
000000010000d1c8 T _kexploit_scan_write_failures
000000010000d1dc T _kexploit_set_scan_budget
000000010000d278 T _kexploit_stop_requested
000000010000bd1c T _kwrite_count_reset
... (+ the 13 other kwrite_count_*/kwrite_src_* entries, _kwrite_zone_element*, _probe_exit_action_for, _tweak_log_fsync_due/_now)

== strings: the wording claims (BUG.5) ==
  no kernel writes                         5
  zero kernel writes                       0
  zero writes                              0
  measured by kwrite_counter               1
  cancel                                   19
  pe_v2 scan stopped on request            1
```

### The three deliverables, in the source and not only in the lint's verdict

Scan budget, engine (`kexploit/kexploit_opa334.m`):

```
254:#define EXPLOIT_SCAN_BUDGET_SEC 600
255:static _Atomic int g_scanBudgetSec = EXPLOIT_SCAN_BUDGET_SEC;
258:void kexploit_set_scan_budget(int seconds) {
259:    if (seconds < KEXPLOIT_SCAN_BUDGET_MIN) seconds = KEXPLOIT_SCAN_BUDGET_MIN;
260:    if (seconds > KEXPLOIT_SCAN_BUDGET_MAX) seconds = KEXPLOIT_SCAN_BUDGET_MAX;
261:    atomic_store_explicit(&g_scanBudgetSec, seconds, __ATOMIC_RELAXED);
263:int kexploit_scan_budget(void) { return SCAN_BUDGET_SEC(); }
```

and the public pair in `kexploit/kexploit_opa334.h:31-34` (`MIN 30`, `MAX 1800`,
`void kexploit_set_scan_budget(int seconds);` / `int kexploit_scan_budget(void);`). App side,
`term_settings.m`: `50: static int g_scanBudget = 600`, `91:` the persisted value is accepted
only if it is one of the row's values, `99: kexploit_set_scan_budget(g_scanBudget)` in `+load`,
`173: + (int)scanBudget`, `181: g_scanBudget = seconds` in the setter, plus
`scanBudgetCount`/`scanBudgetSeconds:`/`scanBudgetIndex`/`scanBudgetName:` for the row.
`SettingsViewController.m:550-558` builds the `UISegmentedControl` from those and
`690: [TermSettings setScanBudget:[TermSettings scanBudgetSeconds:idx]]` is the change handler;
`term_bridge.m:434` prints the banner from `kexploit_scan_budget()` - the value read back FROM
the engine, which is the check that the row really reached it.

CANCEL (`TerminalViewController.m` / `term_bridge.m`): `36:
_Static_assert(TERM_CANCEL_CONTROL_W == 96, ...)` with `34: TERM_CANCEL_CONTROL_W =
TERM_CANCEL_LABEL_W + TERM_CANCEL_GAP + TERM_DOT_W`; `192: UIControl *dot = [[UIControl alloc]
initWithFrame:CGRectMake(0, 0, TERM_CANCEL_CONTROL_W, 36)];` with `194: [dot addTarget:self
action:@selector(dotTapped:) ...]`, `199-206:` the `cancel` label (monospaced 9 pt, accent,
`userInteractionEnabled = NO`, `alpha = 0.0` until a run is in flight), `445:
self.cancelLabel.alpha = 1.0;` where the run state is 1. The tap reaches the engine through
one bridge, `term_bridge.m:233-240`:

```
void term_bridge_cancel(void) {
    if (atomic_load(&g_exploitRunning)) {
        kexploit_request_stop();
        TweakLog("[w0lf] cancel requested - the scan will stop at its next check");
    } else {
        TweakLog("[w0lf] nothing is running");
    }
}
```

The cancel path's release half, `kexploit/kexploit_opa334.m` (pe_v2; pe_v1's is the funnel the
lint and E3 drive):

```
2542:        // Count BEFORE the release - sockets_release clears the arrays, so
2543:        // reading the count afterwards always logged 0.
2544:        unsigned long releasedSockets = (unsigned long)[socketPcbIds count];
2545:        sockets_release(socketPorts, socketPcbIds);
2548:        // BUG.2 audit: the search mapping is mlock'd by surface_mlock() above on
2549:        // EVERY iteration - including this cancel/abort one - and was deallocated
2550:        // without the matching munlock, leaving one IOSurface (and the pages it
2551:        // pins) behind per iteration. Munlock first, then deallocate.
2552:        surface_munlock(searchMappingAddress, searchMappingSize);
2553:        kr = mach_vm_deallocate(mach_task_self(), searchMappingAddress, searchMappingSize);
```

and the A18 branch turns that stop into the app's `-7` (`2735: if (g_peV2Aborted) { ... 2744:
return -7; }`, logging `pe_v2 scan stopped on request (cancel or %ds budget)`).

The "zero writes" claim: there is no such string left in either tree's shipped sources. The
only hits are comments describing the bug history and the lint's own needle list:

```
W0lfSword/kexploit/kwrite_counter.h:5://  BUG.5 (2026-09-11 device day): "readonly = zero kernel writes" was prose.
W0lfSword/kexploit/kexploit_opa334.h:45:// measurement and the old "zero kernel writes" sentence. ...
W0lfSword/scripts/run_kwrite_counter_host_test.sh:3:# readonly scan does "zero kernel writes". ...
W0lfSword/tests/kwrite_counter_host_test.c:3://  W0lfSword - host test for BUG.5 (the "zero writes" claim).
W0lfTerm/term_settings.m:147:        // BUG.2 (W0lfSword BUG.5): "zero kernel writes" read as "safe to leave running" ...
W0lfSword/scripts/check_host_verification.sh:166:  ... for m in cancel "pe_v2 scan stopped on request" "no kernel writes" "zero kernel writes" ...
```

What the UI says instead is measured: `no kernel writes ... (engine-counted per run)`,
`[w0lf] kernel writes %s: %llu write(s) / %llu byte(s) (engine-counted, reset per attempt;
refused: %llu) - BUG.5` (`term_bridge.m:247-248`, called at 295/305/377), and the counters come
from `kexploit/kwrite_counter.{c,h}` (124 + 73 lines, `kwrite_count_emit` /
`kwrite_count_failed` called by the one primitive that emits bytes). The 1 GB/day tie is E6's
8th check above.

### HARD RULE compliance (this pass)

- HARD RULE 1 (no exploit, no device command): every command above is host `cc`/`clang`,
  `python3`, `bash`, a Theos cross-compile or a read of a built Mach-O. No `idevice*`, no
  `ssh`, no `usbmuxd`, no exploit, no device addressed or attached. `scripts/regression.sh`
  was not run whole: E12 extracts lines 1-139 into `/tmp/regression_host_half.sh` and the
  device section (158-171) is excluded by construction.
- HARD RULE 2 (no git write command): no `git add`/`commit`/`push`/`checkout`/`reset`/`stash`.
  Read-only `git status` only.
- HARD RULE 3 (no file deletion): nothing deleted. The W0lfTerm build script rewrites its own
  `dist/`/`.theos/` outputs, which it does on every run.
- Working tree only: this pass added `docs/verification/2026-09-11-0.12/t14_verify/` (21 files
  + `MANIFEST.txt`) and this entry. No engine, CLI or app source was touched.

### What this pass does NOT cover (plainly)

- No device run, so every item stays "NOT device-verified": tapping `cancel` mid-run, the SE
  banner reading `600` back, and the `-7` reaching the app are device-day checks.
- The disk accounting is a SOURCE arithmetic guard, not a measurement (it prints what the
  parsed constants imply: 8064 MB dirtied per run on the 3 GB class against a 1 GB/day limit).
  How many bytes one fsync flushes is the log file's own dirty pages, and how the device's
  1073.75 MB splits between the log and the scan half stays a device measurement
  (`W0lfTerm.diskwrites_resource-*.ips`). The scan half is still over the limit; the check
  makes the ratio impossible to move unnoticed, it does not fix it.
- A prior pass claimed `scripts/build_ipa.sh` was "not installed". It is in the tree
  (`/home/kaffein/Desktop/W0lfTerm/scripts/build_ipa.sh`, 3855 bytes) and E9 ran it to exit 0,
  producing `dist/W0lfTerm-0.20-sideload.ipa` - that claim was wrong and this entry is the
  correction.
- The settable budget is wired engine -> W0lfTerm app only, which is where the task put it: a
  grep for `budget`/`timeout` in the W0lfSword bash CLI (`W0lfSword`) and in this repo's
  `README.md` returns nothing, so there is no `--budget`-style flag to document. The engine API
  it would call (`kexploit_set_scan_budget` / `kexploit_scan_budget`) is exported and host-tested.



## T14c - every T14 host command re-run from the working tree, with its output

Task 14/14 closing pass, 2026-09-12 00:03 +0200. Same scope as `T14b` and the same constraint set, but this
time the per-command output is embedded below *from the captured log files*, not summarised.

Nothing in the engine, the app or the CLI changed in this pass: the three deliverables
(settable scan budget, a CANCEL that releases the leaked search mapping and drains the
socket spray, the measured write count in place of the "zero writes" claim) are the
ones tasks 10-13 landed, and this pass is the re-run that proves they still hold on this
working tree. The only files added are under `docs/verification/2026-09-11-0.12/t14c/`
and this entry.

### Command table (cwd `/home/kaffein/Desktop/W0lfSword` unless noted; `$TERM_SRC` = `/home/kaffein/Desktop/W0lfTerm`)

| # | command | what it is |
| - | ------- | ---------- |
| | `bash scripts/run_krw_zone_write_host_test.sh` | KRW: the 32-byte block writer's object clamp + the unconditional-restore policy (BUG.1) |
| | `bash scripts/run_kwrite_counter_host_test.sh` | KRW: the write counter (BUG.5), counted outcomes per route |
| | `bash scripts/run_probe_restore_e2e_host_test.sh` | KRW: the probe's save/corrupt/exit/put-back sequence end to end (BUG.1) |
| | `python3 scripts/probe_restore_e2e_selftest.py --selftest` | the same harness's own selftest |
| | `bash scripts/run_tweak_log_throttle_host_test.sh` | KRW: the fsync rate gate (BUG.6), simulated clock |
| | `bash scripts/run_trm_host_test.sh` | TRM: the route-A in-process shell host suite |
| | `python3 scripts/check_scan_budget_cancel_writes.py` | end-to-end source lint for BUG.3/BUG.4/BUG.5/BUG.6 |
| | `python3 scripts/check_scan_budget_cancel_writes.py --selftest` | that lint's mutation selftest |
| | `python3 scripts/check_pressure_budget.py` | BUG.1 probe field + BUG.2 pressure + the disk-write accounting vs 1 GB/day |
| | `python3 scripts/check_pressure_budget.py --selftest` | that check's mutation selftest |
| | `python3 scripts/check_bug2_release_paths.py` | the release-path lint (BUG.2 / BUG.1 step 3b) |
| | `python3 scripts/check_bug2_release_paths.py --selftest` | that lint's mutation selftest |
| | `python3 -m py_compile scripts/check_scan_budget_cancel_writes.py scripts/check_bug2_release_paths.py scripts/check_pressure_budget.py scripts/probe_restore_e2e_selftest.py` | the four Python checks compile |
| | `bash -n scripts/run_krw_zone_write_host_test.sh scripts/run_probe_restore_e2e_host_test.sh scripts/run_kwrite_counter_host_test.sh scripts/run_tweak_log_throttle_host_test.sh scripts/build_libengine.sh scripts/regression.sh` | the six harness scripts parse |
| | `make THEOS=$HOME/theos libengine` | W0lfTerm's engine archive, built from THIS tree |
| | `sha256sum .theos/libengine/libw0lfengine.a` | its hash |
| | `bash scripts/build_ipa.sh sideload 0.20` | the W0lfTerm ipa (sideload 0.20) |
| | `sha256sum dist/Payload/W0lfTerm.app/W0lfTerm` | the linked app binary's hash |
| | `sha256sum dist/W0lfTerm-0.20-sideload.ipa` | the ipa's hash (zip mtimes - not byte-stable, see below) |
| | `bash scripts/check_host_verification.sh --with-builds` | the hash-pinned suite: all of the above that regression.sh owns, plus both builds |

### The exit codes, as captured (`t14c/RC.txt`)

```
e1_krw_zone_write rc=0
e2_kwrite_counter rc=0
e3_probe_restore_e2e rc=0
e3b_probe_restore_selftest rc=0
e7_tweak_log_throttle rc=0
e8_trm_shell rc=0
e5_scan_budget_cancel rc=0
e5b_scan_budget_cancel_self rc=0
e6_pressure_budget rc=0
e6b_pressure_budget_selftest rc=0
e4_bug2_release_paths rc=0
e4b_bug2_release_paths_self rc=0
py_compile rc=0
bash_syntax rc=0
e9_engine_lib_build rc=0
e9b_engine_lib_archive_hash rc=0
e9c_app_ipa_build rc=0
e9d_app_binary_hash rc=0
e9e_app_ipa_hash rc=0
```

Every command exited 0. The three non-zero-free rows in `regression.sh`'s own list
(`rm a non-empty dir`, `kread 0x0`, the gated `fetch`) are assertions inside the TRM
harness, not failures - it counts them as `ok`.

### Per-command output

### e1_krw_zone_write

```
cd $ROOT
$ bash scripts/run_krw_zone_write_host_test.sh
```

exit 0 - full output:

```
krw_zone_write_host_test (BUG.1: clamp the 32-byte writer + the unconditional-restore path)

the block writer's object clamp (step 3 + step 3b):
  ok   len < 0x20 is refused
  ok   len < 0x20 emits no block
  ok   len < 0x20 logs why
  ok   len 0x40 (multiple of 0x20) inside a declared object is written
  ok   len 0x40 emits 2 blocks
  ok   blocks are dst, dst+0x20 (no shift)
  ok   both blocks inside the object
  ok   the requested bytes landed
  ok   the rest of the object was not touched
  ok   shifted tail without a declared object is refused
  ok   refused write emits no block (no half-applied write)
  ok   refused write changed no kernel byte
  ok   refusal logs 'refusing 32-byte block: shifted start ... has no enclosing object declared'
  ok   shifted tail with the object declared is written
  ok   no refusal logged when the write is allowed
  ok   len 0x38 emits 1 full block + the shifted tail
  ok   last block is the backward-shifted dst+0x18
  ok   shifted block ends exactly at dst+len (never past the request)
  ok   every block (and the RMW read) inside the object
  ok   the requested bytes landed
  ok   RMW put the object bytes outside the request back unchanged
  ok   nothing before the object was touched
  ok   SE write (0x50 into a 0x60 object) is refused
  ok   SE write emits no block
  ok   no 32-byte write left the object
  ok   SE refusal logs the block and the object bounds
  ok   shifted variant of the SE write is refused
  ok   no block emitted, nothing outside the object
  ok   a declaration that does not contain dst is treated as no declaration
  ok   foreign declaration emitted no block
  ok   window contains its base
  ok   window contains its last byte
  ok   window excludes base+size
  ok   window excludes base-1
  ok   base 0 = nothing declared
  ok   size 0 = nothing declared
  ok   shifted start below objBase is refused
  ok   reported shifted start is dst+len-0x20
  ok   writer path reports the same call as 'no object declared'
  ok   a write ending exactly at the object end is allowed
  ok   its last block starts at base+0x40
  ok   its last block ends exactly at base+0x60 (inside kalloc.96)
  ok   nothing left the object
  ok   one byte past the object end is refused
  ok   the refusal emits no block
  ok   the refusal changed no kernel byte
  ok   the refusal names the object bounds
  ok   the SE write itself: one block at +0x50 of a 0x60 object
  ok     ... emitted no block and no RMW read
  ok     ... changed no kernel byte
  ok     ... and the log says which declaration is missing
  ok   a block at the object base (inside the object, but unprovable)
  ok     ... emitted no block and no RMW read
  ok     ... changed no kernel byte
  ok     ... and the log says which declaration is missing
  ok   two blocks in the middle
  ok     ... emitted no block and no RMW read
  ok     ... changed no kernel byte
  ok     ... and the log says which declaration is missing
  ok   a write with a shifted tail
  ok     ... emitted no block and no RMW read
  ok     ... changed no kernel byte
  ok     ... and the log says which declaration is missing
  ok   a write one byte over a block boundary
  ok     ... emitted no block and no RMW read
  ok     ... changed no kernel byte
  ok     ... and the log says which declaration is missing
  ok   a window that does not contain dst is no window
  ok   the foreign window emitted no block
[krw] refusing 32-byte block at 0xffffffe000000080 (len 0x20): no enclosing object declared - a block that is not provably inside its allocation panics the device (2026-09-11 SE, zalloc.c:1322); declare it with kwrite_zone_element_declared(dst, src, len, base, size) or kwrite_zone_element_set_object(base, size) when the caller knows the allocation
  ok   size 0 is nothing declared
  ..   swept 4753 dst/len combinations (len 0x20..0x80, dst base..base+0x30)
  ok   sweep: not one emitted block left the object
  ok   sweep: verdict is OK exactly when dst+len fits the object
  ok   sweep: allowed writes landed correctly and stayed inside the object
  ..   swept 768 undeclared shapes (len 1..0x100, dst base..base+0x40)
  ok   sweep: not one undeclared shape emitted a block (default deny)

the clamped qword write the probe uses (step 3b):
  ok   qword at +0x50 of a 0x60 object with the object declared is written
  ok   it emits the 0x20-aligned block containing the qword (base+0x40, not base+0x50)
  ok   that block ends exactly at the object end - inside kalloc.96
  ok   the qword landed at the requested address
  ok   the RMW read and the block stayed inside the object
  ok   the RMW put the surrounding bytes back unchanged (only the qword changed)
  ok   a window ending mid-block is refused (the aligned block would leave it)
  ok   the refusal emitted nothing
  ok   the refusal names the object bounds
  ok   an undeclared qword write is refused
  ok   the undeclared qword write emitted no block
[krw] refusing 32-byte block at 0xffffffe0000000d0 (len 0x8): no enclosing object declared - a block that is not provably inside its allocation panics the device (2026-09-11 SE, zalloc.c:1322); declare it with kwrite_zone_element_declared(dst, src, len, base, size) or kwrite_zone_element_set_object(base, size) when the caller knows the allocation
  ok   a qword write under a window that excludes it is refused
  ok   a qword whose aligned block would start below the declared base is refused
  ok   that refusal names the base it would precede
  ok   the aligned block of the inpcb's filt/chksum qwords is 0x140 (0x160 is already aligned)
  ok   no field end = no window (nothing declared)
  ok   a field ending inside the first block needs one block
  ok   a field ending on a block boundary stays there
  ok   one byte over a boundary rounds up
  ok   18.x/26.x (filt 0x148, chksum 0x150)
  ok     ... both put-back qwords sit in the same aligned block
  ok     ... the restore's two qword writes are inside the declared window
  ok     ... and neither left the inpcb window
  ok     ... both saved values landed where the restore writes them
  ok   17.0-17.7.x (filt 0x150, chksum 0x158)
  ok     ... both put-back qwords sit in the same aligned block
  ok     ... the restore's two qword writes are inside the declared window
  ok     ... and neither left the inpcb window
  ok     ... both saved values landed where the restore writes them

the staged write probe's restore contract (step 1, probe_restore_policy.c):
  ok   the promotion code is KERN_SUCCESS (0)
  ok   the promotion is the ONE exit handed to the caller (there the socket IS the primitive)
  ok   probe exit -1 restores before the caller sees it
  ok   probe exit -7 restores before the caller sees it
  ok   an exit code the policy has never seen still restores (fail-safe default, not hand-off)
  ok   before the release funnel: the restore re-opens from the spray tracking array
  ok   the tracking array wins while it still holds the pair
  ok   array emptied, promotion fds live: the restore still reaches the pair
  ok   neither source: UNREACHABLE (the engine logs a failure, never a silent success)
  ok   staged -5 step 1: at promotion time the array holds the pair
  ok   staged -5 step 3: the restore is NOT unreachable after the spray array was released
  ok   staged -5 step 3: it writes the saved values back through the promotion's fds
  ok   a pair opened for an earlier save is refused (no write through a foreign socket)

checks=116 failures=0
KRW_ZONE_WRITE_HOST_TEST PASS
```

### e2_kwrite_counter

```
cd $ROOT
$ bash scripts/run_kwrite_counter_host_test.sh
```

exit 0 - full output:

```
kwrite_counter host test (BUG.5: measured kernel writes, not a claim)

fresh state:
  ok   reset: accepted write total is 0
  ok   reset: byte total is 0
  ok   reset: refusal total is 0
  ok   reset: refused-byte total is 0
  ok   reset: per-route write count is 0
  ok   reset: per-route refusal count is 0
  ok   reset: per-route write count is 0
  ok   reset: per-route refusal count is 0
  ok   reset: per-route write count is 0
  ok   reset: per-route refusal count is 0

counting one accepted write:
  ok   one emit: total is 1
  ok   one emit: bytes is 32
  ok   one emit: attributed to early_kwrite64
  ok   one emit: the other routes stay 0
  ok   one emit: the clamped writer stays 0
  ok   three emits: total is 3
  ok   three emits: bytes is 96
  ok   per-route: the direct 32-byte write is counted
  ok   per-route: the clamped block writer is counted
  ok   per-route: early_kwrite64 is counted once

the byte total:
  ok   sum: three accepted writes
  ok   sum: 32 + 8 + 0 bytes

what the kernel refused:
  ok   refusal: total still counts only the accepted write
  ok   refusal: byte total excludes the refused bytes
  ok   refusal: both refusals counted
  ok   refusal: refused bytes counted separately
  ok   refusal: attributed to the clamped writer
  ok   refusal: does not inflate the accepted count

attribution stack:
  ok   stack: default route is the direct 32-byte write
  ok   stack: push returns the previous route
  ok   stack: current is early_kwrite64
  ok   stack: nested push returns the inner route
  ok   stack: current is the clamped writer
  ok   stack: pop restores the outer route
  ok   stack: pop restores the default
  ok   stack: emit inside push is attributed to that route
  ok   stack: the default route keeps its own count
  ok   stack: an out-of-range push is ignored
  ok   stack: an out-of-range write is still counted
  ok   stack: out-of-range lookup reads nothing
  ok   stack: pop of the ignored push leaves the default

route names:
  ok   name: KWRITE_SRC_KRW32
  ok   name: KWRITE_SRC_KRW64
  ok   name: KWRITE_SRC_ZONE
  ok   name: an out-of-range route is safe to print

two writers at once:
  ok   threads: each thread saw the route it pushed (thread-local stack)
  ok   threads: no increment lost under two writers
  ok   threads: byte total matches both threads
  ok   threads: refusals counted from both threads
  ok   threads: route 0 kept its own count
  ok   threads: route 1 kept its own count
  ok   threads: per-route counts add up to the total
  ok   threads: the pushing threads did not leak a route here

checks=53 failures=0
KWRITE_COUNTER_HOST_TEST PASS
```

### e3_probe_restore_e2e

```
cd $ROOT
$ bash scripts/run_probe_restore_e2e_host_test.sh
```

exit 0 - full output:

```
probe_restore_e2e_host_test (BUG.1: the 32-byte overrun clamp + the restore path, end to end)

1. the 32-byte overrun (the SE panic) is injected and refused:
  ok   control: the harness counts a raw 32-byte write at +0x50 of a 0x60 object (the SE overrun)
  ok   injected overrun (0x20 at +0x50 of 0x60) is REFUSED
  ok   the refusal emitted no block and no RMW read
  ok   the refused overrun changed no kernel byte
  ok   the refusal is logged with the block and the object bounds
  ok   the qword shape at the same address is allowed (block +0x40..+0x60)
  ok   it emits the aligned block +0x40..+0x60, wholly inside the 0x60 object
  ok   the first qword past the object end is refused
  ok   and it emits no block either
  ok   and the refusal says the object does not contain the target

2. the probe's save -> corrupt -> exit -> put-back sequence, on ERROR:
  ok     18.x/26.x (filt 0x148, chksum 0x150): the probe's marker write is inside the declared window
  ok     ... and the marker is in the object (the corruption is live)
  ok     exit -1 (write-verify exhaustion) restores
  ok     ... through the spray tracking array (it still holds the pair)
  ok     ... and the saved values are back in the object (read back, not assumed)
  ok     ... both fields byte-identical to the saved values (marker gone)
  ok     ... the put-back emitted exactly the two blocks (one per qword)
  ok     ... and not one of them left the declared inpcb window
  ok     ... the qword before the first put-back field was not touched
  ok     17.0-17.7.x (filt 0x150, chksum 0x158): the probe's marker write is inside the declared window
  ok     ... and the marker is in the object (the corruption is live)
  ok     exit -1 (write-verify exhaustion) restores
  ok     ... through the spray tracking array (it still holds the pair)
  ok     ... and the saved values are back in the object (read back, not assumed)
  ok     ... both fields byte-identical to the saved values (marker gone)
  ok     ... the put-back emitted exactly the two blocks (one per qword)
  ok     ... and not one of them left the declared inpcb window
  ok     ... the qword before the first put-back field was not touched

3. the same sequence on CANCEL (-7), including after the spray array was released:
  ok   cancel (-7) restores (it is not the promotion)
  ok   cancel in the write-verify loop: the pair is re-opened from the array and the values go back
  ok   cancel: both fields are byte-identical to the saved values again
  ok   cancel after the array was released: the promotion's fds are used (not UNREACHABLE)
  ok   cancel after the release funnel: the saved values still go back (BUG.1's 'one exit later')
  ok   cancel with no usable fd pair: the restore writes NOTHING (no write through a foreign socket)
  ok     ... and it reports a FAILED restore, never a silent success
  ok     ... the field is still corrupted, which is what the failure report says

4. the promotion is handed over, not restored:
  ok   the promotion (0) is handed to the caller
  ok     ... and this path issues no put-back at all (the corrupted socket IS the primitive)

5. the clamp covers the restore's own put-back (step 3b):
  ok   the restore is attempted (its fd pair is live) with the kalloc.96 bucket declared
  ok     ... and it is reported as a FAILED restore, never as a written one
  ok     ... not one block was emitted for the put-back (refused, not written unproven)
  ok     ... no kernel byte changed anywhere in the window
  ok     ... and the refusal names the missing declaration
  ok   a window that cuts the put-back's aligned block: refused, no block, no restore claimed
  ok     ... the refusal names the block and the object it would leave
  ok     ... and no kernel byte changed
  ok   the same put-back under the engine's field-derived window does go back
  ok     ... with every block and RMW read inside the declared window

6. the declared window is derived from the field offsets:
  ok   18.x/26.x (filt 0x148, chksum 0x150): the declared window is 0x160 (field end rounded up)
  ok   18.x/26.x (filt 0x148, chksum 0x150): both put-back qwords share one 0x20-aligned block
  ok   18.x/26.x (filt 0x148, chksum 0x150): the declared window contains both put-back qwords
  ok   18.x/26.x (filt 0x148, chksum 0x150): the 32-byte block holding them ends inside the window (no refusal)
  ok   17.0-17.7.x (filt 0x150, chksum 0x158): the declared window is 0x160 (field end rounded up)
  ok   17.0-17.7.x (filt 0x150, chksum 0x158): both put-back qwords share one 0x20-aligned block
  ok   17.0-17.7.x (filt 0x150, chksum 0x158): the declared window contains both put-back qwords
  ok   17.0-17.7.x (filt 0x150, chksum 0x158): the 32-byte block holding them ends inside the window (no refusal)

checks=56 failures=0
PROBE_RESTORE_E2E_HOST_TEST PASS
```

### e3b_probe_restore_selftest

```
cd $ROOT
$ python3 scripts/probe_restore_e2e_selftest.py --selftest
```

exit 0 - full output:

```
PASS  selftest baseline: the harness passes on the unmutated sources
PASS  selftest: the harness rejects - the clamp's block-end refusal removed (krw_zone_write_qword) first failure: FAIL a window that cuts the put-back's aligned block: refused, no block, no restore claimed
PASS  selftest: the harness rejects - the writer's default deny removed (an undeclared qword is emitted) first failure: FAIL the first qword past the object end is refused
PASS  selftest: the harness rejects - the cancel/budget exit handed off instead of restored first failure: FAIL cancel (-7) restores (it is not the promotion)
PASS  selftest: the harness rejects - the promotion-fd fallback removed (the staged exit writes nothing back) first failure: FAIL cancel after the array was released: the promotion's fds are used (not UNREACHABLE)

selftest: all mutations caught
```

### e7_tweak_log_throttle

```
cd $ROOT
$ bash scripts/run_tweak_log_throttle_host_test.sh
```

exit 0 - full output:

```
tweak_log_throttle host test (BUG.6: the disk-write budget, counted)

the gate's first line and its counters:
  ok   first line: granted (the banner reaches the disk even at t=0)
  ok   first line: the gate recorded the grant
  ok   first line: nothing suppressed yet
  ok   same timestamp again: suppressed (no free second flush)
  ok   same timestamp again: counted as suppressed

the 200 ms window edge:
  ok   199 ms after the last grant: suppressed
  ok   exactly 200 ms after the last grant: granted (the edge is inclusive)
  ok   199 ms after THAT grant: suppressed again (the window restarts at each grant)
  ok   one full window after the last grant: granted
  ok   edge case: exactly 3 grants over 400 ms

bursts of log lines:
  ok   10k lines 1 ms apart: grants == duration/window + 1 (the bound is the window)
  ok   10k lines 1 ms apart: every other line was suppressed, none dropped
  ok   10k lines 1 ms apart: granted + suppressed == lines offered
  ok   10k lines 1 ms apart: the grant count honours the bound
       counter report - a 510 ms window at increasing line rates:
             1 line/s        1 line(s)       1 fsync(s)  (0 suppressed)
            10 line/s        5 line(s)       3 fsync(s)  (2 suppressed)
           100 line/s       51 line(s)       3 fsync(s)  (48 suppressed)
           450 line/s      229 line(s)       3 fsync(s)  (226 suppressed)
          5000 line/s     2550 line(s)       3 fsync(s)  (2547 suppressed)
  ok   the line rate does not change the grant band (2..4 over 510 ms)
  ok   100 line/s over 510 ms: 3 grants - the counter report above
  ok   600 s run: exactly 3000 grants (one per 200 ms window, first line inclusive)
  ok   600 s run: within the advertised bound of 3001 fsyncs, however many lines the scan logs
  ok   600 s run: no line is unaccounted for

a clock that steps backwards:
  ok   clock stepped back 500 ms: suppressed (a backwards step buys no flush)
  ok   199 ms after the grant, still suppressed
  ok   the window after the grant: granted again (the gate did not wedge)
  ok   clock step: exactly 2 grants

why one gate, not one per translation unit:
  ok   two gates at the same instant: BOTH grant
  ok   two gates at the same instant: 2 fsyncs - which is why tweak_log.m owns the single process-wide gate

a missing gate:
  ok   no gate: granted (a missing gate must not silently stop flushing)

is this check vacuous?
  ok   pre-fix policy: one fsync per line (10000 of 10000)
  ok   pre-fix policy violates the bound the gate asserts (the check is not vacuous)
       counter report - 10k lines 1 ms apart: gated 50 fsync(s) vs one-per-line 10000 (200x fewer)

the shared constant:
  ok   the shared interval is 200 ms (the forensic window the sink's comment states)
  ok   the interval is not zero (which would grant every line)

checks=30 failures=0
TWEAK_LOG_THROTTLE_HOST_TEST PASS
```

### e8_trm_shell

```
cd $ROOT
$ bash scripts/run_trm_host_test.sh
```

exit 0 - verdict tail (the complete 278-line log is `docs/verification/2026-09-11-0.12/t14c/e8_trm_shell.log`):

```
[7] selftest path (the device smoke test, stubbed deps)
  ok   trm_shell_selftest() ran without crashing

[8] redirection (TRM.2)
  rc=0  write with >                           | [sh] 1 line(s) written to redir_out.txt
  ok   reports 'written to' after a redirect
  ok   the payload landed in the file
  rc=0  append with >>                         | [sh] 1 line(s) appended to redir_out.txt
  ok   >> added the second line
  ok   >> did not truncate (2 lines)
  rc=0  truncate again                         | [sh] 1 line(s) written to redir_out.txt
  ok   plain > truncates back to 1 line
  ok   the truncated content is gone
  ok   the redirected payload did not print to the terminal
  ok   and it is in the file
  ok   an unwritable target fails
  ok   the failure is still reported in the terminal
  ok   a missing path after '>' is refused
  rc=0  no-space '>' stays part of the argument | [sh] a>b
  ok   '>' inside a word is not a redirect
  rc=0  the shell still works afterwards       | [sh] after
  ok   normal commands are unaffected

[9] completion (TRM.1)
  ok   a command name completes and gains a space
  ok   gated command names complete too
  ok   kwrite8/16/32/64 are all candidates
  ok   an ambiguous token with no common prefix is left alone
  ok   the candidate list names them
  ok   no candidate stays silent
  ok   path completion appends the rest of the name
  ok   three entries share the prefix
  ok   an already-complete common prefix reports no change
  ok   a directory candidate gets a trailing slash
  ok   a non-path command gets no path candidates
  ok   an unmatched path stays silent
  ok   an empty line completes to nothing

checks=108 failures=0
TRM_SHELL_HOST_TEST PASS
```

### e5_scan_budget_cancel

```
cd $ROOT
$ python3 scripts/check_scan_budget_cancel_writes.py
```

exit 0 - full output:

```
BUG.3 + BUG.5 + BUG.4 + BUG.6 end-to-end lint
  engine root: /home/kaffein/Desktop/W0lfSword
  app root:    /home/kaffein/Desktop/W0lfTerm

  ok   every source this lint reads exists
  ok   BUG.3 engine: the default budget is the one that fits the walk (600 s)
  ok   BUG.3 engine: the budget is settable and clamped, and every scan/spray loop reads it
  ok   BUG.3 engine: the cancel/budget check sits INSIDE each walk, not after it
  ok   BUG.4 engine: the socket spray honours a CANCEL (it is the longest pre-walk cost)
  ok   BUG.3 app: the default budget matches the engine default and is pushed in at load
  ok   BUG.3 app: a SET row exists, persists, and pushes every change into the engine
  ok   BUG.3 app: the boot banner reads the budget back from the ENGINE
  ok   BUG.5 counter: the module exists and exposes the measured getters
  ok   BUG.5 counter: the ONE write primitive counts both outcomes
  ok   BUG.5 counter: each entry point attributes its writes to its own route
  ok   BUG.5 engine: the counters reset per attempt, are exported, and are printed
  ok   BUG.5 app: the run log carries the measured number, not the claim
  ok   BUG.5: no shipped log/UI string claims 'zero writes' any more
  ok   BUG.4 app: a visible CANCEL control that is on only while a run is in flight
  ok   BUG.4 app: the tap reaches the engine stop flag through the one bridge
  ok   BUG.4 app: the run loop treats -7 as cancelled and STOPS (no retry)
  ok   BUG.4 engine pe_v1: the -7 cancel exit releases the spray AND the mappings
  ok   BUG.4 engine pe_v1: every -7 exit goes through the funnel (no cancel exit leaks)
  ok   BUG.4 engine pe_v2: the aborted (-7) path frees the mapping, the object and the spray
  ok   BUG.4 engine: both cancel paths reach the app as -7 (cancelled, not failed)
  ok   BUG.6 throttle: the log sink fsyncs only through the rate gate
  ok   BUG.6 throttle: one process-wide gate, not one per translation unit
  ok   BUG.6 throttle: the gate is a compiled, host-tested policy in both builds
  ok   BUG.6 throttle: no other fsync-per-line sink in the shipped code

25 check(s) passed, 0 failed

SCAN_BUDGET_CANCEL_WRITES LINT PASS
```

### e5b_scan_budget_cancel_self

```
cd $ROOT
$ python3 scripts/check_scan_budget_cancel_writes.py --selftest
```

exit 0 - verdict tail (the complete 583-line log is `docs/verification/2026-09-11-0.12/t14c/e5b_scan_budget_cancel_self.log`):

```
  ok   BUG.4 app: the run loop treats -7 as cancelled and STOPS (no retry)
  ok   BUG.4 engine pe_v1: the -7 cancel exit releases the spray AND the mappings
  ok   BUG.4 engine pe_v1: every -7 exit goes through the funnel (no cancel exit leaks)
  ok   BUG.4 engine pe_v2: the aborted (-7) path frees the mapping, the object and the spray
  ok   BUG.4 engine: both cancel paths reach the app as -7 (cancelled, not failed)
  ok   BUG.6 throttle: the log sink fsyncs only through the rate gate
  ok   BUG.6 throttle: one process-wide gate, not one per translation unit
  FAIL BUG.6 throttle: the gate is a compiled, host-tested policy in both builds - 200 ms=False decision=True archive=True tweak=True host test compiles it=True counter arithmetic=True window edge=True non-vacuous=True
  ok   BUG.6 throttle: no other fsync-per-line sink in the shipped code
  ok   mutation caught: the rate window is 0 ms (grants every line)
  ok   every source this lint reads exists
  ok   BUG.3 engine: the default budget is the one that fits the walk (600 s)
  ok   BUG.3 engine: the budget is settable and clamped, and every scan/spray loop reads it
  ok   BUG.3 engine: the cancel/budget check sits INSIDE each walk, not after it
  ok   BUG.4 engine: the socket spray honours a CANCEL (it is the longest pre-walk cost)
  ok   BUG.3 app: the default budget matches the engine default and is pushed in at load
  ok   BUG.3 app: a SET row exists, persists, and pushes every change into the engine
  ok   BUG.3 app: the boot banner reads the budget back from the ENGINE
  ok   BUG.5 counter: the module exists and exposes the measured getters
  ok   BUG.5 counter: the ONE write primitive counts both outcomes
  ok   BUG.5 counter: each entry point attributes its writes to its own route
  ok   BUG.5 engine: the counters reset per attempt, are exported, and are printed
  ok   BUG.5 app: the run log carries the measured number, not the claim
  ok   BUG.5: no shipped log/UI string claims 'zero writes' any more
  ok   BUG.4 app: a visible CANCEL control that is on only while a run is in flight
  ok   BUG.4 app: the tap reaches the engine stop flag through the one bridge
  ok   BUG.4 app: the run loop treats -7 as cancelled and STOPS (no retry)
  ok   BUG.4 engine pe_v1: the -7 cancel exit releases the spray AND the mappings
  ok   BUG.4 engine pe_v1: every -7 exit goes through the funnel (no cancel exit leaks)
  ok   BUG.4 engine pe_v2: the aborted (-7) path frees the mapping, the object and the spray
  ok   BUG.4 engine: both cancel paths reach the app as -7 (cancelled, not failed)
  ok   BUG.6 throttle: the log sink fsyncs only through the rate gate
  ok   BUG.6 throttle: one process-wide gate, not one per translation unit
  ok   BUG.6 throttle: the gate is a compiled, host-tested policy in both builds
  FAIL BUG.6 throttle: no other fsync-per-line sink in the shipped code - 14 file(s) scanned (archive sources + their local headers + the app sources); fsync call sites: term_bridge.m, utils/tweak_log.h
  ok   mutation caught: the app grows a second, ungated fsync sink

selftest: all mutations caught

SCAN_BUDGET_CANCEL_WRITES LINT PASS
```

### e6_pressure_budget

```
cd $ROOT
$ python3 scripts/check_pressure_budget.py
```

exit 0 - full output:

```
BUG.1 probe field + BUG.2 pressure-source check (host only)
  engine root: /home/kaffein/Desktop/W0lfSword
  app root:    /home/kaffein/Desktop/W0lfTerm

  ok   every source this check reads exists
  ok   BUG.2 pressure: every page of every search mapping is still marked
       pressure report - pe_v1's search space, as the source computes it:
         3 GB    98304 page(s)     384 MB total  12 x  32.0 MB mapping(s)
         4 GB   131072 page(s)     512 MB total  16 x  32.0 MB mapping(s)
         6 GB   196608 page(s)     768 MB total  24 x  32.0 MB mapping(s)
         8 GB    65536 page(s)     256 MB total   8 x  32.0 MB mapping(s)
  ok   BUG.2 pressure: the mapping arithmetic is pinned (a constant change fails here)
  ok   BUG.2 pressure: the up-front spray bound is pinned
  ok   BUG.2 pressure: the per-cycle release funnel is still what bounds the peak
       disk-write accounting (the report: 1073.75 MB in 1083 s, limit 1 GB/day):
         scan:  384 MB per cycle x 7 cycle(s) x 3 attempt(s) = 8064 MB dirtied per run (7.88x the limit)
         log:   600 s run, one fsync per 200 ms = at most 3001 fsync(s) (bytes per fsync are the log file's dirty pages - a device measurement)
         => the scan's per-page marker writes are the half over the limit; this round bounds the LOG half only (BUG.6), unchanged for the scan (BUG.2 residual)
  ok   BUG.5/BUG.6 disk budget: the write accounting is pinned against the 1 GB/day limit
  ok   BUG.1 probe field: nothing in the shipped code consumes the probed qword
  ok   BUG.1 probe field: the probe body does not touch the icmp6 filter pointer

8 check(s) passed, 0 failed

PRESSURE_BUDGET LINT PASS
```

### e6b_pressure_budget_selftest

```
cd $ROOT
$ python3 scripts/check_pressure_budget.py --selftest
```

exit 0 - verdict tail (the complete 191-line log is `docs/verification/2026-09-11-0.12/t14c/e6b_pressure_budget_selftest.log`):

```
  ok   every source this check reads exists
  ok   BUG.2 pressure: every page of every search mapping is still marked
       pressure report - pe_v1's search space, as the source computes it:
         3 GB    98304 page(s)     384 MB total  12 x  32.0 MB mapping(s)
         4 GB   131072 page(s)     512 MB total  16 x  32.0 MB mapping(s)
         6 GB   196608 page(s)     768 MB total  24 x  32.0 MB mapping(s)
         8 GB    65536 page(s)     256 MB total   8 x  32.0 MB mapping(s)
  ok   BUG.2 pressure: the mapping arithmetic is pinned (a constant change fails here)
  ok   BUG.2 pressure: the up-front spray bound is pinned
  ok   BUG.2 pressure: the per-cycle release funnel is still what bounds the peak
       disk-write accounting (the report: 1073.75 MB in 1083 s, limit 1 GB/day):
         scan:  384 MB per cycle x 7 cycle(s) x 3 attempt(s) = 8064 MB dirtied per run (7.88x the limit)
         log:   600 s run, one fsync per 200 ms = at most 3001 fsync(s) (bytes per fsync are the log file's dirty pages - a device measurement)
         => the scan's per-page marker writes are the half over the limit; this round bounds the LOG half only (BUG.6), unchanged for the scan (BUG.2 residual)
  ok   BUG.5/BUG.6 disk budget: the write accounting is pinned against the 1 GB/day limit
  ok   BUG.1 probe field: nothing in the shipped code consumes the probed qword
  FAIL BUG.1 probe field: the probe body does not touch the icmp6 filter pointer - writes to the icmp6filt field in the probe body: none; saves the chksum qword (filt+8): False; put-back is clamped: True
  ok   mutation caught: the probe preserves the filter pointer instead of the chksum qword
  ok   every source this check reads exists
  ok   BUG.2 pressure: every page of every search mapping is still marked
       pressure report - pe_v1's search space, as the source computes it:
         3 GB    98304 page(s)     384 MB total  12 x  32.0 MB mapping(s)
         4 GB   131072 page(s)     512 MB total  16 x  32.0 MB mapping(s)
         6 GB   196608 page(s)     768 MB total  24 x  32.0 MB mapping(s)
         8 GB    65536 page(s)     256 MB total   8 x  32.0 MB mapping(s)
  ok   BUG.2 pressure: the mapping arithmetic is pinned (a constant change fails here)
  ok   BUG.2 pressure: the up-front spray bound is pinned
  FAIL BUG.2 pressure: the per-cycle release funnel is still what bounds the peak - allocate-failure path goes to the funnel: False; funnel call sites in pe_v1: 8; cycle cap: 6
       disk-write accounting (the report: 1073.75 MB in 1083 s, limit 1 GB/day):
         scan:  384 MB per cycle x 7 cycle(s) x 3 attempt(s) = 8064 MB dirtied per run (7.88x the limit)
         log:   600 s run, one fsync per 200 ms = at most 3001 fsync(s) (bytes per fsync are the log file's dirty pages - a device measurement)
         => the scan's per-page marker writes are the half over the limit; this round bounds the LOG half only (BUG.6), unchanged for the scan (BUG.2 residual)
  ok   BUG.5/BUG.6 disk budget: the write accounting is pinned against the 1 GB/day limit
  ok   BUG.1 probe field: nothing in the shipped code consumes the probed qword
  ok   BUG.1 probe field: the probe body does not touch the icmp6 filter pointer
  ok   mutation caught: the mapping-allocate failure path stops calling the funnel

selftest: all mutations caught

PRESSURE_BUDGET LINT PASS
```

### e4_bug2_release_paths

```
cd $ROOT
$ python3 scripts/check_bug2_release_paths.py
```

exit 0 - full output:

```
PASS  pe_v1: every exit is preceded by pe_v1_release_cycle(  9 exit(s) traced, unreleased: none
        pe_v1 src line 1975: FAILURE_V(0, -1);   <- holds nothing (branch marker matched)
        pe_v1 src line 2004: return -7;   <- pe_v1_release_cycle(
        pe_v1 src line 2016: return -4;   <- pe_v1_release_cycle(
        pe_v1 src line 2026: return -1;   <- pe_v1_release_cycle(
        pe_v1 src line 2050: FAILURE_V(0, -1);   <- pe_v1_release_cycle(
        pe_v1 src line 2135: FAILURE_V(0, -1);   <- pe_v1_release_cycle(
        pe_v1 src line 2251: FAILURE_V(0, -1);   <- pe_v1_release_cycle(
        pe_v1 src line 2268: return testResult;   <- pe_v1_release_cycle(
        pe_v1 src line 2279: return 0;   <- pe_v1_release_cycle(
PASS  pe_v2: every exit is preceded by wired_pages_cleanup(  4 exit(s) traced, unreleased: none
        pe_v2 src line 2308: return;   <- holds nothing (branch marker matched)
        pe_v2 src line 2330: FAILURE(0);   <- holds nothing (branch marker matched)
        pe_v2 src line 2410: FAILURE(0);   <- wired_pages_cleanup(
        pe_v2 src line 2429: FAILURE(0);   <- wired_pages_cleanup(
PASS  pe_v1: the release funnel is the only release site  0 direct sockets_release/deallocate/munlock call(s) in the body
PASS  every surface_mlock() expression has a documented surface_munlock() path  4 mlock site(s) ['wiredMapping', 'searchMappingAddress', 'wiredAddr', 'searchMappingAddress'], unaccounted: none
PASS  pe_v1 funnel empties the mapping array before releasing  pattern found
PASS  pe_v2: the found wired page is munlocked before its deallocate  pattern found
PASS  pe_v2: the walk's search mapping is munlocked before its deallocate  pattern found
PASS  pe_v2: the wiredAddrs tracker is released on all four exit shapes  pattern found
PASS  pe_v2: the tail cleans the wired pages up before releasing the tracker  assertion holds
PASS  no bare memory-object deallocate outside release_memory_object  assertion holds
PASS  release_memory_object is used by pe_v1 and pe_v2  pattern found
PASS  pe_v1: A18 wired mapping is only deallocated on a terminal exit  pattern found
PASS  log line: socket spray release  pattern found
PASS  log line: wired page release  pattern found
PASS  log line: memory object release  pattern found
PASS  log line: pe_v1 search mapping release  pattern found
PASS  log line: pe_v1 wired mapping release  pattern found
PASS  log line: pe_v2 search mapping release  pattern found
PASS  log line: pe_v2 found wired page release  pattern found

round 3 — the three leaks the first pass left 'documented, not fixed':
PASS  kexploit_opa334: every exit after pe_init() runs the attempt teardown  11 exit(s) traced (pe_init at src line 2733), without teardown: none, unexpected: none
        kexploit_opa334 src line 2711: return -6;   <- pre-init (holds nothing)
        kexploit_opa334 src line 2714: return -1;   <- pre-init (holds nothing)
        kexploit_opa334 src line 2744: return -7;   <- teardown
        kexploit_opa334 src line 2754: return -2;   <- teardown
        kexploit_opa334 src line 2759: return -3;   <- teardown
        kexploit_opa334 src line 2764: return -4;   <- teardown
        kexploit_opa334 src line 2771: return -7;   <- teardown
        kexploit_opa334 src line 2776: return -1;   <- teardown
        kexploit_opa334 src line 2840: return -5;   <- teardown
        kexploit_opa334 src line 2843: FAILURE_V(0, -1);   <- teardown
        kexploit_opa334 src line 2886: return 0;   <- teardown
PASS  pe_v1: the single exit funnel releases the spray-tracking pair  tracker_arrays_release() found in pe_v1_release_cycle
PASS  pe_v2: every exit releases the spray-tracking pair  4 exit(s) checked, missing: none
PASS  pe_v1: every terminal exit releases the gencnt tracker  8 exit(s) checked, missing: none
PASS  pe_v2: every terminal exit releases the gencnt tracker  2 exit(s) checked, missing: none
PASS  the spray trackers are only created inside tracker_arrays_reset()  2 creation site(s) in the file, 2 inside the helper
PASS  initialize_physical_read_write: the previous OOB mapping is released first  release_physical_mapping() precedes the new mapping
PASS  pe_init: the free thread is created only when none is live  guard/create/set present
PASS  teardown: sets the stop flag, joins the thread, clears the live flag  stop/join/clear present
PASS  free_thread: every wait can be broken by the stop flag  5 stop-flag check(s) in free_thread (want 5)
PASS  log line: teardown (free thread)  pattern found
PASS  log line: teardown (target fds)  pattern found
PASS  log line: spray tracker pair  pattern found
PASS  log line: gencnt tracker  pattern found
PASS  log line: previous OOB mapping  pattern found

BUG.1 step 1 - the staged write probe's unconditional restore:
PASS  find_and_corrupt_socket: the exit is classified, then restored  policy call + restore present
PASS  the restore asks the policy which fds it may write through  probe_restore_fd_source() in restore_corrupted_socket
PASS  the restore handles all three fd sources (array / promotion fds / loud failure)  unreachable-returns-false + promotion-fd branch present
PASS  the live-fd test requires the socket index AND the save generation  stamp checks present
PASS  open_probe_socket_fds opens into locals and stamps only a successful pair  commit-on-success + generation stamp present
PASS  the save site bumps the corruption generation  stamp found
PASS  the restore's OOB verify context is cleared when its memory object is released  clear after release_memory_object present
PASS  probe_exit_action_for: exactly one hand-off, and the default is RESTORE  1 hand-off return(s), fail-safe default present
PASS  probe_restore_fd_source: the promotion-fd fallback is the array-gone case  fallback present

BUG.1 step 3b - the clamp covers the probe, and nothing is written undeclared:
PASS  the writer's bound check refuses a call with no object declared  default-deny branch present
PASS  the whole range is proved before the emit loop  planning pass precedes the first block yes
PASS  the qword writer refuses an undeclared or out-of-window block  guards present
PASS  the qword writer patches the 0x20-aligned block, not 32 bytes at dst  aligned block used
PASS  find_and_corrupt_socket_probe holds no unclamped write  early_kwrite64/32bytes absent
PASS  the probe's marker write and its own restore both use the clamped helper  2 clamped call(s) in the probe
PASS  restore_corrupted_socket holds no unclamped write  early_kwrite64/32bytes absent
PASS  the restore's put-back uses the clamped helper and handles a refusal  2 clamped call(s) + refusal branch in the restore
PASS  krw_sockets_leak_forever's inpcb write is clamped too  clamped yes
PASS  probe_inpcb_window_size derives the window from the probed field offset  derivation present
PASS  the offsets-table window uses the inp6_chksum field the table pins  offset constant used
PASS  sandbox.m declares the object instead of calling the undeclared writer  bare call absent, declared call present
PASS  sandbox.m states the struct it knows and checks the verdict  struct size + verdict check present

56 check(s) passed, 0 failed
```

### e4b_bug2_release_paths_self

```
cd $ROOT
$ python3 scripts/check_bug2_release_paths.py --selftest
```

exit 0 - full output:

```
PASS  selftest baseline: the lint passes on the unmutated source
PASS  selftest: the lint rejects - pe_v1 loses its release funnel before the -4 exit first check that failed: FAIL  pe_v1: every exit is preceded by pe_v1_release_cycle(  8 exit(s) traced, unreleased: [(2003, 'return -7;')]
PASS  selftest: the lint rejects - pe_v1's -4 exit loses the attempt teardown first check that failed: FAIL  kexploit_opa334: every exit after pe_init() runs the attempt teardown  11 exit(s) traced (pe_init at src line 2733), without teardown: [(2763, 'return -4;')], unexpected: none
PASS  selftest: the lint rejects - a pe_v1 cycle goes back to a bare [NSMutableArray new] tracker pair first check that failed: FAIL  the spray trackers are only created inside tracker_arrays_reset()  4 creation site(s) in the file, 2 inside the helper
PASS  selftest: the lint rejects - initialize_physical_read_write forgets the previous OOB mapping first check that failed: FAIL  initialize_physical_read_write: the previous OOB mapping is released first  release_physical_mapping() MISSING before create_physically_contiguous_mapping()
PASS  selftest: the lint rejects - the teardown stops breaking free_thread's first wait first check that failed: FAIL  free_thread: every wait can be broken by the stop flag  4 stop-flag check(s) in free_thread (want 5)
PASS  selftest: the lint rejects - a release site bypasses release_memory_object first check that failed: FAIL  no bare memory-object deallocate outside release_memory_object  assertion VIOLATED
PASS  selftest: the lint rejects - pe_v2's tail stops releasing its wiredAddrs tracker first check that failed: FAIL  pe_v2: the wiredAddrs tracker is released on all four exit shapes  pattern MISSING
PASS  selftest: the lint rejects - the probe's exit funnel enumerates rc != KERN_SUCCESS again instead of the policy first check that failed: FAIL  find_and_corrupt_socket: the exit is classified, then restored  policy call + restore MISSING from the wrapper
PASS  selftest: the lint rejects - the restore stops asking the policy which fds it may write through first check that failed: FAIL  the restore asks the policy which fds it may write through  probe_restore_fd_source() MISSING
PASS  selftest: the lint rejects - the promotion's fds are accepted without the save-generation check first check that failed: FAIL  the live-fd test requires the socket index AND the save generation  stamp checks MISSING (a pair from an earlier save would be used)
PASS  selftest: the lint rejects - the restore's OOB verify context is not cleared when its port is released first check that failed: FAIL  the restore's OOB verify context is cleared when its memory object is released  clear after release_memory_object MISSING
PASS  selftest: the lint rejects - the policy hands every exit over instead of restoring by default first check that failed: FAIL  probe_exit_action_for: exactly one hand-off, and the default is RESTORE  2 hand-off return(s), fail-safe default MISSING (an unseen exit code would not restore)
PASS  selftest: the lint rejects - the policy drops the promotion-fd fallback (the staged -5 restore) first check that failed: FAIL  probe_restore_fd_source: the promotion-fd fallback is the array-gone case  fallback MISSING (the staged -5 restore would write nothing)
PASS  selftest: the lint rejects - the restore goes back to the unclamped early_kwrite64 put-back first check that failed: FAIL  restore_corrupted_socket holds no unclamped write  early_kwrite64/32bytes PRESENT (the put-back would bypass the clamp)
PASS  selftest: the lint rejects - the probe's marker round trip goes back to the unclamped early_kwrite64 first check that failed: FAIL  find_and_corrupt_socket_probe holds no unclamped write  early_kwrite64/32bytes PRESENT in the probe
PASS  selftest: the lint rejects - the qword writer stops refusing an undeclared call first check that failed: FAIL  the qword writer refuses an undeclared or out-of-window block  guards MISSING from krw_zone_write_qword
PASS  selftest: the lint rejects - the bound check stops refusing a call with no object declared first check that failed: FAIL  the whole range is proved before the emit loop  planning pass precedes the first block NO
PASS  selftest: the lint rejects - the qword writer RMWs 32 bytes at dst instead of the aligned block first check that failed: FAIL  the qword writer patches the 0x20-aligned block, not 32 bytes at dst  aligned block MISSING (an unaligned RMW can straddle two blocks)
PASS  selftest: the lint rejects - sandbox.m calls the undeclared writer again first check that failed: FAIL  sandbox.m declares the object instead of calling the undeclared writer  bare call PRESENT at char 11920, declared call MISSING

selftest: all mutations caught
```

### py_compile

```
cd $ROOT
$ python3 -m py_compile scripts/check_scan_budget_cancel_writes.py scripts/check_bug2_release_paths.py scripts/check_pressure_budget.py scripts/probe_restore_e2e_selftest.py
```

exit 0 - full output:

```

```

### bash_syntax

```
cd $ROOT
$ bash -n scripts/run_krw_zone_write_host_test.sh scripts/run_probe_restore_e2e_host_test.sh scripts/run_kwrite_counter_host_test.sh scripts/run_tweak_log_throttle_host_test.sh scripts/build_libengine.sh scripts/regression.sh
```

exit 0 - full output:

```

```

### e9_engine_lib_build

```
cd $ROOT
$ make THEOS=$HOME/theos libengine
```

exit 0 - full output:

```
bash scripts/build_libengine.sh
OK: .theos/libengine/libw0lfengine.a (804K, 52 objects)
```

### e9b_engine_lib_archive_hash

```
cd $ROOT
$ sha256sum .theos/libengine/libw0lfengine.a
```

exit 0 - full output:

```
263ae60d49fd0c1557ac8d26f365b6d9d4c8475387ab45451306da31167f9661  .theos/libengine/libw0lfengine.a
```

### e9c_app_ipa_build

```
cd $TERM_SRC
$ bash scripts/build_ipa.sh sideload 0.20
```

exit 0 - full output:

```
== 1/6 engine lib ==
  reusing libw0lfengine.a (REBUILD_ENGINE=1 forces a rebuild)
== 2/6 theos build ==
[1;31m> [1;3;39mMaking all for application W0lfTerm…[m
[0;35m==> [1;39mCopying resource directories into the application wrapper…[m
[0;32m==> [1;39mCompiling main.m (arm64)…[m
[0;32m==> [1;39mCompiling engine_stubs.m (arm64)…[m
[0;32m==> [1;39mCompiling /home/kaffein/Desktop/W0lfSword/terminal/trm_probe.c (arm64)…[m
[0;32m==> [1;39mCompiling /home/kaffein/Desktop/W0lfSword/terminal/trm_common.c (arm64)…[m
[0;32m==> [1;39mCompiling term_settings.m (arm64)…[m
[0;32m==> [1;39mCompiling AppDelegate.m (arm64)…[m
[0;32m==> [1;39mCompiling /home/kaffein/Desktop/W0lfSword/terminal/trm_shell.c (arm64)…[m
[0;32m==> [1;39mCompiling term_bridge.m (arm64)…[m
[0;32m==> [1;39mCompiling SettingsViewController.m (arm64)…[m
[0;32m==> [1;39mCompiling TerminalViewController.m (arm64)…[m
[0;33m==> [1;39mLinking application W0lfTerm (arm64)…[m
ld64.lld: warning: Option `-ios_version_min' is not yet implemented. Stay tuned...
ld64.lld: warning: Option `-multiply_defined' is obsolete. Please modernize your usage.
[0;34m==> [1;39mSigning W0lfTerm…[m
  built: .theos/obj/debug/W0lfTerm.app
== 3/6 entitlements (sideload) ==
== 4/6 assemble Payload/W0lfTerm.app + sign ==
== 5/6 package .ipa ==
== 6/6 verify ==
Archive:  dist/W0lfTerm-0.20-sideload.ipa
  Length      Date    Time    Name
---------  ---------- -----   ----
        0  2026-09-12 00:01   Payload/
        0  2026-09-12 00:01   Payload/W0lfTerm.app/
     1459  2026-09-12 00:01   Payload/W0lfTerm.app/Info.plist
  code signature:
Identifier=W0lfTerm
CodeDirectory v=20400 size=4321 flags=0x0(none) hashes=125+7 location=embedded
  entitlements:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>get-task-allow</key>
<true/>
</dict>
</plist>
  markers:
    [boot] W0lfTerm              1
    terminal/exec probe          1
    route A in-process shell     1
  substrate-free: 0 hits (want 0)
  fixups: LC_DYLD_INFO_ONLY=1 LC_DYLD_CHAINED_FIXUPS=0 (chained must be 0 for sideload re-signers)

OK: dist/W0lfTerm-0.20-sideload.ipa
```

### e9d_app_binary_hash

```
cd $TERM_SRC
$ sha256sum dist/Payload/W0lfTerm.app/W0lfTerm
```

exit 0 - full output:

```
2922ebb3c8138e6dcbd2efb95101afdceb26e409b83f8129d28bdb351eaf14c8  dist/Payload/W0lfTerm.app/W0lfTerm
```

### e9e_app_ipa_hash

```
cd $TERM_SRC
$ sha256sum dist/W0lfTerm-0.20-sideload.ipa
```

exit 0 - full output:

```
73bac448c3498dec88f71f3eff856da2e0b28c1fb36c0f07f80b3d621eeb971c  dist/W0lfTerm-0.20-sideload.ipa
```

### e11_host_suite_with_builds

```
cd $ROOT
$ bash scripts/check_host_verification.sh --with-builds
```

exit ? - full output:

```
host verification suite - cwd=/home/kaffein/Desktop/W0lfSword
raw logs: /tmp/w0lf_host_verification

ok   krw_zone_write                     rc=0 1386b0b6e393b492... (7492 bytes)
ok   probe_restore_e2e                  rc=0 62f760e7402071fc... (4830 bytes)
ok   probe_restore_e2e_self             rc=0 97e2173af1a31a7e... (852 bytes)
ok   kwrite_counter                     rc=0 1dc9c1d4b0e35b86... (2629 bytes)
ok   tweak_log_throttle                 rc=0 d59cd9fd7d8be99c... (2873 bytes)
ok   scan_budget_cancel                 rc=0 4dc5246d0662e7df... (2161 bytes)
ok   scan_budget_cancel_self            rc=0 e24a0f3e9a1e9bc7... (46714 bytes)
ok   bug2_release_paths                 rc=0 1df3ce4c11439d92... (7170 bytes)
ok   bug2_release_paths_self            rc=0 03bc081c48798f73... (4768 bytes)
ok   test_offsets                       rc=0 eead34fbfc466f96... (552 bytes)
ok   pressure_budget                    rc=0 91bd530e7bf386a5... (1666 bytes)
ok   pressure_budget_self               rc=0 98be7a751526bbd2... (17515 bytes)
ok   test_chain_select                  rc=0 9a596a45ef210f9b... (2129 bytes)
ok   trm_shell_host_test                rc=0 42305c27487f35be... (15415 bytes)
ok   py_compile                         rc=0 e3b0c44298fc1c14... (0 bytes)
ok   bash_syntax                        rc=0 e3b0c44298fc1c14... (0 bytes)

ok   engine_lib_build                   rc=0 334a5c211aedbcef... (88 bytes)
ok   engine_lib_archive                 263ae60d49fd0c15...
ok   app_ipa_build                      rc=0 e4f7235f621013d6... (2282 bytes)
ok   app_binary                         2922ebb3c8138e6d...
ok   app_static_symbols                 rc=0 fd7a746a6f461d09... (943 bytes)

host verification: 21 ok, 0 drift
```

### The app side, from the linked binary (E10)

Host-only static read of the 0.20 Mach-O the E9c build produced (`llvm-nm-19`,
`strings -a`, `llvm-objdump-19 -d --macho --symbolize-operands`):

```
# app-side static evidence (llvm-nm-19 / llvm-objdump-19 on the linked 0.20 binary)
$ sha256sum dist/Payload/W0lfTerm.app/W0lfTerm
2922ebb3c8138e6dcbd2efb95101afdceb26e409b83f8129d28bdb351eaf14c8  dist/Payload/W0lfTerm.app/W0lfTerm

== nm: cancel + budget + write-accounting symbols (T = defined text) ==
000000010000d298 T _kexploit_clear_stop
000000010000d254 T _kexploit_request_stop
000000010000d238 T _kexploit_scan_budget
000000010000d1b4 T _kexploit_scan_write_bytes
000000010000d1c8 T _kexploit_scan_write_failures
000000010000d1a0 T _kexploit_scan_writes
000000010000d1dc T _kexploit_set_scan_budget
000000010000d2b8 T _kexploit_spray_total
000000010000d278 T _kexploit_stop_requested
000000010000c0bc T _kwrite_count_bytes
000000010000bdb4 T _kwrite_count_emit
000000010000bf28 T _kwrite_count_failed
000000010000c184 T _kwrite_count_failed_bytes
000000010000c244 T _kwrite_count_failed_for
000000010000c120 T _kwrite_count_failed_total
000000010000c1e8 T _kwrite_count_for
000000010000bd1c T _kwrite_count_reset
000000010000c058 T _kwrite_count_total
000000010000c3e4 T _kwrite_src_current
000000010000c2a0 T _kwrite_src_name
000000010000c388 T _kwrite_src_pop
000000010000c324 T _kwrite_src_push
000000010001df28 T _term_bridge_cancel

== strings markers (count) ==
  cancel                             19
  pe_v2 scan stopped on request      1
  no kernel writes                   5
  zero kernel writes                 0
  engine-counted                     2

-[TerminalViewController dotTapped:]:
    calls: _TermClick, _termHapticLight, _term_bridge_cancel
    -> contains 'term_bridge_cancel': YES
_term_bridge_cancel:
    calls: _TweakLog, _kexploit_request_stop
    -> contains 'kexploit_request_stop': YES
+[TermSettings load]:
    calls: _kexploit_set_scan_budget, _trm_shell_set_package_enabled
    -> contains 'kexploit_set_scan_budget': YES
+[TermSettings setScanBudget:]:
    calls: _kexploit_set_scan_budget
    -> contains 'kexploit_set_scan_budget': YES

functions inspected with a call edge: 4
```

`zero kernel writes` occurs 0 times in the shipped binary; `no kernel writes` (the
measured phrasing, `... no kernel writes (engine-counted per run)`) occurs 5 times, and
`engine-counted` twice. The only `zero kernel writes` strings left in either tree are
comments describing this bug plus the lint's own needle list (`check_scan_budget_cancel_writes.py:371`).

### Build artifacts and hashes this pass produced

```
build artifacts this pass produced (hashed on disk):
  263ae60d49fd0c1557ac8d26f365b6d9d4c8475387ab45451306da31167f9661  engine archive  /home/kaffein/Desktop/W0lfSword/.theos/libengine/libw0lfengine.a
  2922ebb3c8138e6dcbd2efb95101afdceb26e409b83f8129d28bdb351eaf14c8  app binary  /home/kaffein/Desktop/W0lfTerm/dist/Payload/W0lfTerm.app/W0lfTerm
  00827826d3ef17ea6c4a6aa71275168879890ebd6a4b1fd65c7f477a2578d261  app ipa (zip mtimes, not byte-stable)  /home/kaffein/Desktop/W0lfTerm/dist/W0lfTerm-0.20-sideload.ipa
```

`engine archive` and `app binary` are byte-identical to the hashes pinned in
`scripts/check_host_verification.sh` (263ae60d.../2922ebb3...), which is what E11 confirms.
The ipa is not byte-stable - it is a zip carrying mtimes - which is why the pinned suite
compares the *build log* in canon mode and hashes the binary instead.

### Evidence directory

`docs/verification/2026-09-11-0.12/t14c/` - the 20 logs above, `RC.txt`, `COMMANDS.txt`,
`capture.sh` (the re-runnable capture), `extract_edges.py`, `write_manifest.py` and
`MANIFEST.txt` with a sha256 + byte size for every one of them.
Re-run the capture with:

```
bash docs/verification/2026-09-11-0.12/t14c/capture.sh
```

### HARD RULE compliance (this pass)

- HARD RULE 1 (no exploit, no device command): every command above is host `cc`/`clang`,
  `python3`, `bash`, `make` for the Theos cross-compile, or a read of a built Mach-O. No
  `idevice*`, no `ssh`, no `usbmuxd`, no exploit, no device addressed or attached.
- HARD RULE 2 (no git write command): no `git add`/`commit`/`push`/`checkout`/`reset`/`stash`;
  read-only `git status` only.
- HARD RULE 3 (no file deletion): nothing deleted.
- Working tree only: this pass added `docs/verification/2026-09-11-0.12/t14c/` and this entry; no engine, CLI or app source was touched.

### What this pass does NOT cover (plainly)

- No device run, so every item stays "NOT device-verified": tapping `cancel` mid-run and
  watching the `[cleanup]` lines, the SE banner reading `600` back from the engine, and the
  `-7` reaching the app are device-day checks.
- The disk accounting is a SOURCE arithmetic guard, not a measurement: 8064 MB dirtied per
  run on the 3 GB class against the 1 GB/day limit. The scan half is still over the limit;
  the check makes the ratio impossible to move unnoticed, it does not fix it.
- The settable budget is wired engine -> W0lfTerm app only. A grep for `budget`/`timeout`/
  `cancel` in the W0lfSword bash CLI (`W0lfSword`) returns nothing: that CLI builds, installs and
  monitors, it does not run the scan loops in-process, so there is no flag for it to pass.
  The engine API it would call is exported and host-tested (`kexploit_set_scan_budget`,
  `kexploit_scan_budget` - both `T` in the linked app binary).
- `[TermSettings scanBudget]` (the getter) is in the source and the settings row, but has no
  `bl` edge of its own: it returns the file-static `g_scanBudget`. The two edges that matter
  (`load` -> `kexploit_set_scan_budget`, `setScanBudget:` -> the same) are in the disassembly
  above.

## T15 - BUG.1 closing verification: the three sub-steps, per case, host only

Task 15/16, 2026-09-12 00:10 +0200. Scope: `ROADMAP.md` 0.12 `BUG.1` (the 2026-09-11 SE
zone-bound write), quoted as read:

> `BUG.1` - **the staged write probe panics the device.** A 32-byte write from
> `early_kwrite32bytes` (via `kwrite_zone_element`'s backward-shifted RMW) lands past the end
> of a kalloc.96 object -> `zalloc.c:1322` zone bound check -> panic. Twice confirmed (SG.8,
> SG.9), both times with `Panicked task: W0lfTerm`. Fix: (1) restore the saved values
> unconditionally on every path, not only after a successful read-back; (2) probe a field with
> no concurrent reader (`so_usecount` / `inp_depend6_chksum`) or a scratch object we own,
> never the icmp6 filter pointer the kernel dereferences on the next packet; (3) clamp the
> writer so a 32-byte block that is not provably inside the target object is refused.

All three sub-steps are in the working tree already (steps 1/2/3 and the 3b pass that closed
the two gaps 3 left). **This pass changed no engine source**: what it adds is the per-case
evidence the item was missing, an independent (non-project) check of the clamp, and one
re-runnable capture. Files added: `docs/verification/2026-09-11-0.12/t15/` and this entry.

### The three sub-steps, where they live, what proved them

| sub-step | shipped implementation | host artifact | result this pass |
| --- | --- | --- | --- |
| 1. restore on every exit | `kexploit/kexploit_opa334.m:1740` `if (probe_exit_action_for(rc) == PROBE_ACTION_RESTORE) { restore_corrupted_socket(); }` - the single wrapper around `find_and_corrupt_socket_probe()`, plus `kexploit/probe_restore_policy.c:27` (the fail-safe default: 1 hand-off, 1 RESTORE return) | `tests/probe_restore_e2e_host_test.c` (the -1 and -7 exits, both inpcb layouts) + `tests/krw_zone_write_host_test.c` (policy + the staged -5 shape) | `PROBE_RESTORE_E2E_HOST_TEST PASS`, `KRW_ZONE_WRITE_HOST_TEST PASS` |
| 2. inert probe field | `kexploit/kexploit_opa334.m:1580` `const uint64_t chksumFieldOff = filtOffset + 8;` (the `inp6_chksum` qword), fingerprint at `:1408` `== 0x0000ffffffffffffULL`; the filter pointer is only ever written where it IS the primitive | `scripts/check_pressure_budget.py` (asserts the probe body never writes `inp6_icmp6filt`, preserves the `filt+8` qword, and that no `send`/`recv`-family call exists anywhere to consume it) | `8 check(s) passed, 0 failed`, `selftest: all mutations caught` |
| 3. clamped writer | `kexploit/krw_zone_write.c:73-116` (`krw_zone_check_bounds`: whole range proved before the first byte, `:85` default-deny when no object is declared, `:108` `writeDst + 0x20 > objBase + objSize` refusal), `:227-258` (`krw_zone_write_qword`: 0x20-aligned block only), called by `kexploit/krw.m:203/211/221`; the two other live-inpcb callers declare too (`VM.m:237`, `sandbox.m:271`) | `tests/krw_zone_write_host_test.c` + `tests/probe_restore_e2e_host_test.c` | `116` + `56` cases, 0 failures |

Two of the harness cases are the SE write itself:

```
  ok   SE write (0x50 into a 0x60 object) is refused          (s1_krw_zone_write_host_test.log:26)
  ok   injected overrun (0x20 at +0x50 of 0x60) is REFUSED    (s1_probe_restore_e2e.log:5)
  ok   the refusal emitted no block and no RMW read
```

and the restore half, on both layouts:

```
  ok   exit -1 (write-verify exhaustion) restores
  ok     ... both fields byte-identical to the saved values (marker gone)
  ok   staged -5 step 3: the restore is NOT unreachable after the spray array was released
  ok   staged -5 step 3: it writes the saved values back through the promotion's fds
  ok   cancel with no usable fd pair: the restore writes NOTHING (no write through a foreign socket)
  ok     ... and it reports a FAILED restore, never a silent success
```

### Commands this pass ran (host only, no device, no exploit)

All 15 returned rc=0; every line below is from the captured log, not retyped.

| command | result |
| --- | --- |
| `bash scripts/run_krw_zone_write_host_test.sh` | `checks=116 failures=0` / `KRW_ZONE_WRITE_HOST_TEST PASS` (sha256 `1386b0b6...`) |
| `bash scripts/run_probe_restore_e2e_host_test.sh` | `checks=56 failures=0` / `PROBE_RESTORE_E2E_HOST_TEST PASS` (`62f760e7...`, the hash ROADMAP 0.12 already quotes) |
| `python3 scripts/probe_restore_e2e_selftest.py --selftest` | `selftest: all mutations caught` (4/4) (`97e2173a...`) |
| `python3 scripts/check_bug2_release_paths.py` | `56 check(s) passed, 0 failed` (`1df3ce4c...`) |
| `python3 scripts/check_bug2_release_paths.py --selftest` | `selftest: all mutations caught` (`03bc081c...`) |
| `python3 scripts/check_pressure_budget.py` | `8 check(s) passed, 0 failed` / `PRESSURE_BUDGET LINT PASS` (`91bd530e...`) |
| `python3 scripts/check_pressure_budget.py --selftest` | `selftest: all mutations caught` (`98be7a75...`) |
| `make THEOS=$HOME/theos libengine` | `OK: .theos/libengine/libw0lfengine.a (804K, 52 objects)`, 88-byte log (zero warnings) |
| `sha256sum .theos/libengine/libw0lfengine.a` | `263ae60d49fd0c1557ac8d26f365b6d9d4c8475387ab45451306da31167f9661` - byte-identical to the hash `scripts/check_host_verification.sh` pins, so the verified sources ARE the shipped archive |
| `llvm-nm-19 <archive>` | defines `_krw_zone_write_qword`, `_krw_zone_block_align_down`, `_krw_zone_window_for_field_end`, `_kwrite_zone_element_qword`, `_probe_exit_action_for`, `_probe_restore_fd_source`; `kexploit_opa334.o` references the qword writer (`U`) - the engine links the clamped path |
| `cc -fsyntax-only ... kexploit/krw_zone_write.c kexploit/probe_restore_policy.c` | rc=0, no diagnostics |
| `bash scripts/check_host_verification.sh` | `host verification: 16 ok, 0 drift` - every hash the bug-list prose quotes still reproduces |
| the BUG.1 section of `scripts/regression.sh` alone (lines 41-101) | `5 ok, 0 bad` (116 + 56 + 4 + 56 + 8 checks) |
| `./W0lfSword audit` | `AUDIT PASSED` (shellcheck clean, 178 defs / 0 dead, 56 shell+python files parse) |
| `bash docs/verification/2026-09-11-0.12/t15/capture.sh` | the whole list above, 15/15 rc=0 |

### Independent clamp check (written for this pass, not a re-run)

`docs/verification/2026-09-11-0.12/t15/independent_clamp_sweep.c` links the shipped
`kexploit/krw_zone_write.c` against a monitor **this file owns** (not the project harness)
and sweeps 15253 address/length shapes - offsets -0x40..+0x80 around the object, lengths
0x08..0x100, five object sizes (0x20/0x40/0x60/0x80/0x160), declared and undeclared, range
and qword form - asserting the one property that matters on device. Result:

```
  ok   SE write shape (0x20 at +0x50 of a 0x60 object, declared=1): refused, 0 blocks emitted
  ok   SE write shape (0x20 at +0x50 of a 0x60 object, declared=0): refused, 0 blocks emitted
  ok   the last legal block (0x20 at +0x40 of a 0x60 object) is written, 1 block, inside

shapes=15253 allowed=2460 refused=12793 violations=0
INDEPENDENT_CLAMP_SWEEP PASS
```

2460 allowed shapes exist in the same sweep, so the pass is not a writer that refuses
everything; 12793 refusals produced 0 blocks and 0 changed bytes.

### Evidence

`docs/verification/2026-09-11-0.12/t15/`: one log per command, `COMMANDS.txt`,
`RC.txt` (15/15 rc=0), `BUG1-CASES.txt` (all 172 harness cases with their per-case
ok/FAIL), `BUG1-EVIDENCE.txt` (each sub-step -> the file:line that implements it -> the
result it printed), `independent_clamp_sweep.c` + its log, `capture.sh` (re-runnable),
`extract_cases.py`, `write_manifest.py`, `MANIFEST.txt` (sha256 + size of every file).
Re-run everything with:

```
bash docs/verification/2026-09-11-0.12/t15/capture.sh
python3 docs/verification/2026-09-11-0.12/t15/extract_cases.py
python3 docs/verification/2026-09-11-0.12/t15/write_manifest.py
```

Determinism: the first runs of the seven harness/lint commands and the `capture.sh`
re-runs are **byte-identical** (same sha256 per pair - recorded in `MANIFEST.txt`), so the
numbers above are reproducible and not a single lucky run.

### Re-run (second round, same tree)

The whole list was run again on the unchanged tree and reproduced: `capture.sh` 15/15
commands rc=0, `s1_krw_zone_write_host_test: 116 ok, 0 FAIL (of 116)`,
`s1_probe_restore_e2e: 56 ok, 0 FAIL (of 56)`, `check_host_verification.sh` `16 ok, 0
drift`, `make libengine` -> the same 804K / 52-object archive with sha256
`263ae60d...`, and the independent sweep `allowed=2460 refused=12793 violations=0`.
One fix to a helper this pass owns: `extract_cases.py` printed `len(text)` labelled as
"bytes" (5810 for a 5890-byte `BUG1-EVIDENCE.txt`, because the generated files carry
non-ASCII arrows/box lines); it now reports `os.path.getsize(path)`, so its own line and
`MANIFEST.txt` agree byte-for-byte. No engine, app or CLI source was touched by that fix.

### HARD RULE compliance (this pass)

- HARD RULE 1 (no exploit, no device command): every command is host `cc`/`clang`, `python3`,
  `bash`, `make` for the Theos cross-compile, `llvm-nm-19`, or `sha256sum`. No `idevice*`, no
  `ssh`, no `usbmuxd`, no exploit run, no device addressed or attached.
- HARD RULE 2 (no git write command): no `add`/`commit`/`push`/`checkout`/`reset`/`stash`;
  read-only `git status`.
- HARD RULE 3 (no file deletion): nothing deleted (the two early duplicate logs from the
  first ad-hoc runs are kept as the determinism record).
- No engine, app or CLI source was touched: the only files added are under `t15/` plus this
  entry. `.theos/libengine/libw0lfengine.a` was rebuilt and came out byte-identical.

### What this pass does NOT cover (plainly)

- **BUG.1 is still NOT device-verified.** No device ran, so the real confirmation - the SE
  reaching the write probe with no `zalloc.c:1322`, the `[STAGED] probe restored (...)`
  line, and readonly staying the only offered mode on unproven pairs - is the next device
  day.
- The clamp verifies a block against the window it is GIVEN; address trust stays where it
  was (the 0.13 canonical-pointer guard + the live-inpcb value check). A true kalloc size
  probe (`inpcbinfo.ipi_zone` -> `elem_size`) is BUG.7/0.13 and needs a `struct zone` offset
  this tree does not have.
- `kwritebuf` / `early_kwrite64` / `kwrite32` / `kwrite64` remain outside the clamp by
  design (they would all be refused without per-caller declarations); the `so_usecount`
  writes in `krw_sockets_leak_forever` stay on `early_kwrite64` because `struct socket` has
  no field table here. That residual is BUG.7 in the 0.13 section, unchanged by this pass.
- A clamp REFUSAL is a KPRINTF line (`[krw] refusing 32-byte block ...`,
  `[STAGED] ... REFUSED by the zone writer (verdict N)`) and is deliberately NOT folded into
  the BUG.5 write counter: `kwrite_counter.h` counts writes that went out and writes the
  kernel refused, and a refused block never reaches the kernel (nothing was emitted). So on a
  device log a clamp refusal shows up as a log line, not in the `(refused: N)` figure of the
  `[SCAN] kernel writes issued ...` summary - worth knowing when reading a device log.

## T16 - BUG.3 / BUG.4 / BUG.5 closing verification (engine + app), host only

Task 16/16 asked for the settable scan budget (`kexploit_scan_budget` / `g_scanBudgetSec` /
`EXPLOIT_SCAN_BUDGET_SEC`), a visible CANCEL, and the removal of the "zero writes" claim in
favour of the measured counter (`kwrite_count_emit` / `kexploit_scan_writes`), each verified
with `scripts/check_scan_budget_cancel_writes.py` / `scripts/check_pressure_budget.py` or
equivalent. All three were already implemented end to end by the earlier tasks; this pass is
the independent verification, and it found no gap to fill - so the deliverable is the
evidence, not a code change. **No engine, app or CLI source was touched by this pass**; the
only files added are `docs/verification/2026-09-11-0.12/t16/` (capture.sh, the logs, RC.txt,
COMMANDS.txt, BUG345-EVIDENCE.md) plus this entry.

### Commands this pass ran (host only, no device, no exploit)

- `python3 scripts/check_scan_budget_cancel_writes.py` -> `25 check(s) passed, 0 failed` (rc=0)
  including the six `BUG.3` checks, the three `BUG.5` claim/counter checks and the three
  `BUG.4` app checks; `--selftest` -> `selftest: all mutations caught` (21).
- `python3 scripts/check_pressure_budget.py` -> `8 check(s) passed, 0 failed` (rc=0), its 8th
  check pinning the write accounting against the 1 GB/day limit (the report figure:
  `1073.75 MB in 1083 s`); `--selftest` -> `selftest: all mutations caught` (9).
- `bash scripts/run_kwrite_counter_host_test.sh` -> `checks=53 failures=0` / PASS,
  `bash scripts/run_tweak_log_throttle_host_test.sh` -> `checks=30 failures=0` / PASS,
  `bash scripts/run_probe_restore_e2e_host_test.sh` -> `checks=56 failures=0` / PASS.
- `W0LF_TERM=~/Desktop/W0lfTerm bash scripts/check_host_verification.sh --with-builds` ->
  `host verification: 21 ok, 0 drift` (rc=0). That command REBUILDS
  `.theos/libengine/libw0lfengine.a` and `dist/W0lfTerm-0.20-sideload.ipa` from this tree and
  compares them with the pinned hashes: `engine_lib_archive` `263ae60d49fd0c15...` and
  `app_binary` `2922ebb3c8138e6d...` both unchanged, so the artifact below is this tree's.

### Independent of the lint: the linked binary was read, not assumed

`llvm-nm-19` on `dist/Payload/W0lfTerm.app/W0lfTerm` (sha256 `2922ebb3c8138e6d...`) shows
`T _kexploit_scan_budget`, `_kexploit_set_scan_budget`, `_kexploit_scan_writes`,
`_kexploit_scan_write_bytes`, `_kexploit_scan_write_failures`, `_kwrite_count_emit`,
`_kwrite_count_reset`, `_kexploit_request_stop`, `_kexploit_stop_requested`,
`_kexploit_clear_stop`, and no `_kexploit`/`_kwrite` symbol left undefined.
`llvm-objdump-19` gives the two UI edges in that same binary:

```
+[TermSettings setScanBudget:]  100020c30 str w8, [x9, #0xd38]   (g_scanBudget)
                                100020c38 bl ... <_kexploit_set_scan_budget>
-[TerminalViewController dotTapped:]  100007f44 bl ... <_term_bridge_cancel>
_term_bridge_cancel             10001df50 bl ... <_kexploit_request_stop>
_kexploit_request_stop          10000d26c stlr w8, [x9]          (the atomic the walks read)
```

Marker counts in that binary: `cancel` 19, `pe_v2 scan stopped on request` 1,
`no kernel writes` 5, `zero kernel writes` **0**, `zero writes` **0**,
`measured by kwrite_counter` 1, plus the two measured-write format strings
(`[SCAN] kernel writes issued ...` and `[w0lf] kernel writes ... (engine-counted ...)`).

### Re-run

`capture.sh` was run twice (00:19, 00:22). Second run: identical rc=0,
`host verification: 21 ok, 0 drift`, same pinned hashes, same marker counts.

### HARD RULE compliance (this pass)

- Rule 1 (never run an exploit or a device command): nothing was executed on or against a
  device. Every command compiles C with the host cc, runs a Python lint, runs the Theos
  cross-build, or reads a Mach-O on this host; the ssh-based "Live device smoke" section of
  `scripts/regression.sh` was not invoked (the capture script says so in its header).
- Rule 2 (no git commit / push / checkout / reset): none. The tree is left dirty exactly as
  found; the new evidence files are untracked additions.
- Rule 3 (no file deletion): nothing deleted. The one `rm -f` in the capture re-run removes
  the 2.3 MB `linked_binary.dis` that the previous run of the same script had written, i.e. a
  regenerable intermediate of this pass, not a repo file - the current copy is on disk.

### What this pass does NOT cover (plainly)

- **None of the three is device-verified.** The device halves are the next device day's
  measurements: a 600 s run reaching the target instead of stopping a quarter in, a mid-run
  `cancel` tap printing the `[cleanup]` lines, and the readonly run's counter reading 0.
- W0lfTerm 0.6 `BUG.5` (`keyBarSize` persisted, the bar rebuilt every time) is a different
  bug and stays open.
- The scan's own dirty-page half of the disk budget (~1 GB/cycle, printed by
  `check_pressure_budget.py` as 8064 MB per run = 7.88x the 1 GB/day limit) is W0lfSword
  0.12 `BUG.2`'s residual; this task bounds the log half only.
- `check_scan_budget_cancel_writes.py` is a source lint plus a link/marker read of the built
  binary. It proves the wiring, not the behaviour: that the budget really stretches a walk,
  that a CANCEL really lands mid-spray and that the counter really reads 0 on device are
  runtime claims this host cannot make.

## T16 round 2 - the same items re-run into a second evidence directory

The pass above is the record for this item; it was re-verified from the working tree
with a second script, writing into
`docs/verification/2026-09-11-0.12/t16/round-t16b/` rather than over the first
bundle. `bash rerun.sh` there -> `rerun.sh: all commands rc=0` (`RC.txt` = `0`,
`rerun.output.log`):

```
rc=0   python3    SCAN_BUDGET_CANCEL_WRITES LINT PASS     (25 check(s) passed, 0 failed)
rc=0   python3    SCAN_BUDGET_CANCEL_WRITES LINT PASS     (--selftest: all mutations caught, 21/21)
rc=0   python3    PRESSURE_BUDGET LINT PASS               (8 check(s) passed, 0 failed)
rc=0   python3    PRESSURE_BUDGET LINT PASS               (--selftest: all mutations caught, 9/9)
rc=0   bash       KWRITE_COUNTER_HOST_TEST PASS           (checks=53 failures=0)
rc=0   bash       TWEAK_LOG_THROTTLE_HOST_TEST PASS       (checks=30 failures=0)
rc=0   env        host verification: 21 ok, 0 drift
rc=0   python3    callgraph checks read out of .../W0lfTerm: 6 ok, 0 failed
rc=0   python3    invariant checks: 27 ok, 0 failed
```

Both artifacts were rebuilt by that run and carry the hashes the suite pins
(`263ae60d49fd0c15...` archive, `2922ebb3c8138e6d...` linked binary), and the
marker counts in the fresh binary are unchanged: `cancel` 19, `pe_v2 scan stopped
on request` 1, `no kernel writes` 5, `zero kernel writes` 0, `zero writes` 0,
`measured by kwrite_counter` 1, `engine-counted` 2.

Source read directly (not inferred from the lints) in this pass: the engine's
budget block `kexploit/kexploit_opa334.m:254-263` (one `#define
EXPLOIT_SCAN_BUDGET_SEC 600`, clamped `kexploit_set_scan_budget`, accessor
`kexploit_scan_budget`), the app's push sites `term_settings.m:99` / `:182` and
banner read-back `term_bridge.m:433-434`, the cancel control
`TerminalViewController.m:192-208` / `setRunState:` `:441-453` / `dotTapped:`
`:490-495`, the bridge guard `term_bridge.m:233-240`, the run loop's `-7` exit
`term_bridge.m:327-332`, the counter's single emit site
`kexploit_opa334.m:1163` inside `early_kwrite32bytes` (the only `setsockopt`
write path besides the probe's own corruption write), and the app's measured
number `term_bridge.m:247-253`. All of it is present in the working tree; no
source change was needed in this round. Raw output and the quoted ROADMAP
0.12 / 0.6 items: `docs/verification/2026-09-11-0.12/t16/round-t16b/SUMMARY.md`.



## T17 (second pass) - host re-run, and every claim reconciled against a capture

The task was run twice. The first pass left two problems: numbers the roadmaps
quote were kept rather than corrected (the KRW writer harness's `41 checks` next
to the `checks=116` the tree actually prints, and the TRM harness's `65/65`), and
the replayed revision trees were exported out of the repo, so the capture stopped
resolving once the temp directory was cleared. Both are fixed here, and the
run set is narrowed to the three harnesses the task names.

Commands this pass ran (all host only, no device, no exploit, nothing committed):

```
bash docs/verification/2026-09-11-0.12/t17/capture.sh            # + WITH_BUILDS=1
bash scripts/run_krw_zone_write_host_test.sh                          rc=0  checks=116 failures=0
bash scripts/run_kwrite_counter_host_test.sh                          rc=0  checks=53 failures=0
bash scripts/check_host_verification.sh                               rc=0  host verification: 16 ok, 0 drift
bash scripts/check_host_verification.sh --with-builds                 rc=0  host verification: 21 ok, 0 drift
python3 docs/verification/2026-09-11-0.12/t17/check_capture_paths.py  rc=0  capture path check: 73 ok, 0 bad
```

(the `73` is this pass's count of cited evidence paths; the retained log
`t17/capture_path_check.log` now holds the re-run below, which cites more paths
and prints `78 ok, 0 bad` - the `0 bad` half is the claim, the `ok` count grows
whenever a doc cites one more path)

The suite entry `check_host_verification.sh` drives ten further host harnesses
itself; their output is captured here as the output of that command
(`suite_logs/w0lf_host_verification/`), not as separately-run checks. Verdicts it
printed: `probe_restore_e2e checks=56 failures=0`, `trm_shell_host_test
checks=108 failures=0`, `tweak_log_throttle checks=30 failures=0`,
`scan_budget_cancel 25 check(s) passed, 0 failed`, `bug2_release_paths 56 check(s)
passed, 0 failed`, `pressure_budget 8 check(s) passed, 0 failed`, each `--selftest`
-> `selftest: all mutations caught`, and the cross-builds `engine_lib_archive
263ae60d...`, `app_binary 2922ebb3...`.

Count provenance, which is what this pass is for:

- `checks=116` (and `1386b0b6...`, unchanged from the first pass) is the number of
  THIS tree. So is `checks=108` for the TRM harness - it comes out of the
  authorized suite run, and `git diff --stat HEAD -- tests/trm_shell_host_test.c
  terminal/` is empty, so that harness is the committed one.
- `41` is the count of the clamp-only KRW harness revision as committed at `HEAD`,
  reproduced by `replay_revisions.sh` (`revisions/krw_head/`, plus the second
  capture in `head_replay/`) and now labelled HISTORICAL everywhere it appears.
  Same for `65` (route A, `8e97aa7`) and `95` (TRM.2, `dfe75f2`).
- `7 check(s) passed` for `check_pressure_budget.py` (BUG.2's note) was a dated
  count from before the 8th check existed; the doc now says 8 and quotes the log.
- Self-contained revision trees: `revisions/<label>/tree/` holds a sparse export
  (only the paths that harness compiles, ~0.6 MB each instead of a 15 MB
  whole-repo export); the round-1 housekeeping script that moved them out is kept
  in `docs/verification/2026-09-11-0.12/retired-round1/` with the reason.

Reconciliation table, correction list and the reproduction order:
`docs/verification/2026-09-11-0.12/t17/CLAIMS-RECONCILED.md`. The path check's
raw output is `docs/verification/2026-09-11-0.12/t17/capture_path_check.log`. What it does not
cover is unchanged: nothing here was run on a phone, and every device half - the
restore on the SE, the banner reading 600 back, the cancel tap and the `[cleanup]`
lines, the readonly run's counter reading 0 - still waits for a device day.
readonly stays the only mode on unproven device/iOS pairs.

### T17 (re-run) - the capture re-taken, and every claim re-asserted against it

The capture above was re-taken from the working tree as it stands, and this time
the claims were re-asserted mechanically instead of by reading. Nothing else
changed and nothing was committed; no device command was issued.

```
bash docs/verification/2026-09-11-0.12/t17/capture.sh                     # WITH_BUILDS=1, rc=0 x4
python3 docs/verification/2026-09-11-0.12/t17/verify_bug_claims.py        rc=0  claim check: 64 ok, 0 bad
python3 docs/verification/2026-09-11-0.12/t17/check_capture_paths.py      rc=0  capture path check: 78 ok, 0 bad
bash docs/verification/2026-09-11-0.12/t17/replay_revisions.sh            rc=0  41 (HEAD) / 65 / 95 / 108
bash docs/verification/2026-09-11-0.12/t17/make_manifest.sh               MANIFEST.txt refreshed
```

The three anchor hashes (`krw_zone_write.log 1386b0b6...`, `kwrite_counter.log
1dc9c1d4...`, `probe_restore_e2e.log 62f760e7...`) came back byte-identical, so
every count in the section above holds for this tree; the volatile-by-design pair
(`trm_shell_host_test.log`, the app-build log) is the only output that moves, and
the suite's `0 drift` covers both (it pins a canonical hash for the first and
hashes the second in `canon` mode).

`verify_bug_claims.py` is new here and is the point of this pass: one row per
claim of both bug lists (`BUG.1` steps 1/2/3/3b, `BUG.3`, `BUG.4`, `BUG.5`,
`BUG.6`), each naming a capture file and the exact line that must appear in it,
plus the anchor hashes, the three HISTORICAL revision counts, `checks=108`, the
two suite summary lines and the four `rc=0` entries. It exits non-zero on any
unbacked row - it caught one wrong row of its own while being written (the
cancel exit prints `cancel (-7) restores (it is not the promotion)`, not the
wording I first assumed), which is exactly the failure mode this pass exists to
remove. Raw output: `t17/verify_bug_claims.log`.

Three ATTRIBUTION errors (counts right, cited file wrong) were corrected - the
`checks=108` handed to the suite command itself in both roadmaps and the README,
when the count line lives in the suite's `trm_shell_host_test` entry raw log - and
the one item of the two bug lists that had no T17 note, W0lfTerm `0.6` `BUG.3`
(disk writes), now carries its re-run (`tweak_log_throttle.log` ->
`checks=30 failures=0`, the four `BUG.6` checks inside the 25-check lint, the
1 GB/day accounting re-read from the fresh `pressure_budget.log`). The correction
table is section 7 of `CLAIMS-RECONCILED.md`.

---

## T18 + landing pass (2026-09-15) - the yields, and the suite put back in sync

Scope: the working tree carried two things nobody had committed - the T18 yield
edit in `kexploit/kexploit_opa334.m` and every T11-T17 verification artifact - and
the pinned suite no longer matched either. This pass lands both: it fixes what the
suite caught, re-takes every pin with the reason, and re-captures the evidence.
Host only; no device command was issued (no phone was attached) and nothing was
deleted.

### T18 - the CPU axis SG.10 named

`free_thread`'s three waits were bare `;` hot spins (the first one yielded, the
other two did not). SG.10's kill was a userspace watchdog panic (CPU 90 s / 180 s,
wakeups 45k / 300 s): SpringBoard stopped checking in while the two target cores
spun. Both remaining waits now end in `pthread_yield_np();` - a yield, not a
sleep, so the thread stays runnable and the race window's latency is unchanged
while the wasted cycle goes back to the core driving the race. The comment above
the waits carries the reasoning. NOT device-verified: the CPU/wakeup reports
(`idevicecrashreport -e <dir>`) for a run with the yields in place are the device
half, exactly like the fsync throttle under BUG.6.

### What the pinned suite said about the tree as it stood

```
bash scripts/check_host_verification.sh               # 13 ok, 3 drift
bash scripts/check_host_verification.sh --with-builds # 15 ok, 6 drift
```

Two of the six were real defects, not drift:

- `bug2_release_paths_self` exited **1** - `selftest: SOME MUTATIONS WERE
  MISSED`. One mutation still targeted the pre-yield `while (...) ;` shape, so it
  never applied: the rule "free_thread's waits honour the stop flag" had been
  untested since the T18 edit. The mutation now drops the stop-flag half of the
  first wait (the `freeThreadStart` one); the selftest is `all mutations caught`
  (19/19) again.
- `trm_shell_host_test`'s canon hash drifted between runs of the SAME tree. Cause
  was the harness, not the tests: its stdout is fully buffered when redirected, so
  a `df` child spawned by the selftest path wrote into the middle of a parent
  line and the interleave moved run to run (`rc=0  89e5f65f...` three times in a
  row after the fix, and the pre-fix logs differ only in that interleave).

The other four are one cause: the T18 edit landed AFTER the last capture, so
everything derived from the engine moved.

### Re-pins (old -> new, all six in `scripts/check_host_verification.sh`)

| entry | was | now | why |
| --- | --- | --- | --- |
| `bug2_release_paths` | `1df3ce4c...` | `7c2c853a...` | the lint prints each traced exit's src line number and the yield edit moved them; 56 checks / 0 failed, unchanged |
| `bug2_release_paths_self` | `03bc081c...` | `53a89a3b...` | rc 1 -> 0, the mutation above applies again |
| `trm_shell_host_test` (canon) | `42305c27...` | `89e5f65f...` | the interleave above; content identical after the harness fix |
| `engine_lib_archive` | `263ae60d...` | `32f6af7e...` | the engine's code size grew by the yields |
| `app_binary` | `2922ebb3...` | `167faf5d...` | the same edit, linked into the app |
| `app_static_symbols` | `fd7a746a...` | `5b4ab0e4...` | `nm` addresses shifted by that code size; the symbol SET and the string counts are identical (`cancel 19`, `pe_v2 scan stopped on request 1`, `no kernel writes 5`, `zero kernel writes 0`, `measured by kwrite_counter 1`) |

`docs/verification/2026-09-11-0.12/t17/verify_bug_claims.py` pins the archive and
binary hashes too; its two anchor rows are re-pinned to the values above with the
same reason. README's quoted suite entry (`ok   trm_shell_host_test rc=0
89e5f65f65e23cc4...`) was updated with it.

### Evidence (all host, all re-run on the tree being landed)

```
WITH_BUILDS=1 bash docs/verification/2026-09-11-0.12/t17/capture.sh   # 4/4 entries rc=0
bash scripts/check_host_verification.sh                                # 16 ok, 0 drift
bash scripts/check_host_verification.sh --with-builds                  # 21 ok, 0 drift
python3 scripts/check_bug2_release_paths.py                            # 56 check(s) passed, 0 failed
python3 scripts/check_bug2_release_paths.py --selftest                 # selftest: all mutations caught (19/19)
python3 docs/verification/2026-09-11-0.12/t17/verify_bug_claims.py     # claim check: 64 ok, 0 bad
bash docs/verification/2026-09-11-0.12/t17/make_manifest.sh            # MANIFEST refreshed
```

`RC.txt` is `0` for all four capture entries, the per-entry logs are the committed
ones under `t17/`, and every historical count (`41` HEAD clamp-only, `65` route A,
`95` TRM.2) still reproduces from git via `replay_revisions.sh` - none of them was
re-pinned, they are counts of named revisions and stay HISTORICAL.

What this pass does NOT do: nothing here was run on a phone. Every device half of
BUG.1/BUG.3/BUG.4/BUG.5/BUG.6 - the restore on the SE, the banner reading 600
back, the cancel tap and the `[cleanup]` lines, the readonly run's write counter
reading 0, the CPU/wakeup/disk-write reports with the yields and the fsync
throttle in place - still waits for a device day, and readonly stays the only mode
on unproven device/iOS pairs.

---

## T19 (2026-09-18) - BUG.7 closed on the host: the window is the kalloc bucket the ZONE reports, not the struct's field span

Scope: the open half of BUG.7 (ROADMAP 0.13). BUG.1 step 3b made every 32-byte
write prove itself against an object, but the object a caller could name was the
inpcb's own field span (`0x160` from `filt+8`) - a statement about a struct, not
about the allocation. The zone an object came from carries the element size it
was allocated with, and that number is printed by the very check that panicked the
SE (`zone bound checks: buffer %p of length %zd overflows object %p of size %zd in
zone %p[%s%s]`), so it is readable off a kernelcache instead of guessed.

HARD RULE compliance: host only. No device command, no exploit run, no
`scripts/regression.sh` (its "Live device smoke" section would ssh to
`.w0lfsword/active_device`). Every command below either compiles C with the host
`cc`, runs a Python source lint, or runs the Theos cross-build.

What changed:

- `scripts/kc_zone_fields.py` (new): reads `struct zone`'s field offsets off a
  kernelcache or a decompressed Mach-O by locating the zone bound-check routine
  and following the zone register. Agrees across all eight kernelcaches on hand
  (17.0 + 18.4.1 t8030, 26.1/26.2 t8110, 26.6/26.6.1 on both boards): z_name
  +0x10, z_quo_magic +0x28, `z_elem_size` +0x34, z_elem_offs +0x36, flags +0x3c.
- `kexploit/krw_zone_size.c` / `.h` (new, engine + tweak build): the whole chain
  `pcb -> inpcbinfo.ipi_zone -> z_elem_size` with an injected reader
  (`krw_zone_bucket_for_pcb` - one canonical-pointer check per hop, one aligned
  qword read, masked to the u16, rejected unless it is a kalloc size class) and
  the window decision (`krw_zone_window_from_bucket`: bucket >= field span ->
  declare the bucket; 0/implausible -> keep the field span; a plausible bucket
  SMALLER than the field span -> refuse with window 0).
- `kexploit/kexploit_opa334.m`: `probe_zone_bucket_size()` now delegates to that
  chain through a one-line kernel-I/O wrapper (`probe_zone_read64`), and the
  window it feeds the clamp comes from `probe_window_for_pcb()`; a window of 0 is
  never written through (`if (windowSize == 0)` logs the contradiction and
  returns false). `run_write_test()` logs the bucket it *would* declare before any
  write, so a device log answers "does the zone read work" first.
- `offsets.m`: `off_zone_elem_size = 0x34` in all three version blocks
  (kernelcache-verified via the tool above).
- `tests/krw_zone_size_host_test.c` + `scripts/run_krw_zone_size_host_test.sh`
  (new): compiles the shipped decision file against a fake kernel window and
  drives the qword extraction, the size classes, every refused hop, the window
  verdicts and the SE's own shape end to end.
- `scripts/check_bug2_release_paths.py`: six new zone-window checks plus four new
  selftest mutations, so the delegation, the injected reader and the refusal
  branch cannot be edited away silently.
- `scripts/regression.sh`: the new harness in the BUG.1 host section (six host
  results now). `scripts/check_host_verification.sh`: new entry `krw_zone_size`,
  and the four re-pins below plus `_krw_zone_bucket_for_pcb` added to the app-side
  `nm` check.

### Evidence (all host, all re-run on the tree being landed)

```
bash scripts/run_krw_zone_size_host_test.sh              # checks=57 failures=0, PASS   sha256 5d1e08cf... (3637 B)
python3 scripts/check_bug2_release_paths.py              # 61 check(s) passed, 0 failed sha256 68e092eb... (7645 B)
python3 scripts/check_bug2_release_paths.py --selftest   # selftest: all mutations caught (23/23) sha256 eb73de27...
bash scripts/run_krw_zone_write_host_test.sh             # checks=116 failures=0, PASS  sha256 1386b0b6...
bash scripts/run_probe_restore_e2e_host_test.sh          # checks=56 failures=0, PASS   sha256 62f760e7...
bash scripts/check_host_verification.sh                  # 17 ok, 0 drift             sha256 f1074dbb...
bash scripts/check_host_verification.sh --with-builds    # 22 ok, 0 drift             sha256 f56ed9c6...
python3 scripts/test_offsets.py                          # PASS                       sha256 eead34fb...
./W0lfSword audit                                        # AUDIT PASSED (180 defs/0 dead, 61 files parse)
THEOS=$HOME/theos make package DEBUG=0                   # 1.5.0-13 arm64 .deb; dylib ships the new log strings
THEOS=$HOME/theos make libengine                         # OK: .theos/libengine/libw0lfengine.a (808K, 53 objects)
```

All eleven `rc=0`; raw logs, command lines and the sha256 of each are under
`docs/verification/2026-09-18-bug7/` (`capture.sh` reproduces the whole set,
`MANIFEST.txt` hashes it, `*.log` stays local by the usual rule). The engine
archive recorded there is `9acea9964e08984d43c9805c0d01247c1a55044479674b8620dd8e0129d7b035`
with a 0-byte build log (zero warnings, zero errors).

Link-level proof rather than "it compiles": `llvm-nm` shows the archive defines
`_krw_zone_bucket_for_pcb`, `_krw_zone_window_from_bucket` and
`_krw_zone_elem_size_from_qword` with `kexploit_opa334.o` referencing (U) them,
and the W0lfTerm app binary (0.20) lists `T _krw_zone_bucket_for_pcb` at
`0x10000b634` - and that symbol is now one of the nm entries the suite pins.

### Re-pins (old -> new, six entries, all in `scripts/check_host_verification.sh`)

| entry | was | now | why |
| --- | --- | --- | --- |
| `krw_zone_size` (new) | - | `5d1e08cf...` | the new harness; entry 3 of the suite, 57 checks |
| `bug2_release_paths` | `7c2c853a...` | `68e092eb...` | six zone-window checks added (55 -> 61 checks) |
| `bug2_release_paths_self` | `53a89a3b...` | `eb73de27...` | four mutations added (19 -> 23), all caught |
| `engine_lib_build` | `334a5c21...` | `573a137e...` | the archive gained a member: 804K/52 objects -> 808K/53 |
| `engine_lib_archive` | `32f6af7e...` | `9acea996...` | the same new member and the engine edit |
| `app_binary` | `167faf5d...` | `39615183...` | the app links the rebuilt archive (no app-side source change) |
| `app_static_symbols` | `5b4ab0e4...` | `abe1e022...` | `_krw_zone_bucket_for_pcb` added to the nm list, plus the address shifts above |

No HISTORICAL count was touched: the `41 checks` clamp-only revision, the `65`
route-A count, the `95` TRM.2 count and the withdrawn `65`/`43` figures all stay
what they were, since every one of them is the count of a nameable revision.

### What this pass does NOT prove

Nothing was run on a phone. The device half of BUG.7 is whether the zone read
(`pcbinfo -> ipi_zone -> z_elem_size`) returns a real bucket on the SE, and
whether the new `[STAGED] zone window: ...` line reports `bucket` rather than
`field span (bucket unknown)` there - that is the next device day, and readonly
stays the only mode offered on unproven device/iOS pairs until it happens. Two
things stay open by design: the `so_usecount` writes still go through
`early_kwrite64` (no field table for `struct socket` in this tree), and the clamp
still checks a block against the window it is *given*, so address trust remains
with the canonical-pointer guard plus the live-inpcb value check.
