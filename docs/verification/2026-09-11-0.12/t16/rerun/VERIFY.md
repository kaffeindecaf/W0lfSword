# T16 verification pass - BUG.3 / BUG.4 / BUG.5, re-run on the current tree

Task 16/16. Host only: no device command, no exploit run, no git command, nothing
deleted. Every number below is the output of `rerun.sh` in this directory; each
command also has its own `.log` here.

Re-run: `bash rerun.sh` (~2.5 min, both cross-builds) or
`SKIP_BUILDS=1 bash rerun.sh` (~40 s, host checks only). `RC.txt` holds the exit
status; `rerun.output.log` is the whole run.

## The items addressed, quoted

W0lfSword `ROADMAP.md` 0.12 (line 1044):

> `BUG.3` - **the 120 s budget is shorter than a full walk on this device.** The
> 19:10 run aborted at offset `0x1cc4000` of the mapping after exactly 120 s,
> i.e. roughly a quarter of the walk, so a full walk needs on the order of 8.5
> minutes. ... Decide: raise the budget (and accept the resource axes), make it a
> persisted setting (e.g. 120 / 300 / 600 s), or speed up the walk ...

W0lfSword `ROADMAP.md` 0.12 (line 1114):

> `BUG.4` - **no visible CANCEL in the app.** ... Add one that appears while a run
> is in flight (the run-state dot in the input bar is the natural place to hang
> it) so a spinning run can be stopped without typing into a busy UI.

W0lfSword `ROADMAP.md` 0.12 (line 1262):

> `BUG.5` - **"readonly = zero writes" is too strong a claim.** It is zero KERNEL
> writes ... the wording in the app's settings row, the boot banner and this
> roadmap should say "no kernel writes" and keep the resource caveat next to it.

W0lfTerm `ROADMAP.md` 0.6 (line 134) - the app half of the same three: `BUG.3`
(1.07 GB/18 min fsync blowout against the 1 GB/day limit -> the disk half and the
scan budget), `BUG.1` (no visible CANCEL), `BUG.2` ("readonly ... zero kernel
writes" reads as safe to leave running). `BUG.5` in that file is `keyBarSize`
(the bar is rebuilt on every `applySettings`) - a different bug, untouched.

## Commands actually run, with their output

```
$ python3 scripts/check_scan_budget_cancel_writes.py
25 check(s) passed, 0 failed
SCAN_BUDGET_CANCEL_WRITES LINT PASS                                    rc=0
$ python3 scripts/check_scan_budget_cancel_writes.py --selftest
selftest: all mutations caught          (21 mutations, one per check)  rc=0
$ python3 scripts/check_pressure_budget.py
8 check(s) passed, 0 failed
PRESSURE_BUDGET LINT PASS                                              rc=0
$ python3 scripts/check_pressure_budget.py --selftest
selftest: all mutations caught          (9 mutations)                 rc=0
$ bash scripts/run_kwrite_counter_host_test.sh
checks=53 failures=0
KWRITE_COUNTER_HOST_TEST PASS                                          rc=0
$ bash scripts/run_tweak_log_throttle_host_test.sh
checks=30 failures=0
TWEAK_LOG_THROTTLE_HOST_TEST PASS                                      rc=0
$ W0LF_TERM=/home/kaffein/Desktop/W0lfTerm \
      bash scripts/check_host_verification.sh --with-builds
ok   engine_lib_build      rc=0 334a5c211aedbcef...      (88 bytes)
ok   engine_lib_archive    263ae60d49fd0c15...
ok   app_ipa_build         rc=0 e4f7235f621013d6...      (2282 bytes)
ok   app_binary            2922ebb3c8138e6d...
ok   app_static_symbols    rc=0 fd7a746a6f461d09...      (943 bytes)
host verification: 21 ok, 0 drift                                      rc=0
```

Both artifacts were rebuilt by that last command, so the hashes below are this
tree's, not a reused build (`binary_hashes.log`):

```
263ae60d49fd0c1557ac8d26f365b6d9d4c8475387ab45451306da31167f9661  .theos/libengine/libw0lfengine.a
2922ebb3c8138e6dcbd2efb95101afdceb26e409b83f8129d28bdb351eaf14c8  W0lfTerm dist/Payload/W0lfTerm.app/W0lfTerm
```

The BUG.3 / BUG.4 / BUG.5 checks inside the 25-check lint, all `ok`:

```
ok   BUG.3 engine: the default budget is the one that fits the walk (600 s)
ok   BUG.3 engine: the budget is settable and clamped, and every scan/spray loop reads it
ok   BUG.3 engine: the cancel/budget check sits INSIDE each walk, not after it
ok   BUG.3 app: the default budget matches the engine default and is pushed in at load
ok   BUG.3 app: a SET row exists, persists, and pushes every change into the engine
ok   BUG.3 app: the boot banner reads the budget back from the ENGINE
ok   BUG.4 engine: the socket spray honours a CANCEL (it is the longest pre-walk cost)
ok   BUG.4 engine pe_v1: every -7 exit goes through the funnel (no cancel exit leaks)
ok   BUG.4 engine pe_v1: the -7 cancel exit releases the spray AND the mappings
ok   BUG.4 engine pe_v2: the aborted (-7) path frees the mapping, the object and the spray
ok   BUG.4 engine: both cancel paths reach the app as -7 (cancelled, not failed)
ok   BUG.4 app: a visible CANCEL control that is on only while a run is in flight
ok   BUG.4 app: the tap reaches the engine stop flag through the one bridge
ok   BUG.4 app: the run loop treats -7 as cancelled and STOPS (no retry)
ok   BUG.5 counter: the module exists and exposes the measured getters
ok   BUG.5 counter: the ONE write primitive counts both outcomes
ok   BUG.5 counter: each entry point attributes its writes to its own route
ok   BUG.5 engine: the counters reset per attempt, are exported, and are printed
ok   BUG.5 app: the run log carries the measured number, not the claim
ok   BUG.5: no shipped log/UI string claims 'zero writes' any more
```

## Two checkers written for this pass (the lint reads sources; these read the artifact)

A lint that drifts from the tree, or a claim that only exists in roadmap prose,
would still pass the lint. So this pass adds two independent readers:

`callgraph_check.py` - drives the call graph out of the linked Mach-O
(`linked_binary.dis`, `callgraph_check.log`):

```
ok   -[TerminalViewController dotTapped:]          100007f44: bl _term_bridge_cancel
ok   _term_bridge_cancel                           10001df50: bl _kexploit_request_stop
ok   _kexploit_request_stop                        10000d26c: stlr w8, [x9]
ok   +[TermSettings setScanBudget:]                100020c38: bl _kexploit_set_scan_budget
ok   -[SettingsViewController scanBudgetChanged:]  100026afc: ldr x1, [x8, #0x5f0] ; Objc selector ref: setScanBudget:
ok   _term_log_write_count                         10002016c: bl _kexploit_scan_writes | 100020174: bl _kexploit_scan_write_bytes | 10002017c: bl _kexploit_scan_write_failures
callgraph checks read out of .../W0lfTerm: 6 ok, 0 failed
```

`invariant_check.py` - 27 assertions over both trees plus the binary
(`invariant_check.log`):

```
ok   BUG.3: the engine has a default budget  [#define EXPLOIT_SCAN_BUDGET_SEC 600]
ok   BUG.3: the app has the same default budget  [engine 600 / app 600]
ok   BUG.3: the default is the one that fits the walk (600 s, not the old 120)
ok   BUG.3: the budget is clamped to [MIN, MAX]  [header 30..1800, both bounds applied in the setter]
ok   BUG.3: the setter writes the same atomic the accessor reads
ok   BUG.3: the value is read at every guard site (>= 6 reads incl. the walks)  [13 read(s) of SCAN_BUDGET_SEC()]
ok   BUG.4: the app has a tappable control with the word 'cancel'
ok   BUG.4: the label is visible only while a run is in flight
ok   BUG.4: the tap reaches the engine's stop flag through the one bridge
ok   BUG.4: the control has an accessible name for VoiceOver
ok   BUG.4: the engine honours the stop inside the spray and both walks  [7 stop-flag check(s) in the engine]
ok   BUG.5: one write primitive counts, both outcomes
ok   BUG.5: the counters reset per attempt  [2 reset site(s)]
ok   BUG.5: the engine prints the measured total on a run exit
ok   BUG.5: the app logs the measured number
ok   BUG.5: the app's readonly row does NOT claim 'zero writes'
ok   BUG.5: the linked binary carries 0 'zero writes' / 'zero kernel writes'  [zero writes=0 zero kernel writes=0 no kernel writes=5]
ok   BUG.5: the binary carries the measured-writes line
ok   linked binary defines _kexploit_set_scan_budget / _kexploit_scan_budget /
     _kexploit_scan_writes / _kexploit_scan_write_bytes / _kexploit_scan_write_failures /
     _kexploit_request_stop / _kexploit_stop_requested / _kwrite_count_emit
invariant checks: 27 ok, 0 failed
```

Both scripts strip `//`-comments before matching source text on purpose: these
trees record the old wording verbatim in history comments (the engine still notes
`the old hard-coded #define EXPLOIT_SCAN_BUDGET_SEC 120 lived here`, the app still
notes that `"zero kernel writes"` read as "safe to leave running"). A raw grep
counts the record of the bug as an instance of the bug - the first draft of
`invariant_check.py` failed on exactly those two lines, which is why the stripping
is in the checker and not a caveat in this file.

Strings in the linked binary (`linked_binary_marker_counts.log`):

```
  cancel                             19
  pe_v2 scan stopped on request      1
  no kernel writes                   5
  zero kernel writes                 0
  zero writes                        0
  measured by kwrite_counter         1
  engine-counted                     2
```

## What is measured where, one line each

- `BUG.3` engine: `kexploit_set_scan_budget()` / `kexploit_scan_budget()`
  (`kexploit/kexploit_opa334.m:254-263`), `_Atomic g_scanBudgetSec`, default
  `EXPLOIT_SCAN_BUDGET_SEC 600`, clamped 30..1800 (`kexploit_opa334.h:31-32`), 13
  reads of `SCAN_BUDGET_SEC()` inside the spray/race/pe_v1/pe_v2 loops.
- `BUG.3` app: `term_settings.m:50` default 600, menu 120/300/600, pushed at load
  (`:99`) and on every change (`:182`), persisted (`w0lfterm.scanBudget`), row
  `SettingsViewController.m:550-558` -> `scanBudgetChanged:` (`:686`), banner
  prints the value read back from the engine (`term_bridge.m:434`).
- `BUG.4` app: 96 pt `UIControl` (`_Static_assert(TERM_CANCEL_CONTROL_W == 96)`)
  with the word `cancel`, visible only while `runState == 1`, `dotTapped:` ->
  `term_bridge_cancel()` -> `kexploit_request_stop()`, VoiceOver label `cancel`.
- `BUG.4` engine: 7 `kexploit_stop_requested()` sites (up-front spray, both batch
  sprays, both walks, the read race), every `-7` exit through the release funnel.
- `BUG.5` engine: `kwrite_count_emit()` in the one primitive that emits bytes
  (`early_kwrite32bytes`), reset per attempt, exported and printed on teardown.
- `BUG.5` app: `term_log_write_count()` -> `[w0lf] kernel writes ...: N write(s) /
  M byte(s) (engine-counted, reset per attempt; refused: R)`, the readonly row
  says "no kernel writes (engine-counted per run)" plus the resource caveat.

## Still open (stated, not implied)

- Nothing here is device-verified. No device command was run (hard rule 1), so the
  three device measurements remain: a 600 s run reaching the target, a mid-run
  `cancel` tap printing the `[cleanup]` lines, and the readonly counter reading 0
  after a run.
- The scan's own dirty-page cost (~1 GB/cycle-class) is W0lfSword `BUG.2`'s
  residual, printed by `check_pressure_budget.py` as
  `scan: 384 MB per cycle x 7 cycle(s) x 3 attempt(s) = 8064 MB dirtied per run
  (7.88x the limit)`; this task bounds the log half, not that one.
- The clamp measures writes that LAND through the one primitive; a write the
  zone-writer clamp refuses never reaches the counter (that is what the refusal
  counter counts).
