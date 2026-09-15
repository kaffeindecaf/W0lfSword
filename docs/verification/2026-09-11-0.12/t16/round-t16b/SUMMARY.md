# T16 round 2 - BUG.3 / BUG.4 / BUG.5 re-verified from the working tree

Task 16/16, second pass. Host only: no device command, no exploit run, no git
command, nothing deleted. Every number below is this directory's output of
`bash rerun.sh` (see `rerun.output.log`, `RC.txt` = `0`); each command also has
its own `.log` next to this file.

The first pass's record is `../rerun/` (VERIFY.md, rerun.sh, RC.txt, *.log) and
is left untouched: this pass re-ran the same checks with a second script into a
second directory, so the same result exists twice from two independent runs.
Both print the same counts and the same artifact hashes as `../rerun/`, i.e. the
recorded evidence reproduces rather than being quoted forward.

## The items addressed, quoted

W0lfSword `ROADMAP.md` 0.12, line 1044 - this is `BUG.3`:

> `BUG.3` - **the 120 s budget is shorter than a full walk on this device.** The
> 19:10 run aborted at offset `0x1cc4000` of the mapping after exactly 120 s,
> i.e. roughly a quarter of the walk, so a full walk needs on the order of 8.5
> minutes. Consequence: a budget-run will almost always report "cancelled"
> instead of reaching the target. Decide: raise the budget (and accept the
> resource axes), make it a persisted setting (e.g. 120 / 300 / 600 s), or speed
> up the walk (fewer retries per offset, bigger stride) so a full pass fits
> inside 120 s.

W0lfSword `ROADMAP.md` 0.12, line 1136 - this is `BUG.4`:

> `BUG.4` - **no visible CANCEL in the app.** `cancel` / `abort` / `stop` work
> from the terminal, and the engine honours the flag at all three loop levels
> now, but there is no button. Add one that appears while a run is in flight
> (the run-state dot in the input bar is the natural place to hang it) so a
> spinning run can be stopped without typing into a busy UI.

W0lfSword `ROADMAP.md` 0.12, line 1303 - this is `BUG.5`:

> `BUG.5` - **"readonly = zero writes" is too strong a claim.** It is zero
> KERNEL writes, but ... the wording in the app's settings row, the boot banner
> and this roadmap should say "no kernel writes" and keep the resource caveat
> next to it.

W0lfTerm `ROADMAP.md` 0.6, lines 136 / 258 / 354 - the app halves of the same
three (the numbering differs in this repo):

> `BUG.1` - no visible CANCEL. Shipped in 0.14: the run-state dot in the input
> bar is a 36 pt control; tapping it while a run is in flight calls the engine's
> stop flag (all three loops honour it) ...

> `BUG.2` - "readonly (scan + validate offsets, zero kernel writes)" reads as
> "safe to leave running". ... Reword to "no kernel writes" and keep the
> resource caveat on the same row.

> `BUG.3` - the log fsync added for panic forensics exceeded the disk-write
> budget on its own (1.07 GB/18 min against a 1 GB/day limit). Rate limited to
> one fsync per 200 ms in 0.12; a panic now loses at most 200 ms of lines.

(W0lfTerm 0.6 `BUG.5` - `keyBarSize` persisted but the bar rebuilt on every
`applySettings` - is a different bug and stays open.)

## The commands, with their output

```
$ python3 scripts/check_scan_budget_cancel_writes.py
25 check(s) passed, 0 failed
SCAN_BUDGET_CANCEL_WRITES LINT PASS                                     rc=0
$ python3 scripts/check_scan_budget_cancel_writes.py --selftest
selftest: all mutations caught   (21 mutations)                         rc=0
$ python3 scripts/check_pressure_budget.py
8 check(s) passed, 0 failed
PRESSURE_BUDGET LINT PASS                                               rc=0
$ python3 scripts/check_pressure_budget.py --selftest
selftest: all mutations caught   (9 mutations)                          rc=0
$ bash scripts/run_kwrite_counter_host_test.sh
checks=53 failures=0
KWRITE_COUNTER_HOST_TEST PASS                                           rc=0
$ bash scripts/run_tweak_log_throttle_host_test.sh
checks=30 failures=0
TWEAK_LOG_THROTTLE_HOST_TEST PASS                                       rc=0
$ W0LF_TERM=/home/kaffein/Desktop/W0lfTerm \
      bash scripts/check_host_verification.sh --with-builds
ok   engine_lib_build      rc=0 334a5c211aedbcef...   (88 bytes)
ok   engine_lib_archive    263ae60d49fd0c15...
ok   app_ipa_build         rc=0 e4f7235f621013d6...   (2282 bytes)
ok   app_binary            2922ebb3c8138e6d...
ok   app_static_symbols    rc=0 fd7a746a6f461d09...   (943 bytes)
host verification: 21 ok, 0 drift                                       rc=0
```

Both halves were rebuilt by that last command, so these are this tree's
artifacts (`binary_hash.log`), not a reused build:

```
263ae60d49fd0c1557ac8d26f365b6d9d4c8475387ab45451306da31167f9661  .theos/libengine/libw0lfengine.a
2922ebb3c8138e6dcbd2efb95101afdceb26e409b83f8129d28bdb351eaf14c8  W0lfTerm dist/Payload/W0lfTerm.app/W0lfTerm
```

### BUG.3 (scan budget)

Engine, read in the source (not inferred from a symbol name):

```
kexploit/kexploit_opa334.m:254  #define EXPLOIT_SCAN_BUDGET_SEC 600
kexploit/kexploit_opa334.m:255  static _Atomic int g_scanBudgetSec = EXPLOIT_SCAN_BUDGET_SEC;
kexploit/kexploit_opa334.m:256  #define SCAN_BUDGET_SEC() ((int)atomic_load_explicit(&g_scanBudgetSec, __ATOMIC_RELAXED))
kexploit/kexploit_opa334.m:258  void kexploit_set_scan_budget(int seconds) {
kexploit/kexploit_opa334.m:259      if (seconds < KEXPLOIT_SCAN_BUDGET_MIN) seconds = KEXPLOIT_SCAN_BUDGET_MIN;
kexploit/kexploit_opa334.m:260      if (seconds > KEXPLOIT_SCAN_BUDGET_MAX) seconds = KEXPLOIT_SCAN_BUDGET_MAX;
kexploit/kexploit_opa334.m:263  int kexploit_scan_budget(void) { return SCAN_BUDGET_SEC(); }
```

`grep -rn "define EXPLOIT_SCAN_BUDGET_SEC"` over the engine finds exactly one
definition (the second hit is the history comment saying the old 120 s one lived
there), so the duplicate-define the 0.12 note mentions is gone. 13 reads of
`SCAN_BUDGET_SEC()` sit in the spray / race / pe_v1 / pe_v2 guards
(`invariant_check.py`: "the value is read at every guard site ... 13 read(s)").

App: `term_settings.m:50` default `600`, menu `{120, 300, 600}`, pushed at load
(`:99`) and on every change (`:182`), persisted under `w0lfterm.scanBudget`; the
row is `SettingsViewController.m:550-558` -> `scanBudgetChanged:` (`:686`); the
boot banner prints the value read back FROM the engine
(`term_bridge.m:433-434`, `kexploit_scan_budget()`).

Lint lines: "BUG.3 engine: the default budget is the one that fits the walk
(600 s)", "... the budget is settable and clamped, and every scan/spray loop
reads it", "... the cancel/budget check sits INSIDE each walk", "BUG.3 app: the
default budget matches the engine default and is pushed in at load", "BUG.3 app:
a SET row exists, persists, and pushes every change into the engine", "BUG.3 app:
the boot banner reads the budget back from the ENGINE" - all `ok`.

### BUG.4 (visible CANCEL)

App: 96 pt `UIControl` in the input bar carrying the word `cancel`
(`TerminalViewController.m:192-208`), `_Static_assert(TERM_CANCEL_CONTROL_W ==
96)` on the label+gap+dot enum, label alpha `1.0` only at `runState == 1`
(`:441-453`, faded, frames never move), VoiceOver label `cancel` / hint "stop
the running kernel scan" (`:474-486`), `dotTapped:` -> `TermClick()` +
`termHapticLight()` + `term_bridge_cancel()` (`:490-495`).

Engine/bridge: `term_bridge.m:233-240` (`g_exploitRunning` ? `kexploit_request_stop()`
+ log : "[w0lf] nothing is running"); 7 `kexploit_stop_requested()` sites in the
engine (up-front spray, both batch sprays, both walks, the read race); the app's
run loop treats `-7` as cancelled and returns without retrying
(`term_bridge.m:327-332`).

Call graph straight out of the linked binary (`callgraph_check.log`):

```
ok   -[TerminalViewController dotTapped:]           100007f44: bl _term_bridge_cancel
ok   _term_bridge_cancel                            10001df50: bl _kexploit_request_stop
ok   _kexploit_request_stop                         10000d26c: stlr w8, [x9]
ok   +[TermSettings setScanBudget:]                 100020c38: bl _kexploit_set_scan_budget
ok   -[SettingsViewController scanBudgetChanged:]   100026afc: ldr x1, [x8, #0x5f0] ; Objc selector ref: setScanBudget:
ok   _term_log_write_count                          10002016c: bl _kexploit_scan_writes | 100020174: bl _kexploit_scan_write_bytes | 10002017c: bl _kexploit_scan_write_failures
callgraph checks read out of .../W0lfTerm: 6 ok, 0 failed
```

### BUG.5 (measured writes instead of the claim)

Engine: `kwrite_count_emit()` is called in `early_kwrite32bytes` - the one
primitive that emits bytes to the kernel (`grep -rn setsockopt kexploit/ utils/`
finds three sites: the OOB read probe, the socket probe's own corruption write,
and `early_kwrite32bytes` itself, which is what every `kwrite*` / `kwritebuf` /
probe path funnels into). `kwrite_count_reset()` runs per attempt
(`kexploit_opa334.m:2701`, also from `kexploit_telemetry_reset()`), and the
getters are exported:

```
kexploit/kexploit_opa334.m:167  uint64_t kexploit_scan_writes(void) { return kwrite_count_total(); }
kexploit/kexploit_opa334.m:170  uint64_t kexploit_scan_write_bytes(void) { return kwrite_count_bytes(); }
kexploit/kexploit_opa334.m:173  uint64_t kexploit_scan_write_failures(void) { return kwrite_count_failed_total(); }
```

App: `term_bridge.m:247-253` `term_log_write_count()` prints
`[w0lf] kernel writes ...: N write(s) / M byte(s) (engine-counted, reset per
attempt; refused: R)`, called after each attempt (`:305`). Wording: the readonly
row / banner / SET red line all say "no kernel writes" plus the resource caveat.

Shipped strings, in the linked binary (`linked_binary_marker_counts.log`):

```
  cancel                             19
  pe_v2 scan stopped on request      1
  no kernel writes                   5
  zero kernel writes                 0
  zero writes                        0
  measured by kwrite_counter         1
  engine-counted                     2
```

The only remaining `zero kernel writes` / `zero writes` text in either tree is in
comments that record the bug (`kwrite_counter.h:5`, `kexploit_opa334.h:45`,
`term_settings.m:147`, the README's change history, the roadmaps) - a raw grep
hits the record of the bug, which is why `invariant_check.py` strips `//`
comments before matching and also asserts on the binary's strings.

## This pass's own checks (independent readers, host only)

`../rerun/callgraph_check.py` -> `6 ok, 0 failed` (above) and
`../rerun/invariant_check.py` -> `27 ok, 0 failed` (`invariant_check.log`),
including `BUG.3: the budget is clamped to [MIN, MAX]  [header 30..1800, both
bounds applied in the setter]`, `BUG.4: the label is visible only while a run is
in flight`, `BUG.5: the linked binary carries 0 'zero writes' / 'zero kernel
writes'  [zero writes=0 zero kernel writes=0 no kernel writes=5]`, and the eight
`linked binary defines _kexploit_...` / `_kwrite_count_emit` assertions.

## Still open (stated, not implied)

- Nothing here is device-verified, and no device command was run (hard rule 1).
  The three device measurements stay open: a 600 s run reaching the target, a
  mid-run `cancel` tap printing the `[cleanup]` lines, and the readonly run's
  counter reading 0.
- The scan's own dirty-page cost (printed by `check_pressure_budget.py` as
  `384 MB per cycle x 7 cycle(s) x 3 attempt(s) = 8064 MB dirtied per run (7.88x
  the limit)`) is W0lfSword `BUG.2`'s residual; this task bounds the log half
  (`BUG.6`), not that one.
- The budget/cancel/counter checks are structural plus link-level. They prove the
  wiring in the artifact a device would install, not the runtime behaviour.
