# BUG.3 / BUG.4 / BUG.5 - closing verification (T16, task 16/16)

Host only: no device command, no exploit run, no commit. Every number below comes from a
command in `COMMANDS.txt` and its `.log` in this directory.

## The items, quoted

**W0lfSword `ROADMAP.md` section 0.12 (line 1044):**

> `BUG.3` - **the 120 s budget is shorter than a full walk on this device.** The 19:10
> run aborted at offset `0x1cc4000` of the mapping after exactly 120 s, i.e. roughly a
> quarter of the walk, so a full walk needs on the order of 8.5 minutes. Consequence: a
> budget-run will almost always report "cancelled" instead of reaching the target.
> Decide: raise the budget (and accept the resource axes), make it a persisted setting
> (e.g. 120 / 300 / 600 s), or speed up the walk (fewer retries per offset, bigger
> stride) so a full pass fits inside 120 s.

**W0lfSword `ROADMAP.md` section 0.12 (line 1114):**

> `BUG.4` - **no visible CANCEL in the app.** `cancel` / `abort` / `stop` work from the
> terminal, and the engine honours the flag at all three loop levels now, but there is no
> button. Add one that appears while a run is in flight (the run-state dot in the input
> bar is the natural place to hang it) so a spinning run can be stopped without typing
> into a busy UI.

**W0lfSword `ROADMAP.md` section 0.12 (line 1262):**

> `BUG.5` - **"readonly = zero writes" is too strong a claim.** It is zero KERNEL writes
> (`wolf_test_mode == 1` returns before the corruption), but the scan still dirties ~1 GB
> of file-backed memory and pegs a core; the wording in the app's settings row, the boot
> banner and this roadmap should say "no kernel writes" and keep the resource caveat next
> to it. Users read "zero writes" as "safe to leave running".

**W0lfTerm `ROADMAP.md` section 0.6 (the app-side half of the same three):** `BUG.3` (the
log fsync exceeded the disk-write budget), `BUG.1` (no visible CANCEL), `BUG.2`
("readonly (scan + validate offsets, zero kernel writes)" reads as safe to leave running).
The last line of the section, `BUG.5` in that file, is `keyBarSize` persisted but the bar
rebuilt - a different bug, untouched here.

## What closes each item, and the check that fails without it

| item | implementation | check that would fail without it |
| --- | --- | --- |
| `BUG.3` engine | `kexploit/kexploit_opa334.m:254-263`: `#define EXPLOIT_SCAN_BUDGET_SEC 600`, `static _Atomic int g_scanBudgetSec`, `SCAN_BUDGET_SEC()` relaxed load, `kexploit_set_scan_budget()` clamped to `[KEXPLOIT_SCAN_BUDGET_MIN, KEXPLOIT_SCAN_BUDGET_MAX]` = 30..1800 s (`kexploit/kexploit_opa334.h:31-32`); declared at `kexploit/kexploit_opa334.h:33-34`; read at the five in-walk guard sites (`:930` read race, `:1290`, `:1997` spray/race cycle, `:2150` offset walk, `:2447` pe_v2 walk) and in the six `-7`/message reads (`:933, :1999, :2152, :2449, :2742, :2769`) | `BUG.3 engine: the default budget is the one that fits the walk (600 s)`, `... the budget is settable and clamped, and every scan/spray loop reads it`, `... the cancel/budget check sits INSIDE each walk, not after it` |
| `BUG.3` app | `term_settings.m:50` `g_scanBudget = 600`, menu `kScanBudgetSecs` 120/300/600, `:99` pushes it into the engine at load, `:116` persists it (`w0lfterm.scanBudget`), `:175-182` `setScanBudget:` validates against the menu and pushes live; SET row `SettingsViewController.m:550-558` (`UISegmentedControl`), handler `:686-690`; `term_bridge.m:434` banner prints `kexploit_scan_budget()` read back from the engine | `BUG.3 app: the default budget matches the engine default and is pushed in at load`, `... a SET row exists, persists, and pushes every change into the engine`, `... the boot banner reads the budget back from the ENGINE` |
| `BUG.4` engine | stop flag `_Atomic g_stopRequested` (`:268-272`), checked at the top of the socket spray and inside both batch sprays plus each walk/race cycle (`:1289, :1996, :2071, :2149, :2163, :2446, :2499`); each `-7` exit goes through the release funnel | `BUG.4 engine: the socket spray honours a CANCEL (it is the longest pre-walk cost)`, `... pe_v1: every -7 exit goes through the funnel (no cancel exit leaks)`, `... the -7 cancel exit releases the spray AND the mappings` |
| `BUG.4` app | `TerminalViewController.m`: the 96 pt `statusDot` `UIControl` carries a `cancel` label, `dotTapped:` -> `term_bridge_cancel()`; the word is on exactly while `runState == 1` (`setRunState:` `:430-450`); `term_bridge.m:233-240` sets the flag and logs; `:327-332` the run loop treats `-7` as cancelled and returns | `BUG.4 app: a visible CANCEL control that is on only while a run is in flight`, `... the tap reaches the engine stop flag through the one bridge`, `... the run loop treats -7 as cancelled and STOPS (no retry)` |
| `BUG.5` engine | `kexploit/kwrite_counter.c/.h`: `kwrite_count_emit(src, len)` counts accepted/refused per route with a thread-local route stack; `kexploit_scan_writes()` / `_write_bytes()` / `_write_failures()` reset per attempt and are printed on every tearing-down exit | `BUG.5 counter: the ONE write primitive counts both outcomes`, `... each entry point attributes its writes to its own route`, `... the counters reset per attempt, are exported, and are printed` |
| `BUG.5` app | `term_bridge.m:243-253` `term_log_write_count()` prints `kexploit_scan_writes()` / `_write_bytes()` / `_write_failures()`; the readonly row says `scan + validate offsets, no kernel writes (engine-counted per run). still pegs a core + dirties ~1 GB of file-backed memory (SG.10)` - claim replaced by the measured number, resource caveat kept | `BUG.5 app: the run log carries the measured number, not the claim`, `BUG.5: no shipped log/UI string claims 'zero writes' any more` |

## Independent cross-check (not the lint)

The lint reads sources. So this pass also rebuilt and disassembled the artifact a device
would install (`2922ebb3c8138e6dcbd2efb95101afdceb26e409b83f8129d28bdb351eaf14c8`, rebuilt
from this tree by `scripts/check_host_verification.sh --with-builds`, hash unchanged) and
read the call graph out of it:

```
== +[TermSettings setScanBudget:] (the SET row -> engine) ==
100020c30:  str w8, [x9, #0xd38]                 ; g_scanBudget
100020c38:  bl  0x10000d1dc <_kexploit_set_scan_budget>
== -[TerminalViewController dotTapped:] (the CANCEL tap) ==
100007f44:  bl  0x10001df28 <_term_bridge_cancel>
== _term_bridge_cancel ==
10001df50:  bl  0x10000d254 <_kexploit_request_stop>
== _kexploit_request_stop ==
10000d26c:  stlr w8, [x9]                        ; the atomic the walks read
```

and the string markers in that binary: `cancel` 19, `pe_v2 scan stopped on request` 1,
`no kernel writes` 5, `zero kernel writes` **0**, `zero writes` **0**,
`measured by kwrite_counter` 1.

## Re-run

`capture.sh` was run twice (00:19 and 00:22). Second run: same rc=0, same
`host verification: 21 ok, 0 drift`, same pinned hashes, same marker counts.

## T16 re-run on the same tree (`rerun/`)

`rerun/rerun.sh` re-does the whole pass from the current working tree and writes
its own logs, so nothing above has to be taken on trust:

```
$ bash rerun.sh
rc=0   python3   SCAN_BUDGET_CANCEL_WRITES LINT PASS      (25 check(s) passed, 0 failed)
rc=0   python3   SCAN_BUDGET_CANCEL_WRITES LINT PASS      (--selftest: all mutations caught, 21/21)
rc=0   python3   PRESSURE_BUDGET LINT PASS                (8 check(s) passed, 0 failed)
rc=0   python3   PRESSURE_BUDGET LINT PASS                (--selftest: all mutations caught, 9/9)
rc=0   bash      KWRITE_COUNTER_HOST_TEST PASS            (checks=53 failures=0)
rc=0   bash      TWEAK_LOG_THROTTLE_HOST_TEST PASS        (checks=30 failures=0)
rc=0   env       host verification: 21 ok, 0 drift
rc=0   python3   callgraph checks ... 6 ok, 0 failed
rc=0   python3   invariant checks: 27 ok, 0 failed
rerun.sh: all commands rc=0
```

The two new files are the independent half: `rerun/callgraph_check.py` (BUG.3/4/5
call edges out of the linked Mach-O) and `rerun/invariant_check.py` (27
assertions over both trees plus the binary). `rerun/VERIFY.md` quotes the items
again and lists the outputs line by line; `rerun/RC.txt` is `0`.

## What is still open

- **Nothing in this task is device-verified.** No device command was run (hard rule 1), so
  the three device halves - a 600 s run reaching the target, a mid-run `cancel` tap
  printing the `[cleanup]` lines, and the readonly counter reading 0 after a run - are the
  next device day's measurements.
- `BUG.5` in W0lfTerm's 0.6 (`keyBarSize` persisted, bar rebuilt every time) is a different
  bug and stays open.
- The scan's own ~1 GB/cycle dirty-page half of the disk budget is W0lfSword `BUG.2`'s
  residual (printed by `check_pressure_budget.py`: 8064 MB dirtied per run, 7.88x the
  1 GB/day limit); this task bounds the log half only.
