# Per-item evidence index - 0.12 BUG.1..BUG.6 (+ W0lfTerm 0.6)

Everything here is HOST-ONLY: no exploit run, no `idevice*` command, no `ssh`.
cwd is `/home/kaffein/Desktop/W0lfSword` unless the row says otherwise.
`$SUITE` = `bash scripts/check_host_verification.sh --with-builds` re-runs every
command below and compares its exit status and output hash against the values
pinned in that script (and recorded in `docs/WORKLOG.md`).

| item | roadmap quote (headline) | change made | one-command artifact | observed |
|------|--------------------------|-------------|----------------------|----------|
| `BUG.1` 🛑 staged write probe panics the device; restore unconditionally, probe a field with no concurrent reader, clamp the writer | `W0lfSword/ROADMAP.md:450` - "A 32-byte write from `early_kwrite32bytes` ... lands past the end of a kalloc.96 object -> `zalloc.c:1322` zone bound check -> panic ... Fix: (1) restore the saved values unconditionally on every path ... (2) probe a field with no concurrent reader ... (3) clamp the writer so a 32-byte block that is not provably inside the target object is refused" | step 1 `kexploit/probe_restore_policy.c` (restore on every exit unless promoted); step 2 the probe moved to `inp6_chksum` (`kexploit/kexploit_opa334.m`); step 3/3b `kexploit/krw_zone_write.c` default-deny + `krw_zone_write_qword()` | `bash scripts/run_krw_zone_write_host_test.sh` | `checks=116 failures=0` / `KRW_ZONE_WRITE_HOST_TEST PASS`, exit 0 |
| `BUG.1` (field choice, whole-process property) | `W0lfSword/ROADMAP.md:450` - "never the icmp6 filter pointer the kernel dereferences on the next packet" | the probe preserves the chksum qword at `filt+8`; nothing in the compiled sources sends or receives on that socket | `python3 scripts/check_pressure_budget.py` | `7 check(s) passed, 0 failed`; `--selftest` `all mutations caught` (7/7), exit 0 |
| `BUG.1` end to end (task 13) - the overrun injected, then the restore path on the `-1` and `-7` exits | `W0lfSword/ROADMAP.md:450` - "Fix: (1) restore the saved values unconditionally on every path ... (3) clamp the writer so a 32-byte block that is not provably inside the target object is refused" | new host harness driving the two REAL engine files through save -> corrupt -> exit -> put-back; its own selftest mutates them four ways | `bash scripts/run_probe_restore_e2e_host_test.sh` (+ `python3 scripts/probe_restore_e2e_selftest.py --selftest`) | `checks=56 failures=0` / `PROBE_RESTORE_E2E_HOST_TEST PASS` (exit 0, raw sha256 `62f760e7...`); selftest `all mutations caught` (4/4), exit 0 |
| `BUG.2` leaked search mapping + socket spray on cancel | `W0lfSword/ROADMAP.md:703` - "pe_v2's cancel path returned before its cleanup and leaked the search mapping + memory object + socket spray" | release funnel per exit; pe_v2 abort path frees mapping/object/spray before `break` | `python3 scripts/check_bug2_release_paths.py` (+ `--selftest`) | `56 check(s) passed, 0 failed`; `selftest: all mutations caught` (19/19), exit 0 |
| `BUG.2` (cancel half, both walks) | same item | `pe_v1` `-7` funnel + `g_peV2Aborted` propagation | `python3 scripts/check_scan_budget_cancel_writes.py` | `25 check(s) passed, 0 failed`, exit 0 |
| `BUG.2` (remaining pressure sources - NOT patched, now pinned) | `W0lfSword/ROADMAP.md:703` - "the scan writes `randomMarker` into EVERY page of every search mapping (~30 MB mapped and dirtied per pass), and the initial spray holds ~22.5k sockets" | no technique change (deliberate); the arithmetic is now parsed out of the engine and pinned | `python3 scripts/check_pressure_budget.py` | pressure report: 3 GB -> `98304 page(s) 384 MB total 12 x 32.0 MB mapping(s)` (the item's "~30 MB" is wrong, see below); spray bound 22528; `7 check(s) passed` |
| `BUG.3` 120 s budget too short | `W0lfSword/ROADMAP.md:908` - "the 19:10 run aborted at offset `0x1cc4000` ... roughly a quarter of the walk, so a full walk needs on the order of 8.5 minutes" | `kexploit_set_scan_budget()` + 600 s default in both trees, SET row pushes, banner reads back | `python3 scripts/check_scan_budget_cancel_writes.py` | `ok BUG.3 engine: the default budget is the one that fits the walk (600 s)`; `ok BUG.3 app: the boot banner reads the budget back from the ENGINE`; 25 checks, 0 failed |
| `BUG.4` no visible CANCEL | `W0lfSword/ROADMAP.md:978` - "there is no button. Add one that appears while a run is in flight ... so a spinning run can be stopped without typing into a busy UI" | 96 pt `cancel` control `UIControl` -> `term_bridge_cancel()` -> `kexploit_request_stop()`; spray honours the flag; release on the `-7` path | `llvm-objdump-19 -d --macho dist/Payload/W0lfTerm.app/W0lfTerm` (cwd `~/Desktop/W0lfTerm`) | `-[TerminalViewController dotTapped:]` -> `bl _term_bridge_cancel`; `_term_bridge_cancel` -> `bl _kexploit_request_stop` |
| `BUG.5` "readonly = zero writes" claim | `W0lfSword/ROADMAP.md:1126` - "It is zero KERNEL writes ... but the scan still dirties ~1 GB of file-backed memory and pegs a core ... Users read \"zero writes\" as \"safe to leave running\"" | `kexploit/kwrite_counter.c` counts every emitted write per route; engine + app print the measured total; wording changed everywhere | `bash scripts/run_kwrite_counter_host_test.sh` | `checks=53 failures=0` / `KWRITE_COUNTER_HOST_TEST PASS`; lint check "no shipped log/UI string claims 'zero writes'"; binary strings `no kernel writes`=5, `zero kernel writes`=0 |
| `BUG.6` stale pairing blocks log pulls (docs) | `W0lfSword/ROADMAP.md:1224` - "After the watchdog panic the host got `Invalid HostID (-21)` on lockdown ... silently kills `idevicesyslog`, `idevicecrashreport` and the afc log pull" | app README section verified in place; the engine-side doc the item names was MISSING and was created | `test -f references/dead-device-usb-triage.md && wc -c references/dead-device-usb-triage.md` | `present`, `3205` bytes; `grep -c 'Invalid HostID'` = 2, `'idevicecrashreport'` = 2 |
| `BUG.6` disk-write throttling vs 1 GB/day (task's BUG.6; W0lfTerm `0.6 BUG.3`) | `W0lfTerm/ROADMAP.md:277` - "the log fsync added for panic forensics exceeded the disk-write budget on its own (1.07 GB/18 min against a 1 GB/day limit)" | `utils/tweak_log_policy.c` (rate gate, one process-wide gate, in both builds); `kexploit/kwrite_counter.h`-style counting not needed - the gate counts grants/suppressions | `bash scripts/run_tweak_log_throttle_host_test.sh` | `checks=30 failures=0`; counter report `10k lines 1 ms apart: gated 50 fsync(s) vs one-per-line 10000 (200x fewer)`; `510 ms -> 3 fsync(s)` at 10/100/450/5000 line/s |
| all | - | - | `$SUITE` | `host verification: 19 ok, 0 drift`, exit 0 |
| all | - | - | `./W0lfSword audit` | `AUDIT PASSED` (178 defs / 0 dead, 53 files parse) |

## Correction found while building the BUG.2 pressure pin

The item says the scan maps and dirties "~30 MB per pass". The source says
otherwise, and the checker prints the table for every RAM class:

```
3 GB    98304 page(s)  384 MB total  12 x  32.0 MB mapping(s)
4 GB   131072 page(s)  512 MB total  16 x  32.0 MB mapping(s)
6 GB   196608 page(s)  768 MB total  24 x  32.0 MB mapping(s)
8 GB    65536 page(s)  256 MB total   8 x  32.0 MB mapping(s)
```

The 3 GB row is the SE2/iPhone12,8 class the 2026-09-11 report came from:
`(3GB / 8) / 4096` = 98304 pages = 384 MB per cycle as 12 x 32 MB mappings, which
also matches the engine's own comment on the allocate-failure path ("up to 12 x
32MB per cycle", `kexploit/kexploit_opa334.m:2047-2049`). So the device-day
`1073.75 MB dirtied in 1083 s` is best read against 384 MB per cycle (re-dirtied
per spray/race cycle, up to 6), not against 30 MB. The "~30 MB" figure is left in
place in the item with this correction next to it rather than silently rewritten.

## What is NOT verified here (plainly)

- Nothing on a device. No exploit was run and no device command was issued; the
  staged probe's on-device restore, the cancel tap and the resource budgets are
  still device-day checks.
- The throttled fsync's BYTES: the gate bounds the calls (<= 1 per 200 ms per
  process); bytes-per-fsync is the file's own dirty pages.
- The BUG.2 technique option (allocate/scan/free one mapping at a time, or mark
  fewer pages) is deliberately not implemented - it changes a proven kernel path
  whose only verification is a device run. What is verified is that the pressure
  numbers cannot grow unnoticed (`scripts/check_pressure_budget.py`).
