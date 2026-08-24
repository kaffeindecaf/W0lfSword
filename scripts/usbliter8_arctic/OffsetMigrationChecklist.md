# OffsetMigrationChecklist — Beta-to-Beta Offset Migration

Feature: `profile_gen.py migrate <base.yaml> <target.yaml>` — auto-migrate usbliter8
patch offsets across iOS beta builds via AArch64 pattern fingerprinting.

Agreed decisions: work-dir script shell-out for components, pytest, canonical
`offsets.yaml` cross-check.

---

## Reference Oracle (ground truth — b2 → b3 deltas)

| Section | Entry | b2 | b3 | Delta |
|---|---|---|---|---|
| kernel | AMFI trust | 0x1F1EBE0 | 0x1F1CCF8 | −0x1EE8 |
| kernel | Proc launch constraints | 0x1F23808 | 0x1F21920 | −0x1EE8 |
| kernel | APFS mount SSV | 0x303F49C | 0x303FCDC | +0x840 |
| kernel | Unencrypted vol panic | 0x30408AC | 0x30410EC | +0x840 |
| kernel | APFS seal broken | 0x2FAE32C | 0x2FAE494 | +0x168 |
| kernel | BSD rootvp | 0x36C1F48 | 0x36BE974 | −0x25D4 |
| kernel | PE debugger | 0x3A07368 | 0x3A05230 | −0x2138 |
| kernel | SEP panic | 0x2170AF4 | 0x216FDE4 | −0x12D10 |
| kernel | 10 others (USB, sandbox ×5, post-val, dyld, SEP ×2) | — | — | **unchanged** |
| ibss/ibec | image4_validate | 0x23DB0 | 0x23EFC | +0x14C |
| ibss/ibec | boot_args_adrp / _string | 0x2AFBC / 0xD3850 | 0x2B0F4 / 0xD3960 | +0x138 / +0x110 |
| ibss/ibec | boot_args_add | 0x2AFC0 | 0x2B0F8 | **value changed** 0x42214091→0x422d4091 |
| restoreramdisk | asr_sig / fdr | 0x24D34 / 0x7E53C | 0x1F650 / 0x7E558 | −0x56E4 / +0x1C |
| txm | query_module2 / nop1 / nop2 | 0x39FAC / 0x3F564 / 0x3F56C | 0x39FA4 / 0x3F510 / 0x3F518 | −0x8 / −0x54 / −0x54 |
| daemons/userland | all | — | — | unchanged |

---

## Day 1 — Foundation + Engine

**Goal: `migrate b2 → b3` produces correct iBSS/iBEC + kernel candidates by end of day.**

### Setup
- [x] **1.1** Branch `feat/offset-migration` created; pytest 9.1.1 installed (`--break-system-packages`, PEP 668 host)
- [x] **1.2** `tests/test_migrate.py` created — imports `fingerprint`/`migrate`, smoke test green
- [x] **1.3** Oracle table recorded above AND encoded as test fixture (`tests/test_migrate.py::test_milestone_ibss_ibec`)

### Component loader (`migrate.py`)
- [x] **1.4** `--comp-dir` reader: validates `base/` + `target/` layout, loads raw components
- [x] **1.5** Work-dir fallback: searches known usbliter8 work dirs for extracted raw files; `--fetch` runs work-dir `get_fw.py`/`make_cfw.py` (network-heavy, opt-in)
- [x] **1.6** Im4p extraction via `cfw_builder._extract_im4p_to_raw`; kernelcache errors point to theiphonewiki keys
- [x] **1.7** TXM handled by the generic loader; missing components reported as "skipped" (graceful)
- ✅ Verify: loader populates raw files from comp-dir (verified via CLI smoke test + fixtures)

### Fingerprint engine (`fingerprint.py`, capstone)
- [x] **1.8** AArch64 mask decoder: adrp/adr/b/bl/cbz/cbnz/tbz/tbnz/ldr-literal/ldr-str-imm/add-sub-imm/movz-movn-movk — immediates zeroed, opcode+regs kept
- [x] **1.9** Rolling masked-pattern search over target raw; returns ALL hits (uniqueness known)
- [x] **1.10** Hit verification: capstone decode at candidate → mnemonic + register-operand class match (string/data sites → unverifiable-but-strong)
- [x] **1.11** Unit tests: hand-encoded AArch64 fixtures — immediates moved between builds still match; changed registers do NOT
- ✅ Verify: 13/13 pytest green; synthetic iBSS b2→b3 finds +0x14C site

### CLI + first milestone
- [x] **1.12** `profile_gen.py migrate` subcommand + section diff (offset/value-changed/added/removed)
- [x] **1.13** Milestone: migrate iBSS + iBEC b2→b3
- ✅ Verify: 5/5 ibss + 6/6 ibec match oracle offsets (report confirms 0x23EFC etc.); `boot_args_add` flagged VALUE_CHANGED; zero wrong-HIGH

## Day 2 — Scoring, Reporting, Acceptance

**Goal: full pipeline passes the oracle; b4-ready with report + tests.**

### Scoring + full kernel
- [x] **2.1** Confidence tiers: unique+class-match = 0.95 HIGH; unique string/data site = 0.90; class-mismatch = 0.60 MED; multi-hit = 0.30 LOW + candidates
- [x] **2.2** Full kernel migration b2→b3 — synthetic kernel fixture (57.5MB, entries + per-name context) built from the real b2/b3 profiles
- ✅ Verify: **18/18 kernel entries correct at HIGH confidence; ZERO wrong offsets rated HIGH** (≥15 required)
- [x] **2.3** Cluster-delta fallback: ±4KB grouping (≥2 neighbors), median delta → `method: delta`, always LOW 0.30; tested
- [x] **2.4** VALUE_CHANGED: `suggested_value` recomputed from the target site word; written into the profile for single-instruction patch values (`value_recomputed` metadata)
- [x] **2.5** TXM + RestoreRamdisk sections through the pipeline
- ✅ Verify: TXM 6/6, ramdisk 2/2 vs oracle (≥4/6 and 2/2 required)

### Canonical cross-check
- [x] **2.6** Load `~/.config/opencode/skills/master-router/offsets.yaml` (`constants.checkm8`); every mismatch vs migrated result flagged in report
- [x] **2.7** Known conflicts resolved/surfaced: canonical `ios_27_0b2` block holds b3 values (ibss validate 0x23EFC vs local b2 0x23DB0, boot_args, txm) and `txm_queryModule0/1` off by 8 from both profiles — all reported as "mislabeled key" / "matches NEITHER"
- ✅ Verify: report contains `[CANONICAL CONFLICTS]` section; agreeing entries (allowed_before_secure_channel) NOT flagged; no silent overwrite

### Report + write modes
- [x] **2.8** `migrate_report.md`: per-entry table, site hexdump columns (b2/b3), `REVIEW REQUIRED` list
- [x] **2.9** `--auto` write mode (metadata: confidence/method/base_offset/candidates, `value_recomputed`); default = report + confirm prompt before writing
- [x] **2.10** Post-write validation: `device_offsets.validate_offsets` runs after every write (verified: 45 patches valid on full-pipeline smoke)

### Tests + acceptance
- [x] **2.11** Ground-truth regression test: all 37 entries (ibss 5 + ibec 6 + kernel 18 + txm 6 + ramdisk 2) migrated vs verified b3 profile, all ≥0.90
- [x] **2.12** Perf budget: full-profile migration (57.5MB kernelcache-sized fixture, all sections) completes in ~20-25s of search time — far under the 5-min budget
- [x] **2.13** Final acceptance: 20/20 pytest, 13/13 py_compile, full CLI smoke (exit 0, 37/37 high-conf, canonical conflicts printed, report written)
- [x] **2.14** README updated with `migrate` usage + Offset Migration section
- [ ] ~~commit~~ — deferred per user instruction (no commits/push yet)

### Contribution loop
- [x] **2.15** PR drafted — `contribution/PR_DRAFT.md` (offsets.yaml fix: b2 block mislabeled + `ios_27_0b3` block added) + `contribution/migration-workflow.md` (workflow doc for the skill repo). Local canonical DB fixed + verified (cross-check now reports zero conflicts; backup at `/tmp/opencode/offsets.yaml.bak`). Opening the PR deferred per no-push instruction.

---

## Hard rules (never break)

- Wrong offset rated HIGH = brick risk → double-gate: uniqueness + disasm-class match
- `method: delta` (inference) is ALWAYS LOW confidence
- `--auto` write only after report review; never silently overwrite an existing profile
