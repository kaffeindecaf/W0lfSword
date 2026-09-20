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
| kernel | Post-validation | 0x1F2B368 | 0x1F29480 | −0x1EE8 |
| kernel | Check dyld policy (site 1 / site 2) | 0x1F2B8C8 / 0x1F2B8D4 | 0x1F299E0 / 0x1F299EC | −0x1EE8 |
| kernel | 7 others (USB, sandbox ×5, SEP ×2) | — | — | **unchanged** |

> Corrected 2026-09-20 by `source_audit.py`: the b3 profile had carried the b2
> values for post-validation and the dyld-policy site, and the dyld site 2
> entry was missing. Upstream `work-27.0b3/make_cfw.py` patches 0x1F29480,
> 0x1F299E0 and 0x1F299EC, and the whole AMFI compilation unit shifts by the
> same −0x1EE8. `txm.query_module0/1` were stale in the same way (0x39CB0 /
> 0x39E18 instead of 0x39CA8 / 0x39E10).
| ibss/ibec | image4_validate | 0x23DB0 | 0x23EFC | +0x14C |
| ibss/ibec | boot_args_adrp / _string | 0x2AFBC / 0xD3850 | 0x2B0F4 / 0xD3960 | +0x138 / +0x110 |
| ibss/ibec | boot_args_add | 0x2AFC0 | 0x2B0F8 | **value changed** 0x42214091→0x422d4091 |
| restoreramdisk | asr_sig / fdr | 0x24D34 / 0x7E53C | 0x1F650 / 0x7E558 | −0x56E4 / +0x1C |
| txm | query_module0 / 1 / 2 | 0x39CB0 / 0x39E18 / 0x39FAC | 0x39CA8 / 0x39E10 / 0x39FA4 | −0x8 |
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
- [x] **2.15** PR opened — https://github.com/kaffeindecaf/Apple-Bug-Bounty-Skill/pull/1 (offsets.yaml fix: b2 block mislabeled + `ios_27_0b3` block added, plus `docs/offset-migration-workflow.md`). Local canonical DB fixed + verified (cross-check reports zero conflicts; backup at `/tmp/opencode/offsets.yaml.bak`).

---

## Day 3 — Cross-source audit + new build import (2026-09-20)

**Goal: no profile entry that upstream contradicts, and a repeatable way to
import a build nobody here has touched.**

### Tools
- [x] **3.1** `source_audit.py` (`script` / `liter8`): parses upstream make_cfw.py patch sites or Liter8 fixtures and diffs them byte by byte against a profile; statuses COVERED / PARTIAL / MISMATCH / REVIEW / MISSING / PROFILE-ONLY; report to `research/work/`
- [x] **3.2** `kczip.py` + `fetch_components.py`: ranged IPSW component fetch ported from W0lfSword (zip64 EOCD, central directory, CRC32, zip64 extra, local-path cache); fetches iBSS/iBEC/TXM/DeviceTree/kernelcache/provenance.txt
- [x] **3.3** `liter8_import.py`: maps Liter8 fixture oracles onto our entry names with a payload-equality gate, contiguity check, string-fit check and optional byte verification against fetched components; unmapped entries stay `pending`
- ✅ Verify: 69 pytest (17 new: audit classification, importer gates, kczip over a local Range-serving HTTP server)

### Findings applied
- [x] **3.4** b3 profile: post-validation 0x1F29480, dyld 0x1F299E0 + new site 2 0x1F299EC, txm query_module0/1 0x39CA8 / 0x39E10
- [x] **3.5** b2 + b3: AMFI trust entry expanded to the full 20-byte upstream sequence; launch-constraints payload aligned to upstream (`mov w0,#0; ret`)
- [x] **3.6** b2 + b3: `kernel.Kernel identity string 1/2` added (`/RELEASE_ARM64_T8030` → `/PATCHED_ARM64_T8030`, both upstream sites); `cfw_builder.patch_kernel` now writes ASCII payloads
- [x] **3.7** b2 + b3: `ibec.keep_nonce_b` corrected to `0a000014` (b #0x28). Original site is `tbnz w8,#1,#+0x28`; the old `28000014` encoding (b #0xA0) lands in unrelated code. Verified in the real iBEC binaries for both builds
- [x] **3.8** New profiles `offsets/iPhone12,1_27.0.yaml` (24A437) and `offsets/iPhone12,1_27.0b4.yaml` (24A5390f) imported from Liter8 fixtures; 45/48 and 41/48 entries filled, 16 sites byte-verified against the shipped components (iBSS/iBEC/TXM are byte-identical for n104 on 24A437)
- [x] **3.9** `profile_gen.propagate` refuses to copy kernel offsets between boards with different kernelcache components (iPhone12,1 vs iPhone12,3); `DEVICE_DB` now carries the component per board
- ✅ Verify: `source_audit.py script` on both b3 and b2 scripts reports no MISSING/MISMATCH left (only the expected boot_args_string trailing-NUL PARTIAL and the adrp/add REVIEW)

### Reported, not applied (needs a device decision)
- [ ] **3.10** b2 upstream also patches `restored_external` at 0x49E38 / 0x49DC0 and the kernel at 0x2126F18 (IOLog nop) / 0x216DD04 (AppleSEPManager `_powerChangeNotificationHandler`). The b3 script does not, so adding them to b2 only would break the b2/b3 entry pairing the migration tests rely on. Left in the audit report
- [ ] **3.11** Liter8 covers sites our scheme has no entry for: `kernel.aks.*` (a 20-word inline rewrite instead of mov/ret), `kernel.credential-manager.*` (52), `kernel.persona.*`, `kernel.amfi.developer-mode.*`, `txm.constraints.restricted-entitlements`, `txm.developer-mode.publish`, `ibec.pinot.*`. 143 sites for n104 24A435
- [ ] **3.13** The installed canonical `offsets.yaml` (`~/.config/opencode/skills/master-router/`) carried the same stale b3 values: its `ios_27_0b3` block now says `txm_queryModule0/1 = 0x39CA8/0x39E10` (backup at `/tmp/opencode/offsets.yaml.bak.20260920`). Needs a PR to Apple-Bug-Bounty-Skill like the previous one, otherwise `test_canonical_crosscheck_agrees_after_fix` only passes on machines with the local fix
- [ ] **3.12** iPhone12,1 27.0 still needs 3 entries before it can flash: `ibec.keep_nonce_b`, `kernel.Post-validation bypass` (upstream uses `ff070071` on this build, not our `1f00006b`) and `kernel.AppleSEPKeyStore bypass`. Fetched components for 24A437/24A5380h/24A5370h (d421 and n104) make these discoverable with `profile_gen.py migrate --comp-dir`

---

## Day 4 — Preflight verification + evidence ledger (2026-09-20)

**Goal: never flash a profile that has not been checked against the real
firmware bytes.** Plain usbliter8 trusts hardcoded offsets; this repo now
verifies them before the build.

### Tools
- [x] **4.1** `preflight.py`: loads the real components (auto-discovered `research/extracted/<Model>_<ios>_<build>/`, a local IPSW, or a range fetch with automatic IPSW url resolution via ipsw.me/ipsw.dev) and classifies every entry: `match` / `plausible` / `already-patched` / `changed` / `implausible` / `out-of-range` / `skipped`; verdict ok|review|blocked; exit 0 or 2
- [x] **4.2** `--record` writes `offsets/evidence/<profile>.json` (component sha256 + original bytes + timestamp) so a profile becomes self-verifying: later runs re-check the recorded bytes and block when a different board/build is supplied
- [x] **4.3** offset-space structure checks without any component: duplicate offsets, overlapping entries, out-of-range sites; provenance.txt device check
- [x] **4.4** string/identity entries are treated as data (empty slot = plausible) and `pending: true` entries are skipped, never failed
- [x] **4.5** `cfw_builder._profile_gate`: validation + pending check + preflight before patching; `--force` is the only override, and the TUI asks before using it
- [x] **4.6** `profile_gen.py gaps` + `coverage --json` + `device_offsets list/validate --json`; gaps flags profiles whose kernel offsets came from another board's kernelcache
- [x] **4.7** canonical DB: `UL8_OFFSETS_YAML` > user dotfiles > in-repo `offsets/canonical.yaml` (corrected b3 txm values), so the cross-check works on a fresh clone and in CI
- [x] **4.8** confidence floor is enforced in code (`apply_offsets(min_confidence)`) with an explicit `migrate --force-low`; report starts with a `VERDICT:` line
- ✅ Verify: 99 pytest (30 new in `tests/test_preflight.py` + `tests/test_tooling.py`), `preflight.py` blocked a real wrong-component run (iPhone12,1 profile vs iPhone12,3 b3 components: 0 verified, 16 bad), evidence recorded for iPhone12,1 27.0 and iPhone12,3 b2/b3

### Still open
- [ ] **4.9** kernelcache verification needs the wiki IV+key: fetch the decrypted `kernelcache.raw` and preflight will verify the kernel section the same way
- [ ] **4.10** `--json` for `migrate` itself (coverage/gaps/list/preflight are done)
- [ ] **4.11** the 8 A13 sibling profiles whose kernel sections were propagated from `iphone12` (iPhone12,1/12,8, iPad12,1/12,2 b2+b3) should be re-discovered from their own kernelcache component; `profile_gen.py gaps` lists them

---

## Hard rules (never break)

- Wrong offset rated HIGH = brick risk → double-gate: uniqueness + disasm-class match
- `method: delta` (inference) is ALWAYS LOW confidence
- `--auto` write only after report review; never silently overwrite an existing profile
