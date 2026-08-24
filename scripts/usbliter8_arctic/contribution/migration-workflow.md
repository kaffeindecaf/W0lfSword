# Beta-to-Beta Offset Migration Workflow

For the Apple-Bug-Bounty-Skill knowledge base. Cross-references:
`ios-research-methodology` (offset discovery) and `ios-bootchain-exploit`
(IMG4/patch offsets). Implementation lives in `usbliter8-arctic`
(`profile_gen.py migrate`, `fingerprint.py`, `migrate.py`).

## When to use

A verified offset profile exists for iOS build N and a new beta (N+1) ships.
Instead of re-discovering every offset by hand, migrate automatically and
review only the low-confidence results.

## Method

1. **Extract components** for both builds: kernelcache (decrypted), iBSS,
   iBEC, RestoreRamdisk, TXM. Sources: work-dir `get_fw.py`/`make_cfw.py`,
   keys from The iPhone Wiki, or pre-extracted `--comp-dir`.
2. **Fingerprint each patch site** in the base binary: take a 32-byte window,
   zero the immediate bits of AArch64 instructions (adrp/adr/b/bl/cbz/tbz/
   ldr-literal/ldr-str-imm/add-sub-imm/movz-movn-movk). Opcode + register +
   condition bits are kept — they survive compilation-unit shifts; immediates
   do not.
3. **Search** the target binary for the masked pattern (word-aligned rolling
   scan) and **verify** each hit with capstone: mnemonic + register-operand
   class must match.
4. **Score confidence**:

   | tier | condition | action |
   |---|---|---|
   | 0.95 HIGH | unique hit + disasm class match | accept |
   | 0.90 HIGH | unique hit at string/data site | accept |
   | 0.60 MED | unique hit, class mismatch | manual review |
   | 0.30 LOW | multiple hits (candidates listed) | manual review |
   | 0.30 LOW | delta-inferred (±4KB cluster median) | never trust without review |
5. **VALUE_CHANGED**: if the site word differs only in immediate bits
   (e.g. `boot_args_add`), recompute the patch value from the target bytes.
6. **Cross-check** against the canonical `offsets.yaml` checkm8 block — flag
   mislabeled version keys, stale values, and "matches neither" cases.
7. **Write** the target profile (`--auto`, with `migrated:` metadata per
   entry) and run post-write validation.

## Ground truth (iPhone12,3 / d421ap, iOS 27.0b2 → 27.0b3)

Kernel deltas are per-compilation-unit, NOT a global slide:

| entry | b2 | b3 | delta |
|---|---|---|---|
| AMFI trust / Proc launch | 0x1F1EBE0 / 0x1F23808 | 0x1F1CCF8 / 0x1F21920 | −0x1EE8 |
| APFS mount SSV / vol panic | 0x303F49C / 0x30408AC | 0x303FCDC / 0x30410EC | +0x840 |
| APFS seal / BSD rootvp | 0x2FAE32C / 0x36C1F48 | 0x2FAE494 / 0x36BE974 | +0x168 / −0x25D4 |
| PE debugger | 0x3A07368 | 0x3A05230 | −0x2138 |
| SEP panic | 0x2170AF4 | 0x216FDE4 | −0x12D10 |
| USB / sandbox ×5 / post-val / dyld / SEP ×2 | — | — | unchanged |

iBSS/iBEC: validate +0x14C, boot_args +0x138, string +0x110,
`boot_args_add` value changed (0x42214091 → 0x422d4091).
RestoreRamdisk: asr −0x56E4, fdr +0x1C. TXM: −0x8 / −0x54 ×2. Daemons: unchanged.

## Hard rules

- A wrong offset rated HIGH bricks the device — uniqueness + disasm class
  match is the double gate.
- Delta inference is always LOW.
- `--auto` only after report review; never overwrite silently.
- Re-verify against canonical `offsets.yaml`; conflict = evidence, not an
  error to hide.

## Validation

`pytest tests/test_migrate.py` in usbliter8-arctic: 21 tests including the
37-entry ground-truth regression (all ≥0.90) and canonical cross-check
(bad-DB fixture → flags; fixed-DB → zero conflicts).
