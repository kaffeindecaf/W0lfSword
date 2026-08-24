# PR DRAFT — Apple-Bug-Bounty-Skill

> Ready to open against https://github.com/kaffeindecaf/Apple-Bug-Bounty-Skill
> once push authorization is given. `gh` PR creation left to the user.

## Title

fix(offsets.yaml): correct checkm8 block — b2 values were actually b3's; add ios_27_0b3 block

## Body

### Problem

`offsets.yaml → constants.checkm8.ios_27_0b2` contained values that belong to
**iOS 27.0b3**, and two TXM entries matched neither profile. Discovered by the
`usbliter8-arctic` beta-to-beta offset migration engine
(`profile_gen.py migrate`) whose canonical cross-check flagged all mismatches,
then confirmed against the verified working profile
(`offsets/iPhone12,3_27.0b3.yaml`).

### Wrong values (before)

| key | DB value | b2 (correct) | b3 (verified) |
|---|---|---|---|
| `ibss_image4_validate` | `0x23EFC` | `0x23DB0` | `0x23EFC` |
| `ibss_boot_args_ptr` | `0x2B0F4` | `0x2AFBC` | `0x2B0F4` |
| `ibss_boot_args_string` | `0xD3960` | `0xD3850` | `0xD3960` |
| `txm_queryModule0` | `0x39ca8` | `0x39CB0` | `0x39CB0` |
| `txm_queryModule1` | `0x39e10` | `0x39E18` | `0x39E18` |
| `txm_queryModule2` | `0x39fa4` | `0x39FAC` | `0x39FA4` |
| `txm_constraints_sig` | `0x3f510` | `0x3F564` | `0x3F510` |
| `txm_allowedBeforeSecure` | `0x2bcb4` | `0x2BCB4` (ok) | `0x2BCB4` (ok) |
| `mobileactivationd_should_hactivate` | `0x2EBB14` | `0x2EBB14` (ok) | `0x2EBB14` (ok) |

### Change

- Fix `ios_27_0b2` block to hold actual b2 values
- Add `ios_27_0b3` block with the verified b3 values

```diff
   checkm8:
     ios_27_0b2:
-      ibss_image4_validate: "0x23EFC"
-      ibss_boot_args_ptr: "0x2B0F4"
-      ibss_boot_args_string: "0xD3960"
-      txm_queryModule0: "0x39ca8"
-      txm_queryModule1: "0x39e10"
-      txm_queryModule2: "0x39fa4"
-      txm_constraints_sig: "0x3f510"
+      ibss_image4_validate: "0x23DB0"
+      ibss_boot_args_ptr: "0x2AFBC"
+      ibss_boot_args_string: "0xD3850"
+      txm_queryModule0: "0x39CB0"
+      txm_queryModule1: "0x39E18"
+      txm_queryModule2: "0x39FAC"
+      txm_constraints_sig: "0x3F564"
       txm_allowedBeforeSecure: "0x2bcb4"
       mobileactivationd_should_hactivate: "0x2EBB14"
+    ios_27_0b3:
+      ibss_image4_validate: "0x23EFC"
+      ibss_boot_args_ptr: "0x2B0F4"
+      ibss_boot_args_string: "0xD3960"
+      txm_queryModule0: "0x39CB0"
+      txm_queryModule1: "0x39E18"
+      txm_queryModule2: "0x39FA4"
+      txm_constraints_sig: "0x3F510"
+      txm_allowedBeforeSecure: "0x2BCB4"
+      mobileactivationd_should_hactivate: "0x2EBB14"
```

### Evidence

- Source: `offsets/iPhone12,3_27.0b2.yaml` + `offsets/iPhone12,3_27.0b3.yaml`
  (usbliter8-arctic, verified working profiles from wh1te4ever/usbliter8-fun)
- Ground-truth migration test: 37/37 patch entries reproduce the verified b3
  profile at ≥0.90 confidence (`pytest tests/test_migrate.py`)
- The engine's canonical cross-check flagged exactly these mismatches before
  the fix and reports zero conflicts after it

### Also in this PR (second commit, optional)

- `docs/offset-migration-workflow.md` — the beta-to-beta migration workflow
  (see `contribution/migration-workflow.md` in usbliter8-arctic): AArch64
  pattern fingerprinting, confidence tiers, delta fallback, canonical
  cross-check. Relevant to `ios-research-methodology` + `ios-bootchain-exploit`.
