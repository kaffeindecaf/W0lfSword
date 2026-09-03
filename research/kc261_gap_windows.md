# 26.6.1 kernel shift clusters and gap windows (BB-050 follow-up)

Re-run and refinement of the BB-050 26.6 (23G71) to 26.6.1 (23G83) kernel
patch-diff, 2026-09-03, t8110 + t8030, no device needed. Evidence files:
ios-bounty-hunt/reports/bb050-reread-20260903/ (ha_reread_20260903.txt =
11 named-function window diffs, shift-clusters.txt = anchor shift map).

## Named-function windows: still relink noise

Re-ran the ha_diff.py window diff on both SoCs (6 windows t8110, 5 t8030,
including proc_get_syscall_filter_mask_size, vn_kqfilter,
load_static_trust_cache, pmap_enter_options_addr, pmap_remove_options,
phys_attribute_clear_with_flush_range, pmap_pin_kernel_pages).

- every function length-identical old vs new (0x28, 0x964, 0x668, ...)
- 66 non-equal opcode regions total, all 1-2 byte branch-displacement
  replaces, 0 insert, 0 delete
- verdict unchanged from BB-050: named functions carry no semantic change;
  the 26.6.1 fixes live in uncovered code

Method note: the repo ha_diff.py kdecompress fails on the bvx2 payloads
(returns None for all 4 img4s), the earlier session must have fed it
xpf-cli-decompressed Mach-Os. Symlinking firmware/*.kc (already
decompressed) into /tmp/ha_kcs makes the diff phase run clean.

## Shift cluster map (refined)

Cross-SoC consistent anchor shift steps, ordered by old vmaddr:

t8110: boot-data +320 (gPhysBase/gPhysSize/ptov_table), fatal_error_fmt
+1120, pmap cluster +476 (pmap_enter_options_addr through vn_kqfilter),
proc_get +796, load_static_trust_cache +748, phystokv +1092.

t8030: gVirt/gPhys data +320, fatal_error_fmt +1088, pmap cluster +580
(pmap_pin_kernel_pages through vn_kqfilter), proc_get +908.

Matches BB-050's earlier cluster numbers exactly when converted (boot-data
+0x140 = 320, pmap t8110 +0x1dc = 476, t8030 +0x244 = 580, fatal_error_fmt
+0x460 = 1120), which validates both runs.

## Gap windows (new signal)

Inter-anchor gap delta (distance from each symbol to the next resolved
anchor above it, 26.6 vs 26.6.1). A nonzero delta means code was inserted
or removed between that anchor and the next one. Both SoCs agree:

- +320 between vn_kqfilter and proc_get_syscall_filter_mask_size
  (t8110 +320, t8030 +328)
- +344 between load_static_trust_cache and phystokv (t8110)
- +476/+580 between task_crashinfo_release_ref and its next anchor
- removal above fatal_error_fmt (t8110 -1120 net into the pmap cluster,
  t8030 -1088)

The vn_kqfilter +320 window is the most interesting for the 26.6.1 advisory
set (65343 remote-term UAF, 65349 OOBR): vn_kqfilter itself is untouched,
so the sibling code right above it grew on both SoCs. That window and the
load_static_trust_cache +344 window are the two candidate fix-site regions
with named anchor boundaries. Per-function attribution inside a window
needs Ghidra function discovery on the decompressed kcs (release kcs carry
no symtab/funcstarts), which is the next step.

## ALAC retest (same session)

poclab alac-fuzz (45 s) reproduced a fresh heap-buffer-overflow at
dp_dec.c:99 (unpc_block) on 2026-09-03, artifact
research/alac_poc/crashes/crash-d8cb84f0657019ba0bf6853f4bc167460f53eb4d.
poclab test alac re-verified the BB-038/BB-039 harness mechanics. Corpus
and crash artifacts stay gitignored-local by design. Production verdict on
18.4.1 remains BB-056 (negative), unsubmitted.
