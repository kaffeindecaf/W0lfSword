# research/ - W0lfSword Research Notes & Tooling

> Everything that isn't shipped in the tweak itself: fuzzing tooling, deep
> dives, and struct research. Local-only hunt notes (fuzzing campaigns,
> per-bug status, gap analysis) live here too but are gitignored - this
> index lists the tracked files only.

## Tooling

| File | What | How to run |
|------|------|-----------|
| `imageio_fuzz.sh` | K4.2 ImageIO fuzzing harness: prepare → push → run → collect → report (per-sample crash attribution + signature dedup) + `probe` (K4.13, headless imgio_probe decode - no UI, no respring) | `./W0lfSword fuzz [prepare\|list\|push\|run\|probe\|collect\|report]` |
| `imageio_mutate.py` | Deterministic mutator: validated DNG/TIFF + JPEG parsers, structure-aware recipes (CVE-2025-43300 mismatch, AppleJPEG OOB-write families), TSV manifest | `python3 imageio_mutate.py <seed> <outdir> [--strategy dng\|jpeg\|generic\|all]` |
| `gen_jpeg_seed.py` | Bootstrap JPEG corpus (Pillow): baseline 420/444, grayscale, progressive, optimized, EXIF | `python3 gen_jpeg_seed.py [outdir]` |
| `gen_raster_seed.py` | Bootstrap raster corpus for the ImageIO harness | `python3 gen_raster_seed.py [outdir]` |

## Docs

| File | Topic |
|------|-------|
| `kernel26_cves.md` | C5.1: kernel-CVE catalog for iOS 26.1-26.6.1 (release map, master CVE table, DirtySlide + CVE-2025-46285 deep dives, top LPE candidates) |
| `kcwatch.md` | kernel-deltas feed repo design: auto-detect new builds, ranged kernelcache download, XPF offset resolution, per-release change report |
| `moreprojects_deep_dive.md` | The 5 new `referenceforAI/moreprojects` repos: CVE-2026-20687 (AppleJPEGDriver kernel UAF), DirtySlide (dyld slide LPE), CVE-2026-28990 (EXR ImageIO heap overflow), Glass-Cage duplicate, SEP exhaustion DoS - bug mechanics + W0lfSword relevance + menu-integration assessment |
| `applejpeg_cve-2025-43539.md` | K4.8: AppleJPEG (userspace codec) OOB-write campaign - decode paths, fuzzer recipes, hardware reproduction checklist, Chain B escalation |
| `TCC_BYPASS.md` | TCC database modification research (roadmap C2.1) |
| `sandbox_research.h` | Reverse-engineered sandbox struct definitions |

## Status

- Hardware-gated items (repro CVE-2025-43539 on 26.1, K4.7, K4.8) are tracked in
  `../ROADMAP.md` Section 0.2 - fuzzer targeting is done; reproduction needs an
  iOS 26.1 arm64e device.
- Fuzz state lives in `.w0lfsword/fuzz/` (corpus, manifest, results, signatures - gitignored).
