# research/ — W0lfSword Research Notes & Tooling

> Everything that isn't shipped in the tweak itself: fuzzing tooling, deep dives,
> bug-bounty notes, and struct research.

## Tooling

| File | What | How to run |
|------|------|-----------|
| `imageio_fuzz.sh` | K4.2 ImageIO fuzzing harness: prepare → push → run → collect → report (per-sample crash attribution + signature dedup) + `probe` (K4.13, headless imgio_probe decode — no UI, no respring) | `./W0lfSword fuzz [prepare\|list\|push\|run\|probe\|collect\|report]` |
| `imageio_mutate.py` | Deterministic mutator: validated DNG/TIFF + JPEG parsers, structure-aware recipes (CVE-2025-43300 mismatch, AppleJPEG OOB-write families), TSV manifest | `python3 imageio_mutate.py <seed> <outdir> [--strategy dng\|jpeg\|generic\|all]` |
| `gen_jpeg_seed.py` | Bootstrap JPEG corpus (Pillow): baseline 420/444, grayscale, progressive, optimized, EXIF | `python3 gen_jpeg_seed.py [outdir]` |

## Docs

| File | Topic |
|------|-------|
| `moreprojects_deep_dive.md` | The 5 new `referenceforAI/moreprojects` repos: CVE-2026-20687 (AppleJPEGDriver kernel UAF), DirtySlide (dyld slide LPE), CVE-2026-28990 (EXR ImageIO heap overflow), Glass-Cage duplicate, SEP exhaustion DoS — bug mechanics + W0lfSword relevance + menu-integration assessment |
| `applejpeg_cve-2025-43539.md` | K4.8: AppleJPEG (userspace codec) OOB-write campaign — decode paths, fuzzer recipes, hardware reproduction checklist, Chain B escalation |
| `bug_bounty_writeup.md` | DarkSword-ecosystem findings mapped to Apple bounty categories (KASLR leak, sandbox escape, etc.) |
| `TCC_BYPASS.md` | TCC database modification research (roadmap C2.1) |
| `sandbox_research.h` | Reverse-engineered sandbox struct definitions |

## Status

- Hardware-gated items (repro CVE-2025-43539 on 26.1, K4.7, K4.8) are tracked in
  `../ROADMAP.md` Section 0.2 — fuzzer targeting is done; reproduction needs an
  iOS 26.1 arm64e device.
- Fuzz state lives in `.w0lfsword/fuzz/` (corpus, manifest, results, signatures — gitignored).
