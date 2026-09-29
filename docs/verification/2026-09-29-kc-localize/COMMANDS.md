# K4.7 evidence - exact invocations

Regenerated 2026-09-29. Working directory for every command:
`/home/kaffein/Desktop/W0lfSword`. Host: Linux x86_64, Python 3.13, capstone
(`pip show capstone` for the version). No device attached, no device command run.

`*.log` is gitignored in this repo, so the raw outputs stay local by design;
the sha256 below covers each command's complete stdout+stderr and is the check
that a local re-run reproduces the recorded result. The `.json`/`.diff` artifacts
are committed.

| command | rc | output | sha256 (stdout+stderr) |
| --- | --- | --- | --- |
| `diff -u <xnu-12377.41.6>/osfmk/vm/vm_map_xnu.h <xnu-12377.61.12>/osfmk/vm/vm_map_xnu.h` | 1 | `vm_map_xnu.h_12377.41.6_to_61.12.diff` | `c0bd7403bb8f3b23f0c00d03571f5072` |
| `python3 scripts/kc_funcdiff.py --selftest` | 0 | `selftest.log` | `e6b3b88180ec1e1ef454d909309b4d79` |
| `python3 scripts/kc_funcdiff.py .w0lfsword/kernelcaches/macho_18.7.2 .w0lfsword/kernelcaches/macho_18.7.3 --owner com.apple.kernel --region __TEXT_EXEC --json /home/kaffein/Desktop/W0lfSword/docs/verification/2026-09-29-kc-localize/funcs_kernel.json` | 0 | `funcdiff_kernel.log` | `0f9e9ba4c3e4ab0227f52742b8ba5323` |
| `python3 scripts/kc_funcdiff.py .w0lfsword/kernelcaches/macho_18.7.2 .w0lfsword/kernelcaches/macho_18.7.3 --region __TEXT_EXEC --json /home/kaffein/Desktop/W0lfSword/docs/verification/2026-09-29-kc-localize/funcs_all_text.json` | 0 | `funcdiff_all_text.log` | `23f09f33413908d14f3bd9d8d43c8ea5` |
| `python3 scripts/kc_funcdiff.py .w0lfsword/kernelcaches/macho_26.1 .w0lfsword/kernelcaches/macho_26.2 --owner com.apple.kernel --region __TEXT_EXEC --json /home/kaffein/Desktop/W0lfSword/docs/verification/2026-09-29-kc-localize/funcs_kernel_26x.json` | 0 | `funcdiff_kernel_26x.log` | `be908d264190e10f46958c5984a51b41` |
| `python3 scripts/kc_pairs.py .w0lfsword/kernelcaches/macho_18.7.2 .w0lfsword/kernelcaches/macho_18.7.3 --owner com.apple.kernel --max 40` | 0 | `pairs_kernel.log` | `ec4949529f647f6fb3eddd1d6538f456` |
| `bash -c for v in 18.7.2 18.7.3; do echo "##### macho_$v"; python3 scripts/kc_xref.py .w0lfsword/kernelcaches/macho_$v --find-string 'VM map copies' --window 40 --seg com.apple.kernel; done` | 0 | `xref_string_18x.log` | `2870a87e3928212972592e27485d22cb` |
| `bash -c for v in 18.7.2 18.7.3; do echo "##### macho_$v"; python3 scripts/kc_xref.py .w0lfsword/kernelcaches/macho_$v --disasm --at 0xfffffff0085eb64c --size 0x120; done` | 0 | `maps_zone_18x.log` | `94bd4e3b06473814b0d4a63090776235` |
| `bash -c python3 scripts/kc_xref.py .w0lfsword/kernelcaches/macho_26.1 --disasm --at 0xfffffff0087e0c60 --size 0xf0; python3 scripts/kc_xref.py .w0lfsword/kernelcaches/macho_26.2 --disasm --at 0xfffffff0087e6544 --size 0xf0` | 0 | `maps_zone_26x.log` | `4957990f25a6e8452adb683f7b267262` |
| `bash -c for r in __TEXT __PPLTEXT __PPLTRAMP __KLD; do echo "### $r"; python3 scripts/kc_funcdiff.py .w0lfsword/kernelcaches/macho_18.7.2 .w0lfsword/kernelcaches/macho_18.7.3 --owner com.apple.kernel --region $r; done` | 0 | `regions_zero.log` | `de3bc75f6e194295731b3461ea1f7b61` |
| `bash scripts/kc_localize.sh .w0lfsword/kernelcaches/macho_26.1 .w0lfsword/kernelcaches/macho_26.2 /home/kaffein/Desktop/W0lfSword/docs/verification/2026-09-29-kc-localize/driver-26x` | 0 | `driver_26x.log` | `f06f70cce994aa6ad2e1b30f498e0614` |
| `bash scripts/kc_localize.sh .w0lfsword/kernelcaches/macho_18.7.2 .w0lfsword/kernelcaches/macho_18.7.3 /home/kaffein/Desktop/W0lfSword/docs/verification/2026-09-29-kc-localize/driver-18x` | 0 | `driver_18x.log` | `368f662deea8a347d21504ba361f2e7c` |

Kernelcache inputs (also in `SHA256SUMS`):

- `macho_18.7.2` 56590336 bytes sha256 `f102a72b2fec2eb721cd4724c30c1eb4c290e113f47e71f7a11927fbd39c19ad`
- `macho_18.7.3` 56590336 bytes sha256 `e3172e5364910053ab48fe0a8fd89165bdf7463ae71ed6c131c292f02223558f`
- `macho_26.1` 64389120 bytes sha256 `2ba97f893395eedb51014edbdb384e97e51703d6a9a8117e96382e1e2da36c65`
- `macho_26.2` 64405504 bytes sha256 `3dc5b2d30f6597bc7f2132c2f11ca5733939a2cdaae16664670464ca256fe073`

