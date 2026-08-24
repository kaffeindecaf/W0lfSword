# kcwatch — Kernelcache Delta Watcher

> **One-liner:** automatically detect new iOS builds, pull just the kernelcache
> (ranged download, no 6GB IPSW), resolve every XPF offset, and publish a
> human-readable "what changed in the kernel" report per release.
>
> **Delivery (decided):** Option C — a public GitHub repo with an auto-updating
> `kernel-deltas.md` feed, generated on a schedule, free for researchers to
> follow. It builds reputation, acts as a changelog for `offsets.m` users, and
> feeds bounty targeting.
>
> **Status:** Plan. All pipeline pieces already exist in the W0lfSword repo;
> the only new code is a zip64 remote range reader.

---

## 1. Why

Every iOS release starts the same race: Apple ships a new kernel, and anyone
working on offsets or exploits wants to know "what changed in the kernel
between 26.6 and 26.6.1?" Today that is the manual K4.1 flow — find the IPSW,
pull the kernelcache, run xpf-cli, diff. kcwatch automates the loop:

```
poll for new builds → ranged-fetch kernelcache → xpf-cli resolve
→ diff vs previous build → publish kernel-deltas.md report
```

It also fixes a real maintenance problem: `kexploit/offsets.m` gets a new
version block only when someone manually verifies a build. With kcwatch, the
answer to "does the 26.0.x block still apply?" is computed within hours of a
release, not weeks.

## 2. Background — the K4.1 method (proven 2026-08-14)

The original verification (ROADMAP K4.1, tools/xpf-cli README):

- Pulled iPhone18,1 (T8150) kernelcaches for 26.0.1 (23A355, xnu-12377.2.9)
  and 26.1 (23B85, xnu-12377.42.6) **via ranged IPSW downloads from the Apple
  CDN** — the technique kcwatch generalizes.
- Ran the host-side XPF resolver (`tools/xpf-cli`, Linux shims, SIGSEGV-guarded
  item resolution, SPTM-aware) on both.
- Diffed 64 resolvable items → struct constants identical, 30 symbol-address
  shifts → **offsets.m 26.0.x block applies to 26.1**.
- Flagged one discrepancy (`task.itk_space`: XPF says 0x310 on T8150, offsets.m
  says 0x318 on SE3 — per-SoC delta, needs on-device confirmation).

kcwatch turns this one-off into a continuously running service.

## 3. Pipeline

### Step 1 — Poll for new builds

```
GET https://api.ipsw.me/v4/device/iPhone12,8/releases
```

JSON per release: `version`, `buildid`, `signed`, `sha256sum`, `url`
(Apple CDN, `updates.cdn-apple.com`). Compare `buildid` + `sha256sum` against
a local `state/last-seen.json`. New build → proceed. Poll once per day
(betas: weekly; stable: quarterly). Be polite — one ranged fetch per build.

Board choice: **t8030** (A13 — the SE2). The kernelcache is **SoC-shared**,
so one download covers every A13 device of that build.

### Step 2 — Ranged fetch (the one new piece of code)

An IPSW is a zip; the directory (file table: names, offsets, sizes) is at the
END of the file. Therefore:

1. HTTP `Range: bytes=N-` the last ~64KB → End of Central Directory.
   Parse it → locate `kernelcache.release.t8030`, its offset + compressed size.
2. HTTP `Range` exactly that byte range → raw kernelcache bytes.
   Total: ~60–100MB instead of 6–8GB.

**Gotcha:** modern IPSWs are >4GB → **zip64**. The directory is not in the
classic EOCD record; the parser must follow the zip64 EOCD locator. This is
the ~150-line Python module that does not exist yet (`scripts/kczip.py` or
`tools/kczip/`). Everything after it already exists.

### Step 3 — Resolve (exists)

`tools/xpf-cli/xpf-cli kernelcache.release.t8030` — handles IMG4→IM4P→krnl
+ LZFSE/LZSS internally. Output: header (`# kernel`, `# darwin`, `# xnu`,
`# os`, `base`, `entry`) + one line per item:

```
0x0000000000000748 <- kernelStruct.proc.struct_size
0x000000000000022e <- kernelConstant.nsysent
0x0000000000000000 <- kernelStruct.thread.ast [UNRESOLVED/crash]
```

### Step 4 — Diff (exists)

`scripts/xpf_diff.py` (added 2026-08-24): identical / changed / one-sided
counts + changed values, plus `--json`.

### Step 5 — Render the report (new, small)

Templated markdown → `reports/<board>-<version>-<buildid>.md` +
append to `kernel-deltas.md` index.

## 4. What each delta signal means

| Signal | Meaning | Action |
|--------|---------|--------|
| Struct offset moved | Kernel struct layout changed | New `offsets.m` block needed |
| Symbol address shifted | Code around that symbol changed | Cross-ref Apple advisory → patch-diffing lead |
| `nsysent` / `mach_trap_count` changed | Syscall added/removed | New attack surface |
| Item → `[UNRESOLVED]` | Field/function vanished | Structural change, investigate |
| Kernel base/entry moved | KASLR layout change | Note for exploit geometry |

The single most useful line in each report: the **offsets.m verdict** —
"26.0.x block applies: YES/NO" — computed by comparing the diff against the
highest `SYSTEM_VERSION_GREATER_THAN_OR_EQUAL_TO` threshold in offsets.m.

## 5. Example report (`kernel-deltas.md` entry)

```markdown
## iOS 26.6 (23G83) — t8030 — 2026-08-17

xnu: 12377.2.9~1 -> 12377.42.6~55    darwin: 25.0.0 -> 25.1.0
resolved: A=64  B=64   identical: 61   changed: 3

CHANGED:
  kernelStruct.task.itk_space:  0x310 -> 0x318   <- offsets.m needs a new block!
  kernelConstant.nsysent:       0x22e  -> 0x230  <- 2 syscalls added
  kernelSymbol.some_kext_fn:    0xfffffe0008a1c000 -> 0xfffffe0008a41000

VERDICT: iOS 26.6 is NOT covered by the 26.0.x offsets block — verify on
device before deploying. Full report: reports/t8030-26.6-23G83.md
```

## 6. Delivery — Option C: public community feed

A dedicated public repo, e.g. `kaffeindecaf/kernel-deltas`:

```
kernel-deltas/
├── README.md            # what it is, methodology, how to subscribe, credits
├── kernel-deltas.md     # index: latest report + table of releases (the feed)
├── reports/             # one file per build: reports/t8030-26.6-23G83.md
├── scripts/             # poll.py, kczip.py, render.py (vendored from W0lfSword)
├── state/               # last-seen.json (committed; the diff baseline)
└── .github/workflows/watch.yml
```

Auto-update via **GitHub Actions cron** (e.g. `cron: '0 6 * * *'`):

1. Poll ipsw.me for configured boards (start: t8030; add T8103/T8140 later)
2. New build → ranged fetch → xpf-cli resolve → diff vs state
3. Render report → commit `reports/*.md` + updated `kernel-deltas.md`
   (workflow commits with `actions-x/commit` style)
4. Optionally open an issue tagged `new-build` so subscribers get notified

Why it works as a community asset:

- **Subscribers** follow the repo or the feed file; `kernel-deltas.md` is a
  plain markdown changelog — diffable, watchable, PR-able.
- **Reputation**: you become the person who publishes kernel deltas first;
  researchers and jailbreak teams link it.
- **offsets.m changelog**: every report is a ready-made note for the next
  offsets block.
- **Bounty targeting**: when Apple's advisory for a release lists a kernel
  fix, the corresponding report shows exactly which symbols moved — patch
  leads for free.

Complementary (optional, non-blocking):

- **Option A — W0lfSword subcommand** (`./W0lfSword kcwatch poll|report`):
  lets users run the same pipeline locally against their own boards.
- **Option B — Hermes cron**: push the new-report summary to a Telegram
  channel the day a build drops. (Works alongside the GitHub repo.)

## 7. Gotchas

- **zip64**: mandatory — modern IPSWs exceed 4GB.
- **Rate limits**: one ranged fetch per new build, cache aggressively.
- **Encrypted kernelcaches**: A12+ (t8030, T8103, T8140...) unencrypted =
  covered. A10/A11 need IV+Key from theiphonewiki → skip those boards.
- **Fileset/SPTM**: some PPL items print `[UNRESOLVED/crash]` — expected;
  xpf_diff.py already handles them.
- **Offsets ≠ exploitability**: a clean diff means the layout is the same,
  not that any exploit works (same caveat as the xpf-cli README).
- **Per-SoC deltas**: `task.itk_space` 0x310 (T8150) vs 0x318 (SE3) shows
  offsets can differ per SoC within a build — reports must state the board,
  and the offsets.m verdict must account for it.
- **Advisory timing**: Apple publishes security content after (or alongside)
  the release; the watcher is the *before* half of the picture.

## 8. Scope / milestones

**M1 — Core (1–2 days)**
- `scripts/kczip.py`: zip64-aware remote range reader (EOCD/zip64 locator,
  entry lookup, ranged fetch with retries + sha256 verify)
- `scripts/kcwatch.py`: poll → fetch → xpf-cli resolve → xpf_diff → render;
  `state/last-seen.json`
- Manual run on a known build to validate end-to-end against real bytes

**M2 — Public feed (1 day)**
- `kaffeindecaf/kernel-deltas` repo: README, feed template, GitHub Actions
  cron workflow with auto-commit
- First live report for the most recent t8030 build (26.6.1, 23G83)

**M3 — Extras (as wanted)**
- offsets.m verdict logic (auto "block applies: yes/no" per release)
- More boards (T8103 M1, T8140 A16, T8150) — each is a config line
- W0lfSword `kcwatch` subcommand reusing the same scripts
- Telegram push via Hermes cron on new reports

## 9. What already exists (reuse map)

| Piece | Where |
|-------|-------|
| XPF host resolver (IMG4 + LZFSE decode) | `tools/xpf-cli/` (built binary present) |
| Offset diff (identical/changed/one-sided, --json) | `scripts/xpf_diff.py` |
| IPSW kernelcache extraction (local zip) | `W0lfSword` `kernelcache extract` |
| Ranged-download proof | K4.1 notes (ROADMAP, tools/xpf-cli README) |
| Board/SoC knowledge (t8030 etc.) | referenceforAI/RESEARCH.md, ios-firmware-offset-research skill |
| Release feed data | api.ipsw.me/v4 (free, no auth) |

## 10. Decisions to make before building

1. Repo name: `kernel-deltas` / `ios-kernel-deltas` / `kcwatch`?
2. Boards to watch at launch: t8030 only, or t8030 + T8103 (M1) + T8140?
3. Feed format: single `kernel-deltas.md` vs `reports/` + RSS/Atom?
4. Should the offsets.m verdict live in each report from day one?

---

*Plan written 2026-08-24. Rooted in the K4.1 verification and the
xpf-cli/xpf_diff tooling added the same week.*
