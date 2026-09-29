# W0lfSword Hub shell

The in-repo test-harness app for the kernel engine. Built with the Theos
application target, so it builds on Linux with no Xcode and no macOS.

Why it exists: the tweak is the production path, but it needs Filza plus a
sideload or a jailbreak to run. A plain app can link the same engine and
report what it sees from an ordinary sideload, which is the cheap way to try
engine changes on a device.

State: builds and links the engine on Linux (checked by `scripts/regression.sh`
since L8.2). It has never run on hardware yet, so nothing in this folder is
device-verified. `pocs/hub_shell/` is a real directory in the repo, but think of
it as a shell with probes, not a product.

## Scope (L1.4)

v1 is a test harness, not a jailbreak:

- no boot-time injection, no launch daemons, no persistence. Everything runs
  while the app is open and leaves nothing behind except its own flag files
  under `Library/Application Support/` (crash counter, success flag, disable
  flag).
- nothing auto-runs. There is no exploit runner in the app yet (L6.1), so the
  app cannot start the chain by itself. When the runner lands it keeps its
  defaults from the SG.7/0.12 lesson: auto-run off, mode `readonly` first, and a
  warning line before any mode that can write kernel memory.
- kernel work is gated by the panic guard: three launches without a proven
  success disable every kernel probe, and the disable flag has to be removed by
  hand. A gated probe reports `disabled (panic guard)` instead of touching
  kernel memory.

## What works today

- **build path** (L2.1): Theos application target, `arm64`, iOS 15.0 minimum,
  bundle id `com.kaffeindecaf.w0lfswordhubshell`, display name `W0lfSword Hub`.
- **engine link** (L2.2/L3.3): the app links `.theos/libengine/libw0lfengine.a`
  and calls `kexploit_opa334()`, `kread64()`, `sandbox_escape()`,
  `patch_sandbox_ext()` with the tweak's own error codes.
- **offsets at boot** (L3.1): picks the highest `offsets.json` threshold that is
  <= the running iOS and prints it with the offset count and `itk_space`. A
  version with no threshold prints `unsupported iOS <x.y>` instead of guessing.
- **kernel r/w status** (L5.2): `kread64` smoke test on the pid field of its own
  proc -> `live`, or `not acquired (exploit not run)`.
- **credentials** (L5.1): reads `uid`/`gid`/`groups[0]` back through
  `proc_ro -> ucred` -> `root:wheel active` or `user creds (uid=.. gid=..)`.
- **panic guard** (L7.2): the A3.1 crash counter ported to app-scoped flag
  files. Registers each launch, resets the counter when a run proves the
  exploit completed.

Both probes are read-only and gated on `exploit_is_done()`. The screen is one
black label with those lines on it.

## What it does not do (yet)

- no exploit runner, retry ladder or live status: L6.1 to L6.4
- no sandbox-escape test suite or result export: L4.1 to L4.4
- no SSV panel or escalation report: L5.3 to L5.5
- no icons or launch screen (L2.6), no in-app confirm gates or limits screen
  (L7.1, L7.3, L7.4)
- no XPF-verified offset table beyond the generated `offsets.json` (L3.2), and
  no `TweakLog` plumbing into an app log view or file export (L3.5)
- never tested on hardware (L8.1), no release build (L8.3)

## Build and install

```bash
export THEOS=$HOME/theos
make libengine                          # repo root; the shared engine archive
bash scripts/build_hub_ipa.sh trollstore 1.0
```

`scripts/build_hub_ipa.sh [sideload|trollstore] [version]` does the Theos build,
writes the entitlement plist, assembles `Payload/W0lfSwordHub.app`, signs the
binary with `scripts/ldid` and zips the result to
`.w0lfsword/dist/W0lfSwordHub-<version>-<mode>.ipa`. It then prints the IPA
listing, the CodeDirectory line and the entitlements it applied.

Two delivery modes:

- `trollstore` (primary): `get-task-allow` plus `platform-application`, which
  only TrollStore can grant. No developer account involved.
- `sideload` (secondary): `get-task-allow` only. The bundle id is an ordinary
  developer id, not `com.apple.*`, so it is registrable from a free Apple ID,
  but `platform-application` cannot be granted this way and free-account
  sideloads expire.

Signing uses the vendored Procursus `scripts/ldid`. The toolchain's bundled ldid
is a no-op stub, so a dylib or app signed with it has no code signature and dyld
refuses to load it.

## Engine reuse rule

The app does not keep its own copy of engine sources. `Makefile` compiles only
`main.m`, `AppDelegate.m`, `engine_stubs.m` and `hub_guard.c`, and links the
archive, so one engine fix serves the tweak, this app and the standalone
terminal app. `engine_stubs.m` supplies the tweak-only UI callbacks
(`tweak_exploit_set_cycle`, `_set_status`, `_status`, `_attempt`, `_cycle`) that
`kexploit_opa334.m` references but the archive excludes. If the engine grows
another tweak-only symbol, the link fails here on purpose: that is the signal to
add a stub instead of pulling the tweak into the app.
