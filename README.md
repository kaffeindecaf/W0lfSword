# W0lfSword

[![GitHub stars](https://img.shields.io/github/stars/kaffeindecaf/W0lfSword?style=flat-square&color=389df8)](https://github.com/kaffeindecaf/W0lfSword/stargazers)
[![License](https://img.shields.io/github/license/kaffeindecaf/W0lfSword?style=flat-square&color=blue)](LICENSE)
[![iOS](https://img.shields.io/badge/iOS-17.0%E2%80%9326.0.1-8A2BE2?style=flat-square)](https://github.com/kaffeindecaf/W0lfSword)
[![DarkSword](https://img.shields.io/badge/exploit-DarkSword%20R%2FW-FF4D4D?style=flat-square)](https://github.com/kaffeindecaf/W0lfSword)
[![Status](https://img.shields.io/badge/status-active%20development-39D353?style=flat-square)](https://github.com/kaffeindecaf/W0lfSword)

W0lfSword puts a kernel exploit inside Filza, the iOS file manager. The tweak runs
every time Filza opens, and when it lands, Filza stops being a sandboxed app:
`/System`, `/usr`, `/bin` and every other app's container become readable and
writable from the normal file browser UI.

Nothing is written to disk. The exploit lives in kernel memory only, so a reboot
puts the phone back exactly the way it was.

Two things it is not:

- **not a jailbreak.** No Cydia, no Sileo packages, no changed code signing, no
  files dropped into system paths. Kernel read/write exists only while Filza runs.
- **not a Filza installer.** You bring your own Filza (TrollStore, Sideloadly,
  whatever you already use); W0lfSword only injects into it.

It is a research toolkit first: one exploit chain, studied on real hardware, with
the host-side tooling (offset research, kernelcache diffs, crash classification,
fuzzing harnesses) that the chain needs to stay working across iOS builds.

Current release: v1.5.0.

## How it works

Every iOS app runs in a sandbox: a short list of paths the kernel lets it touch.
Filza is no exception, which is why a stock Filza cannot open `/System` or another
app's container.

The tweak does four things, in order, each one buying the next:

1. **Hook Filza's UI immediately.** Padlock bypass, license alerts, zip handling.
   This part is a plain jailbreak tweak and touches no kernel memory.
2. **Run DarkSword** (CVE-2025-43520): an ICMPv6 socket spray plus a race through
   an IOSurface out-of-bounds bug. Winning the race produces a read/write
   primitive on kernel memory.
3. **Patch Filza's sandbox rules** through that primitive, so the kernel now
   considers `/` an allowed path for this process.
4. **Make the sealed system volume writable**, so `/System` and `/usr` can be
   edited even though Apple's signature normally forbids it.

From there it is ordinary file access through Filza's own UI, under Filza's
process, with a root credential patch for new files.

```
Filza opens
  -> tweak loads, UI hooks active right away
  -> ~1s later: socket spray + OOB race -> kernel R/W
  -> sandbox rules rewritten to "/"
  -> sealed system volume writable
  -> root-owned writes inside the normal file browser
```

Step 2 is a race. It usually wins; if it loses, the tweak retries and, when it
gives up, Filza keeps working as a normal sandboxed app.

![Architecture](W0lfSwordArchitecture.png)
![Exploit Pipeline](W0lfSwordChain.png?v=2)

## Quick start

```bash
git clone https://github.com/kaffeindecaf/W0lfSword.git
cd W0lfSword

./W0lfSword setup              # install build tools, one time
sudo ./W0lfSword adderall      # find the phone, build, deploy, verify
```

`adderall` is the whole run in one command: it finds the phone over USB or WiFi,
installs anything missing, checks the model and iOS version against the
compatibility matrix before building, generates its own SSH key, builds and
deploys the tweak, restarts Filza, and reports whether the escape worked. It only
stops to ask you two things, the trust prompt on the phone and which Filza
version you have.

- `sudo ./W0lfSword adderall --safe` runs the UI tweaks only and skips the kernel
  part. Good first run: it proves the whole pipeline works and changes nothing.
- `sudo ./W0lfSword adderall --yes` answers the remaining prompts.
- `./W0lfSword r` (readiness) prints a full device report without SSH.

Once a run succeeds, open Filza. The exploit fires a second or two later.

## What it gives you in Filza

- the whole filesystem, sealed system volume included
- `chown` / `chmod` on anything, hide and unhide files
- padlocks and license screens gone
- zip and unzip anywhere
- an on-screen status panel (collapsible) with the live log, a LOG button that
  exports the log, and RERUN to try the exploit again without relaunching Filza
- a small in-process shell under that panel: `ls`, `cat`, `cd`, `stat`, `mkdir`,
  `rm`, `mv`, `cp`, `chmod`, `ps`, `df` and kernel read/write commands. Read-only
  until you type `unsafe 1`

Everything resets on reboot. Open Filza again and it is back.

## Safety and limits

This is a real kernel exploit. Read this part before running it on a phone you
care about.

- **A kernel panic means a reboot, not data loss.** The exploit writes to kernel
  memory only, so a panic costs you a restart. Do not run it on a phone you
  cannot force restart.
- **Stay in read-only mode on any device and iOS version we have not verified.**
  Writes go through a hardened path that is checked twice (a size bound on every
  32-byte block, and the object size asked from the kernel's own allocator), and
  that work is host-tested, but it has not been re-verified on hardware yet. Three
  of our own test runs panicked during that validation, all on write-capable
  modes, and the read-only mode is the one with a clean record.
- **The write modes are opt-in.** Switch with a file on the phone:
  `Documents/w0lf_test_mode` containing `1` (read-only), `2` (single-socket write
  probe, restores what it touched, then stops), `3` (full chain immediately). With
  no file, the release build walks the staged ladder: compatibility check, then a
  bounded write probe, then the full chain, and a failed stage stops with the
  device untouched instead of retrying.
- **Three panics in a row disables the tweak.** Delete
  `/var/mobile/Documents/.filza_tweak_disable` to re-enable it.
- **iOS 26.1 and newer: no kernel stage.** Apple patched DarkSword in 26.1, so
  there is no kernel read/write there. The userspace modules still work:
  container access via `mha`/`nj`, and the `bad_query` read-escape.
- **iPhone 17 (A19) and M5 iPads are out of scope.** Apple moved those to Memory
  Tagging Extension, which kills this whole exploit class.
- **The padlock bypass hooks Filza's UI classes by name.** A Filza update that
  renames them brings some padlocks back until the hooks are updated. The exploit,
  the sandbox escape and the SSV writes are unaffected.
- **SSV writes can fail on the first try** under memory pressure. The tweak
  retries; occasionally you tap the operation again.
- **It does not cover A10/A11 phones.** The kernel stage is implemented for
  A12 and newer; the older SoCs are on the roadmap (kfd port) and not shipped.

## Supported devices

| iOS | A12–A14 | A15 | A16 | A17 | A18 | M1–M4 |
|-----|---------|-----|-----|-----|-----|-------|
| 17.0–17.7 | yes | yes | yes | yes | no | yes |
| 18.0–18.7.7 | yes | yes | yes | yes | yes | yes |
| 26.0–26.0.1 | yes | yes | yes | yes | yes | yes |

A18 phones (iPhone 16 and later) use a second code path for the same bug
(`pe_v2`) because the allocation layout differs. Both paths are in the same build;
the script picks the right one from the device model.

Outside those ranges the tweak stays quiet instead of guessing: unknown iOS
versions get the userspace modules only, and the script prints what is available
for your version right after it detects the device.

## Requirements

On the phone:

- iOS 17.0–26.0.1 on a supported SoC (table above)
- Filza installed
- a jailbreak (for the tweak to load) and OpenSSH listening on port 22 for deploy
  over WiFi. USB-only deploy needs no WiFi (`adderall --usb`)
- `nojailbreak` mode instead of a jailbreak: it installs a re-signed Filza over
  USB and runs the same kernel path

On the computer:

- Linux or macOS 13+, `./W0lfSword setup` installs the rest (needs `sudo` on
  Linux, and must not have it on macOS because Homebrew refuses to run as root)
- clang and the iPhoneOS SDK for the tweak build. On macOS Xcode Command Line
  Tools provide clang, on Linux `setup` installs the toolchain it needs
- Theos at `~/theos` or `/opt/theos`, dpkg for packaging, libimobiledevice for USB
  work. `./W0lfSword doctor` checks all of it.

`BUILD.md` has the detailed build environment notes (gitignored, kept locally).

## Commands

`./W0lfSword` with no arguments opens the interactive menu. The same commands work
on the command line, and `./W0lfSword commands` prints the full index with
aliases, interactive keys and groups (52 commands at v1.5.0). The ones people
actually use:

| Command | What it does | Example |
|---------|--------------|---------|
| `adderall` | discover, build, deploy, verify (needs sudo) | `sudo ./W0lfSword adderall` |
| `adderall --safe` | UI hooks only, no kernel writes | `sudo ./W0lfSword adderall --safe` |
| `adderall --usb` | force USB transport instead of WiFi | `sudo ./W0lfSword adderall --usb` |
| `adderall --test` | build the safety-ladder variant (read-only by default) | `sudo ./W0lfSword adderall --test` |
| `adderall --force-jb` | run the kernel race on an already-jailbroken kernel | `sudo ./W0lfSword adderall --force-jb` |
| `nojailbreak (nj)` | install Filza over USB and run the exploit, no jailbreak | `sudo ./W0lfSword nj --test` |
| `readiness (r)` | full device report with no SSH, read from the on-device log | `./W0lfSword r` |
| `quick` | build, deploy and verify in one shot | `./W0lfSword quick` |
| `build` / `deploy <ip>` | tweak into a .deb / install it | `./W0lfSword deploy 192.168.1.5` |
| `safe on|off` | turn the kernel part off or on remotely | `./W0lfSword safe on` |
| `toggle on|off` | enable or disable the tweak entirely | `./W0lfSword toggle off` |
| `log [n]` / `monitor` | pull the tweak log / watch it live with colors | `./W0lfSword log 100` |
| `targets (t)` | supported apps and the exploit technique matrix | `./W0lfSword targets` |
| `chains [a-g|best]` | attack-chain catalog; `best` picks for the connected phone | `./W0lfSword chains best` |
| `cve [filter]` | CVE tracker: kernel, userspace, sandbox, tcc, ssv, live | `./W0lfSword cve live` |
| `offsets [ver]` | offset coverage per iOS version | `./W0lfSword offsets 26.0` |
| `mobilegestalt (mg)` | read and edit MobileGestalt keys on 17.0–26.0.1 | `./W0lfSword mg set dynamic-island 1 --respring` |
| `sbtweak (sbt)` | live SpringBoard edits (5-icon dock), revert on reboot | `./W0lfSword sbtweak dock 5` |
| `tweaks install <id>` | build and deploy a catalog tweak | `./W0lfSword tweaks install five_icon_dock` |
| `mha <ipa>` | re-sign Filza as MobileHouseArrest for container access | `./W0lfSword mha Filza.ipa` |
| `poclab list` / `poclab test <id>` | research PoCs and their status / run one on this host | `./W0lfSword poclab test alac` |
| `fuzz [cmd]` | ImageIO fuzz harness: mutate, push, open or probe, catch crashes | `./W0lfSword fuzz probe` |
| `device add|list|switch` | manage several phones | `./W0lfSword device add 192.168.1.5` |
| `status` / `diag` / `doctor` | project health / all three diagnostics / build environment | `./W0lfSword diag` |
| `audit` | static analysis: shellcheck, dead functions, CLI consistency | `./W0lfSword audit` |
| `--json` | machine-readable output on status, offsets, audit, commands | `./W0lfSword status --json` |

Log colors: green for success, red for errors, yellow for retries, cyan for
structure. Devices, profiles and history live in `.w0lfsword/` (gitignored).

The menu itself is configurable: `.w0lfsword/config` is a plain key=value file
covering animations, animation speed, the wolf art, compact mode, device scanning,
colors, confirmation prompts and the prompt symbol, or use
`./W0lfSword config set <key> <value>`.

## Host tools, no phone needed

Roughly half the repo works without a device attached. These are the parts that
did the real research behind the offsets in this tree, and they are how a new iOS
build gets supported:

- `kernelcache` resolves struct offsets out of a kernelcache, diffs two builds, or
  extracts the kernelcache from an IPSW.
- `diffs` reads [blacktop/ipsw-diffs](https://github.com/blacktop/ipsw-diffs), which
  publishes Apple's own `ipsw diff` output for every consecutive build pair. It
  pulls single files from raw.githubusercontent and caches them, so nothing is
  cloned and no multi-gigabyte IPSW is downloaded, and turns them into per-kext
  section, symbol and string deltas.
- `drift` groups every offset in `kexploit/offsets.h` by the struct it belongs to
  and reports which groups a build pair actually moved, so an unverified iOS
  version arrives with a re-verify list instead of a surprise. `--fail-on layout`
  makes it exit non-zero for CI.
- `kcwatch` polls Apple for new builds, fetches just the kernelcache, runs the XPF
  resolver and writes a verdict on whether the offset tables still hold.
- `panic` classifies a crash log (.ips) and names the subsystem.
- `poclab`, `fuzz` and the harnesses in `research/` are the exploit-hunting side:
  host fuzzers for the ALAC decoder and ImageIO, with the on-device probe for the
  ImageIO path.

```bash
./W0lfSword diffs index                              # every build pair (152)
./W0lfSword diffs kexts 26_6_23G71_vs_26_6_1_23G83   # per-kext delta table
./W0lfSword drift --pair 23G71 23G83                 # what needs re-verifying
./W0lfSword drift --fail-on layout                    # exit 3 when a group moved
./W0lfSword kernelcache diff a.img4 b.img4
```

The host test suites run without a device and without network access (C harnesses
for the write path and the shell, Python lints over the sources, 30 assertions
over the diff dataset). `bash scripts/check_host_verification.sh` runs the whole
pinned set and hashes every output, so a change that moves a behaviour shows up as
drift instead of a surprise; `--with-builds` adds the Theos cross-builds.

<details>
<summary><b>howl (ascii art)</b></summary>

```text
                              __
                            .d$$b
                          .' TO$;\
                         /  : TP._;
                        / _.;  :Tb|
                       /   /   ;j$j
                   _.-"       d$$$$
                 .' ..       d$$$$;
                /  /P'      d$$$$P. |\
               /   "      .d$$$P' |\^"l
             .'           `T$P^"""""  :
         _.'      _.'                ;
      `-.-".-'-' ._.       _.-"    .-"
    `.-" _____  ._              .-"
   -(.g$$$$$$$b.              .'
     ""^^T$$$P^)            .(:
       _/  -"  /.'         /:/;
    ._.'-'`-'  ")/         /;/;
 `-.-"..--""   " /         /  ;
.-" ..--""        -'          :
..--""--.-"         (\      .-(\
  ..--""              `-\(\/;`
    _.                      :
                            ;`-
                           :\
                           ;
```

</details>

## Troubleshooting

"ESCAPE NOT CONFIRMED" after a run:

1. `./W0lfSword offsets <your iOS version>`: is your version covered?
2. `./W0lfSword log 100`: read the actual failure.
3. Run it again. Losing the race on the first two attempts is normal.

Build problems:

- `theos/makefiles/common.mk: No such file` -> `export THEOS=~/theos`
- `iPhoneOS.sdk not found` -> put an SDK from [theos/sdks](https://github.com/theos/sdks) in `$THEOS/sdks/`
- `dpkg-deb: command not found` -> `brew install dpkg` or `sudo apt install dpkg`
- `clang: error: no such file: 'XPF/src/xpf.c'` -> `git submodule update --init`

Device problems:

- Filza crashes on launch -> a previous run panicked the kernel, reboot the phone
- `ssh: connect refused` -> OpenSSH is not listening on the phone (port 22). This
  is the most common deploy failure and no transport fixes it: USB SSH only
  replaces WiFi, sshd still has to be running. Also confirm the IP with
  `./W0lfSword device add <ip>` if it changed.
- `Permission denied (publickey)` -> run `ssh root@<phone-ip>` once and accept the key
- the tweak does nothing -> kill-switch flag is set, run `./W0lfSword toggle off`
- writes fail on system paths -> SSV did not activate, look for
  `ensureSSVActive set active=1` in the log

## What gets installed on the phone

Two files, nothing else:

```
/Library/MobileSubstrate/DynamicLibraries/
+-- FilzaApplySandboxExt.dylib     # the tweak (arm64)
+-- FilzaApplySandboxExt.plist     # inject only into Filza
```

It injects into `com.tigisoftware.Filza` and `com.tigisoftware.Filza000`
(Filza 4.0.2). Restart Filza and the exploit runs. Logs go to `/tmp/FilzaTweak.log`
(4 MB rotation), `Documents/FilzaTweak.log`, and os_log; the HUD's LOG button
exports the live log over USB.

## Releases

One asset per release on the GitHub releases page, all built from your own
`Filza.ipa` by the `mha` and `nojailbreak` commands:

- `FilzaArctic.ipa`: release build, display name "Filza Arctic", original Filza
  icons, full chain, cleans up after itself on failure.
- `FilzaArctic-Test.ipa`: same build with the safety ladder. Read-only by default;
  write modes need `Documents/w0lf_test_mode`.
- `FilzaArctic-JBtest.ipa`: test-bed build with the jailbreak force override.

Bundle IDs matter for sideloading. The release asset keeps the MobileHouseArrest
identity for TrollStore installs. To sideload with Apple ID (PlumeImpactor,
AltStore), build with `BUNDLE_ID=com.kaffeindecaf.w0lfsword.filza`, or let
`./W0lfSword nojailbreak` do it: Apple's developer portal rejects every
`com.apple.*` identifier with API error 9400, so the MHA identity can never be
registered through a sideloader.

## For developers

Layout:

```
W0lfSword                  # CLI: menu, build, deploy, diagnostics, host tools
+-- Tweak.m                # the tweak's entry point and exploit driver
+-- TweakExploit.m         # exploit sequencing, retries, staged ladder
+-- sandbox_escape.m       # sandbox escape by patching kernel extension rules
+-- FilzaPadlockBypass.xm  # Filza UI hooks (Logos)
+-- kexploit/              # DarkSword engine, kernel R/W primitives, clamp
+-- SSV/                   # sealed system volume bypass
+-- terminal/              # in-process shell (route A) + command packages
+-- mobilegestalt/         # MobileGestalt editing module
+-- sbtweak/               # SpringBoard live-edit module
+-- utils/                 # logging, permissions, hide/reveal
+-- kpf/ + XPF/            # kernelcache grabber and offset patchfinder
+-- tools/xpf-cli/         # host-side XPF resolver
+-- pocs/                  # panic PoCs and the ImageIO probe
+-- tweaks/                # SpringBoard tweak catalog and installer
+-- tests/ + scripts/      # host harnesses, lints, regression and verification
+-- docs/                  # guides, ADRs, verification logs, WORKLOG
+-- research/              # framework research, fuzz harnesses, CVE catalogs
```

Build it:

```bash
sudo ./W0lfSword setup
make package                          # debug build
make package FINALPACKAGE=1 DEBUG=0   # release, no address-leak logging
```

Supporting a new iOS version: pull the kernelcache for that build, run the XPF
resolver on it (`tools/xpf-cli`, or `./W0lfSword kernelcache`), add a
`SYSTEM_VERSION_GREATER_THAN_OR_EQUAL_TO` block in `kexploit/offsets.m`, verify on
hardware, open a PR. Every offset that ships is read off a real kernelcache; none
of them are guessed. Run `./W0lfSword audit` and
`bash scripts/check_host_verification.sh --with-builds` before committing, and
record what ran in `docs/WORKLOG.md`. `docs/GLOSSARY.md` explains the vocabulary,
`docs/OFFSET_RESOLUTION_GUIDE.md` walks through the offset workflow, and
`docs/THREAT_MODEL.md` writes down what this tool is and is not safe against.

## Release history

<details>
<summary><b>v1.5.0, v1.4.0, and earlier</b></summary>

- **v1.5.0**: one command registry drives the whole CLI (menu rows, shortcuts,
  help and the new `commands` index are generated from it, so they cannot disagree
  any more); `commands (cmds)` index; audit now also parses every shell and Python
  file and runs `scripts/cli_consistency.py` to prove the registry, dispatch, menu,
  handlers, help text and section map still match.
- **v1.4.0**: main-device safety ladder (test builds read-only by default, modes
  switched with `Documents/w0lf_test_mode`), HUD device line, LOG export and
  RERUN buttons, failure cleanup that removes everything a failed run created,
  unsupported iOS goes quiet, `readiness (r)` with no SSH, 26.0.1 t8110 offsets
  XPF-verified.
- **v1.3.0**: crash reports for critical errors (version, commit, command line,
  config, device, log tail) with optional one-key filing as a GitHub issue via
  `gh`, `report` command, `report_errors` config key.
- **v1.2.0**: boot animation (the wolf's own characters scramble and settle, the
  menu text materializes below it), `config` command and `.w0lfsword/config`.
- **v1.1.0**: `usbtest` (harmless USB and pairing check), `panic` (crash-log
  classification mapped to known CVEs), `kernelcache` (offline offset research),
  `--json` output, version-aware hints after device detection, usbliter8 bundle
  refreshed, exploit matrix corrected.

</details>

## Credits

[Huy Nguyen](https://github.com/34306/) : original FilzaJailedDS .
[wh1te4ever](https://github.com/wh1te4ever/) : DarkSword exploit, XPF
offset engine . [opa334](https://github.com/opa334/) : XPF patchfinder,
krw primitives, sandbox structures . [khanhduytran0](https://github.com/khanhduytran0/) :
sandbox hook token technique . [CrazyMind90](https://github.com/crazymind90/) :
sandbox token acquisition via kernel R/W . [XEmaz](https://x.com/XEmaz_) :
SSV bypass, root chown, padlock/license bypass, zip hooks .
[kaffeindecaf](https://github.com/kaffeindecaf/) : 26.0.1 stability,
retries, threading, logging, tooling.

Built with knowledge from [felix-pb/kfd](https://github.com/felix-pb/kfd),
[opa334/TrollStore](https://github.com/opa334/TrollStore) and
[opa334/opainject](https://github.com/opa334/opainject).

## Reference library (`referenceforAI/`)

A local knowledge base that used to hold 23 third-party repos
(`projects/` + `moreprojects/`). On 2026-08-24 a full final research pass was
completed and archived into
[`referenceforAI/RESEARCH.md`](referenceforAI/RESEARCH.md): per-repo deep
dives (bug mechanics, object layouts, key files, PoC stages, live-versus-patched
status), a corrected technique matrix, roadmap mapping, and a provenance table
with every upstream URL and commit so any repo can be re-cloned in one command.
The project folders were then deleted; the skills, docs and SandboxEscape.md are
kept.

Highlights preserved in the archive:

- Exploit chains: `darksword-kexploit`, `DarkSword-RCE` (WebKit to kernel),
  `excalibur`, `kfd` (PUAF), `xnu_1day_practice` (14 CVE PoCs with analyses)
- WebKit/zero-click: Coruna kit (CVE-2024-23222), Glass Cage
  (CVE-2025-24085/24201)
- ImageIO: `CVE-2025-43300-hunters` (DNG 0-click + analyzer),
  `CVE-2025-43300-PwnToday`, `zero-click-exploit-analysis` (CVE-2025-55177),
  `CVE-2023-41064` (BLASTPASS), `exr-imageio-poc` (CVE-2026-28990)
- Kernel bugs: `CVE-2026-20687` (AppleJPEGDriver UAF), `DirtySlide`
  (CVE-2026-43724), `SEP-Exhaustion-Kernel-Panic`
- Sandbox escapes: `bad_query` (containermanagerd traversal, iOS 26–27),
  `FilzaSlop` (MCM container access, ported into `kexploit/mcm_bridge.m`)
- Bootchain: `usbliter8-fun`, `usbliter8-fun2` (A12/A13 SecureROM, iOS 27)
- Tooling: `iDevice-Toolkit` (CVE-2025-24203), `Mugunghwa`, `opainject`,
  `TrollStore`

The active research doc is
[`referenceforAI/SandboxEscape.md`](referenceforAI/SandboxEscape.md),
hunting a new sandbox escape for iOS 26.1 via the ImageIO memory
corruption angle.

## More docs

`CONTEXT.md` : project knowledge base, start here when resuming . `ROADMAP.md` :
the task list, including the open bugs with their evidence . `BUG_BOUNTY.md` :
security findings and Apple bounty ranges . `AUDIT_REPORT.md` : audit findings and
fixes . `DEBUG_TRACKING.md` : every log statement mapped . `BUILD.md` : Theos setup
and troubleshooting . `docs/WORKLOG.md` : what each host verification run actually
executed . `research/README.md` : index of the research tooling and deep dives.

## License

Code from DarkSword (wh1te4ever) and XPF/ChOma (opa334) remains under its
original authors' licenses. The integration layer and tooling are released
as-is for research and testing.

Modifying system files can leave your device unbootable. You've been warned.
