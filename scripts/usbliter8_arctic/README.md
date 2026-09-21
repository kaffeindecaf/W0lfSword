# usbliter8-arctic

The usbliter8 tethered jailbreak, wrapped in something you can actually operate. One TUI walks the whole chain, offsets live in validated YAML profiles, and nothing gets flashed before the profile has been checked against the real firmware bytes.

![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB) ![Tests](https://img.shields.io/badge/tests-345%20passing-2ea44f) ![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-5272A8) ![Exploit](https://img.shields.io/badge/exploit-usbliter8_%E2%80%A2_RP2350-8B5CF6)

Upstream usbliter8 is a folder of shell scripts and offsets you edit by hand. One wrong number and the device panics on boot. This repo keeps the same exploit (rav000's RP2350 firmware) and rebuilds the parts that hurt:

- a guided setup that walks wiring, firmware flashing and the first PWN, with retries
- offsets as YAML profiles that validate, carry evidence, and migrate across iOS betas on their own
- a preflight gate that compares every patch site against the actual firmware before the builder touches anything
- a build that prints what it patched, what it skipped, and why

Around 10,100 lines of Python in 26 modules, 305 tests. Two pip packages cover the basics (pyusb, pyyaml). pyimg4 is only needed to read firmware components off macOS, and capstone only for beta migration.

```
   [ IPSW ]  +  [ offset profile ]             [ RP2350 board ]
              |                                       |
              v                                       v
      +---------------+   patched CFW     +-----------------------+
      |  cfw_builder  |------------------>|  restore over USB     |
      +-------+-------+                   +-----------+-----------+
              ^                                       |
              |                                       v
      preflight: profile vs the              device boots patched.
      real component bytes.                   The exploit is re-applied
      Blocks on a mismatch.                   on every cold boot.
```

## What you get

**Guided setup instead of guesswork.** Board picker (Waveshare RP2350-USB-A, Pico 2, RP2350-Zero, Tiny2350), wiring diagrams, LED states, firmware download with UF2 magic validation, and PWN verification that polls the board instead of assuming.

**Profiles that know what they are.** Every offset profile is a YAML file with a per-entry sentinel, hex and type check, an active-device pointer, and an evidence file recording the original bytes preflight saw. A profile that drifted from its firmware reports that, it does not flash anyway.

**Beta migration that is not a guess.** `profile_gen.py migrate` fingerprints AArch64 instruction patterns with immediates wildcarded, finds them in the new build, and verifies each hit with capstone. Unique class match is 0.95, ambiguous is 0.60, delta-inferred is 0.30 and never auto-written. Every run leaves a report with a `REVIEW REQUIRED` section.

**The build tells on itself.** The CFW builder ends with a per-section manifest: patched, skipped, mismatch, failed, and which component file each section came from. The DeviceTree is patched in-tree by a native FDT parser, so a missing upstream checkout no longer means a silently skipped section.

## Quick start

Linux, macOS and Windows all work. The first run detects your OS, checks what is missing and offers to install it.

```bash
# Linux (root for raw USB) and macOS (no sudo)
git clone https://github.com/kaffeindecaf/usbliter8-arctic.git
cd usbliter8-arctic
chmod +x usbliter8 main.py
sudo ./usbliter8
```

```powershell
# Windows
git clone https://github.com/kaffeindecaf/usbliter8-arctic.git
cd usbliter8-arctic
py main.py
```

Then pick `1` in the menu. Guided Setup is the intended first run: it checks the board, flashes the exploit firmware, and ends with a verified PWN DFU before you build anything.

Nothing to install by hand up front, see [Dependencies](#dependencies-detected-and-offered) if you would rather do it yourself. What you do need: Python 3.9 or newer, an RP2350 board (not RP2040, A13 needs the RP2350) and a Lightning-to-USB-A cable.

```
./usbliter8 help          # every command
./usbliter8 pwn           # board + device + DFU state
./usbliter8 ul8 gaps      # which profiles still need offsets
```

## Menu

| Key | Action |
|---|---|
| `1` `h` | Guided Setup: wiring, flash firmware, verify PWN |
| `2` `c` | Configure device (model / iOS offset profile) |
| `3` `b` | Build custom firmware (IPSW + offsets) |
| `4` `f` | Flash CFW (erases all data) |
| `5` | Boot SSHRD ramdisk for filesystem access |
| `6` | Normal boot with patches applied |
| `7` | Post-boot setup (USB network, VNC, SSH, Sileo) |
| `8` `p` | Check PWN/DFU status |
| `9` `x` | Health check |
| `i` | Dependencies |
| `0` `e` | Explain the chain |
| `q` | Quit |

## Supported devices

| Device | Chip | Board | iBSS / iBEC | Kernel cache |
|---|---|---|---|---|
| iPhone XS / XS Max (incl. CN) | A12 | d321ap / d331ap / d331pap | d321 / d331 / d331p | 26.x only |
| iPhone XR | A12 | n841ap | n841 | 26.x only |
| iPhone 11 | A13 | n104ap | n104 | kernelcache.release.iphone12b |
| iPhone 11 Pro / Pro Max | A13 | d421ap / d431ap | d421 | kernelcache.release.iphone12 |
| iPhone SE (2nd gen) | A13 | d79ap | d79 | kernelcache.release.iphone12c |
| iPad mini 5 (WiFi / Cell) | A12 | j211ap / j212ap | **j210** | 26.x only |
| iPad Air 3 (WiFi / Cell) | A12 | j213ap / j214ap | **j210** | 26.x only |
| iPad 8 (WiFi / Cell) | A12 | j171ap / j172ap | **ipad11b** | 26.x only |
| iPad 9 (WiFi / Cell) | A13 | j181ap / j182ap | **ipad12p** | kernelcache.release.ipad12p |

Bootloader names are not board names. Apple names iPad bootloaders after the SoC family: an iPad 9 (`j181ap`) boots `Firmware/dfu/iBSS.ipad12p.RELEASE.im4p`, an iPad mini 5 (`j211ap`) boots `iBSS.j210...`, and the XS/XS Max IPSWs carry all three sibling images. `components.py` holds the verified names and refuses to guess when several candidates match (`--force-component` takes the first one on purpose).

Profile status: verified offsets for iPhone 11 Pro on 27.0b2/b3, and for iPhone 11 on 27.0 (24A437) plus 27.0b4 (24A5390f) imported from Liter8 fixtures. iPhone 11 Pro Max shares the Pro's kernel cache. iPhone 11, SE 2 and iPad 9 ship their own kernelcache binaries, so their kernel offsets have to come from that binary (the propagator refuses to copy across components). A12 devices top out at iOS 26 and need first-offset bootstrapping. Live table: `python3 profile_gen.py coverage`.

**iPad 9 is not flashable yet**, for one narrow reason. iBSS/iBEC/TXM offsets for 27.0b2/b3 were discovered from the device's own components (15/17 entries at 0.95 confidence), two `boot_args_string` sites score under 0.90 and stay pending. The kernel section is blocked: iPad 9 boots `kernelcache.release.ipad12p`, no verified offsets exist for it, and it cannot be derived here either, because the Apple Wiki publishes RootFS/Cryptex/SEP keys only for iPad12,x, so that kernelcache cannot be decrypted offline. The profile carries a `blockers:` entry saying exactly this, and the builder refuses those entries even under `--force`. Fixing it needs someone with an iPad 9 deriving the kernel sites, or a published `ipad12p` key.

---

Everything below this line is technical detail.

## Why not just run upstream

| Arctic | Upstream usbliter8 |
|---|---|
| Guided setup: board picker, wiring, LED guide, firmware download with UF2 validation and retries | "Solder D+/D- and figure it out" |
| Offset profiles: per device and iOS, validated, with evidence files and online source lookup | Offsets hardcoded in `make_cfw.py` |
| Beta migration: pattern fingerprinting, confidence scored, delta fallback, canonical cross-check | Re-discover every offset by hand, every beta |
| Hardware awareness: RP2350 VID/PID, DFU/WTF/restore states, PWN serial verification | Blind runs |
| CFW builder with dry-run and a per-section manifest | One device, one path, no preview |
| Restore flow with pre-checks, PWN verification, TSS proxy lifecycle, explicit `YES`, post-write validation | Run `restore_cfw.sh` and pray |
| Post-boot toolkit: USB networking, VNC, SSH (password via `SSHPASS`, never in `ps`) | Manual setup |
| Health check and dependency installer for apt/pacman/dnf/zypper/brew/pip | Cryptic pip errors |
| 305 tests, a b2 to b3 ground-truth oracle, 21 audit bugs found and fixed (`foundbugs.md`) | Hacked together |

## How the chain works

1. The RP2350 exploits the A12/A13 SecureROM, device enters PWND DFU
2. PWN DFU grants unsigned firmware execution: iBoot, kernel and device tree patches apply
3. A custom firmware is built from an Apple IPSW with the security bypasses patched in
4. Tethered: the exploit is re-applied on every cold boot

![Connection Overview](ConnectionOverview.png)

### Soldered board wiring

For boards without a USB-A host port (Pico 2, RP2350-Zero, Tiny2350), cut a Lightning-to-USB-A cable and solder the four wires:

```
                   SOLDERED BOARD WIRING
               Pico 2 / RP2350-Zero / Tiny2350

    Cut a Lightning-to-USB-A cable. Keep the Lightning
    end, discard the USB-A plug.

   Lightning cable                  Pico 2 board
   +---------------------+      +---------------------------+
   |  Lightning end >    |      |                           |
   |      iPhone         |      |   +--------------+        |
   +----------+----------+      |   | USB-C --> PC |        |
              |                 |   +--------------+        |
              +- Red   (VBUS)---+-> VBUS (pin 40)  5V!       |
              +- White (D+)  ---+-> GP12 (pin 16)           |
              +- Green (D-)  ---+-> GP13 (pin 17)           |
              +- Black (GND) ---+-> GND  (pin 38)           |
                                |                           |
                                +---------------------------+
```

Wire colors vary by brand, so check continuity from the Lightning pin to each wire with a multimeter before soldering. VBUS is 5V: never solder it to 3V3, that kills the board.

## Dependencies: detected and offered

Every entry point (`usbliter8`, `ul8.py`, `main.py`, `cfw_builder.py`, `preflight.py`, ...) runs the same check before it does anything:

1. detects the OS: name, distro, arch, Python version, venv or system, root or not, which package manager exists, and whether the terminal can answer questions
2. checks the packages the thing you asked for actually needs (editing a profile does not need the USB stack, a build does not need the test runner)
3. lists what is missing and why, then asks `install 2 package(s) now? [Y/n]`
4. installs with the right command for your OS: pip, or `uv pip` when the interpreter has no pip, and the detected system manager for libusb
5. re-checks, then continues or prints the exact command to run instead

```bash
python3 ul8.py deps              # report, then offer to install
python3 deps.py --check          # report only, never install
python3 deps.py --json           # machine-readable
python3 deps.py --feature build  # one feature: profiles, usb, build, fetch, migrate, security, tests
python3 deps.py --install --yes  # unattended install (CI, scripted setup)
```

It never installs anything without a `y`. Without a terminal (piped output, CI) it only reports what to run. The command is printed before it runs, so you can run it yourself instead. On PEP 668 distros (Debian 12+, Ubuntu 24+, Parrot) pip gets `--break-system-packages`, which is also printed rather than silently added. Declining is not a crash: the run continues and the step that needs the package says so on its own.

| Platform | Python packages | USB backend |
|---|---|---|
| Linux (apt/pacman/dnf/zypper) | `python -m pip install --user <pkg>` or the distro package | `libusb-1.0-0`, root needed for raw USB access |
| macOS | `python -m pip install --user <pkg>` | `brew install libusb` (bundled `tools/` run natively here) |
| Windows | `py -m pip install <pkg>` | `libusb-package` supplies the DLL; Zadig only if Windows still refuses the device |

The bundled binaries in `tools/` are macOS Mach-O. On Linux and Windows the toolkit prefers a usable binary on your `PATH`, skips the bundled one when it cannot run, and falls back to its own Python IMG4 codec (`img4wrap.py`) when no tool can read a component.

| Variable | Effect |
|---|---|
| `UL8_NO_DEPS=1` | skip the check entirely |
| `UL8_AUTO_INSTALL=1` | install missing packages without asking |
| `UL8_DEBUG=1` | print tracebacks instead of the one-line error |

`--no-deps` does the same as `UL8_NO_DEPS=1` for one run.

## Offset migration (`profile_gen.py migrate`)

Re-discovers patch offsets for a new beta. AArch64 instructions are fingerprinted with immediates wildcarded (`fingerprint.py`), searched in the target binary, and verified with capstone disassembly.

- components: `--comp-dir` with `base/` and `target/` raw files (`kernelcache.raw`, `iBSS.raw`, `iBEC.raw`, `RestoreRamdisk.raw`, `TXM.raw`), or `--fetch` to run the work dir's `get_fw.py`
- confidence: 0.95 unique plus class match, 0.90 unique string site, 0.60 ambiguous, 0.30 multi-hit or delta-inferred
- output: `migrate_report.md` with a per-entry table, site hexdump, and `REVIEW REQUIRED` plus `CANONICAL CONFLICTS` sections. `--auto` writes the target profile with `migrated:` metadata and post-write validation
- safety: nothing under 0.90 gets written automatically, and delta inference is LOW by design

```bash
python3 profile_gen.py migrate offsets/iPhone12,3_27.0b2.yaml offsets/iPhone12,3_27.0b3.yaml \
    --comp-dir extracted/ --report migrate_report.md
python3 profile_gen.py migrate offsets/iPhone12,3_27.0b3.yaml 27.0b4 --auto   # bootstrap a new beta
```

## Preflight: verify before you flash

No usbliter8 fork checks a profile before flashing. This one does, against the real bytes:

```bash
python3 preflight.py offsets/iPhone12,1_27.0.yaml             # auto-finds research/extracted/<Model>_<ios>_<build>/
python3 preflight.py offsets/iPhone12,1_27.0.yaml --fetch --record
python3 preflight.py offsets/iPhone12,3_27.0b3.yaml --components research/extracted/iPhone123_27.0b3_24A5380h --json
python3 cfw_builder.py iPhone12,3_27.0b3.ipsw offsets/iPhone12,3_27.0b3.yaml --check-only
```

Each entry is classified: `match` (the recorded original bytes are there), `plausible` (decodes as a real instruction, nothing recorded yet), `already-patched`, `changed` (recorded bytes absent, so the profile does not belong to this component), `implausible`, `out-of-range`, `skipped` (no raw component: encrypted kernelcache or ramdisk, rootfs daemons). `pending: true` entries are skipped, never failed.

`--record` writes what it verified to `offsets/evidence/<profile>.json` and that file is committed, which makes a profile self-verifying: point it at another board's firmware and it reports `changed` and blocks. Exit codes are 0 for ok or review and 2 for blocked, so CI or a script can gate a restore. Kernelcaches stay `skipped` until you decrypt them with the wiki IV and key. The builder runs this gate before patching and refuses a blocked profile unless you pass `--force`.

## Patch manifest

`cfw_builder.py` prints what the build actually did: `patched` / `skipped` / `mismatch` / `failed` per section, with the component file each section resolved to. Anything this path cannot apply is reported instead of disappearing:

- DeviceTree is patched in-tree by `dt_patch.py` (content-protect removal, `no-effaceable-storage`, `boot-ios-diagnostics`, `ephemeral-storage`, optional `system_rw`) driven by the profile's flags. It no longer shells out to the upstream work dir's `patch_dt.py` and no longer skips the section when that directory is missing.
- RestoreRamdisk: on iOS 26/27 IPSWs the ramdisk is a bare root-level `.dmg` and those offsets target `restored_external` and `asr` inside the mounted image. That cannot be patched or re-signed here, so the build says so and warns that asr/FDR checks may fail on restore. Classic `.dmg.im4p` layouts are patched in place.
- Kernel entries marked `invalid_component` (derived from another device's kernelcache) are refused even under `--force`.

## Keeping offsets honest

Profiles are only as good as the artefact they came from, so the repo can re-derive and re-check them.

- `fetch_components.py` pulls iBSS/iBEC/TXM/DeviceTree/kernelcache out of any IPSW on Apple's CDN with HTTP range requests (`kczip.py`, ported from W0lfSword), so discovering offsets does not need a 6 GB download. `--list` shows matching entries, `--extract-payload` unwraps the im4p with `img4wrap.py` (or pyimg4 when installed).

  `--profile` is the one-command version: device, build and the component list come from the profile, the output lands in the directory preflight looks in, and the last line tells you the preflight command to run. Components already on disk are skipped (`--refresh` re-downloads), several can come down at once (`--jobs 4`), and every fetch is checked against the recorded evidence, so "3 components, all matching the committed profile" is something you read, not something you assume. Each run writes `provenance.json` next to the components (entry name, size, sha256 of the file and of the payload, evidence verdict).
- `source_audit.py` parses an upstream `make_cfw.py` (wh1te4ever or 34306) or a Liter8 fixture set and diffs it against a profile byte by byte: `COVERED`, `PARTIAL`, `MISMATCH`, `REVIEW` (PC-relative sites such as adrp/add redirects are not comparable across builds), `MISSING`, `PROFILE-ONLY`. Reports land in `research/work/`.
- `liter8_import.py` maps Liter8's reviewed fixture oracles onto our entry names, refuses anything whose payload is not our canonical patch, marks the rest `pending`, and with `--verify-components` re-checks every mapped site against the real binary before writing.
- `profile_gen.py gaps` prints the per-section matrix and flags profiles whose kernel section came from a board with a different kernelcache component.

```bash
python3 fetch_components.py --profile offsets/iPhone12,3_27.0b3.yaml        # everything it needs
python3 fetch_components.py --device iPhone12,3 --build 24A5380h --all --jobs 4
python3 source_audit.py script <usbliter8-fun>/work-27.0b3/make_cfw.py offsets/iPhone12,3_27.0b3.yaml
python3 liter8_import.py --fixtures Liter8/fixtures --build 24A435 --board n104ap \
    --model iPhone12,1 --ios 27.0 --verify-components research/extracted/iPhone121_27.0_24A437 --write
```

### The 2026-09-20 audit

Auditing the iPhone 11 Pro profiles against the upstream scripts and the real b2/b3 components turned up five wrong entries:

| Entry | Was | Is | Why |
|---|---|---|---|
| `kernel.Post-validation bypass` (b3) | 0x1F2B368 | 0x1F29480 | b2 value carried over; upstream b3 script and the AMFI unit shift (-0x1EE8) agree |
| `kernel.Check dyld policy internal` (b3) | 0x1F2B8C8 | 0x1F299E0 (site 2 at 0x1F299EC) | same carry-over; upstream patches two return paths |
| `kernel.AMFI trust everything` (b2/b3) | `200080d2c0035fd6` | `5f2403d5200080d2430000b4600000f9c0035fd6` | 8 of 20 bytes: upstream and Liter8 also write the BTI, cbz and str that publish the result |
| `txm.query_module0/1` (b3) | 0x39CB0 / 0x39E18 | 0x39CA8 / 0x39E10 | all three queryModule sites moved -0x8 in b3, only queryModule2 had been updated |
| `ibec.keep_nonce_b` (b2/b3) | `28000014` (b #0xA0) | `0a000014` (b #0x28) | the original site is `tbnz w8,#1,#+0x28`; b #0xA0 lands in unrelated code, verified in both real iBEC binaries |

`kernel.Kernel identity string 1/2` (the `/RELEASE_ARM64_T8030` to `/PATCHED_ARM64_T8030` rename both upstream projects do) was missing entirely and is now part of the kernel section, and `cfw_builder.py` writes ASCII payloads for string patches as well as hex.

## Sending data back

When a run produces something that belongs in the repo (a profile you filled in, or fresh evidence for one) the toolkit offers to open a **pull request** with it. The files go on a branch cut from `origin/main`, the PR carries the run's context, and nothing is in the repo until you review the diff and merge it:

```
  Send this back?
    These files are waiting in your tree. A pull request adds them to the repo,
    and nothing lands until you merge it:
      offsets/iPhone12,1_27.0b5.yaml  (new, 9214 bytes)
      offsets/evidence/iPhone12,1_27.0b5.json  (new, 4180 bytes)
      branch: offsets/iPhone12-1-27.0b5-24A5400a  ·  base: main

    This is exactly what the pull request body would contain:
      adds: offsets/iPhone12,1_27.0b5.yaml (new, 9214 bytes)
      device: iPhone 11 iPhone12,1 iOS 27.0b5 (24A5400a)
      components: ibec, ibss, txm (sizes + sha256)
      verification: review (16 match, 0 changed)
      environment: Linux / python 3.13.5 / usbliter8 0.2.0-beta
      redacted: 3 identifier(s) (/home/<user>)

  Open a pull request that adds these files? [y/N/never]:
```

How it behaves:

- a worker directory (git worktree) is used, so your checkout, your branch and any uncommitted work are untouched
- only `offsets/` files are ever committed: the profile and its evidence. A dirty README or a source file in the same tree is never included
- the branch is unique per device and build, so a second run does not fight the first; nothing is ever force-pushed and `main` is never written to directly
- if your account cannot push to the repo, it forks it first and opens the PR from the fork
- if there is nothing to add (you verified an existing profile, no new evidence), there is no PR to open, so it files an issue with the same context instead
- if `gh` is missing or the push fails, nothing is lost: the bundle is written to `contribute/inbox/` with the exact commands to run by hand

```
  ./usbliter8 share status        # on or off, what it would send, push access
  ./usbliter8 share preview       # the files, the branch and the bundle: exactly what would go
  ./usbliter8 share send          # asks, then opens the pull request (or the issue)
  ./usbliter8 share send --pr     # insist on a pull request
  ./usbliter8 share send --issue  # insist on a report instead
  ./usbliter8 share off           # never ask again
```

Nothing is sent without the yes. `never` is remembered, `./usbliter8 share on` turns it back on, `UL8_NO_SHARE=1` skips it for one run, and without a terminal it does not prompt at all: it prints the command that would send it. This is the same data `./usbliter8 contribute pr` puts in a PR description, collected automatically from the run.

## CLI usage

Every verb works through any entry point. `ul8.py <verb>` is the shortest one, and modules can still be run directly when you only want that piece.

```bash
python3 ul8.py menu                                   # the TUI (default with no arguments)

python3 ul8.py logs --tail 20 --level ERROR           # what went wrong, from usbliter8.log
python3 ul8.py logs --grep ipad12p --json             # machine-readable
python3 ul8.py logs --summary                         # what recent runs cost, slowest steps
python3 ul8.py share preview                          # the files, branch and bundle that would go back

python3 device_offsets.py list                        # available offset profiles
python3 device_offsets.py validate offsets/iPhone12,3_27.0b2.yaml
python3 device_offsets.py find iPhone11,8             # online offset sources

python3 profile_gen.py list                           # device database
python3 profile_gen.py create iPhone12,3 27.0          # new profile (sentinel offsets)
python3 profile_gen.py coverage                       # per-device status table
python3 profile_gen.py gaps                           # which sections still need offsets

# Sibling propagation: carries kernel/daemon offsets when both boards ship the same
# kernelcache component, and refuses across different ones
# (iPhone12,1 = iphone12b vs iPhone12,3 = iphone12)
python3 profile_gen.py propagate offsets/iPhone12,3_27.0b2.yaml iPhone12,5
python3 profile_gen.py propagate offsets/iPhone12,3_27.0b2.yaml iPhone12,1 \
    --comp-dir extracted/ --force                     # also fingerprints iBSS/iBEC/TXM

# Complete the pending sections of a profile from a verified base plus components
python3 profile_gen.py fill offsets/iPad12,1_27.0b2.yaml --from offsets/iPhone12,3_27.0b2.yaml \
    --comp-dir /tmp/comps --sections ibss,ibec,txm
```

## Exit codes and logs

Nothing should hand you a Python traceback: the device in the loop is real hardware, and "it printed a stack trace" is not a usable report. Every entry point runs through `log_utils.guard()`, so anything that happens ends as a documented exit code, one readable line on screen, and the detail in `usbliter8.log`.

| Exit | Meaning |
|---|---|
| `0` | finished |
| `1` | refused or failed cleanly (bad input, missing file, unknown subcommand) |
| `2` | verification refused to continue, e.g. preflight says the profile does not match the firmware |
| `3` | unexpected exception, traceback recorded in the log |
| `130` | interrupted (Ctrl-C) |

```bash
python3 ul8.py version             # version + commit + log path
python3 ul8.py logs --level ERROR  # what went wrong, with tracebacks
UL8_DEBUG=1 python3 ul8.py build   # also print the traceback on screen
```

In practice: a crash prints `Something went wrong: <type>: <message>` plus the log path, Ctrl-C exits 130 instead of raising, piping into `head` is not an error, prompts tolerate EOF (a prompt that would erase the device stops rather than guessing, `main.py flash < /dev/null` exits 1), an unimplemented subcommand lists what exists instead of opening the menu, and the dangerous stages (restore, normal boot, TSS proxy) log their exit code so the file explains what happened after the fact.

Every error and warning that reaches the screen is appended to `usbliter8.log` in the repo root, tagged with the module and line that produced it. The file is gitignored, capped at 2 MB and rotated to `.1`, `.2`, `.3`.

Every run ends with one line in the log saying what it cost (steps, warnings, errors, wall time, exit code), so `python3 ul8.py logs --summary` can show the recent runs and the slowest steps without reading the raw entries.

```bash
python3 ul8.py logs                            # header plus the last 60 entries
python3 ul8.py logs --summary                  # recent runs, durations, slowest steps
python3 ul8.py logs --since 2026-09-21T14 --grep sandbox
python3 ul8.py logs --path                     # just the file path
python3 ul8.py logs --json | python3 -m json.tool
UL8_LOG_FILE=/tmp/ul8.log python3 ul8.py pwn    # another location
UL8_NO_LOG=1 python3 ul8.py build               # no file at all
```

Logging never breaks a run: an unwritable path prints one stderr note and disables itself, and test runs never touch the repo log.

## Repo safety and CI

The repo is public and its output gets flashed onto real hardware, so two kinds of accident are guarded mechanically: leaking something personal, and shipping offsets that no longer match their evidence.

```bash
python3 safety_check.py            # the same gate CI runs
python3 safety_check.py --strict   # warnings (badge drift, docs style) fail too
```

`safety_check.py` fails on private keys, tokens or UDIDs in tracked files, machine-local home paths, tracked generated files, profiles that do not validate or whose file name disagrees with `model` and `ios_version`, a profile claiming to be verified while it still has pending entries or blockers, and `offsets/evidence/*.json` whose recorded offsets no longer match the profile. It warns on the test badge drifting from the collected count and on em dashes in docs. Append `# safety-allow: <reason>` to a line you deliberately want to keep.

CI runs `compileall`, `safety_check.py`, every profile through `device_offsets.py validate`, and the test suite on 3.13, plus the suite on 3.9.

`main` is protected by the `protect-main` ruleset: no deletion, no force-push, changes through a PR (0 required approvals so solo work is not blocked), and the `tests` job must pass on an up to date branch. The admin role can bypass, which is why a direct push prints `Bypassed rule violations ...` and goes through anyway. A second ruleset, `keep-working-branches`, protects `feat/*` from deletion while leaving force-push available for the amend workflow.

To make the rules apply to everyone, remove the admin bypass: `gh api -X PUT repos/kaffeindecaf/usbliter8-arctic/rulesets/<id> --input -` with `{"bypass_actors": []}`.

Security reports: see [SECURITY.md](SECURITY.md). Use private reporting, not issues.

## Entry points and layout

Three ways in, one place where the commands live:

| You type | What runs | Notes |
|---|---|---|
| `./usbliter8` | the terminal script, which drives the TUI or a subcommand | the friendly front door: root gate for USB commands, progress output, `./usbliter8 ul8 <verb>` forwards to the launcher |
| `python3 ul8.py <verb>` | `ul8.py` -> `cli.py` | standalone, no bash, same verbs, no root gate |
| `python3 main.py <verb>` | `main.py` -> `cli.py` | kept because scripts and the wrapper have always called it |

`cli.py` holds the verb table (verb, description, handler) and is the only dispatcher: the help text, the unknown-subcommand message and the dependency check all read from it, so a command cannot be advertised without being dispatchable. `main.py` is the TUI, `ul8.py` is a three-line shim, and the menu is one verb among the others.

```
usbliter8-arctic/
├── usbliter8             # terminal script (W0lfSword style), friendly front door
├── cli.py                # the verb table: one dispatcher for every subcommand
├── main.py               # TUI: banner, menu, build/flash/boot flows
├── ul8.py                # standalone launcher (shim around cli.py)
├── contribute.py         # offset contribution helper (new/status/pr/share)
├── share.py              # the ask-before-sending flow (bundles, scrubs, opens an issue)
├── toolchain.py          # bundled tool paths (Mach-O aware) + command runner
├── boot_chain.py         # boot / restore / SSH / post-boot utilities
├── cfw_builder.py        # CFW patching pipeline (per-section patch manifest)
├── components.py         # per-device IPSW component resolution (iBSS/iBEC/kernel)
├── dt_patch.py           # native DeviceTree (FDT) patcher
├── pwn_utils.py          # USB detection + PWN verification
├── device_offsets.py     # YAML offset profile manager
├── profile_gen.py        # profile generator + migrate entrypoint
├── migrate.py            # migration orchestrator (delta, canonical check, report)
├── fingerprint.py        # AArch64 pattern fingerprint engine
├── source_audit.py       # upstream script / fixture vs profile diff
├── liter8_import.py      # Liter8 fixture oracle importer
├── fetch_components.py   # ranged IPSW component fetcher + IPSW url resolution
├── preflight.py          # verify a profile against the real component bytes
├── kczip.py              # zip64 range reader (ported from W0lfSword)
├── img4wrap.py           # IMG4/IM4P container read+write (lzfse via pyimg4)
├── safety_check.py       # pre-push/CI gate: leaks, machine paths, profile/evidence drift
├── hardware_guide.py     # guided setup, health check, firmware flashing
├── deps.py               # OS detection, dependency check and installer
├── log_utils.py          # usbliter8.log: errors, warnings, tracebacks, exit guard
├── version.py            # version + git commit of the checkout
├── colors.py             # ANSI helpers
├── .github/workflows/    # CI: compileall + safety check + profiles + tests (3.13 and 3.9)
├── offsets/              # device offset profiles (+ template, sources, canonical.yaml)
│   └── evidence/         # preflight-recorded original bytes per profile
├── tools/                # binary utilities (img4, img4tool, usbliter8ctl)
└── firmware/             # downloaded UF2 firmware files
```

## Contributing offsets

If you have offsets for a device and iOS combo that is not covered, the `contribute` flow handles the whole thing:

```bash
./usbliter8 contribute                              # guided wizard
./usbliter8 contribute status                       # which profiles exist + validation state
./usbliter8 contribute new iPhone12,1 27.0b4        # create a profile from the template
./usbliter8 contribute pr offsets/iPhone12,1_27.0b4.yaml   # PR description + git commands
```

The wizard asks for the model and iOS version, creates the profile from the template with `DEADBEEF` sentinels, opens it in `$EDITOR`, validates your work, and refuses to generate a PR description until every sentinel is gone. The `pr` command prints a copy-paste-ready description (device table, patch counts) plus the git commands. Two rules from `OffsetMigrationChecklist.md` still apply: never rate an inferred offset above LOW confidence, and never let anything under 0.90 auto-write without review.

## Patch overview

- **iBSS / iBEC**: Image4 validation bypass, boot-args injection, nonce preservation
- **Kernel**: USB restriction removal, sandbox bypasses, AMFI trust, APFS seal/SSV bypass, SEP panic bypass, launchd constraints, debugger unlock
- **Device Tree**: content-protection removal, ephemeral storage
- **Restore Ramdisk**: ASR signature bypass, FDR force-succeed
- **Daemons**: coreauthd, ctkd, mobileactivationd activation bypass

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `No backend available` / `libusb-1.0 missing` | pyusb cannot reach libusb. `python -m pip install libusb-package`, or install libusb-1.0 and bind the device with Zadig. `python3 -c "import pwn_utils; print(pwn_utils.usb_problem())"` prints the exact state and per-OS hints |
| `preflight blocked this build: the profile does not match the component` on a correct IPSW | Was a bug: components were compared as IMG4 containers instead of their decompressed payload. Fixed, and unreadable components now report as skipped instead of "changed". If it still blocks, `python3 preflight.py <profile> --quiet` shows the first failing site |
| `no IPSW url found for <device> <build>` | the url lookup does not know that beta build. Harmless when you point the build at a local IPSW |
| `cannot unwrap <component>: ... pip install pyimg4` | the component is lzfse-compressed and no decoder is installed |
| a run ended with exit `3` | unexpected exception: `python3 ul8.py logs --level ERROR` has the traceback, `UL8_DEBUG=1` prints it directly |
| `no pip and no uv in this python - cannot install for you` | the interpreter has neither. `python3 -m ensurepip --upgrade`, or use a venv |
| pip refused with `externally-managed-environment` | PEP 668 distro. The check adds `--break-system-packages` when not in a venv, or use a venv |
| `deps` says a package is missing but `pip list` shows it | different interpreter: the line above the packages says which Python is in use |
| `deps` reports `libusb-1.0 missing` on Linux | install it (`sudo apt install libusb-1.0-0`) and run `sudo ldconfig` |
| a prompt vanished or said "input ended" | stdin is not a terminal (piped or CI). Prompts that could erase the device stop instead of assuming an answer |
| a PR was not opened ("fell back to an issue") | no push access (it forks first), `gh` not logged in, or a git error: the message says which, and the branch it wanted stays printed. The files are still in your tree |
| a "Send this back?" prompt in a script or CI | it must not appear: `UL8_NO_SHARE=1` (or `share off`) disables it, and it never prompts without a terminal |
| `logs --summary` shows a run with no summary | that run was killed, or it is the reader itself: the summary is written when the process exits |
| offsets look unchanged but the device panics | kernel offsets are per `kernelcache.release.*` component. `python3 profile_gen.py gaps` shows a profile whose kernel section came from another board |

## Warnings

- Tethered jailbreak: the device does not boot without the RP2350 exploit applied on every cold start
- Flashing CFW erases all data, so keep a backup
- Kernel exploit: a wrong offset can panic or brick the device. This is a research tool for people who understand that

## Credits

- [rav000/usbliter8](https://github.com/rav000/usbliter8): RP2350 firmware and exploit
- [wh1te4ever/usbliter8-fun](https://github.com/wh1te4ever/usbliter8-fun): CFW scripts and boot chain
- [W0lfSword](https://github.com/W0lfSword): kernel offset research, ranged IPSW fetcher (`kczip.py`)
- [Xplo8E/Liter8](https://github.com/Xplo8E/Liter8): per-build resolver fixtures for iPhone 11 (n104ap)
- [34306/usbliter8-fun](https://github.com/34306/usbliter8-fun): second source for the 27.0b2/b3 patch sites
- [blacktop/ipsw-diffs](https://github.com/blacktop/ipsw-diffs): per-build kernel and kext diffs used as change evidence
- [Octopus1633/usbliter8-firmware](https://github.com/Octopus1633/usbliter8-firmware): prebuilt UF2 binaries
