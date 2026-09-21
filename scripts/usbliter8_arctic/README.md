# usbliter8-arctic

> The easy way to run the usbliter8 tethered jailbreak. A TUI hub that walks you through the whole chain: wire up an RP2350 board, flash the exploit firmware, build a custom firmware for your A12/A13 iPhone or iPad, restore it, and boot. Offsets are managed as validated YAML profiles, and a fingerprint engine migrates them between iOS betas automatically.

![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB) ![Tests](https://img.shields.io/badge/tests-227%20passing-2ea44f) ![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-5272A8) ![Exploit](https://img.shields.io/badge/exploit-usbliter8_%E2%80%A2_RP2350-8B5CF6)

## Quick start

### Linux (Debian / Ubuntu / Parrot)

```bash
git clone https://github.com/kaffeindecaf/usbliter8-arctic.git
cd usbliter8-arctic

sudo apt install python3-usb python3-yaml libusb-1.0-0
chmod +x usbliter8 main.py
sudo ./usbliter8
```

> New to usbliter8? Start with `1` (Guided Setup). It walks you through hardware, firmware flashing and your first PWN with built-in checks and retries.

### macOS

```bash
git clone https://github.com/kaffeindecaf/usbliter8-arctic.git
cd usbliter8-arctic

brew install libusb
python3 -m pip install --user pyusb pyyaml
chmod +x usbliter8 main.py
./usbliter8
```

> The bundled tools in `tools/` are macOS Mach-O binaries, so macOS runs them natively. No sudo needed.

### Windows

```powershell
git clone https://github.com/kaffeindecaf/usbliter8-arctic.git
cd usbliter8-arctic

py -m pip install pyusb pyyaml pyimg4 libusb-package
py main.py
```

> **libusb**: `libusb-package` (installed above) supplies the DLL, so Zadig is only
> needed when Windows still refuses the device: bind the WinUSB driver to the
> RP2350 (RPI-RP2 bootloader) and to the iPhone in DFU mode.
>
> **Firmware components**: `pyimg4` unwraps the IMG4/lzfse containers IPSW
> components ship in. The bundled `tools/` binaries are macOS Mach-O and are
> ignored here, so without `pyimg4` a CFW build cannot read or write components.
> Which of the two is in use is printed by `py deps.py` under `IMG4 codec`.

### The `usbliter8` terminal script

`./usbliter8` is the main entry point, same style as the W0lfSword script: run it bare for an interactive menu, or pass a command for one-shot use.

```bash
./usbliter8 guided        # guided hardware setup
./usbliter8 pwn           # check PWN/DFU status
./usbliter8 coverage      # per-device profile status
./usbliter8 contribute    # add new offsets + prepare a PR
./usbliter8 help          # full command list
```

Run `./usbliter8` bare for the interactive menu. `main.py` and `ul8.py` are the same TUI underneath: `python3 main.py` or `python3 ul8.py menu`. Run `ul8.py` bare for a quick menu, or pass a subcommand: `menu`, `pwn`, `offsets`, `explain`, `health`, `deps`.

| Key | Action |
|---|---|
| `1` `h` | Guided Setup: wiring, flash firmware, verify PWN |
| `2` `c` | Configure device (model / iOS offset profile) |
| `3` `b` | Build custom firmware (IPSW + offsets) |
| `4` `f` | Flash CFW, erases all data |
| `5` | Boot SSHRD ramdisk for filesystem access |
| `6` | Normal boot with patches applied |
| `7` | Post-boot setup (USB network, VNC, SSH, Sileo) |
| `8` `p` | Check PWN/DFU status |
| `9` `x` | Health check |
| `i` | Install dependencies (pyusb, pyyaml, libusb) |
| `0` `e` | Explain capabilities |
| `q` | Quit |

## Why usbliter8-arctic?

The original flow (rav000's RP2350 firmware + wh1te4ever's scripts) is raw scripts and hand-edited offsets. Arctic is the engineering around it:

| Arctic | Original usbliter8 |
|---|---|
| **Guided setup**: board picker, wiring diagrams, LED guide, troubleshooting, firmware download with UF2-magic validation + retries | "Solder D+/D- and figure it out" |
| **Offset profiles**: per-device/iOS YAML with validation (sentinel + type + hex), active-device config, online source lookup | Offsets hardcoded in `make_cfw.py` |
| **Beta-to-beta migration**: `profile_gen.py migrate` auto-finds every patch site in a new beta via AArch64 pattern fingerprinting (capstone-verified), confidence-scored, with delta fallback + canonical cross-check | Re-discover all offsets by hand every beta |
| **Hardware awareness**: RP2350 VID/PID detection, DFU/WTF/restore detection, PWN serial verification with polling | Blind runs |
| **CFW builder with dry-run**: board-aware paths, dry-run simulation, correct IMG4 type tags, temp cleanup | One device, one path, no preview |
| **Safe restore flow**: script pre-checks, PWN verification, TSS proxy lifecycle, explicit `YES`, post-write validation | Run `restore_cfw.sh` and pray |
| **Post-boot toolkit**: USB networking, VNC, SSH (password via `SSHPASS` env, never in `ps` output) | Manual setup |
| **Health check + deps installer**: one command verifies board/firmware/tools/USB; apt/pacman/dnf/brew/pip detection | Cryptic pip errors |
| **Engineered**: 35-test pytest suite with a b2→b3 ground-truth oracle, 21 audit bugs fixed (`foundbugs.md`), session logging, colored TUI | Hacked together |

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

> **Bootloader names are not board names.** Apple names iPad bootloaders after the
> SoC family, not the board: an iPad 9 (`j181ap`) boots
> `Firmware/dfu/iBSS.ipad12p.RELEASE.im4p`, an iPad mini 5 (`j211ap`) boots
> `iBSS.j210...`, and the XS/XS Max IPSWs carry all three sibling images
> (`d321` + `d331` + `d331p`). `components.py` holds the verified per-device
> names and refuses to guess when several candidates match. Pass
> `--force-component` to take the first candidate deliberately.

> **Profile status**: verified offsets exist for iPhone 11 Pro (iPhone12,3) on 27.0b2/b3, and for iPhone 11 (iPhone12,1) on 27.0 (24A437) and 27.0b4 (24A5390f) imported from Liter8 fixtures. iPhone 11 Pro Max shares iPhone 11 Pro's kernel cache; iPhone 11 / SE 2 / iPad 9 have their own kernelcache binaries, so their kernel offsets must come from that component (the propagator refuses to copy across components). A12 devices top out at iOS 26 and need first-offset bootstrapping. Live status: `python3 profile_gen.py coverage`.

### iPad 9 status

iPad 9 (iPad12,1 / iPad12,2) is **not flashable yet**, and the reason is narrow:

* iBSS / iBEC / TXM offsets for 27.0b2/b3 were discovered from the device's own
  components (`profile_gen.py fill ... --comp-dir`, 15/17 entries at 0.95
  confidence). The two remaining `boot_args_string` sites score below the 0.90
  floor and stay pending.
* The **kernel** section is blocked: iPad 9 boots `kernelcache.release.ipad12p`,
  and no verified offsets exist for that component. Offsets cannot be copied
  from an iPhone (different binary), and it cannot be derived here either: The
  Apple Wiki publishes keys for RootFS, Cryptex and SEP only for iPad12,x, so
  the kernelcache cannot be decrypted offline. The profiles carry a `blockers:`
  entry saying exactly this, `device_offsets.py activate` prints it, and the
  builder refuses those entries even under `--force`.
* Making iPad 9 work needs one of: someone with an iPad 9 deriving the kernel
  sites (that is how every other kernel key/offset set started), or a published
  `ipad12p` kernelcache key.

Run `python3 profile_gen.py gaps` to see the same picture per profile.

> **Kernel offsets are per binary, not per SoC**: every A13 board ships a different `kernelcache.release.*`, verified 2026-09-20 against the shipped 27.0 (24A437) IPSWs. iOS 27 dropped the A12 iPhones entirely (no iPhone XS/XR 27.x IPSW exists).

## How it works

1. **RP2350** exploits the A12/A13 SecureROM → device enters **PWND DFU** mode
2. **PWN DFU** grants unsigned firmware execution: iBoot, kernel and device-tree patches are applied
3. **Custom firmware** is built from an Apple IPSW with security bypasses patched in
4. **Tethered boot**: the exploit must be re-applied on every cold boot

## Diagrams

### Connection overview

![Connection Overview](ConnectionOverview.png)

### Soldered board wiring

For boards without a built-in USB-A host port (Pico 2, RP2350-Zero, Tiny2350), cut a Lightning-to-USB-A cable and solder the four internal wires to the GPIO pins:

```
                   SOLDERED BOARD WIRING
               Pico 2 · RP2350-Zero · Tiny2350

    Cut a Lightning-to-USB-A cable. Keep the Lightning
    end, discard the USB-A plug.

   Lightning cable                  Pico 2 board
   ┌─────────────────────┐      ┌───────────────────────────┐
   │  Lightning end ►    │      │                           │
   │      iPhone         │      │   ┌──────────────┐        │
   └──────────┬──────────┘      │   │ USB-C ──► PC │        │
              │                 │   └──────────────┘        │
              ├─ Red   (VBUS)───┤─► VBUS (pin 40) ⚠ 5V!     │
              ├─ White (D+)  ───┤─► GP12 (pin 16)           │
              ├─ Green (D-)  ───┤─► GP13 (pin 17)           │
              └─ Black (GND) ───┤─► GND  (pin 38)           │
                                │                           │
                                └───────────────────────────┘
```

> ⚠️ **Wire colors vary by brand**: verify continuity from the Lightning pin to each wire with a multimeter before soldering.
>
> ⚠️ **VBUS is 5V**: never solder it to the 3V3 pin or you will destroy the board.

## Prerequisites

- **RP2350 board** (NOT RP2040, A13 requires RP2350): Waveshare RP2350-USB-A (recommended, no soldering) · Raspberry Pi Pico 2 · Waveshare RP2350-Zero · Pimoroni Tiny2350
- `pyusb` + `pyyaml` for USB and profiles, `pyimg4` for IPSW components on Linux/Windows (the bundled `tools/` are macOS Mach-O)
- Lightning-to-USB-A cable + a compatible A12/A13 device
- Python 3.9+ (Linux/macOS/Windows)
- Binary tools in `tools/` are macOS Mach-O; the interactive menu guides tool handling, and `deps.py` falls back to tools on your PATH

## CLI usage

Standalone script interfaces:

```bash
python3 ul8.py menu                                   # TUI hub (alias of main.py)

python3 pwn_utils.py scan | wait                      # USB detection / PWN wait
python3 ul8.py logs                                   # errors this far, from usbliter8.log
python3 ul8.py logs --tail 20 --level ERROR           # last 20 errors only
python3 ul8.py logs --grep ipad12p --json             # machine-readable

python3 device_offsets.py list                        # available offset profiles
python3 device_offsets.py validate offsets/iPhone12,3_27.0b2.yaml
python3 device_offsets.py find iPhone11,8             # online offset sources

python3 profile_gen.py list                           # device database
python3 profile_gen.py create iPhone12,3 27.0         # new profile (sentinel offsets)
python3 profile_gen.py diff a.yaml b.yaml

# Sibling propagation: carries kernel/daemon offsets when both boards ship the
# same kernelcache component, and always refuses across different components
# (iPhone12,1 = iphone12b vs iPhone12,3 = iphone12)
python3 profile_gen.py propagate offsets/iPhone12,3_27.0b2.yaml iPhone12,5
python3 profile_gen.py propagate offsets/iPhone12,3_27.0b2.yaml iPhone12,1 \
    --comp-dir extracted/ --force                     # + auto-discover iBSS/iBEC/TXM via fingerprinting
python3 profile_gen.py coverage                       # per-device profile status table

# Pull just the components you need out of an IPSW over HTTP range (no 6 GB download).
# Without --url the IPSW url is resolved for you (ipsw.me for releases, ipsw.dev for betas)
python3 fetch_components.py --device iPhone12,3 --ios 27.0b3 --build 24A5380h --extract-payload
python3 fetch_components.py --device iPhone12,1 --build 24A437 --list

# Verify a profile against the real component bytes BEFORE building (exit 2 = blocked)
python3 preflight.py offsets/iPhone12,1_27.0.yaml
python3 preflight.py offsets/iPhone12,1_27.0.yaml --fetch --record
python3 preflight.py offsets/iPhone12,3_27.0b3.yaml --components research/extracted/iPhone123_27.0b3_24A5380h --json

# Complete the pending device sections of a profile from a verified base + components
python3 profile_gen.py fill offsets/iPad12,1_27.0b2.yaml --from offsets/iPhone12,3_27.0b2.yaml \
    --comp-dir /tmp/comps --sections ibss,ibec,txm

# Which sections still need offsets, and which kernel sections came from the wrong board
python3 profile_gen.py gaps
python3 profile_gen.py coverage --json

# Audit a profile against the upstream script it came from (byte by byte)
python3 source_audit.py script <usbliter8-fun>/work-27.0b3/make_cfw.py offsets/iPhone12,3_27.0b3.yaml

# Import a reviewed fixture set (Liter8) into a profile, verifying every site
# against the fetched component before writing
python3 liter8_import.py --fixtures Liter8/fixtures --build 24A435 --board n104ap \
    --model iPhone12,1 --ios 27.0 --verify-components research/extracted/iPhone121_27.0_24A437 --write

# Offset migration: carry patch offsets across beta builds
python3 profile_gen.py migrate offsets/iPhone12,3_27.0b2.yaml offsets/iPhone12,3_27.0b3.yaml \
    --comp-dir extracted/ --report migrate_report.md
python3 profile_gen.py migrate offsets/iPhone12,3_27.0b3.yaml 27.0b4 --auto   # bootstrap a new beta

python3 cfw_builder.py iPhone12,3_27.0b3.ipsw offsets/iPhone12,3_27.0b3.yaml --check-only
```

### Offset migration (`profile_gen.py migrate`)

Re-discovers patch offsets for a new beta automatically: AArch64 instructions are fingerprinted with immediates wildcarded (`fingerprint.py`), searched in the target binary, and verified with capstone disassembly.

- **Components**: `--comp-dir` with `base/` + `target/` raw files (`kernelcache.raw`, `iBSS.raw`, `iBEC.raw`, `RestoreRamdisk.raw`, `TXM.raw`), or `--fetch` to run the work dir's `get_fw.py`
- **Confidence**: 0.95 unique+class match · 0.90 unique string site · 0.60 ambiguous · 0.30 multi-hit / delta-inferred
- **Output**: `migrate_report.md` (per-entry table, site hexdump, `REVIEW REQUIRED` + `CANONICAL CONFLICTS` sections); `--auto` writes the target profile with `migrated:` metadata + post-write validation
- **Safety**: never trust anything below 0.90 without manual review; delta inference is LOW by design

### Patch manifest, and what a build actually applied

`cfw_builder.py` prints a per-section manifest at the end of every build:
`patched` / `skipped` / `mismatch` / `failed`, with the component file each
section was resolved to. Sections this path cannot apply are reported instead of
disappearing quietly:

* **DeviceTree** is patched in-tree by `dt_patch.py` (content-protect removal,
  `no-effaceable-storage`, `boot-ios-diagnostics`, `ephemeral-storage`,
  optional `system_rw`) driven by the profile's flags. The builder no longer
  shells out to the upstream work dir's `patch_dt.py` / `set_ephemeral.py` and
  no longer skips the DeviceTree when that directory is missing.
* **RestoreRamdisk**: on iOS 26/27 IPSWs the ramdisk is a bare root-level `.dmg`
  and the profile's offsets target `restored_external` / `asr` *inside* the
  mounted image. This path cannot mount and re-sign it, so the build says so and
  warns that asr/FDR checks may fail on restore (classic `.dmg.im4p` layouts are
  still patched in place).
* **Kernel entries marked `invalid_component`** (derived from another device's
  kernelcache) are refused even under `--force`.

### Keeping offsets honest (`source_audit.py`, `fetch_components.py`, `liter8_import.py`)

Profiles are only as good as the artefact they came from, so the repo can now re-derive and re-check them:

- **`fetch_components.py`** pulls iBSS/iBEC/TXM/DeviceTree/kernelcache out of any IPSW on Apple's CDN with HTTP Range requests (ported from W0lfSword's `kczip.py`), so no 6 GB download is needed to discover offsets. `--list` shows the matching entries, `--extract-payload` unwraps the im4p with `img4wrap.py` (pyimg4 when installed).
- **`source_audit.py`** parses an upstream `make_cfw.py` (wh1te4ever / 34306) or a Liter8 fixture set and diffs it against a profile byte by byte: `COVERED`, `PARTIAL` (profile writes less than upstream), `MISMATCH`, `REVIEW` (PC-relative sites such as adrp/add redirects, not comparable across builds), `MISSING`, `PROFILE-ONLY`. Reports land in `research/work/`.
- **`liter8_import.py`** maps Liter8's reviewed fixture oracles onto our entry names, refuses anything whose payload is not our canonical patch, marks everything else `pending`, and (with `--verify-components`) re-checks every mapped site against the real binary before writing.

- **`preflight.py`** is the gate plain usbliter8 does not have: it loads the real firmware components (auto-discovered in `research/extracted/`, read out of a local IPSW, or range-fetched, with the IPSW url resolved for you) and classifies every profile entry against the actual bytes. `--record` writes what it verified to `offsets/evidence/<profile>.json`, so the profile becomes self-verifying: later runs re-check the recorded bytes and block when they are gone (wrong board, wrong build, already-patched image). `cfw_builder` runs the gate before patching and refuses to build on a blocked profile unless you pass `--force`.

Classification: `match` (recorded original bytes present) · `plausible` (site decodes as a real instruction, no recording yet) · `already-patched` · `changed` (recorded bytes absent: profile does not belong to this component) · `implausible` · `out-of-range` · `skipped` (no raw component: encrypted kernelcache/ramdisk, rootfs daemons). Exit codes: 0 ok/review, 2 blocked, so CI or a script can gate a restore. Kernelcaches stay `skipped` until you decrypt them with the wiki IV+key; everything else verifies today.

`profile_gen.py gaps` shows the same picture per section, and flags the profiles whose kernel offsets were propagated from a board with a different kernelcache component.

The 2026-09-20 audit of the iPhone 11 Pro profiles against the upstream scripts and the real b2/b3 components changed five things:

| Entry | Was | Is | Why |
|---|---|---|---|
| `kernel.Post-validation bypass` (b3) | 0x1F2B368 | 0x1F29480 | b2 value had been carried over; upstream b3 script and the AMFI unit shift (-0x1EE8) agree |
| `kernel.Check dyld policy internal` (b3) | 0x1F2B8C8 | 0x1F299E0 (+ site 2 at 0x1F299EC) | same carry-over; upstream patches two return paths |
| `kernel.AMFI trust everything` (b2/b3) | `200080d2c0035fd6` | `5f2403d5200080d2430000b4600000f9c0035fd6` | 8 of 20 bytes: upstream (and Liter8) also write the BTI, cbz and str that publish the result |
| `txm.query_module0/1` (b3) | 0x39CB0 / 0x39E18 | 0x39CA8 / 0x39E10 | all three queryModule sites moved -0x8 in b3; only queryModule2 had been updated |
| `ibec.keep_nonce_b` (b2/b3) | `28000014` (b #0xA0) | `0a000014` (b #0x28) | the original site is `tbnz w8,#1,#+0x28`: upstream's branch reproduces the original target, the b #0xA0 encoding lands in unrelated code (verified in both real iBEC binaries) |

`kernel.Kernel identity string 1/2` (the `/RELEASE_ARM64_T8030` to `/PATCHED_ARM64_T8030` rename both upstream projects perform) was missing entirely and is now part of the kernel section, and `cfw_builder.py` writes ASCII payloads (string patches) as well as hex.

Tests: `python3 -m pytest tests/ -q` (99 tests; offset ground truth = b2 → b3 oracle in `OffsetMigrationChecklist.md`).

## Logging

Every error and warning that reaches the screen is also appended to
`usbliter8.log` in the repo root, so "it failed" can be reported with the actual
reason attached instead of a screenshot of the last line. The file is
gitignored, capped at 2 MB and rotated (`.1` -> `.2` -> `.3`).

```bash
python3 ul8.py logs                            # header + the last 60 entries
python3 ul8.py logs --level ERROR --tail 20    # errors only
python3 ul8.py logs --since 2026-09-21T14 --grep sandbox
python3 ul8.py logs --path                     # just the file path
python3 ul8.py logs --clear                    # truncate (and drop backups)
python3 ul8.py logs --json | python3 -m json.tool
```

What lands in it:

- every `colors.err()` / `colors.warn()` message, tagged with the module and line
  that produced it (`[cfw_builder:412]`), which is how the whole toolkit is
  covered without sprinkling log calls everywhere
- unhandled exceptions with the full traceback (`sys.excepthook` and
  `threading.excepthook`), plus Ctrl-C
- pipeline steps: build start/finish, the per-section patch manifest, preflight
  verdicts and every failed site, firmware/step logging from `hardware_guide`
  and `pwn_utils`

Environment overrides:

```bash
UL8_LOG_FILE=/tmp/ul8.log     python3 ul8.py pwn     # another location
UL8_LOG_LEVEL=INFO            python3 ul8.py build … # also record info/steps
UL8_NO_LOG=1                  python3 ul8.py build … # no file at all
```

Logging never breaks a run: an unwritable path prints one stderr note and
disables itself. Test runs never touch the repo log.

## Repo safety

The repo is public and its output is flashed onto real hardware, so two classes
of accident are guarded mechanically: leaking something personal, and shipping
offset data that no longer matches the evidence it was recorded against.

```bash
python3 safety_check.py            # the same gate CI runs
python3 safety_check.py --strict   # warnings (badge drift, docs style) fail too
python3 safety_check.py --json     # machine-readable
```

`safety_check.py` fails on: private keys / tokens / UDIDs in tracked files,
machine-local home paths, tracked generated files (`usbliter8.log`, `session.log`,
`research/`, `firmware/`, `config.yaml`, `checklist.md`), offset profiles that do
not validate or whose file name disagrees with `model` + `ios_version`, a profile
claiming to be verified while it still has pending entries or blockers, and
`offsets/evidence/*.json` whose recorded offsets no longer match the profile.
It warns (with `--strict`: fails) on the README test badge drifting from the
collected test count and em dashes in the docs. Append `# safety-allow: <reason>`
to a line you deliberately want to keep.

CI (`.github/workflows/tests.yml`) runs `compileall`, `safety_check.py`, every
profile through `device_offsets.py validate` and the test suite on 3.13, plus the
suite on 3.9. Both versions pass locally.

### Branch ruleset

`protect-main` (GitHub -> Settings -> Rules -> Rulesets) applies to the default
branch:

| rule | effect |
|---|---|
| `deletion` | `main` cannot be deleted |
| `non_fast_forward` | no force-push over `main` history |
| `pull_request` | changes reach `main` through a PR (0 required approvals, so solo work is not blocked) |
| `required_status_checks` | the `tests` job must pass, on an up-to-date branch |

The repository admin role can bypass, which is why a direct push prints
`Bypassed rule violations ...` and still goes through. To make the rules hard for
everyone, remove the bypass actor:

```bash
gh api -X PUT repos/kaffeindecaf/usbliter8-arctic/rulesets/<id> --input - <<'JSON'
{"bypass_actors": []}
JSON
```

A second ruleset, `keep-working-branches`, protects `feat/*` from accidental
deletion (force-push stays allowed there, since `--amend` + `--force-with-lease`
is a normal part of the workflow).

Security reports: see [SECURITY.md](SECURITY.md) (private reporting, not issues).

## Contributing offsets

Found offsets for a device/iOS combo that isn't covered yet? The `contribute` flow handles the whole thing:

```bash
./usbliter8 contribute                    # guided wizard
./usbliter8 contribute status             # which profiles exist + validation state
./usbliter8 contribute new iPhone12,1 27.0b4   # create a profile from the template
./usbliter8 contribute pr offsets/iPhone12,1_27.0b4.yaml   # PR description + git commands
```

The wizard asks for the device model and iOS version, creates the profile from the template with DEADBEEF sentinels in place of unknown offsets, opens it in your `$EDITOR` for filling, validates your work, and refuses to generate a PR description until every sentinel is gone. Profiles are validated locally (`device_offsets.py validate`) before anything is submitted, so a PR never ships with placeholder offsets.

The `pr` command prints a copy-paste-ready PR description (device table, patch counts) plus the exact git commands to add, commit and push your profile. Keep in mind the hard rules from `OffsetMigrationChecklist.md`: never rate an inferred (delta) offset above LOW confidence, and never let anything below 0.90 auto-write without review.

## Patch overview

The CFW builder applies hex patches at precise offsets for each component:

- **iBSS / iBEC**: Image4 validation bypass, boot-args injection, nonce preservation
- **Kernel**: USB restriction removal, sandbox bypasses, AMFI trust, APFS seal/SSV bypass, SEP panic bypass, launchd constraints, debugger unlock
- **Device Tree**: content-protection removal, ephemeral storage
- **Restore Ramdisk**: ASR signature bypass, FDR force-succeed
- **Daemons**: coreauthd, ctkd, mobileactivationd activation bypass

## Layout

```
usbliter8-arctic/
├── usbliter8             # terminal script (W0lfSword style), main entry point
├── main.py / ul8.py      # TUI hub + standalone launcher
├── contribute.py         # offset contribution helper (new/status/pr)
├── boot_chain.py         # boot / restore / SSH / post-boot utilities
├── cfw_builder.py        # CFW patching pipeline (per-section patch manifest)
├── components.py         # per-device IPSW component resolution (iBSS/iBEC/kernel/…)
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
├── img4wrap.py           # IMG4/IM4P container read+write (pure Python, lzfse via pyimg4)
├── safety_check.py       # pre-push/CI gate: leaks, machine paths, profile/evidence drift
├── hardware_guide.py     # guided setup, health check, firmware flashing
├── deps.py               # dependency checker & installer
├── log_utils.py          # usbliter8.log: errors, warnings, tracebacks, `ul8.py logs`
├── colors.py
├── .github/workflows/    # CI: compileall + safety check + profiles + tests (3.13 and 3.9)
├── offsets/              # device offset profiles (+ template, sources, canonical.yaml)
│   └── evidence/         # preflight-recorded original bytes per profile (self-verifying)
├── tools/                # binary utilities (img4, img4tool, usbliter8ctl, …)
└── firmware/             # downloaded UF2 firmware files
```

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `No backend available` / `libusb-1.0 missing` | pyusb cannot reach libusb. `python -m pip install libusb-package`, or install libusb-1.0 and bind the device with Zadig. `python3 -c "import pwn_utils; print(pwn_utils.usb_problem())"` prints the exact state and per-OS hints |
| `preflight blocked this build: the profile does not match the component` on a correct IPSW | Was a bug: components were compared as IMG4 containers instead of their decompressed payload. Fixed, and undecodable components are now reported as skipped instead of "changed". If it still blocks, `python3 preflight.py <profile> --quiet` shows the first failing site |
| `no IPSW url found for <device> <build>` | the url lookup does not know that beta build, which is harmless when you point the build at a local IPSW; the message is informational |
| `cannot unwrap <component>: ... pip install pyimg4` | component is lzfse-compressed and no decoder is installed |
| `every module parses` fails in CI | run `python3 -m compileall -q .` locally; a module that tests never import can still be broken |
| offsets look "unchanged" but the device panics | kernel offsets are per `kernelcache.release.*` component; check `python3 profile_gen.py gaps` for a profile whose kernel section came from another board |

## Warnings

- **Tethered jailbreak**: the device will not boot without the RP2350 exploit applied on every cold start
- **Flashing CFW erases all data**: always keep a backup
- **Kernel exploit**: a wrong offset can panic or brick the device. This is a research tool for people who understand the risk

## Credits

- [rav000/usbliter8](https://github.com/rav000/usbliter8): RP2350 firmware and exploit
- [wh1te4ever/usbliter8-fun](https://github.com/wh1te4ever/usbliter8-fun): CFW scripts and boot chain
- [W0lfSword](https://github.com/W0lfSword): kernel offset research, ranged IPSW fetcher (`kczip.py`)
- [Xplo8E/Liter8](https://github.com/Xplo8E/Liter8): per-build resolver fixtures for iPhone 11 (n104ap)
- [34306/usbliter8-fun](https://github.com/34306/usbliter8-fun): second source for the 27.0b2/b3 patch sites
- [blacktop/ipsw-diffs](https://github.com/blacktop/ipsw-diffs): per-build kernel/kext diffs used as change evidence
- [Octopus1633/usbliter8-firmware](https://github.com/Octopus1633/usbliter8-firmware): prebuilt UF2 binaries
