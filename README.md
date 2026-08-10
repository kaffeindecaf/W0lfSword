# W0lfSword — iOS Kernel Exploit Toolkit

> **This project was developed with AI assistance** — audit, refactoring, documentation, and tooling.
> Human-authored components: the DarkSword exploit engine, XPF offset finder, and sandbox extension structures.

> **WARNING: EXTREMELY EXPERIMENTAL — NO REAL DEVICE TESTING HAS BEEN PERFORMED.**
> This code has never been run on a physical iOS device. Kernel panics, data loss,
> and permanent filesystem corruption are expected. Use only on a dedicated test device
> you are willing to restore via DFU. **Do NOT install on a daily-driver device.**

> Kernel-level sandbox escape + Signed System Volume bypass for iOS 17.0–26.0.1
> Powered by the **DarkSword** exploit engine — ICMPv6 + IOSurface → kernel R/W
> Made by **[kaffeindecaf](https://github.com/kaffeindecaf)**

<pre>
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
      ._.'      _.'                ;
   `-.-".-'-' ._.       _.-"    .-"
 `.-" _____  ._              .-"
-.(g$$$$$$$b.              .'
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
</pre>

---

## Quick Start

```bash
git clone https://github.com/kaffeindecaf/W0lfSword.git
cd W0lfSword

# Recommended: fully automated deployment
sudo ./W0lfSword adderall          # USB or WiFi, auto-discover, build, deploy, verify
sudo ./W0lfSword adderall --yes    # Skip all prompts, full auto

# Manual:
./W0lfSword                        # Interactive menu (no args)
./W0lfSword doctor                 # Check build environment
./W0lfSword build                  # Compile the tweak
./W0lfSword deploy 192.168.1.5     # Install on device
./W0lfSword log                    # Fetch device logs
./W0lfSword status                 # Project health overview
```

> **`adderall` is the recommended way to use W0lfSword.** It auto-discovers your device
> via USB or WiFi, checks iOS version/offsets, builds, deploys, and verifies the exploit —
> all in one command. Add `--yes` to skip prompts or `-vv` for extreme verbosity.

---

## Table of Contents

- [Quick Start](#quick-start)
- [Credits](#credits)
- [Features](#features)
- [Supported Devices](#supported-devices--ios-versions)
- [Project Layout](#project-layout)
- [Architecture](#architecture)
- [CLI & Scripts](#cli--scripts)
- [Build Guide](#build-guide)
- [Installation](#installation)
- [Diagnostics](#diagnostics)
- [Troubleshooting](#troubleshooting)
- [Documentation](#documentation)
- [Known Issues](#known-issues)
- [Contributing](#contributing)
- [License](#license)

---

## Credits

*This project builds on the work of many people in the jailbreak community.*

| Person | Contribution |
|--------|-------------|
| **[Huy Nguyen](https://github.com/34306/)** | Original FilzaJailedDS project |
| **[wh1te4ever](https://github.com/wh1te4ever/)** | DarkSword exploit (ICMPv6 + IOSurface) & XPF offset engine |
| **[opa334](https://github.com/opa334/)** | XPF patchfinder, krw primitives, sandbox structures |
| **[Duy Tran](https://github.com/khanhduytran0/)** | Sandbox hook token technique |
| **[CrazyMind90](https://github.com/crazymind90/)** | Sandbox token acquisition via kernel R/W |
| **[XEmaz](https://x.com/XEmaz_)** | SSV bypass, root chown, padlock/license bypass, zip hooks |
| **[kaffeindecaf](https://github.com/kaffeindecaf)** | iOS 26.0.1 stability, retry logic, threading, logging, tooling |

> **This repo:** [`kaffeindecaf/W0lfSword`](https://github.com/kaffeindecaf/W0lfSword) — fork of [`34306/FilzaJailedDS`](https://github.com/34306/FilzaJailedDS)

> **Informed by:** [`felix-pb/kfd`](https://github.com/felix-pb/kfd) (PUAF),
> [`opa334/TrollStore`](https://github.com/opa334/TrollStore) (CoreTrust),
> [`opa334/opainject`](https://github.com/opa334/opainject) (ROP injection)

---

## Features

| Feature | Description |
|---------|-------------|
| **Kernel Exploit** | DarkSword (ICMPv6 socket spray + IOSurface OOB) — kernel R/W |
| **Retry Loop** | Up to 5 attempts with exponential backoff |
| **Sandbox Escape** | Walks `proc → ucred → label → sandbox → ext_set`, patches extensions to `"/"` |
| **SSV Bypass** | Vnode data pointer swap — writes to `/System/`, `/usr/`, `/bin/`, `/sbin/` |
| **Root Ownership** | Auto `chown root:wheel` on files created in sealed paths |
| **Root Helper Bypass** | Intercepts `TGRootFileManager` XPC calls — no helper needed |
| **Zip/Unzip** | Uses Filza's minizip via dlsym (13 function pointers validated) |
| **License Bypass** | Suppresses "binary modified" and activation nag alerts |
| **Padlock Bypass** | Hooks `TIGIBrowserView` / `TGPageViewController` — always allow edit/delete |
| **Apps Manager Fix** | Filesystem scanner populates app list when LSApplicationWorkspace returns empty |
| **Thread Safety** | `_Atomic bool` with `memory_order_acquire/release` for cross-thread flags |
| **Consolidated Logging** | Single `/tmp/FilzaTweak.log` with 4MB rotation + trylock fallback |
| **Runtime Toggle** | `touch /var/mobile/Documents/.filza_tweak_disable` to disable without uninstalling |
| **Offset Verification** | Thread kstackptr validated against VM bounds before any kernel writes |

---

## Supported Devices & iOS Versions

| iOS Version | A12-A14 | A15 | A16 | A17 | A18 | M1-M4 |
|-------------|---------|-----|-----|-----|-----|-------|
| 17.0–17.7   | ✓ | ✓ | ✓ | ✓ | — | ✓ |
| 18.0–18.7.7 | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 26.0–26.0.1 | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |

**Not supported:** iPhone 17 series (A19), iPad M5 — Apple added MTE (Memory Tagging Extension) which blocks kernel R/W.

---

## Project Layout

```
W0lfSword/
├── Tweak.m                          # Main orchestrator
├── TweakExploit.h / .m              # Exploit orchestration + diagnostics
├── sandbox_escape.h / .m            # Sandbox escape via kernel extension patching
├── FilzaPadlockBypass.h / .xm       # Filza UI padlock bypass (Logos hooks)
│
├── kexploit/                        # Kernel Exploit Engine (32 files)
│   ├── kexploit_opa334.h / .m       # DarkSword: ICMPv6 spray + IOSurface OOB
│   ├── krw.h / .m                   # kread64/kwrite64/kreadbuf post-exploit primitives
│   ├── kutils.h / .m                # proc/task/thread lookup, AMFI, label accessors
│   ├── offsets.h / .m               # Per-iOS-version kernel struct offset table
│   ├── sandbox.h / .m               # Extension patching + multi-daemon borrow fallback
│   ├── vnode.h / .m                 # Vnode redirection, child lookup, hide/reveal
│   ├── file.h / .m                  # File overwrite via vnode data pointer swap
│   ├── PAC.h / .m / xpaci.h         # Pointer Authentication Code stripping (arm64e)
│   ├── VM.h / .m                    # Kernel VM map entry/object manipulation
│   ├── Thread.h / .m                # Remote thread state + guard exception injection
│   ├── Exception.h / .m             # Mach exception port + reply construction
│   ├── RemoteCall.h / .m            # Remote function calling via thread hijack
│   ├── MigFilterBypassThread.h / .m # MIG sandbox filter bypass
│   ├── apfs_fsnode.h                # Full reverse-engineered APFS inode struct
│   └── machine_info.h               # CPU family constants (A8–A18 Pro, M1–M4)
│
├── SSV/                             # Signed System Volume Bypass
│   └── SSVUtils.h / .m              # Temp → vnode redirect → write → chown root:wheel
│
├── utils/                           # Utilities
│   ├── state.h / .m                 # Global state with getter/setter API
│   ├── tweak_log.h                  # Consolidated logging (mutex, trylock, 4MB rotation)
│   ├── permission_utils.h / .m      # Kernel-level chown/chmod via fsnode patching
│   ├── file.h / .c                  # File hide/reveal via VISSHADOW vnode flag
│   ├── hexdump.h / .c               # Hex dump output for debugging
│   └── process.h / .c               # Process crash/watch, ASLR toggle
│
├── XPF/                             # XPF Offset Patchfinder
│   ├── src/                         # Core: xpf, common, decompress, bad_recovery, non_ppl, ppl
│   └── external/ChOma/src/         # Mach-O + dyld cache parser
│
├── scripts & docs
│   ├── W0lfSword                    # Project CLI — interactive menu, build, deploy, diagnostics
│   ├── W0lfSword-Beta               # Legacy wrapper (calls W0lfSword)
│   ├── build_and_extract.sh         # Build + auto-extract .dylib
│   ├── validate_offsets.py          # Offset table integrity checker
│   ├── Makefile                     # Theos build system
│   ├── control                      # Debian package metadata
│   ├── FilzaApplySandboxExt.plist  # MobileSubstrate filter (com.tigisoftware.Filza)
│   ├── README.md                    # This file
│   ├── CONTEXT.md                   # Full project knowledge base
│   ├── ROADMAP.md                   # 149-item checklist
│   ├── BUG_BOUNTY.md                # 14 security findings with Apple bounty ranges
│   ├── AUDIT_REPORT.md              # 20 findings + 13 fixes applied
│   ├── DEBUG_TRACKING.md            # Every log statement mapped by file:line
│   └── BUILD.md                     # Theos + build instructions
│
├── kpf/                             # Kernel Patchfinder
│   └── patchfinder.h / .m          # Extract kernelcache → initialize XPF
├── research/                        # Reverse-engineered struct definitions
├── .theos/                          # Theos build artifacts (auto-generated)
└── packages/                        # Pre-built .deb packages
```

---

## Architecture

![W0lfSword Architecture](W0lfSwordArchitecture.png)

### Exploit Pipeline

![Exploit Pipeline](W0lfSwordChain.png?v=2)

```
TweakInit() → installHooks() → scheduleExploitOnce() [1s delay]
→ runExploit() [5 retries, exponential backoff]
  → offsets_init()          [resolve kernel struct offsets]
  → kexploit_opa334()       [socket spray + OOB race → kernel R/W]
  → sandbox_escape()        [walk proc→sandbox ext table, patch to "/"]
  → patch_sandbox_ext()     [SSV write activation, 4-daemon borrow fallback]
→ All hooks active, SSV writes functional
```

---

## CLI & Scripts

### `W0lfSword` — Project CLI

```
╔══════════════════════════════╗
║  W0lfSword                   ║
║  iOS Kernel Exploit Toolkit  ║
╚══════════════════════════════╝

Usage: ./W0lfSword <command> [args...]
```

| Command | Description | Example |
|---------|-------------|---------|
| `adderall` | Fully automated deployment | `sudo ./W0lfSword adderall --yes` |
| `quick` | One-shot: build → deploy → verify | `./W0lfSword quick` |
| `build` | Compile tweak + create .deb | `./W0lfSword build` |
| `deploy <ip>` | Install on device via SCP + dpkg | `./W0lfSword deploy 192.168.1.5` |
| `status` | Project health overview | `./W0lfSword status` |
| `doctor` | Check environment: THEOS, SDK, SSH | `./W0lfSword doctor` |
| `log [n]` | Fetch device log | `./W0lfSword log 100` |
| `monitor` | Real-time log tail with colors | `./W0lfSword monitor` |
| `audit` | Static analysis: braces, offsets | `./W0lfSword audit` |
| `offsets [ver]` | Show offset table coverage | `./W0lfSword offsets 26.0` |
| `profile save\|load\|list` | Manage exploit profiles | `./W0lfSword profile save my-ip14` |
| `device add\|list\|switch\|info` | Multi-device manager | `./W0lfSword device add 192.168.1.5` |
| `history [stats]` | Exploit attempt log + dashboard | `./W0lfSword history stats` |
| `toggle on\|off` | Enable/disable tweak on device | `./W0lfSword toggle off` |
| `clean` | Clean build artifacts | `./W0lfSword clean` |
| `targets` | Show supported apps | `./W0lfSword targets` |
| `extract` | Extract .dylib from .deb | `./W0lfSword extract` |
| `help` | Show all commands | `./W0lfSword help` |

**Device IP** is auto-saved on first deploy. Subsequent commands reuse it.

**Color-coded logs:** green = success / escaped, red = errors, yellow = retries, cyan = structural, dim = detail.

### Interactive Menu

Run with no arguments for the menu. Quick shortcuts: `b`=build, `d`=deploy, `a`=adderall, `s`=status.

```
  device:  192.168.1.5 online

  [1] Quick Exploit      Build → Deploy → Verify
  [2] Deploy Only        Install package on device
  [3] Device Manager     Add / switch / info
  [4] Live Monitor       Real-time log tailing
  [5] Profiles           Save / load configs
  [6] History            Exploit statistics
  [7] Diagnostics        Doctor · Audit · Status
  [8] Targets            Supported apps
```

Data stored in `.w0lfsword/` (profiles, devices, history, session log — gitignored).

### `build_and_extract.sh`

```bash
./build_and_extract.sh              # Build then extract .dylib to project root
./build_and_extract.sh --keep-temp  # Keep the extraction directory for inspection
```

### `validate_offsets.py`

```bash
python3 validate_offsets.py         # Verify offset table integrity
```

---

## Build Guide

### What is Theos?

**Theos** is a cross-platform build system for iOS tweak development. It cross-compiles ObjC/C/Logos for
iOS (arm64/arm64e), links against iOS SDKs, packages into `.deb`, and preprocesses Logos `.xm` files.

### Prerequisites

**macOS:**
```bash
xcode-select --install
bash -c "$(curl -fsSL https://raw.githubusercontent.com/theos/theos/master/bin/install-theos)"
echo 'export THEOS=~/theos' >> ~/.zshrc && source ~/.zshrc
brew install dpkg
```

**Linux:**
```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/theos/theos/master/bin/install-theos)"
echo 'export THEOS=~/theos' >> ~/.bashrc && source ~/.bashrc
# Get iOS SDK from: https://github.com/theos/sdks (place in $THEOS/sdks/)
sudo apt install dpkg fakeroot clang lld
```

### Build

```bash
make package               # Full build + .deb
make                       # Build only (no .deb)
make package FINALPACKAGE=1 # Release (strips debug symbols)
make clean                 # Clean
```

---

## Installation

```bash
# Recommended — use the CLI
sudo ./W0lfSword adderall

# Or manual steps:
./W0lfSword build
./W0lfSword deploy 192.168.1.5
```

The tweak injects into `com.tigisoftware.Filza` via MobileSubstrate.
Restart Filza — the exploit runs automatically within 1–2 seconds.

**What gets installed:**
```
/Library/MobileSubstrate/DynamicLibraries/
├── FilzaApplySandboxExt.dylib     # Compiled tweak (~540KB, arm64)
└── FilzaApplySandboxExt.plist     # Filter: inject only into Filza
```

---

## Diagnostics

### Log file

All logs go to a single file inside Filza's sandbox:
```
/tmp/FilzaTweak.log        # Main log (4MB max, rotates to .old on overflow)
```

Fetch it: `./W0lfSword log` (last 50 lines) or `./W0lfSword log 200`.

### Successful log

```
=== TWEAK LOADED ===
[Tweak] TweakInit started
[Hooks] All hooks installed
[Tweak] Exploit attempt #1...
[Tweak] kexploit succeeded
[SBX] *** SANDBOX ESCAPED (R+W) — 3/3 tests passed ***
[SSV] patch_sandbox_ext succeeded
[SSV] check_sandbox_var_rw result r=0 w=0
[SSV] ensureSSVActive set active=1
```

---

## Troubleshooting

### Build Issues

| Symptom | Cause | Fix |
|---------|-------|-----|
| `theos/makefiles/common.mk: No such file` | THEOS not set | `export THEOS=~/theos` |
| `iPhoneOS.sdk not found` | Missing SDK | Download from [theos/sdks](https://github.com/theos/sdks) |
| `dpkg-deb: command not found` | dpkg missing | `brew install dpkg` / `apt install dpkg` |
| `Undefined symbols for architecture arm64` | Missing framework | Check Makefile `_FRAMEWORKS` |
| `clang: error: no such file: 'XPF/src/xpf.c'` | Submodule not init | `git submodule update --init` |

### Runtime Issues

| Symptom | Cause | Fix |
|---------|-------|-----|
| Filza crashes on launch | Kernel panicked on previous run | Wait for reboot, retry |
| "Sandbox not yet escaped" x5 | Wrong offsets for this iOS build | Run `./W0lfSword offsets` |
| Files show writable but write fails | SSV activation failed | Check log for `ensureSSVActive set active=1` |
| Tweak does nothing | Disabled by flag file | `./W0lfSword toggle off` |
| `thread kstackptr outside valid range` | Wrong SoC/iOS combo | Add per-SoC offset overrides |
| Filza 4.0.2 crashes | Bundle ID mismatch | Use `adderall` — picks correct target |

### Device Issues

| Symptom | Cause | Fix |
|---------|-------|-----|
| `ssh: connect refused` | OpenSSH not installed | Install OpenSSH via Sileo/Cydia |
| `Permission denied (publickey)` | SSH key mismatch | `ssh -o StrictHostKeyChecking=no root@<ip>` |
| Device not discoverable | Different network | Check Wi-Fi IP in Settings |
| `dpkg: error processing package` | Version conflict | `ssh root@<ip> "dpkg --force-depends -i /tmp/...deb"` |

---

## Documentation

| File | Purpose |
|------|---------|
| `CONTEXT.md` | Full project knowledge base — start here when resuming a session |
| `ROADMAP.md` | 149-item checklist: bugs, features, exploits, bug bounty, testing |
| `BUG_BOUNTY.md` | 14 security findings with Apple bounty ranges ($25K–$250K) |
| `AUDIT_REPORT.md` | 20 findings ranked CRITICAL→LOW, 13 fixes applied |
| `DEBUG_TRACKING.md` | Every log statement mapped by file:line, 3-layer strip guide |
| `BUILD.md` | Theos explanation, prerequisites, build commands, troubleshooting |

---

## Known Issues

- **Exploit may take 2–3 attempts** — the retry loop handles this automatically (up to 5 attempts)
- **Padlock bypass is best-effort** — hooks target TG*/TIGI* classes which may change across Filza versions
- **SSV writes are best-effort** — the kernel patch may not activate on first file operation
- **iPhone 17 / M5 will not work** due to Apple's MTE (Memory Tagging Extension)

---

## Contributing

Found a bug? Open an issue. Want to add support for a new iOS version or device?

1. Get the kernelcache from the target device
2. Run XPF on it to resolve new offsets
3. Add a new `SYSTEM_VERSION_GREATER_THAN_OR_EQUAL_TO` block in `kexploit/offsets.m`
4. Test on real hardware
5. Submit a PR

See `ROADMAP.md` for the full task list. Before committing:
```bash
./W0lfSword audit    # Check braces, printf count, offset coverage
./W0lfSword status   # Verify nothing in dirty state
```

---

## License

This project incorporates code from multiple open-source projects:

- DarkSword kernel exploit (wh1te4ever)
- XPF offset engine / sandbox structures (opa334)
- ChOma Mach-O parser

All original code remains under the licenses of their respective authors.
The integration layer and tooling are released as-is for research and testing.

**WARNING:** This is a pre-release testing build. Modifying system files can render your device
unbootable — use at your own risk.
