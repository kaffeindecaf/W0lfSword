# W0lfSword

A Filza tweak and host tools for iOS exploit research.

W0lfSword builds a tweak that gives Filza kernel read/write and sandbox access on supported builds. The same repository includes tools for device setup, offset checks, kernelcache analysis, crash triage and fuzzing.

Use it only on devices you own or are authorized to test. The kernel stage can panic a phone. W0lfSword is not a jailbreak, does not include Filza and is not a recovery tool.

```
host:   check device -> build tweak -> deploy
                                  |
                                  v
iOS:    Filza -> kernel access -> sandbox and file operations
```

- Check the model and iOS build before a device run.
- Build and deploy through one CLI, over USB or SSH.
- Research kernel builds on the host without running the exploit.

## Quick start

Clone the repository with its submodules:

```bash
git clone --recurse-submodules https://github.com/kaffeindecaf/W0lfSword.git
cd W0lfSword
```

Install the build tools once. On Linux, setup needs root. On macOS, do not run setup with `sudo`.

```bash
# Linux
sudo ./W0lfSword setup

# macOS
./W0lfSword setup
```

Check the toolchain and run the project audit:

```bash
./W0lfSword doctor
./W0lfSword audit
```

Before using a device, check its exact model and iOS version:

```bash
./W0lfSword exploits iPhone14,7 26.0.1
```

Replace the example model and version with the values for your test device. The command reports whether a technique is listed for that combination.

## What runs on the phone

The main path is a tweak injected into Filza. It uses the DarkSword kernel exploit to obtain kernel read/write, changes the process sandbox rules, and can activate the sealed system volume path. Filza then uses its normal file browser UI.

The kernel stage is listed for iOS 17.0 through 26.0.1. `pe_v1` covers A12 through A17; `pe_v2` covers A18. Use `exploits <model> [ios]` for the current per-device verdict. Apple patched the DarkSword kernel path in iOS 26.1. Other userspace features have separate support windows; do not infer their status from the kernel matrix.

There are two deployment paths:

- `adderall` discovers the phone, builds and deploys the tweak, then restarts Filza. It requires root on the host and a jailbroken phone with Filza and OpenSSH. `--usb` forces USB transport. `--safe` skips the kernel stage.
- `nojailbreak` installs a substrate-free Filza build over USB, without a jailbreak, SSH or Wi-Fi. It needs a Filza IPA you provide and is listed for iOS 18.0 through 26.0.1. It still runs the kernel exploit, so it can panic the phone.

Get the current flags before a device operation:

```bash
./W0lfSword explain adderall
./W0lfSword explain nojailbreak
```

## Safety

Treat every unverified kernel run as capable of panicking the device. Use a test phone that you can force-restart. Do not use a daily-driver phone.

The release build uses staged mode. It can pass a compatibility check, perform a write probe and continue into the full chain. Staged mode is not read-only. Use `--safe` when you only want to verify the build and deployment path.

A reboot clears the in-memory kernel and sandbox changes. Files you deliberately change are separate and may remain. After a panic, save the device crash report before another run; a later panic can replace the earlier report.

## Host tools

These commands work without running the kernel exploit:

| Command | Use |
| --- | --- |
| `doctor` | Check the host build tools |
| `audit` | Check shell syntax, CLI wiring and repository rules |
| `exploits <model> [ios]` | Read the technique matrix and device verdict |
| `offsets` | Show offset coverage |
| `kernelcache` | Extract, resolve or diff kernelcaches |
| `diffs` | Inspect precomputed Apple build diffs |
| `drift` | Find offsets that need re-verification |
| `kcwatch` | Check new kernel builds and report offset changes |
| `panic analyze <file>` | Classify an iOS crash report |
| `cve [filter]` | Browse the CVE catalog |
| `chains [a-g|best]` | Browse the attack-chain catalog |

`poc`, `poclab` and `fuzz` are research tools. Some tests can crash a device. Read each command's help and use a lab device before running them.

For the full command list, aliases and menu keys:

```bash
./W0lfSword commands
./W0lfSword explain <command>
```

With no arguments, `W0lfSword` opens the interactive menu.

## Build and verify

The host build uses Theos, clang, an iPhoneOS SDK and `dpkg-deb`. `doctor` checks the local toolchain.

```bash
make package
bash scripts/check_host_verification.sh
```

The verification script runs the pinned host tests. Add `--with-builds` to include the Theos cross-builds. Neither command runs an exploit on a phone.

## Repository layout

```
W0lfSword                  CLI and device workflow
Tweak.m                    tweak entry point
TweakExploit.m             exploit sequencing and safety modes
kexploit/                  kernel primitives, offsets and userspace modules
SSV/                       sealed system volume helpers
terminal/                  in-process shell and probes
mobilegestalt/             MobileGestalt module
sbtweak/                   SpringBoard RemoteCall driver
scripts/                   build, research and verification tools
research/                  host research tools and tracked index
pocs/                      research PoCs and Hub app
```

## Further reading

- [Threat model](docs/THREAT_MODEL.md)
- [Offset resolution guide](docs/OFFSET_RESOLUTION_GUIDE.md)
- [Research index](research/README.md)
- [Hub app](pocs/hub_shell/README.md)
- [License](LICENSE)

## Credits

- [Huy Nguyen](https://github.com/34306/): original FilzaJailedDS
- [wh1te4ever](https://github.com/wh1te4ever/): DarkSword exploit and XPF offset engine
- [opa334](https://github.com/opa334/): XPF patchfinder, kernel read/write primitives and sandbox structures
- [khanhduytran0](https://github.com/khanhduytran0/): sandbox hook token technique
- [CrazyMind90](https://github.com/CrazyMind90/): sandbox token acquisition
- [XEmaz](https://x.com/XEmaz_): sealed system volume bypass and Filza hooks
- [kaffeindecaf](https://github.com/kaffeindecaf/): W0lfSword integration, device support and host tooling

Third-party code remains subject to its original license. See [LICENSE](LICENSE) and the relevant upstream repositories.
