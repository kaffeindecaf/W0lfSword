# Security policy

usbliter8-arctic is a tethered jailbreak toolkit: it patches Apple boot-chain
images and flashes them onto A12/A13 devices the owner controls. That makes two
kinds of report interesting, and they need different handling.

## Report privately, not in an issue

Use GitHub's private reporting (**Security** tab -> *Report a vulnerability*) for:

- a way to make the tooling run code, read files or write outside its work
  directory (command injection in a patch step, unsafe temp dir handling, a
  shell call given attacker-controlled input)
- anything that would damage a device beyond the documented "flashing erases
  all data": a profile or builder path that writes a wrong offset, or a gate
  that can be talked out of refusing bad offsets
- leaked credentials, keys, device identifiers (UDIDs, serials) or personal
  paths found in this repository
- a bypass of the safety checks in `safety_check.py` or the `tests` CI job

Please do not open a public issue for those. If private reporting is unavailable,
open an issue that says only that you have a security report and how to reach you.

## What is out of scope here

- **Apple vulnerabilities.** Firmware, SecureROM, MACF or kernel bugs belong to
  Apple: https://security.apple.com/report/ (the `usbliter8` SecureROM exploit is
  a third-party research project, not ours).
- **Factory-unlock, iCloud-bypass or "remove activation lock" requests**, and
  anything aimed at a device the requester does not own. Thery are closed without
  discussion.
- **Bricked devices from a profile that admits it is unverified.** Profiles with
  pending entries or a `blockers:` section are refused on purpose
  (`device_offsets.py`, `cfw_builder._profile_gate`, `preflight.py`); bypassing
  those gates is at your own risk.

## How this repo tries to stay safe on its own

- `python3 safety_check.py` runs in CI and fails on secrets, machine-local paths,
  tracked generated files, invalid/inconsistent offset profiles and evidence that
  no longer matches the profile it was recorded against.
- `.github/workflows/tests.yml` (`tests` job) is the required status check for the
  default branch, so a red check cannot reach `main` through a pull request.
- A branch ruleset blocks force-pushes and branch deletion on `main`.
- `preflight.py` byte-checks every offset against the real firmware component
  before a build, and `cfw_builder` refuses to patch with pending or blocked
  sections.

## Supported versions

Only the default branch is supported. There are no releases or backports; if you
are on an old copy, re-clone.

## Response

This is a hobby project maintained in evenings, by one person. Expect an
acknowledgement within a week and a fix or an explanation shortly after. There is
no bug bounty.
