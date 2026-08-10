# W0lfSword Script — Test Checklist

> Run these tests from the project root. No device needed for most items.

---

## Menu & Display

- [ ] `./W0lfSword` — launches interactive menu, wolf art on first draw only
- [ ] Menu shows device status (USB/WiFi/offline)
- [ ] Typing `q` then enter quits
- [ ] Typing `b` triggers build attempt
- [ ] Typing `s` shows status screen with git/roadmap/device info
- [ ] Typing `help` shows full command reference
- [ ] `./W0lfSword version` prints version

## Direct Commands (no device)

- [ ] `./W0lfSword doctor` — checks THEOS/clang/dpkg/ssh/git/python3
- [ ] `./W0lfSword status` — shows git branch, roadmap %, device
- [ ] `./W0lfSword offsets` — lists iOS version blocks and SoC coverage
- [ ] `./W0lfSword offsets 26.0` — filters for specific version
- [ ] `./W0lfSword targets` — shows current + planned targets
- [ ] `./W0lfSword clean` — runs make clean, removes temp files
- [ ] `./W0lfSword audit` — brace/paren balance check on key files
- [ ] `./W0lfSword help` — full command table
- [ ] `./W0lfSword build` — compiles .deb (needs THEOS)

## Flags

- [ ] `./W0lfSword -v doctor` — verbose mode shows extra output
- [ ] `./W0lfSword -v build` — verbose build shows make output
- [ ] `./W0lfSword -vv doctor` — debug mode (if supported)

## Profile & History

- [ ] `./W0lfSword profile save test` — creates test.json in .w0lfsword/profiles/
- [ ] `./W0lfSword profile list` — shows test profile with * if active
- [ ] `./W0lfSword profile load test` — loads test profile
- [ ] `cat .w0lfsword/profiles/test.json` — valid JSON

## Device Manager (no real device needed)

- [ ] `./W0lfSword device add 192.168.1.100` — adds fake device
- [ ] `./W0lfSword device list` — shows device with offline status
- [ ] `./W0lfSword device switch 192.168.1.100` — switches active
- [ ] `cat .w0lfsword/active_device` — shows the IP

## Safety & Crash

- [ ] `./W0lfSword safe on` — errors (no device) but doesn't crash
- [ ] `./W0lfSword crashlog` — shows "no crash log yet"
- [ ] `cat .w0lfsword/session.log` — has session entries

## Crash Recovery (requires device)

- [ ] Deploy, then `./W0lfSword monitor` — tails device log
- [ ] After kernel panic, `./W0lfSword crashlog` shows last entries
- [ ] `./W0lfSword toggle on` then `toggle off` — flag file created/removed

## USB Detection (requires USB iPhone + libimobiledevice)

- [ ] Plug in iPhone via USB
- [ ] `./W0lfSword` menu shows `⬤ USB  iPhoneName  iOS XX.X  iPhoneXX,Y`
- [ ] `idevice_id -l` shows UUID

## Adderall (full flow — requires device)

- [ ] `sudo ./W0lfSword adderall --safe` — full flow in safe mode
- [ ] Phases 1-5 all complete or fail gracefully
- [ ] Profile saved after flow
- [ ] History entry written

## Stress / Reliability

- [ ] Run `./W0lfSword` 5 times in a row — no terminal glitches
- [ ] Ctrl+C during menu — terminal cursor restored (no stuck cursor)
- [ ] Run with `set -x` (`bash -x ./W0lfSword doctor`) — no syntax errors
- [ ] ShellCheck: `shellcheck W0lfSword` — minimize warnings (some color escape codes expected)

## Build

- [ ] `make package` completes without errors
- [ ] `.deb` appears in `packages/`
- [ ] `./W0lfSword build` shows build success
- [ ] `./W0lfSword extract` extracts .dylib

---

*Tested on: _______  Date: _______  By: _______*
