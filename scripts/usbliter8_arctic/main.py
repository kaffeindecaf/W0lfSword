#!/usr/bin/env python3
"""usbliter8-arctic — Interactive exploit hub for W0lfSword.

TUI menu for: hardware setup, offset management, CFW building,
device restore, SSHRD/normal boot, post-exploit configuration.
"""

import os
import random
import sys
import time
from pathlib import Path

from colors import C, ok, err, warn, info, section, key_value, header, prompt
import log_utils
from device_offsets import list_offset_files, set_active_device, get_active_device, find_online_sources
from pwn_utils import print_device_status, verify_pwn_mode, check_pyusb_installed, wait_for_pwn

PROJECT_ROOT = Path(__file__).parent
SCRIPTS_DIR = Path(__file__).parent
OFFSETS_DIR = SCRIPTS_DIR / "offsets"

def _find_work_dirs() -> list[Path]:
    """Find usbliter8-fun work directories from multiple locations."""
    candidates = [
        Path(__file__).parent.parent / "referenceforAI",
        Path.home() / "Desktop" / "W0lfSword" / "referenceforAI",
        Path.home() / "Desktop" / "W0lfSword" / "referenceforAI" / "projects",
    ]
    for base in candidates:
        if base.exists():
            dirs = list(base.glob("usbliter8-fun*/work-*"))
            if dirs:
                return sorted(dirs)
    return []


def clear():
    os.system("clear 2>/dev/null || true")


WOLF_ASCII_ART = r'''
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
         ._.'      _.'                ;
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
                            ;  (by kaffein)'''

WOLF_GRADIENT = [C.ICE] * 6 + [C.FROST] * 7 + [C.WOLF] * 7 + [C.MOON] * 6


def _wolf_art_lines() -> list[str]:
    return [ln.rstrip() for ln in WOLF_ASCII_ART.strip("\n").splitlines()]


def show_wolf():
    lines = _wolf_art_lines()
    print()
    for i, art in enumerate(lines):
        if i == len(lines) - 1 and art.endswith("(by kaffein)"):
            body = art[: -len("(by kaffein)")]
            art = body + f"{C.AMB}{C.B}(by kaffein){C.NC}"
        color = WOLF_GRADIENT[min(i, len(WOLF_GRADIENT) - 1)]
        print(f"  {color}{art}{C.NC}")
    print()


SCRAMBLE_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789#$%&*+-=<>?/\\|"
SCRAMBLE_SPIN = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]


def wolf_scramble_frame(art: list[str], progress: int, rng: random.Random) -> list[str]:
    """One scramble frame: each non-space char is settled (kept as-is) with
    probability progress/100, otherwise replaced by a random char. Mirrors
    W0lfSword's scramble_wolf frame logic."""
    out = []
    for line in art:
        built = []
        for ch in line:
            if ch == " ":
                built.append(" ")
            elif rng.randint(0, 99) < progress:
                built.append(ch)
            else:
                built.append(rng.choice(SCRAMBLE_CHARS))
        out.append("".join(built))
    return out


def scramble_wolf(frames: int = 12, spinner: bool = True, pause: float = 0.05):
    """Cmatrix-style scramble of the wolf art's own characters that settles
    into the real art. Ported from W0lfSword's scramble_wolf (bash). Falls
    back to a static wolf when stdout is not a terminal."""
    if not sys.stdout.isatty():
        show_wolf()
        return
    art = _wolf_art_lines()
    rng = random.Random()
    sys.stdout.write("\033[?25l")
    sys.stdout.flush()
    try:
        for f in range(frames):
            progress = int(f * 100 / frames)
            sys.stdout.write("\033[H\033[2J")
            if spinner:
                sys.stdout.write(f"  {C.EYE}{SCRAMBLE_SPIN[f % len(SCRAMBLE_SPIN)]}{C.NC} {C.DIM}loading...{C.NC}\n")
            for line in wolf_scramble_frame(art, progress, rng):
                sys.stdout.write("  " + line + "\n")
            sys.stdout.flush()
            time.sleep(pause)
    finally:
        sys.stdout.write("\033[?25h")
        sys.stdout.flush()
    sys.stdout.write("\033[H\033[2J")
    show_wolf()


def show_banner():
    print()
    print(f"  {C.SNOW}{C.B}usbliter8-arctic{C.NC}")
    print(f"  {C.FROST}CFW Builder · PWN DFU · Restore · Boot{C.NC}")
    print(f"  {C.DIM}usbliter8 exploit by {C.NC}{C.DIM}rav000 · wh1te4ever · Octopus1633{C.NC}")
    print()


def show_device_status():
    """Display active device config and hardware status."""
    active = get_active_device()
    print(f"  {C.GREY}── device ──────────────────────────────────────────────────────{C.NC}")
    if active:
        model = active.get("model", "?")
        name = active.get("device", "?")
        ios = active.get("ios_version", "?")
        soc = active.get("soc", "?")
        board = active.get("board", "?")
        print(f"  {C.EYE}{name}{C.NC}   {C.DIM}{model}{C.NC}   {C.FROST}{soc}{C.NC}   board {C.EYE}{board}{C.NC}   iOS {C.FROST}{ios}{C.NC}")
    else:
        print(f"  {C.DIM}no device configured — use [2] Configure Device{C.NC}")
    print()


def show_board_status():
    """Display RP2350 board and firmware status."""
    from hardware_guide import _load_config, check_firmware
    cfg = _load_config()
    board_id = cfg.get("selected_board", "unknown")
    print(f"  {C.GREY}── microcontroller ──────────────────────────────────────────────{C.NC}")

    board_names = {
        "pico2": "Raspberry Pi Pico 2",
        "waveshare_usb_a": "Waveshare RP2350-USB-A",
        "waveshare_usb_c": "Waveshare RP2350-USB-C",
        "waveshare_zero": "Waveshare RP2350-Zero",
        "waveshare_pizero": "Waveshare RP2350-Pizero",
        "pimoroni_tiny2350": "Pimoroni Tiny2350",
    }
    name = board_names.get(board_id, board_id)

    fw_ok = check_firmware(board_id)
    fw_tag = f"{C.GRN}installed{C.NC}" if fw_ok else f"{C.RED}not installed{C.NC}"

    parts = [f"{C.EYE}{name}{C.NC}", f"firmware  {fw_tag}"]

    if check_pyusb_installed():
        from pwn_utils import detect_rp2350
        rp = detect_rp2350()
        if rp:
            parts.append(f"{C.GRN}usb detected{C.NC} (bus {rp['bus']}, addr {rp['address']})")
        else:
            parts.append(f"{C.DIM}no usb device{C.NC}")
    else:
        parts.append(f"{C.DIM}pyusb not installed{C.NC}")

    print(f"  {' · '.join(parts)}")
    print()


def menu():
    """Main interactive menu loop."""
    first_run = True
    while True:
        clear()
        if first_run:
            scramble_wolf()
            first_run = False
        show_banner()
        show_device_status()
        show_board_status()

        # Menu items — aligned columns with consistent spacing
        items = [
            ("1", "Guided Setup",       f"{C.AMB}★ recommended for beginners{C.NC} — wire · flash · test"),
            ("2", "Configure Device",   "Select model / iOS · edit offsets"),
            ("3", "Build CFW",          "Patch IPSW → custom firmware"),
            ("4", "Flash Device",       f"Restore CFW {C.RED}(ERASES DEVICE!){C.NC}"),
            ("5", "SSHRD Boot",         "Ramdisk · mount · edit filesystem"),
            ("6", "Normal Boot",        "Full iOS boot with patches"),
            ("7", "Post-Boot Setup",    "USB network · VNC · SSH · bootstrap"),
            ("8", "Check PWN Status",   "Verify DFU / PWND state · wait for device"),
            ("9", "Health Check",       "Verify hardware, tools, firmware"),
            ("i", "Install Dependencies", "pyusb · pyyaml · libusb"),
            ("0", "Explain",            "What can you do with usbliter8?"),
        ]
        for num, title, desc in items:
            tcolor = C.AMB if num == "1" else C.SNOW
            print(f"  {C.EYE}{C.B}[ {num} ]{C.NC}  {tcolor}{title:<20}{C.NC} {C.DIM}{desc}{C.NC}")

        print()
        print(f"  {C.GREY}── shortcuts ────────────────────────────────────────────────────{C.NC}")
        shortcuts = [
            ("h", "hw guide"), ("c", "config"), ("b", "build"),
            ("f", "flash"), ("p", "pwn check"), ("e", "explain"),
            ("x", "health"), ("i", "deps"), ("q", "quit"),
        ]
        cols = 4
        width = 19
        rows = [shortcuts[i:i + cols] for i in range(0, len(shortcuts), cols)]
        for row in rows:
            cells = []
            for key, label in row:
                cells.append(f"{C.EYE}[{key}]{C.NC} {C.DIM}{label:<{width}}{C.NC}")
            print(f"  {'   '.join(cells)}")

        print()
        try:
            choice = log_utils.safe_input(f"  {C.FROST}{C.B}usbliter8 ▸{C.NC} ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print(); break

        print()
        choice = choice or " "

        # Dispatch
        if choice in ("1", "h", "hw"):
            from hardware_guide import guided_setup
            guided_setup()

        elif choice in ("2", "c", "config"):
            menu_configure()

        elif choice in ("3", "b", "build"):
            menu_build()

        elif choice in ("4", "f", "flash"):
            menu_flash()

        elif choice in ("5",):
            menu_sshrd()

        elif choice in ("6",):
            menu_normal_boot()

        elif choice in ("7",):
            menu_postboot()

        elif choice in ("8", "p", "pwn"):
            print_device_status()
            if verify_pwn_mode()[0]:
                pass
            else:
                ans = log_utils.safe_input(prompt("Wait for PWN DFU? [y/N]: ") or "n")
                if ans.lower() in ("y", "yes"):
                    wait_for_pwn(timeout=60)

        elif choice in ("9", "x", "health"):
            from hardware_guide import run_health_check
            run_health_check()

        elif choice in ("i", "deps"):
            from deps import install_dependencies
            install_dependencies()

        elif choice in ("0", "e", "explain"):
            from boot_chain import explain_usbliter8
            explain_usbliter8()

        elif choice in ("q", "quit", "exit", ""):
            print(f"  {C.WOLF}~ back to W0lfSword ~{C.NC}")
            break

        else:
            print(warn(f"Unknown: '{choice}' — try 1-9, h/c/b/f/p/e/x/i, or q"))

        log_utils.safe_input(f"\n  {C.DIM}── Press Enter to continue ──{C.NC}")


def menu_configure():
    """Sub-menu: configure device and offsets."""
    print(header("Configure Device"))
    print()

    # Show available offset files
    files = list_offset_files()
    if files:
        print(section("Available Offset Configurations"))
        print()
        for i, f in enumerate(files):
            icon = C.GRN + "✓" if f["status"] == "ready" else C.AMB + "⚠"
            print(f"  {C.EYE}[{i + 1}]{C.NC} {icon}{C.NC} {C.SNOW}{f['device']}{C.NC} ({C.DIM}{f['model']}{C.NC}) — iOS {C.FROST}{f['ios']}{C.NC}  [{f['soc']}]  {f['passed']} patches")
        print()

    print(f"  {C.EYE}[f]{C.NC} Find online offset sources for a device model")
    print(f"  {C.EYE}[v]{C.NC} Validate a custom offset file")
    print(f"  {C.EYE}[a]{C.NC} Audit a profile against an upstream make_cfw.py script")
    print(f"  {C.EYE}[r]{C.NC} Fetch IPSW components over HTTP range (no full download)")
    print(f"  {C.EYE}[p]{C.NC} Preflight: verify a profile against the real components")
    print(f"  {C.EYE}[g]{C.NC} Gap matrix: which sections still need offsets")
    print()

    choice = log_utils.safe_input(prompt("Select device [#], find [f], validate [v], audit [a], fetch [r], "
                          "preflight [p], gaps [g], or [b]ack: ") or "").strip().lower()

    if choice == "p":
        path = log_utils.safe_input(prompt("Profile YAML (blank = active device): ")).strip()
        argv = [path] if path else []
        record = log_utils.safe_input(prompt("Record verified bytes as evidence? [y/N]: ")).strip().lower()
        if record in ("y", "yes"):
            argv.append("--record")
        import preflight
        preflight.main(argv or None)
    elif choice == "g":
        import profile_gen
        profile_gen.cmd_gaps()
    elif choice == "a":
        script = log_utils.safe_input(prompt("Path to upstream make_cfw.py: ")).strip()
        profile = log_utils.safe_input(prompt("Path to profile YAML: ")).strip()
        if script and profile:
            import subprocess
            subprocess.run([sys.executable, str(PROJECT_ROOT / "source_audit.py"),
                            "script", script, profile])
    elif choice == "r":
        url = log_utils.safe_input(prompt("IPSW url (Apple CDN): ")).strip()
        model = log_utils.safe_input(prompt("Device model (e.g. iPhone12,1): ")).strip()
        if url and model:
            import subprocess
            cmd = [sys.executable, str(PROJECT_ROOT / "fetch_components.py"),
                   "--url", url, "--device", model, "--extract-payload"]
            subprocess.run(cmd)
    elif choice == "f":
        model = log_utils.safe_input(prompt("Enter device model (e.g. iPhone12,1): ")).strip()
        if model:
            sources = find_online_sources(model)
            if sources:
                print()
                print(section(f"Online sources for {model}"))
                for s in sources:
                    print(f"  {C.EYE}{s['name']}{C.NC}")
                    print(f"    {C.DIM}{s.get('url', 'N/A')}{C.NC}")
                    if s.get("notes"):
                        print(f"    {C.GREY}{s['notes']}{C.NC}")
            else:
                print(warn(f"No known online sources for {model}"))
    elif choice == "v":
        path = log_utils.safe_input(prompt("Path to offset YAML file: ")).strip()
        if path:
            from device_offsets import validate_offsets
            passed, failed, errors = validate_offsets(Path(path))
            if failed == 0:
                print(ok(f"All {passed} patches valid"))
            else:
                print(err(f"{passed} passed, {failed} failed:"))
                for e in errors:
                    print(f"    {C.RED}{e}{C.NC}")
    elif choice == "b":
        return
    elif choice.isdigit():
        idx = int(choice) - 1
        if 0 <= idx < len(files):
            f = files[idx]
            offset_path = OFFSETS_DIR / f["file"]
            if set_active_device(offset_path):
                pass


def _run_build_gate(offset_path) -> bool:
    """Verify the profile before a build; ask before overriding a block."""
    from device_offsets import pending_entries, validate_offsets
    import preflight
    report = preflight.run_preflight(offset_path)
    if report.verdict == "ok":
        print(ok(f"preflight: {report.count('match', 'plausible')} sites verified"))
        return True

    print()
    preflight.print_report(report, verbose=False)
    if report.verdict == "blocked":
        ans = log_utils.safe_input(prompt("preflight BLOCKED this build — build anyway? [y/N]: ") or "n")
        if ans.lower() not in ("y", "yes"):
            return False
        import cfw_builder
        cfw_builder.FORCE = True
        return True
    if pending_entries(offset_path) > 0:
        ans = log_utils.safe_input(prompt("profile has pending offsets — build anyway? [y/N]: ") or "n")
        return ans.lower() in ("y", "yes")
    _ = validate_offsets
    return True


def menu_build():
    """Sub-menu: build CFW."""
    print(header("Build Custom Firmware"))
    print()

    active = get_active_device()
    if not active:
        print(err("No device configured — use [2] Configure Device first"))
        return

    model = active.get("model", "?")
    ios = active.get("ios_version", "?")
    print(key_value("Device", f"{active.get('device', '?')} ({model})"))
    print(key_value("iOS", ios))
    print()

    ipsw_path = log_utils.safe_input(prompt("Path to IPSW file: ")).strip()
    if not ipsw_path or not Path(ipsw_path).exists():
        print(err("IPSW not found — download from https://updates.cdn-apple.com/"))
        return

    dr = log_utils.safe_input(prompt("Dry-run (validate only, no writes)? [y/N]: ") or "n")
    if dr.lower() in ("y", "yes"):
        import cfw_builder
        cfw_builder.DRY_RUN = True

    # Find source offset file
    source_file = active.get("_source_file", "")
    if source_file and Path(source_file).exists():
        offset_path = Path(source_file)
    else:
        offset_path = OFFSETS_DIR / f"{model}_{ios}.yaml"

    from cfw_builder import build_cfw
    build_cfw(Path(ipsw_path), offset_path)


def menu_flash():
    """Sub-menu: flash/restore device."""
    print(header("Flash Custom Firmware"))
    print()

    print(f"  {C.RED}{C.B}⚠  THIS ERASES THE DEVICE COMPLETELY{C.NC}")
    print()

    # Find work directory
    work_dirs = _find_work_dirs()
    if work_dirs:
        print(section("Available Work Dirs"))
        for i, d in enumerate(work_dirs):
            print(f"  {C.EYE}[{i + 1}]{C.NC} {C.DIM}{d}{C.NC}")

    work_dir = log_utils.safe_input(prompt("Path to work directory (or press Enter to skip): ")).strip()
    if not work_dir:
        print(info("Flash skipped — return to Configure and Build first"))
        return

    # Check PWN DFU
    from pwn_utils import verify_pwn_mode
    is_pwned, msg = verify_pwn_mode()
    if not is_pwned:
        print(err(f"Device not in PWN DFU: {msg}"))
        ans = log_utils.safe_input(prompt("Continue anyway? [y/N]: ") or "n")
        if ans.lower() not in ("y", "yes"):
            return

    from boot_chain import restore_device
    restore_device(Path(work_dir))


def menu_sshrd():
    """Sub-menu: SSHRD boot."""
    print(header("SSHRD Boot"))
    print()

    is_pwned, msg = verify_pwn_mode()
    if not is_pwned:
        print(err(f"Not in PWN DFU: {msg}"))
        return

    work_dirs = _find_work_dirs()
    work_dir = None
    if work_dirs:
        work_dir = Path(log_utils.safe_input(prompt(f"Work dir [{work_dirs[0]}]: ") or str(work_dirs[0])))
    else:
        work_dir = Path(log_utils.safe_input(prompt("Work directory path: ")).strip())

    if not work_dir.exists():
        print(err(f"Directory not found: {work_dir}"))
        return

    from boot_chain import sshrd_boot
    sshrd_boot(work_dir)


def menu_normal_boot():
    """Sub-menu: normal boot."""
    print(header("Normal Boot"))
    print()

    is_pwned, msg = verify_pwn_mode()
    if not is_pwned:
        print(err(f"Not in PWN DFU: {msg}"))
        return

    work_dirs = _find_work_dirs()
    work_dir = None
    if work_dirs:
        work_dir = Path(log_utils.safe_input(prompt(f"Work dir [{work_dirs[0]}]: ") or str(work_dirs[0])))
    else:
        work_dir = Path(log_utils.safe_input(prompt("Work directory path: ")).strip())

    if not work_dir.exists():
        print(err(f"Directory not found: {work_dir}"))
        return

    from boot_chain import normal_boot
    normal_boot(work_dir)


def menu_postboot():
    """Sub-menu: post-exploit configuration."""
    while True:
        print(header("Post-Boot Setup"))
        print()

        items = [
            ("1", "USB Network",       "Share Mac internet over USB"),
            ("2", "VNC Remote Control", "View/control iPhone screen"),
            ("3", "SSH to Device",     "Open interactive shell"),
            ("4", "Bootstrap",         "Install Sileo + packages"),
        ]
        for num, title, desc in items:
            print(f"  {C.EYE}[ {num} ]{C.NC}  {C.SNOW}{title:<20}{C.NC} {C.DIM}{desc}{C.NC}")
        print()
        print(f"  {C.EYE}[ b ]{C.NC}  {C.SNOW}{'Back':<20}{C.NC}")
        print()

        choice = log_utils.safe_input(prompt("Choose: ")).strip().lower()

        if choice == "1":
            from boot_chain import setup_usb_network
            setup_usb_network()
        elif choice == "2":
            from boot_chain import setup_vnc
            setup_vnc()
        elif choice == "3":
            from boot_chain import ssh_connect
            ssh_connect()
            break  # exec'd into SSH
        elif choice == "4":
            print(info("Bootstrap instructions:"))
            print(f"  1. Extract bootstrap tarball to /var/jb")
            print(f"  2. Run /var/jb/prep_bootstrap.sh")
            print(f"  3. dpkg -i /var/jb/sileo.deb")
            print(f"  4. uicache to refresh app list")
        else:
            break

        log_utils.safe_input(f"\n  {C.DIM}── Press Enter to continue ──{C.NC}")
        clear()


# ═══════════════════════════════════════════════════════════════
#  Entry
# ═══════════════════════════════════════════════════════════════

def _argv_after(verb: str) -> list[str]:
    """Raw argv after a subcommand verb, so its own options pass through intact."""
    argv = sys.argv[1:]
    if verb in argv:
        return argv[argv.index(verb) + 1:]
    return []

def _cli() -> int:
    """Command line entry point: whatever it raises, guard() turns into an exit code."""
    import argparse

    import log_utils
    log_utils.install()          # usbliter8.log + unhandled-exception logging
    p = argparse.ArgumentParser(description="usbliter8-arctic — iOS exploit hub")
    p.add_argument("--dry-run", action="store_true", help="Simulate without modifying files")
    p.add_argument("command", nargs="?", default="menu",
                   help="Subcommand: menu, pwn, offsets, coverage, gaps, preflight, "
                        "audit, fetch, migrate, build, flash, boot, sshrd, net, vnc, "
                        "ssh, postboot, explain, version, logs")
    p.add_argument("profile", nargs="?", default="", help="profile path for preflight/audit")
    # flags for the wrapped tool (--json, --fetch, --record, ...) pass through
    args, extra = p.parse_known_args()

    if args.dry_run:
        import cfw_builder, boot_chain
        cfw_builder.DRY_RUN = True
        boot_chain.DRY_RUN = True

    if args.command == "menu":
        menu()
    elif args.command == "pwn":
        print_device_status()
    elif args.command == "offsets":
        from device_offsets import list_offset_files
        for f in list_offset_files():
            icon = "✓" if f["status"] == "ready" else "⚠"
            print(f"  {icon} {f['device']} ({f['model']}) — iOS {f['ios']} [{f['soc']}]  {f['passed']} patches")
    elif args.command == "explain":
        from boot_chain import explain_usbliter8
        explain_usbliter8()
    elif args.command == "coverage":
        import profile_gen
        profile_gen.cmd_coverage(json_out="--json" in extra)
    elif args.command == "gaps":
        import profile_gen
        profile_gen.cmd_gaps(json_out="--json" in extra)
    elif args.command in ("preflight", "verify"):
        import preflight
        argv = ([args.profile] if args.profile else []) + extra
        raise SystemExit(preflight.main(argv or None))
    elif args.command == "fetch":
        import fetch_components
        raise SystemExit(fetch_components.main(extra))
    elif args.command == "audit":
        argv = ([args.profile] if args.profile else []) + extra
        if not argv:
            print(err("usage: main.py audit <make_cfw.py> <profile.yaml>"))
            raise SystemExit(2)
        import source_audit
        raise SystemExit(source_audit.main(argv))
    elif args.command == "migrate":
        import migrate
        migrate.cli_main(([args.profile] if args.profile else []) + extra)
    elif args.command == "build":
        menu_build()
    elif args.command == "flash":
        menu_flash()
    elif args.command == "boot":
        menu_normal_boot()
    elif args.command == "sshrd":
        menu_sshrd()
    elif args.command == "net":
        from boot_chain import setup_usb_network
        setup_usb_network()
    elif args.command == "vnc":
        from boot_chain import setup_vnc
        setup_vnc()
    elif args.command == "ssh":
        from boot_chain import ssh_connect
        ssh_connect()
    elif args.command == "postboot":
        menu_postboot()
    elif args.command == "version":
        import version
        raise SystemExit(version.main(_argv_after("version")))
    elif args.command == "logs":
        raise SystemExit(log_utils.main(_argv_after("logs")))
    else:
        print(err(f"unknown subcommand '{args.command}'"))
        print(info("try: menu, pwn, offsets, coverage, gaps, preflight, audit, fetch, "
             "migrate, build, flash, boot, sshrd, net, vnc, ssh, postboot, "
             "explain, version, logs"))
        return log_utils.EXIT_ERROR
    return log_utils.EXIT_OK


if __name__ == "__main__":
    import log_utils

    log_utils.install()          # usbliter8.log + clean exits
    sys.exit(log_utils.guard(_cli))
