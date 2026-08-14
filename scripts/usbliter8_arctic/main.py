#!/usr/bin/env python3
"""usbliter8-arctic — Interactive exploit hub for W0lfSword.

TUI menu for: hardware setup, offset management, CFW building,
device restore, SSHRD/normal boot, post-exploit configuration.
"""

import os
import sys
import time
from pathlib import Path

from colors import C, ok, err, warn, info, stage, section, key_value, divider, header, prompt
from device_offsets import list_offset_files, set_active_device, get_active_device, find_online_sources
from pwn_utils import print_device_status, verify_pwn_mode, check_pyusb_installed, wait_for_pwn

PROJECT_ROOT = Path(__file__).parent.parent.parent
SCRIPTS_DIR = Path(__file__).parent
OFFSETS_DIR = SCRIPTS_DIR / "offsets"


def clear():
    os.system("clear 2>/dev/null || true")


def show_wolf():
    print()
    print(f"{C.WOLF}")
    print("                          .d$$b")
    print("                        .' TO$;\\")
    print("                       /  : TP._;")
    print("                      / _.;  :Tb|")
    print("                     /   /   ;j$j")
    print("                 _.-\"       d$$$$")
    print("               .' ..       d$$$$;")
    print("              /  /P'      d$$$$P. |\\")
    print("             /   \"      .d$$$P' |\\^\"l")
    print("           .'           `T$P^\"\"\"\"\"\"  :")
    print(f"{C.NC}")
    print()


def show_banner():
    print()
    print(f"  {C.DIM}╔══════════════════════════════════════════════════════════╗{C.NC}")
    print(f"  {C.DIM}║{C.NC}  {C.SNOW}{C.B}W0lfSword · usbliter8-arctic{C.NC}                          {C.DIM}║{C.NC}")
    print(f"  {C.DIM}║{C.NC}  {C.FROST}CFW Builder · PWN DFU · Restore · Boot{C.NC}                {C.DIM}║{C.NC}")
    print(f"  {C.DIM}╚══════════════════════════════════════════════════════════╝{C.NC}")


def show_device_status():
    """Display active device config and hardware status."""
    active = get_active_device()
    print(f"  {C.GREY}── device ─────────────────────────────────────────────────────{C.NC}")
    if active:
        model = active.get("model", "?")
        name = active.get("device", "?")
        ios = active.get("ios_version", "?")
        soc = active.get("soc", "?")
        board = active.get("board", "?")
        print(f"  Target:  {C.EYE}{name}{C.NC} ({C.DIM}{model}{C.NC}) · {C.FROST}{soc}{C.NC} · board {C.EYE}{board}{C.NC}")
        print(f"  iOS:     {C.FROST}{ios}{C.NC}")
    else:
        print(f"  {C.DIM}No device configured — use [2] Configure Device{C.NC}")
    print()


def show_board_status():
    """Display RP2350 board and firmware status."""
    from hardware_guide import _load_config, check_firmware, UF2_FILES
    cfg = _load_config()
    board_id = cfg.get("selected_board", "unknown")
    print(f"  {C.GREY}── microcontroller ─────────────────────────────────────────────{C.NC}")

    board_names = {
        "pico2": "Raspberry Pi Pico 2",
        "waveshare_usb_a": "Waveshare RP2350-USB-A",
        "waveshare_usb_c": "Waveshare RP2350-USB-C",
        "waveshare_zero": "Waveshare RP2350-Zero",
        "waveshare_pizero": "Waveshare RP2350-Pizero",
        "pimoroni_tiny2350": "Pimoroni Tiny2350",
    }
    name = board_names.get(board_id, board_id)
    print(f"  Board:   {C.EYE}{name}{C.NC}")

    if check_firmware(board_id):
        print(f"  Firmware: {C.GRN}installed{C.NC}")
    else:
        print(f"  Firmware: {C.RED}NOT installed{C.NC}")

    if check_pyusb_installed():
        from pwn_utils import detect_rp2350
        rp = detect_rp2350()
        if rp:
            print(f"  USB:     {C.GRN}detected{C.NC} (bus {rp['bus']}, addr {rp['address']})")
        else:
            print(f"  USB:     {C.DIM}no RP2350 device detected{C.NC}")
    print()


def menu():
    """Main interactive menu loop."""
    first_run = True
    while True:
        clear()
        if first_run:
            show_wolf()
            first_run = False
        show_banner()
        show_device_status()
        show_board_status()

        print(f"  {C.EYE}{C.B}[ 1 ]{C.NC}  Hardware Setup     {C.DIM}Wiring guide · flash firmware · test PWN{C.NC}")
        print(f"  {C.EYE}{C.B}[ 2 ]{C.NC}  Configure Device   {C.DIM}Select model / iOS · edit offsets{C.NC}")
        print(f"  {C.EYE}{C.B}[ 3 ]{C.NC}  Build CFW          {C.DIM}Patch IPSW → custom firmware{C.NC}")
        print(f"  {C.EYE}{C.B}[ 4 ]{C.NC}  Flash Device       {C.DIM}Restore CFW {C.RED}(ERASES DEVICE!){C.NC}")
        print(f"  {C.EYE}{C.B}[ 5 ]{C.NC}  SSHRD Boot         {C.DIM}Ramdisk · mount · edit filesystem{C.NC}")
        print(f"  {C.EYE}{C.B}[ 6 ]{C.NC}  Normal Boot        {C.DIM}Full iOS boot with patches{C.NC}")
        print(f"  {C.EYE}{C.B}[ 7 ]{C.NC}  Post-Boot Setup    {C.DIM}USB network · VNC · SSH · bootstrap{C.NC}")
        print(f"  {C.EYE}{C.B}[ 8 ]{C.NC}  Check PWN Status   {C.DIM}Verify DFU / PWND state · wait for device{C.NC}")
        print(f"  {C.EYE}{C.B}[ 9 ]{C.NC}  Health Check        {C.DIM}Verify hardware, tools, firmware{C.NC}")
        print(f"  {C.EYE}{C.B}[ 0 ]{C.NC}  Explain             {C.DIM}What can you DO with usbliter8?{C.NC}")
        print()
        print(f"  {C.DIM}─── shortcuts ───{C.NC}")
        print(f"  {C.EYE}h{C.NC}=hw guide  {C.EYE}c{C.NC}=config  {C.EYE}b{C.NC}=build  {C.EYE}f{C.NC}=flash  {C.EYE}p{C.NC}=pwn check  {C.EYE}e{C.NC}=explain  {C.EYE}x{C.NC}=health")
        print()
        print(f"  {C.EYE}{C.B}[ q ]{C.NC}  Back to W0lfSword")
        print()

        try:
            choice = input(f"  {C.FROST}{C.B}usbliter8 ▸{C.NC} ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print(); break

        print()
        choice = choice or " "

        # Dispatch
        if choice in ("1", "h", "hw"):
            from hardware_guide import interactive_hardware_setup
            interactive_hardware_setup()

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
                ans = input(prompt("Wait for PWN DFU? [y/N]: ") or "n")
                if ans.lower() in ("y", "yes"):
                    wait_for_pwn(timeout=60)

        elif choice in ("9", "x", "health"):
            from hardware_guide import run_health_check
            run_health_check()

        elif choice in ("0", "e", "explain"):
            from boot_chain import explain_usbliter8
            explain_usbliter8()

        elif choice in ("q", "quit", "exit", ""):
            print(f"  {C.WOLF}~ back to W0lfSword ~{C.NC}")
            break

        else:
            print(warn(f"Unknown: '{choice}' — try 1-9, h/c/b/f/p/e, or q"))

        input(f"\n  {C.DIM}── Press Enter to continue ──{C.NC}")


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
    print()

    choice = input(prompt("Select device [#], find [f], validate [v], or [b]ack: ") or "").strip().lower()

    if choice == "f":
        model = input(prompt("Enter device model (e.g. iPhone12,1): ")).strip()
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
        path = input(prompt("Path to offset YAML file: ")).strip()
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

    ipsw_path = input(prompt("Path to IPSW file: ")).strip()
    if not ipsw_path or not Path(ipsw_path).exists():
        print(err("IPSW not found — download from https://updates.cdn-apple.com/"))
        return

    dr = input(prompt("Dry-run (validate only, no writes)? [y/N]: ") or "n")
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
    work_dirs = list(PROJECT_ROOT.glob("referenceforAI/usbliter8-fun*/work-*"))
    if work_dirs:
        print(section("Available Work Dirs"))
        for i, d in enumerate(work_dirs):
            print(f"  {C.EYE}[{i + 1}]{C.NC} {C.DIM}{d}{C.NC}")

    work_dir = input(prompt("Path to work directory (or press Enter to skip): ")).strip()
    if not work_dir:
        print(info("Flash skipped — return to Configure and Build first"))
        return

    # Check PWN DFU
    from pwn_utils import verify_pwn_mode
    is_pwned, msg = verify_pwn_mode()
    if not is_pwned:
        print(err(f"Device not in PWN DFU: {msg}"))
        ans = input(prompt("Continue anyway? [y/N]: ") or "n")
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

    work_dirs = list(PROJECT_ROOT.glob("referenceforAI/usbliter8-fun*/work-*"))
    work_dir = None
    if work_dirs:
        work_dir = Path(input(prompt(f"Work dir [{work_dirs[0]}]: ") or str(work_dirs[0])))
    else:
        work_dir = Path(input(prompt("Work directory path: ")).strip())

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

    work_dirs = list(PROJECT_ROOT.glob("referenceforAI/usbliter8-fun*/work-*"))
    work_dir = None
    if work_dirs:
        work_dir = Path(input(prompt(f"Work dir [{work_dirs[0]}]: ") or str(work_dirs[0])))
    else:
        work_dir = Path(input(prompt("Work directory path: ")).strip())

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
        print(f"  {C.EYE}[ 1 ]{C.NC}  USB Network        {C.DIM}Share Mac internet over USB{C.NC}")
        print(f"  {C.EYE}[ 2 ]{C.NC}  VNC Remote Control  {C.DIM}View/control iPhone screen{C.NC}")
        print(f"  {C.EYE}[ 3 ]{C.NC}  SSH to Device       {C.DIM}Open interactive shell{C.NC}")
        print(f"  {C.EYE}[ 4 ]{C.NC}  Bootstrap           {C.DIM}Install Sileo + packages{C.NC}")
        print(f"  {C.EYE}[ b ]{C.NC}  Back{C.NC}")
        print()

        choice = input(prompt("Choose: ")).strip().lower()

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

        input(f"\n  {C.DIM}── Press Enter to continue ──{C.NC}")
        clear()


# ═══════════════════════════════════════════════════════════════
#  Entry
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="usbliter8-arctic — iOS exploit hub")
    p.add_argument("--dry-run", action="store_true", help="Simulate without modifying files")
    p.add_argument("command", nargs="?", default="menu", help="Subcommand: menu, pwn, offsets, build, flash, boot, sshrd, net, vnc, explain")

    args = p.parse_args()

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
    else:
        menu()
