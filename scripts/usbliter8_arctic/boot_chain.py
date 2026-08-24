"""Boot chain utilities for usbliter8-arctic.

Handles: normal boot, SSHRD boot, device restore, USB networking,
and VNC remote control setup.
"""

import os
import sys
import time
import subprocess
from pathlib import Path

from colors import C, ok, err, warn, info, stage, section, divider, prompt, header

TOOLS_DIR = Path(__file__).parent / "tools"
DRY_RUN = False


def _tool(name: str) -> str:
    p = TOOLS_DIR / name
    return str(p) if p.exists() else name


def _run(cmd: list[str], cwd: str | None = None, check: bool = False, env: dict | None = None) -> subprocess.CompletedProcess:
    if DRY_RUN:
        print(f"    {C.DIM}[dry-run] {' '.join(cmd)}{C.NC}")
        return subprocess.CompletedProcess(cmd, 0)
    print(f"    {C.DIM}$ {' '.join(cmd)}{C.NC}")
    run_env = {**os.environ, **env} if env else None
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, env=run_env)


def _find_script(name: str) -> Path | None:
    """Locate a helper script in CWD or known usbliter8 work directories."""
    cwd_rel = Path(name)
    if cwd_rel.exists():
        return cwd_rel
    bases = [
        Path(__file__).parent.parent / "referenceforAI",
        Path.home() / "Desktop" / "W0lfSword" / "referenceforAI",
        Path.home() / "Desktop" / "W0lfSword" / "referenceforAI" / "projects",
    ]
    for base in bases:
        for d in base.glob("usbliter8-fun*/work-*"):
            p = d / name
            if p.exists():
                return p
    return None


# ═══════════════════════════════════════════════════════════════
#  Boot chain scripts
# ═══════════════════════════════════════════════════════════════

def normal_boot(work_dir: str | Path, password: str = "") -> bool:
    """Build normal boot chain and send via usbliter8ctl."""
    print(section("Normal Boot"))
    print()

    # Run get_boot.py to build the normal chain
    get_boot = Path(work_dir) / "get_boot.py"
    boot_py = Path(work_dir) / "boot.py"

    if not get_boot.exists():
        print(warn(f"get_boot.py not found in {work_dir}"))
        print(info("Running manually: build ramdisk chain without SSHRD"))
        return False

    print(stage(1, "Building normal boot chain..."))
    r = _run(["python3", str(get_boot)], cwd=str(work_dir))
    if r.returncode != 0:
        print(err("get_boot.py failed"))
        return False
    print(ok("Boot chain built (Ramdisk should NOT contain RestoreRamdisk)"))

    print(stage(2, "Sending boot chain to device..."))
    r = _run(["python3", str(boot_py)], cwd=str(work_dir))
    if r.returncode != 0:
        print(err("boot.py failed"))
        return False

    print(ok("Normal boot sent — device should be booting into iOS"))
    return True


def sshrd_boot(work_dir: str | Path) -> bool:
    """Boot into SSHRD (ramdisk) for filesystem access."""
    print(section("SSHRD Boot"))
    print()
    print(f"  {C.AMB}SSHRD boots into a ramdisk shell — useful for:{C.NC}")
    print(f"    • Mounting and editing the filesystem")
    print(f"    • Pulling SEP firmware for apticket")
    print(f"    • Installing apps/bootstrap")
    print()

    # Copy SSHRD ramdisk chain
    rd_bak = Path(work_dir) / "Ramdisk_SSH_bak"
    ramdisk = Path(work_dir) / "Ramdisk"

    if rd_bak.exists():
        if ramdisk.exists():
            shutil = __import__("shutil")
            shutil.rmtree(str(ramdisk), ignore_errors=True)
        shutil = __import__("shutil")
        shutil.copytree(str(rd_bak), str(ramdisk))
        print(ok("SSHRD chain loaded (Ramdisk ← Ramdisk_SSH_bak)"))

    # Verify no mixing up
    restore_entries = list(ramdisk.glob("RestoreRamdisk*"))
    if restore_entries:
        print(ok(f"SSHRD mode confirmed ({len(restore_entries)} RestoreRamdisk entries)"))

    # Run boot_rd.sh
    boot_rd = Path(work_dir) / "boot_rd.sh"
    if not boot_rd.exists():
        print(err("boot_rd.sh not found"))
        return False

    print(stage(1, "Booting SSHRD ramdisk..."))
    r = _run(["bash", str(boot_rd)], cwd=str(work_dir))
    if r.returncode != 0:
        print(err("boot_rd.sh failed"))
        return False

    print(ok("SSHRD booted! Device is now in ramdisk mode."))
    return True


def restore_device(work_dir: str | Path, password: str = "") -> bool:
    """Restore custom firmware to device (ERASES ALL DATA)."""
    print(section("Restore CFW to Device"))
    print()
    print(f"  {C.RED}{C.B}⚠  THIS WILL ERASE THE ENTIRE DEVICE{C.NC}")
    print(f"  {C.RED}All data, apps, and settings will be permanently deleted.{C.NC}")
    print()

    ans = input(prompt("Type YES to confirm: "))
    if ans != "YES":
        print(info("Restore cancelled."))
        return False

    make_cfw = Path(work_dir) / "make_cfw.py"
    restore_sh = Path(work_dir) / "restore_cfw.sh"
    tss_proxy = Path(work_dir) / "tss_proxy_server.py"

    missing = [str(p.name) for p in (make_cfw, restore_sh, tss_proxy) if not p.exists()]
    if missing:
        print(err(f"Required files not found in {work_dir}: {', '.join(missing)}"))
        return False

    print(stage(1, "Building custom firmware..."))
    r = _run(["python3", str(make_cfw)], cwd=str(work_dir))
    if r.returncode != 0:
        print(err("make_cfw.py failed"))
        return False
    print(ok("CFW built"))

    proxy_proc = None
    print(stage(2, "Starting TSS proxy (background)..."))
    if DRY_RUN:
        print(f"    {C.DIM}[dry-run] python3 {tss_proxy}{C.NC}")
    else:
        proxy_proc = subprocess.Popen(
            ["python3", str(tss_proxy)],
            cwd=str(work_dir),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(2)
    print(ok("TSS proxy running"))

    print(stage(3, "Restoring CFW (this takes 5-15 minutes)..."))
    print(f"  {C.DIM}The device screen will show a progress bar.{C.NC}")
    print(f"  {C.DIM}Wait until the script completes and device returns to recovery.{C.NC}")

    if not DRY_RUN:
        try:
            r = subprocess.run(["bash", str(restore_sh)], cwd=str(work_dir))
            if r.returncode != 0:
                print(err("Restore failed"))
                return False
        finally:
            if proxy_proc and proxy_proc.poll() is None:
                proxy_proc.terminate()
                try:
                    proxy_proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proxy_proc.kill()

    print(ok("Restore complete! Device is now on custom firmware."))
    return True


def setup_usb_network(ssh_password: str = "alpine") -> bool:
    """Set up USB ethernet networking (Mac → iPhone)."""
    print(section("USB Network Setup"))
    print()

    print(f"  {C.SNOW}This shares your computer's internet with the iPhone over USB.{C.NC}")
    print(f"  {C.DIM}Useful when Wi-Fi and cellular are broken after CFW restore.{C.NC}")
    print()

    # Check for net_up.sh in the work dir
    net_up = _find_script("net_up.sh")
    if net_up:
        print(stage(1, "Running net_up.sh..."))
        r = _run(["bash", str(net_up)], cwd=str(net_up.parent))
        if r.returncode == 0:
            print(ok("USB network configured"))
            print(f"  {C.GREY}Mac: en31 = 10.7.0.1{C.NC}")
            print(f"  {C.GREY}Device: en2 = 10.7.0.2, DNS 8.8.8.8{C.NC}")
            return True

    print(info("net_up.sh not found — manual setup required:"))
    print(f"  {C.DIM}# On your Mac:{C.NC}")
    print(f"  sudo ifconfig en31 inet 10.7.0.1 netmask 255.255.255.0")
    print(f"  sudo sysctl -w net.inet.ip.forwarding=1")
    print(f"  echo 'nat on en0 from 10.7.0.0/24 to any -> (en0)' | sudo pfctl -ef -")
    print()
    print(f"  {C.DIM}# On the device (over SSH):{C.NC}")
    print(f"  /sbin/ifconfig en2 inet 10.7.0.2 netmask 255.255.255.0")
    print(f"  /sbin/route -n add default 10.7.0.1")
    return True


def setup_vnc(ssh_password: str = "alpine") -> bool:
    """Set up TrollVNC for remote screen control."""
    print(section("VNC Remote Control"))
    print()

    vnc_up = _find_script("vnc_up.sh")
    if vnc_up:
        print(stage(1, "Running vnc_up.sh..."))
        r = _run(["bash", str(vnc_up)], cwd=str(vnc_up.parent))
        if r.returncode == 0:
            print(ok("VNC server started"))
            print(f"  {C.EYE}vnc://:alpine@10.7.0.2:5901{C.NC}")
            return True

    print(info("Manual VNC setup:"))
    print(f"  {C.DIM}# Start VNC server on device:{C.NC}")
    print(f"  SSHPASS={ssh_password} {_tool('sshpass')} -e ssh root@10.7.0.2 /var/jb/usr/bin/tvncd")
    print()
    print(f"  {C.DIM}# Connect from Mac:{C.NC}")
    print(f"  open vnc://:alpine@10.7.0.2:5901")
    return True


def ssh_connect(ssh_password: str = "alpine") -> bool:
    """Open SSH connection to device."""
    print(section("SSH to Device"))
    print()

    sshpass = _tool("sshpass")
    base_args = ["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
                  "-o", "PreferredAuthentications=password", "-o", "PubkeyAuthentication=no"]
    ssh_env = {"SSHPASS": ssh_password}

    print(info("Trying USB SSH (10.7.0.2)..."))
    r = _run([sshpass, "-e", "ssh"] + base_args + ["root@10.7.0.2", "echo ok"], env=ssh_env)
    if r.returncode == 0:
        print(ok("USB SSH works — connecting interactively..."))
        os.environ["SSHPASS"] = ssh_password
        os.execvp(sshpass, [sshpass, "-e", "ssh"] + base_args + ["root@10.7.0.2"])
        return True

    print(info("Trying iproxy (localhost:2222)..."))
    r = _run([sshpass, "-e", "ssh"] + base_args + ["-p", "2222", "root@localhost", "echo ok"], env=ssh_env)
    if r.returncode == 0:
        print(ok("iproxy SSH works — connecting interactively..."))
        os.environ["SSHPASS"] = ssh_password
        os.execvp(sshpass, [sshpass, "-e", "ssh"] + base_args + ["-p", "2222", "root@localhost"])
        return True

    print(err("SSH failed. Make sure the device is booted and on USB network."))
    return False


def explain_usbliter8():
    """Explain what you can do with usbliter8."""
    print(header("What can you do with usbliter8?"))
    print()

    items = [
        ("Custom Firmware", "Flash a patched iOS with kernel-level modifications. AMFI disabled, "
         "sandbox disabled, SSV read/write enabled — your device runs unsigned code."),
        ("Persistent Root FS", "SSHRD mode lets you mount the system partition as read/write. "
         "Install apps to /Applications, modify system files, add launch daemons."),
        ("TrollStore Lite", "Install TrollStore-compatible IPAs permanently. No 7-day "
         "re-signing. No computer needed after initial setup."),
        ("Sileo Package Manager", "Full APT/dpkg package management. Install tweaks, "
         "themes, command-line tools from any repository."),
        ("USB Networking", "When Wi-Fi/cellular are broken after CFW, your Mac shares "
         "internet over USB. Full network access without wireless radios."),
        ("VNC Remote Control", "View and control the iPhone screen from your Mac over USB. "
         "Mouse = touch, drag = swipe. No Wi-Fi needed."),
        ("Kernel Research", "With a patched kernel, you can load kernel extensions, attach "
         "kernel debuggers, and experiment with custom kernel code."),
        ("Tethered (important)", "This is a TETHERED setup. Every cold boot requires the "
         "RP2350 to PWN DFU again. Keep the rig handy."),
    ]

    for title, desc in items:
        print(f"  {C.EYE}{C.B}▸ {title}{C.NC}")
        print(f"    {C.DIM}{desc}{C.NC}")
        print()

    print(f"  {C.GRN}Scope:{C.NC}     {C.SNOW}A12/A13 devices (iPhone XS/XR, 11 series, SE 2){C.NC}")
    print(f"  {C.GRN}Requires:{C.NC}  {C.SNOW}RP2350 microcontroller + custom firmware IPSW{C.NC}")
    print(f"  {C.DIM}Not for:{C.NC}   A14+ (iPhone 12+) — SecureROM bug is fixed in newer chips{C.NC}")
    print()
