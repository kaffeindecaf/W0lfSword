"""Dependency checker & installer for usbliter8-arctic.

Checks for required Python packages (pyusb, pyyaml), system libraries
(libusb-1.0), and offers interactive installation via apt / pacman / dnf
or pip fallback.
"""

import importlib
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

from colors import C, ok, err, warn, info, section, key_value, header, prompt

PY_PACKAGES = {
    "usb": "pyusb",
    "yaml": "pyyaml",
}

APT_PACKAGES = ["python3-usb", "python3-yaml", "libusb-1.0-0"]
PACMAN_PACKAGES = ["python-pyusb", "python-yaml", "libusb"]
DNF_PACKAGES = ["python3-pyusb", "python3-pyyaml", "libusb1"]

LIBUSB_SONAMES = ("libusb-1.0.so.0", "libusb-1.0.so")


def _python_ok() -> bool:
    for mod, pkg in PY_PACKAGES.items():
        try:
            importlib.import_module(mod)
        except ImportError:
            return False
    return True


def _libusb_ok() -> bool:
    if shutil.which("ldconfig") is None:
        return False
    try:
        out = subprocess.run(
            ["ldconfig", "-p"], capture_output=True, text=True, timeout=10
        ).stdout
        return any(soname in out for soname in LIBUSB_SONAMES)
    except (OSError, subprocess.SubprocessError):
        return False


def check_dependencies() -> dict[str, bool]:
    """Return dependency check results without installing anything."""
    results = {"python_packages": _python_ok(), "libusb": _libusb_ok()}
    for mod, pkg in PY_PACKAGES.items():
        try:
            importlib.import_module(mod)
            results[f"pkg_{pkg}"] = True
        except ImportError:
            results[f"pkg_{pkg}"] = False
    return results


def print_dependency_status() -> dict[str, bool]:
    print(header("Dependency Status"))
    print()

    results = check_dependencies()

    for mod, pkg in PY_PACKAGES.items():
        name = pkg
        if results[f"pkg_{pkg}"]:
            print(key_value(f"py {name}", f"{C.GRN}installed{C.NC}"))
        else:
            print(key_value(f"py {name}", f"{C.RED}missing{C.NC}"))

    print(key_value("libusb-1.0", f"{C.GRN}found{C.NC}" if results["libusb"] else f"{C.RED}missing{C.NC}"))

    # Bundled binary tools
    tools_dir = Path(__file__).parent / "tools"
    n_tools = len(list(tools_dir.glob("*"))) if tools_dir.exists() else 0
    print(key_value("tools/", f"{C.GRN}{n_tools} binaries{C.NC}" if n_tools else f"{C.RED}empty{C.NC}"))

    print()
    if all(results.values()):
        print(ok("All dependencies satisfied"))
    else:
        print(warn("Missing dependencies — use [i] Install Dependencies"))
    return results


def _run(cmd: list[str], sudo: bool = False) -> int:
    if sudo and os.geteuid() != 0:
        cmd = ["sudo", *cmd]
    print(f"  {C.DIM}$ {' '.join(cmd)}{C.NC}")
    try:
        return subprocess.run(cmd).returncode
    except FileNotFoundError:
        print(err(f"Command not found: {cmd[0]}"))
        return 127


def install_dependencies() -> bool:
    """Interactive dependency installer. Returns True if all satisfied."""
    print(header("Install Dependencies"))
    print()

    results = check_dependencies()
    missing = [k for k, v in results.items() if not v]
    if not missing:
        print(ok("All dependencies already installed"))
        return True

    for mod, pkg in PY_PACKAGES.items():
        status = f"{C.GRN}installed{C.NC}" if results[f"pkg_{pkg}"] else f"{C.RED}missing{C.NC}"
        print(key_value(f"py {pkg}", status))
    print(key_value("libusb-1.0", f"{C.GRN}found{C.NC}" if results["libusb"] else f"{C.RED}missing{C.NC}"))
    print()

    distro = platform.system().lower()
    pkg_mgr = None
    if distro == "linux":
        if shutil.which("apt"):
            pkg_mgr = "apt"
        elif shutil.which("pacman"):
            pkg_mgr = "pacman"
        elif shutil.which("dnf"):
            pkg_mgr = "dnf"

    print(section("Install Options"))
    print(f"  {C.EYE}[1]{C.NC} System packages {C.DIM}({pkg_mgr or 'package manager'}){C.NC}")
    print(f"  {C.EYE}[2]{C.NC} pip {C.DIM}(user install, no sudo){C.NC}")
    print(f"  {C.EYE}[3]{C.NC} pip --break-system-packages {C.DIM}(PEP 668 systems){C.NC}")
    print()

    try:
        choice = input(prompt("Choose [1/2/3] or [q]uit: ") or "1").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    if choice in ("q", "quit", ""):
        return False

    if choice == "1":
        if pkg_mgr == "apt":
            _run(["apt", "update"], sudo=True)
            _run(["apt", "install", "-y", *APT_PACKAGES], sudo=True)
        elif pkg_mgr == "pacman":
            _run(["pacman", "-S", "--noconfirm", *PACMAN_PACKAGES], sudo=True)
        elif pkg_mgr == "dnf":
            _run(["dnf", "install", "-y", *DNF_PACKAGES], sudo=True)
        elif distro == "darwin":
            if shutil.which("brew"):
                _run(["brew", "install", "libusb"])
            _run([sys.executable, "-m", "pip", "install", "--user", "pyusb", "pyyaml"])
        else:
            print(warn(f"No supported package manager found — falling back to pip"))
            _run([sys.executable, "-m", "pip", "install", "--user", "pyusb", "pyyaml"])
    elif choice == "2":
        _run([sys.executable, "-m", "pip", "install", "--user", "pyusb", "pyyaml"])
    elif choice == "3":
        _run([sys.executable, "-m", "pip", "install", "--break-system-packages", "pyusb", "pyyaml"])
    else:
        print(warn(f"Unknown option '{choice}' — nothing installed"))
        return False

    # Re-check
    print()
    results = check_dependencies()
    missing = [k for k, v in results.items() if not v]
    if not missing:
        print(ok("All dependencies installed — ready to exploit"))
        return True
    print(warn(f"Still missing: {', '.join(missing)}"))
    print(info("Hint: libusb needs a reboot or `sudo ldconfig` after install in some cases"))
    return False


if __name__ == "__main__":
    install_dependencies()
