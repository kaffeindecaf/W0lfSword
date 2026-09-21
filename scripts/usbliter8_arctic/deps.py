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
import log_utils

PY_PACKAGES = {
    "usb": "pyusb",
    "yaml": "pyyaml",
}

# needed to unwrap/patch IPSW components; without it the bundled macOS-only
# tools/ binaries are the only way, which no Windows or Linux user has
OPTIONAL_PACKAGES = {
    "pyimg4": ("IMG4/lzfse component codec (preflight + CFW build)", ""),
    "libusb_package": ("libusb DLL on Windows (no Zadig needed)", "Windows"),
}
PIP_NAMES = {"usb": "pyusb", "yaml": "pyyaml", "pyimg4": "pyimg4",
             "libusb_package": "libusb-package"}

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
    """Whether pyusb can actually reach libusb (not just whether a file exists).

    Asking pyusb is the only check that covers Windows (libusb-1.0.dll, Zadig,
    libusb-package) and macOS (brew) as well as Linux's ldconfig scan.
    """
    try:
        import pwn_utils
        status = pwn_utils.usb_status()
        if status["pyusb"]:
            return bool(status["ready"])
    except Exception:                                          # noqa: BLE001
        pass

    try:
        import ctypes.util
        if ctypes.util.find_library("usb-1.0") or ctypes.util.find_library("libusb-1.0"):
            return True
    except Exception:                                          # noqa: BLE001
        pass

    if platform.system() == "Windows":
        return any(Path(c).exists() for c in _windows_libusb_paths())

    if shutil.which("ldconfig") is None:
        return False
    try:
        out = subprocess.run(
            ["ldconfig", "-p"], capture_output=True, text=True, timeout=10
        ).stdout
        return any(soname in out for soname in LIBUSB_SONAMES)
    except (OSError, subprocess.SubprocessError):
        return False


def _windows_libusb_paths() -> list[str]:
    candidates = [r"C:\Windows\System32\libusb-1.0.dll",
                  r"C:\Program Files\libusb-1.0\libusb-1.0.dll",
                  r"C:\Program Files (x86)\libusb-1.0\libusb-1.0.dll"]
    for var in ("LOCALAPPDATA", "USERPROFILE"):
        base = os.environ.get(var)
        if base:
            candidates += [os.path.join(base, "libusb-1.0.dll"),
                           os.path.join(base, "libusb", "libusb-1.0.dll")]
    return candidates


def check_dependencies() -> dict[str, bool]:
    """Required and optional dependency status; installs nothing."""
    results = {"python_packages": _python_ok(), "libusb": _libusb_ok()}
    for mod, pkg in PY_PACKAGES.items():
        try:
            importlib.import_module(mod)
            results[f"pkg_{pkg}"] = True
        except ImportError:
            results[f"pkg_{pkg}"] = False
    for mod in OPTIONAL_PACKAGES:
        try:
            importlib.import_module(mod)
            results[f"opt_{mod}"] = True
        except ImportError:
            results[f"opt_{mod}"] = False
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

    for mod, (purpose, platform_only) in OPTIONAL_PACKAGES.items():
        if platform_only and platform.system() != platform_only:
            print(key_value(f"py {mod}", f"{C.DIM}n/a on {platform.system()}{C.NC}"))
            continue
        state = f"{C.GRN}installed{C.NC}" if results[f"opt_{mod}"] else f"{C.AMB}missing{C.NC}"
        print(key_value(f"py {mod}", f"{state}  {C.DIM}{purpose}{C.NC}"))

    # Bundled binary tools (macOS Mach-O: unusable elsewhere)
    tools_dir = Path(__file__).parent / "tools"
    n_tools = len(list(tools_dir.glob("*"))) if tools_dir.exists() else 0
    usable = "usable here" if platform.system() == "Darwin" else "macOS-only, ignored here"
    print(key_value("tools/", f"{C.GRN}{n_tools} binaries{C.NC} {C.DIM}({usable}){C.NC}"
                    if n_tools else f"{C.RED}empty{C.NC}"))

    try:
        import img4wrap
        ready, note = img4wrap.decoder_available()
        print(key_value("IMG4 codec",
                        f"{C.GRN}{note}{C.NC}" if ready else f"{C.AMB}{note}{C.NC}"))
    except Exception:                                          # noqa: BLE001
        pass

    required = [k for k in results if not k.startswith("opt_")]
    optional_needed = [f"opt_{mod}" for mod, (_p, plat) in OPTIONAL_PACKAGES.items()
                       if not plat or platform.system() == plat]
    print()
    if not all(results[k] for k in required):
        print(warn("Missing dependencies — use [i] Install Dependencies"))
    elif not all(results.get(k, False) for k in optional_needed):
        print(warn("Required dependencies satisfied — optional ones missing "
                   "(see above; component extraction needs pyimg4 off macOS)"))
    else:
        print(ok("All dependencies satisfied"))
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
    for mod, (_purpose, platform_only) in OPTIONAL_PACKAGES.items():
        if platform_only and platform.system() != platform_only:
            continue
        status = (f"{C.GRN}installed{C.NC}" if results[f"opt_{mod}"]
                  else f"{C.AMB}missing{C.NC}")
        print(key_value(f"py {mod}", status))
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
        choice = log_utils.safe_input(prompt("Choose [1/2/3] or [q]uit: ") or "1").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    if choice in ("q", "quit", ""):
        return False

    if choice == "1":
        if platform.system() == "Windows":
            _run([sys.executable, "-m", "pip", "install", *PIP_NAMES.values()])
            print(info("USB on Windows also needs the device bound to WinUSB: "
                       "run Zadig once, or rely on libusb-package installed above"))
        elif pkg_mgr == "apt":
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
            _run([sys.executable, "-m", "pip", "install", "--user", *PIP_NAMES.values()])
    elif choice == "2":
        _run([sys.executable, "-m", "pip", "install", "--user", *PIP_NAMES.values()])
    elif choice == "3":
        _run([sys.executable, "-m", "pip", "install", "--break-system-packages",
              *PIP_NAMES.values()])
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
    if platform.system() == "Windows":
        print(info("Windows hints: `python -m pip install libusb-package` supplies the "
                   "DLL, and Zadig (https://zadig.akeo.ie) binds the device to WinUSB"))
    else:
        print(info("Hint: libusb needs a reboot or `sudo ldconfig` after install "
                   "in some cases"))
    return False


if __name__ == "__main__":
    import log_utils
    log_utils.install()
    sys.exit(log_utils.guard(install_dependencies))
