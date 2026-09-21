"""Cross-platform dependency detection and installation.

Everything here is driven by one question: *what does the feature the user is
about to run actually need, and is it here?* So it detects the OS, checks the
packages a feature needs, shows what is missing and why, offers to install it
with the right command for that OS, re-checks, and then either continues or
explains in plain words what to install.

Design notes:
- Python packages come from pip (`sys.executable -m pip`), which is the only
  installer that works the same on Windows, macOS and Linux. System packages
  (libusb) are only used when libusb itself is missing, via the detected package
  manager.
- PEP 668 distros (Debian 12+, Ubuntu 24+, Parrot) refuse a plain pip install.
  That is detected up front (`EXTERNALLY-MANAGED`) and the retry with
  `--break-system-packages` is offered explicitly instead of silently doing it.
- Nothing is installed without a yes: a non-interactive run (piped stdin, CI)
  reports what is missing and what to run, and declining keeps the machine
  untouched.
- Import checks only: no network, no subprocess until the user agrees.
"""

from __future__ import annotations

import importlib
import importlib.util
import os
import platform
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

import log_utils
from colors import C, err, info, key_value, ok, prompt, section, warn

# ── what each package is for and where it comes from ────────────────

@dataclass(frozen=True)
class Package:
    key: str                      # import name
    pip: str                      # pip name
    why: str                      # one line, shown to the user
    features: tuple[str, ...]     # features that want it
    system: dict[str, str] = field(default_factory=dict)   # apt/pacman/dnf/brew
    platform_only: str = ""       # "" = all, else platform.system() value


PACKAGES: tuple[Package, ...] = (
    Package("yaml", "pyyaml", "offset profiles and every YAML config",
            ("profiles", "build", "fetch", "migrate", "security", "tests"),
            {"apt": "python3-yaml", "pacman": "python-yaml", "dnf": "python3-pyyaml",
             "brew": "libyaml"}),
    Package("usb", "pyusb", "board and device detection, PWN DFU, flashing",
            ("usb",),
            {"apt": "python3-usb", "pacman": "python-pyusb", "dnf": "python3-pyusb"}),
    Package("libusb_package", "libusb-package", "supplies the libusb DLL on Windows",
            ("usb",), platform_only="Windows"),
    Package("pyimg4", "pyimg4", "reads/writes IMG4 + lzfse firmware components",
            ("build", "fetch"),
            {}),
    Package("capstone", "capstone", "AArch64 disassembly for offset migration",
            ("migrate",), {"apt": "python3-capstone", "pacman": "python-capstone",
                           "dnf": "python3-capstone", "brew": "capstone"}),
    Package("pytest", "pytest", "running the test suite",
            ("tests",), {"apt": "python3-pytest", "pacman": "python-pytest",
                         "dnf": "python3-pytest", "brew": "pytest"}),
)

FEATURES: dict[str, str] = {
    "profiles": "offset profile handling (validate, list, edit)",
    "usb": "USB: board + device detection, PWN DFU, flash, boot",
    "build": "CFW build: patch and rewrap firmware components",
    "fetch": "fetching components out of an IPSW",
    "migrate": "beta-to-beta offset migration",
    "security": "safety check / audits",
    "tests": "test suite",
}

# which features each CLI verb needs before it can work
COMMAND_FEATURES: dict[str, tuple[str, ...]] = {
    "menu": ("profiles",),
    "guided": ("usb", "profiles"),
    "setup": ("usb", "profiles"),
    "pwn": ("usb",),
    "health": ("usb",),
    "doctor": (),
    "deps": (),
    "offsets": ("profiles",),
    "coverage": ("profiles",),
    "gaps": ("profiles",),
    "audit": ("profiles",),
    "preflight": ("profiles", "build"),
    "verify": ("profiles", "build"),
    "build": ("profiles", "build"),
    "flash": ("usb", "profiles", "build"),
    "boot": ("usb",),
    "sshrd": ("usb",),
    "net": ("usb",),
    "vnc": ("usb",),
    "ssh": ("usb",),
    "postboot": ("usb",),
    "fetch": ("profiles", "fetch"),
    "migrate": ("profiles", "migrate"),
    "contribute": ("profiles",),
    "logs": (),
    "version": (),
    "explain": (),
}

LIBUSB_HINTS = {
    "Linux": "sudo apt install libusb-1.0-0   (or pacman -S libusb / dnf install libusb1)",
    "Darwin": "brew install libusb",
    "Windows": ("python -m pip install libusb-package, or bind the device with Zadig "
                "once (https://zadig.akeo.ie)"),
}


# ── OS / runtime detection ──────────────────────────────────────────

def package_manager() -> str:
    """Detected system package manager: apt/pacman/dnf/brew/zypper/pip-only."""
    if platform.system() == "Darwin":
        return "brew" if shutil.which("brew") else "pip-only"
    if platform.system() == "Windows":
        return "pip-only"
    for name, mgr in (("apt", "apt"), ("apt-get", "apt"), ("pacman", "pacman"),
                      ("dnf", "dnf"), ("zypper", "zypper")):
        if shutil.which(name):
            return mgr
    return "pip-only"


def externally_managed() -> bool:
    """True on PEP 668 distros where a plain `pip install` is refused."""
    for base in (Path(sys.prefix), Path(sys.base_prefix)):
        try:
            if list(base.glob("lib/python*/EXTERNALLY-MANAGED")):
                return True
        except OSError:
            continue
    return False


def in_venv() -> bool:
    return sys.prefix != getattr(sys, "base_prefix", sys.prefix)


def is_root() -> bool:
    """Root (POSIX) or an elevated shell (Windows, best effort)."""
    if platform.system() == "Windows":
        try:
            import ctypes
            shell32 = getattr(ctypes, "windll", None)
            return bool(shell32.shell32.IsUserAnAdmin()) if shell32 else False
        except Exception:                                      # noqa: BLE001
            return False
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False



def is_interactive() -> bool:
    """A terminal we can ask a question on."""
    try:
        return sys.stdin.isatty() and sys.stdout.isatty()
    except (AttributeError, ValueError):
        return False


def platform_info() -> dict:
    """Everything the user needs to know about where they are running."""
    return {
        "os": platform.system(),
        "release": platform.release(),
        "arch": platform.machine(),
        "distro": _distro_name() if platform.system() == "Linux" else "",
        "python": platform.python_version(),
        "python_path": sys.executable,
        "venv": in_venv(),
        "root": is_root(),
        "package_manager": package_manager(),
        "externally_managed": externally_managed(),
        "interactive": is_interactive(),
    }


def _distro_name() -> str:
    try:
        text = Path("/etc/os-release").read_text(encoding="utf-8", errors="replace")
        for line in text.splitlines():
            if line.startswith("PRETTY_NAME="):
                return line.split("=", 1)[1].strip().strip('"')
    except OSError:
        pass
    return ""


def pip_available() -> bool:
    return importlib.util.find_spec("pip") is not None


def uv_available() -> bool:
    return shutil.which("uv") is not None


def installer() -> list[str] | None:
    """How to install a Python package here: pip, else uv, else None.

    uv venvs are created without pip on purpose, so `-m pip` is not always
    there; and on PEP 668 systems pip refuses unless told not to worry.
    """
    if pip_available():
        return [sys.executable, "-m", "pip", "install"]
    if uv_available():
        return ["uv", "pip", "install", "--python", sys.executable]
    return None


# ── package checks ──────────────────────────────────────────────────

def is_installed(pkg: Package) -> bool:
    if pkg.platform_only and platform.system() != pkg.platform_only:
        return True                                  # not applicable here
    try:
        return importlib.util.find_spec(pkg.key) is not None
    except (ImportError, ValueError):
        return False


def libusb_ok() -> bool:
    """Whether pyusb can actually reach libusb, not just whether a file exists."""
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

    system = platform.system()
    if system == "Windows":
        return any(Path(path).exists() for path in _windows_libusb_paths())
    if shutil.which("ldconfig") is None:
        return not system == "Linux"
    try:
        out = subprocess.run(["ldconfig", "-p"], capture_output=True, text=True,
                             timeout=10).stdout
        return any(soname in out for soname in ("libusb-1.0.so.0", "libusb-1.0.so"))
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


def unknown_features(features: tuple[str, ...] | list[str] | str) -> list[str]:
    """Feature names that do not exist: a typo must not silently check nothing."""
    wanted = (features,) if isinstance(features, str) else tuple(features)
    return [name for name in wanted if name not in FEATURES]


def packages_for(features: tuple[str, ...] | list[str] | str) -> list[Package]:
    """The packages a set of features wants, deduplicated and ordered."""
    wanted = (features,) if isinstance(features, str) else tuple(features)
    out: list[Package] = []
    for pkg in PACKAGES:
        if any(feature in pkg.features for feature in wanted) and pkg not in out:
            out.append(pkg)
    return out


def missing_for(features: tuple[str, ...] | list[str] | str) -> list[Package]:
    return [pkg for pkg in packages_for(features) if not is_installed(pkg)]


def missing_summary(features: tuple[str, ...] | list[str] | str) -> list[str]:
    """Short strings for a banner, e.g. ['pyimg4 (build, fetch)']."""
    return [f"{pkg.pip} ({', '.join(pkg.features)})" for pkg in missing_for(features)]


# ── reporting ───────────────────────────────────────────────────────

def status(features: tuple[str, ...] | list[str] | str = ()) -> dict:
    """Machine-readable status for the doctor / --json output."""
    info_row = platform_info()
    packages = packages_for(features) if features else list(PACKAGES)
    return {
        "platform": info_row,
        "features": list(features) if not isinstance(features, str) else [features],
        "packages": [{"key": pkg.key, "pip": pkg.pip, "why": pkg.why,
                      "features": list(pkg.features), "installed": is_installed(pkg),
                      "platform_only": pkg.platform_only}
                     for pkg in packages],
        "libusb": libusb_ok(),
        "pip_available": pip_available(),
        "missing": [pkg.pip for pkg in missing_for(features)] if features else
                   [pkg.pip for pkg in PACKAGES if not is_installed(pkg)],
    }


def print_status(features: tuple[str, ...] | list[str] = (), *, title: str = "Dependencies") -> dict:
    """Human view: where we are running, then each package."""
    data = status(features)
    plat = data["platform"]

    print(section(title))
    print()
    where = f"{plat['os']} {plat['release']} ({plat['arch']})"
    if plat["distro"]:
        where = f"{plat['distro']} - {where}"
    print(key_value("system", where))
    print(key_value("python", f"{plat['python']} {'(venv)' if plat['venv'] else '(system)'}"))
    pep668 = plat["externally_managed"] and not plat["venv"]
    print(key_value("installer", plat["package_manager"] +
                    ("  (PEP 668: pip needs --break-system-packages)" if pep668 else "")))
    if not data["pip_available"]:
        tool = "uv pip (no pip in this python)" if uv_available() else f"{C.RED}no pip, no uv{C.NC}"
    else:
        tool = "pip"
    print(key_value("installer tool", tool))
    if not uv_available() and not data["pip_available"]:
        print(f"  {C.DIM}fix: python3 -m ensurepip --upgrade, or use a venv{C.NC}")
    print(key_value("terminal", "interactive" if plat["interactive"] else
                    "not interactive (no prompts)"))
    print()

    for pkg in data["packages"]:
        if pkg["platform_only"] and plat["os"] != pkg["platform_only"]:
            print(key_value(f"py {pkg['pip']}", f"{C.DIM}n/a on {plat['os']}{C.NC}"))
            continue
        if pkg["installed"]:
            print(key_value(f"py {pkg['pip']}", f"{C.GRN}installed{C.NC}"))
        else:
            print(key_value(f"py {pkg['pip']}",
                            f"{C.RED}missing{C.NC}  {C.DIM}{pkg['why']}{C.NC}"))

    if any("usb" in pkg["features"] for pkg in data["packages"]):
        state = f"{C.GRN}found{C.NC}" if data["libusb"] else f"{C.RED}missing{C.NC}"
        print(key_value("libusb-1.0", state))

    try:
        import img4wrap
        ready, note = img4wrap.decoder_available()
        print(key_value("IMG4 codec", f"{C.GRN}{note}{C.NC}" if ready
                        else f"{C.AMB}{note}{C.NC}"))
    except Exception:                                          # noqa: BLE001
        pass

    tools_dir = Path(__file__).parent / "tools"
    n_tools = len(list(tools_dir.glob("*"))) if tools_dir.exists() else 0
    usable = ("usable here" if plat["os"] == "Darwin"
              else f"macOS-only, ignored on {plat['os']}")
    print(key_value("tools/", f"{C.GRN}{n_tools} binaries{C.NC} {C.DIM}({usable}){C.NC}"
                    if n_tools else f"{C.RED}empty{C.NC}"))

    print()
    if data["missing"]:
        print(warn(f"missing: {', '.join(data['missing'])}"))
        print(f"  {C.DIM}install with: python3 ul8.py deps    "
              f"(or python3 deps.py --install){C.NC}")
    else:
        print(ok("all dependencies for this selection are installed"))
    print()
    return data


# ── installation ────────────────────────────────────────────────────

def install_command(pkgs: list[Package], *, system: bool = False) -> list[str]:
    """The command that installs these packages on this machine."""
    mgr = package_manager()
    if system and mgr != "pip-only":
        names = [pkg.system[mgr] for pkg in pkgs if mgr in pkg.system]
        if names:
            if mgr == "apt":
                return ["sudo", "apt", "install", "-y", *names]
            if mgr == "pacman":
                return ["sudo", "pacman", "-S", "--noconfirm", *names]
            if mgr == "dnf":
                return ["sudo", "dnf", "install", "-y", *names]
            if mgr == "zypper":
                return ["sudo", "zypper", "--non-interactive", "install", *names]
            if mgr == "brew":
                return ["brew", "install", *names]

    launcher = installer()
    if launcher is None:
        return ["python3", "-m", "ensurepip", "--upgrade"]
    cmd = list(launcher)
    if launcher[0] == sys.executable:            # pip accepts --user, uv does not
        if not in_venv() and platform.system() != "Windows":
            cmd.append("--user")
    if externally_managed() and not in_venv():
        cmd.append("--break-system-packages")
    cmd += [pkg.pip for pkg in pkgs]
    return cmd


def _run(cmd: list[str]) -> int:
    print(f"  {C.DIM}$ {' '.join(cmd)}{C.NC}")
    log_utils.log_info(f"install: {' '.join(cmd)}", module="deps")
    try:
        return subprocess.run(cmd).returncode
    except FileNotFoundError:
        print(err(f"command not found: {cmd[0]}"))
        return 127
    except KeyboardInterrupt:
        print()
        return 130


def ensure(features: tuple[str, ...] | list[str] | str,
           *, interactive: bool | None = None, yes: bool = False,
           quiet: bool = False, install_system: bool = True) -> bool:
    """Check (and offer to install) what `features` needs. Returns True when ready.

    Never installs without a yes: a non-interactive run only reports. Declining
    is not fatal - the caller continues and the operation itself fails with a
    precise message if it truly cannot proceed.
    """
    wanted = (features,) if isinstance(features, str) else tuple(features)
    if os.environ.get("UL8_NO_DEPS") in ("1", "true", "yes") or not wanted:
        return True

    unknown = unknown_features(wanted)
    if unknown:
        log_utils.log_warn(f"unknown feature(s) ignored: {', '.join(unknown)} "
                           f"(known: {', '.join(FEATURES)})", module="deps")
        wanted = tuple(name for name in wanted if name not in unknown)

    missing = missing_for(wanted)
    libusb_missing = "usb" in wanted and not libusb_ok()
    if not missing and not libusb_missing:
        log_utils.log_debug(f"dependencies ok for {', '.join(wanted)}", module="deps")
        return True

    if not quiet:
        names = ", ".join(pkg.pip for pkg in missing) or "-"
        print(info(f"missing for {', '.join(wanted)}: {C.B}{names}{C.NC}"))
        for pkg in missing:
            print(f"    {C.DIM}{pkg.pip}: {pkg.why}{C.NC}")
        if libusb_missing:
            print(f"    {C.DIM}libusb-1.0: {LIBUSB_HINTS.get(platform.system(), '')}{C.NC}")

    if interactive is None:
        interactive = is_interactive()
    if yes or os.environ.get("UL8_AUTO_INSTALL") in ("1", "true", "yes"):
        interactive, answer = False, "y"
    elif not interactive:
        answer = "n"
        if not quiet:
            print(f"  {C.DIM}not a terminal: not installing anything. Run "
                  f"`python3 ul8.py deps` yourself.{C.NC}")
    else:
        answer = log_utils.safe_input(
            prompt(f"install {len(missing)} package(s) now? [Y/n]: ") or "n",
            eof_default="n").strip().lower()

    if answer in ("y", "yes", "") and (missing or libusb_missing):
        if missing and installer() is None:
            print(warn("no pip and no uv in this python - cannot install for you"))
            print(f"  {C.DIM}fix: python3 -m ensurepip --upgrade   "
                  f"(or use a venv: python3 -m venv .venv){C.NC}")
            log_utils.log_error("no installer available (pip/uv both missing)", module="deps")
            return False
        if missing:
            cmd = install_command(missing)
            if _run(cmd) != 0:
                print(warn("pip could not install everything"))
                print(f"  {C.DIM}If pip refused because of PEP 668, retry with: "
                      f"{' '.join(install_command(missing))} --break-system-packages{C.NC}")
        if libusb_missing and install_system and not missing:
            # pyusb is there but the backend is not: a system package or a
            # Windows DLL is the only remaining fix
            mgr = package_manager()
            hint = LIBUSB_HINTS.get(platform.system(), "")
            if platform.system() == "Windows":
                _run(install_command([Package("libusb_package", "libusb-package",
                                              "libusb DLL", ("usb",))]))
            elif mgr != "pip-only":
                _run(install_command([Package("libusb", "libusb", "backend", ("usb",),
                                              {"apt": "libusb-1.0-0", "pacman": "libusb",
                                               "dnf": "libusb1", "zypper": "libusb-1_0-0",
                                               "brew": "libusb"})], system=True))
            if hint:
                print(info(f"if it still fails: {hint}"))

        still_missing = [pkg.pip for pkg in missing_for(wanted)]
        if "usb" in wanted and not libusb_ok():
            still_missing.append("libusb-1.0 backend")
        log_utils.log("INFO" if not still_missing else "WARN",
                      f"dependency check after install ({', '.join(wanted)}): "
                      f"{'ready' if not still_missing else 'still missing ' + ', '.join(still_missing)}",
                      module="deps")
        if still_missing and not quiet:
            print(warn(f"still missing: {', '.join(still_missing)}"))
            for hint in _extra_hints(still_missing):
                print(f"    {C.DIM}{hint}{C.NC}")
        return not still_missing

    if missing and not quiet:
        print(warn("continuing without them - the affected step will say what it needs"))
    log_utils.log_warn(f"dependencies missing and not installed ({', '.join(wanted)}): "
                       f"{', '.join(pkg.pip for pkg in missing)}", module="deps")
    return not missing


def _extra_hints(still_missing: list[str]) -> list[str]:
    hints = []
    if any("libusb" in name for name in still_missing):
        hints.append(f"libusb: {LIBUSB_HINTS.get(platform.system(), '')}")
        if platform.system() == "Linux":
            hints.append("after installing libusb, `sudo ldconfig` may be needed")
    if "pyimg4" in still_missing:
        hints.append("pyimg4 needs a C extension: `python3 -m pip install pyimg4` with a "
                     "current pip works on 3.9-3.13")
    return hints


def ensure_for_command(command: str, **kwargs) -> bool:
    """Dependency gate for a CLI verb (see COMMAND_FEATURES)."""
    features = COMMAND_FEATURES.get(command)
    if features is None:
        features = ("profiles",)                    # unknown verb: the basics
    return ensure(features, **kwargs)


# ── CLI: `python3 deps.py [--json|--install|--check]` ───────────────

def doctor(argv: list[str] | None = None) -> int:
    import argparse
    import json

    ap = argparse.ArgumentParser(prog="deps",
                                 description="check (and optionally install) dependencies")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--install", action="store_true",
                    help="install what is missing (default when a terminal is attached)")
    ap.add_argument("--check", action="store_true", help="only report, never install")
    ap.add_argument("--yes", action="store_true", help="install without asking")
    ap.add_argument("--feature", action="append", default=[],
                    help=f"limit to a feature ({', '.join(FEATURES)})")
    args = ap.parse_args(argv if argv is not None else sys.argv[1:])

    features = tuple(args.feature) if args.feature else ()

    unknown = unknown_features(features)
    if unknown:
        print(err(f"unknown feature(s): {', '.join(unknown)}"))
        print(f"  {C.DIM}known features: {', '.join(FEATURES)}{C.NC}")
        return 2

    if args.json:
        print(json.dumps(status(features), indent=2))
        return 0 if not status(features)["missing"] else 1

    print_status(features)

    wanted = features or tuple(FEATURES)
    data = status(wanted)
    if not data["missing"] and not ("usb" in wanted and not data["libusb"]):
        return 0

    # A terminal gets asked; a pipe or --check only gets told what to run.
    if args.check or not is_interactive():
        if not args.check:
            print(f"  {C.DIM}not a terminal: not installing anything "
                  f"(run `python3 deps.py --install --yes` to do it unattended){C.NC}")
        return 1
    ready = ensure(wanted, interactive=True, yes=args.yes)
    return 0 if ready else 1


# ── compatibility API (used by the health check and the menu) ───────

def check_dependencies() -> dict:
    """Legacy shape: {python_packages, libusb, pkg_<name>, opt_<name>}."""
    results: dict[str, bool] = {"libusb": libusb_ok(), "python_packages": True}
    for pkg in PACKAGES:
        installed = is_installed(pkg)
        key = f"opt_{pkg.key}" if pkg.key in ("pyimg4", "capstone", "pytest", "libusb_package") \
            else f"pkg_{pkg.pip}"
        results[key] = installed
        if key.startswith("pkg_") and not installed:
            results["python_packages"] = False
    return results



def install_dependencies() -> bool:
    """Menu action: check everything and offer to install what is missing."""
    features = ("usb", "profiles", "build", "fetch", "migrate")
    print_status(features, title="Install Dependencies")
    if not missing_for(features) and libusb_ok():
        print(ok("everything needed is already installed"))
        return True
    ready = ensure(features, interactive=True)
    if ready:
        print(ok("dependencies ready"))
    else:
        print(warn("some dependencies are still missing (see above)"))
    return ready


if __name__ == "__main__":
    log_utils.install()
    sys.exit(log_utils.guard(doctor))
