"""Hardware setup guide for usbliter8-arctic.

Guided Setup: wiring diagrams, RP2350 board selection, firmware download/flash,
status/health checks, and pre-flash verification.
"""

import sys
import socket
import time
from pathlib import Path
from urllib.request import urlretrieve, URLError

import yaml

from colors import C, ok, err, warn, info, section, key_value, header, divider, prompt
from log_utils import log_info, log_warn, log_error, log_step

TOOLS_DIR = Path(__file__).parent / "tools"
FW_DIR = Path(__file__).parent / "firmware"
CONFIG_PATH = Path(__file__).parent / "config.yaml"

FW_REPO = "https://raw.githubusercontent.com/Octopus1633/usbliter8-firmware/main"
UF2_FILES = {
    "pico2":                 "usbliter8.pico2.uf2",
    "waveshare_usb_a":       "usbliter8.waveshare_rp2350_usb_a.uf2",
    "waveshare_usb_c":       "usbliter8.waveshare_rp2350_usb_c.uf2",
    "waveshare_usb_cm":      "usbliter8.waveshare_rp2350_usb_cm.uf2",
    "waveshare_zero":        "usbliter8.waveshare_rp2350_zero.uf2",
    "waveshare_pizero":      "usbliter8.waveshare_rp2350_pizero.uf2",
    "pimoroni_tiny2350":      "usbliter8.pimoroni_tiny2350.uf2",
}


BOARDS = [
    {
        "id": "waveshare_usb_a",
        "name": "Waveshare RP2350-USB-A",
        "soldering": False,
        "icon": "★",
        "pins": {
            "D+": "Built-in USB-A host port (plug Lightning cable directly)",
            "D-": "Built-in USB-A host port",
            "VBUS": "USB-A provides 5V power",
            "GND": "GND via USB-A shield",
        },
        "note": "RECOMMENDED. No soldering — just plug your Lightning-to-USB-A cable into the board directly.",
    },
    {
        "id": "pico2",
        "name": "Raspberry Pi Pico 2",
        "soldering": True,
        "icon": " ",
        "pins": {"D+": "GP12", "D-": "GP13", "VBUS": "VBUS (NOT 3V3!)", "GND": "GND"},
        "note": "Most common. Requires cutting a Lightning-to-USB-A cable and soldering to GPIO pins.",
    },
    {
        "id": "waveshare_zero",
        "name": "Waveshare RP2350-Zero",
        "soldering": True,
        "icon": " ",
        "pins": {"D+": "GP12", "D-": "GP13", "VBUS": "VBUS", "GND": "GND"},
        "note": "Ultra-compact. Good for permanent rigs.",
    },
    {
        "id": "pimoroni_tiny2350",
        "name": "Pimoroni Tiny2350",
        "soldering": True,
        "icon": " ",
        "pins": {"D+": "GP12", "D-": "GP13", "VBUS": "VBUS", "GND": "GND"},
        "note": "Tiny footprint. Tested and working.",
    },
]


def _load_config() -> dict:
    if CONFIG_PATH.exists():
        with open(CONFIG_PATH) as f:
            return yaml.safe_load(f) or {}
    return {}


def _save_config(cfg: dict):
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_PATH, "w") as f:
        yaml.dump(cfg, f, default_flow_style=False)


def check_firmware(board_id: str) -> bool:
    """Check if firmware UF2 exists and is valid for the given board."""
    fname = UF2_FILES.get(board_id)
    if not fname:
        return False
    return validate_uf2(FW_DIR / fname)


UF2_MAGICS = {0x0A324655, 0x9E5D5157, 0x0AB16F30}


def validate_uf2(path: Path) -> bool:
    """Verify a UF2 file has a valid magic header (not a 404 HTML page)."""
    if not path.exists():
        return False
    try:
        if path.stat().st_size < 512:
            return False
        with open(path, "rb") as f:
            block = f.read(512)
        return len(block) >= 4 and int.from_bytes(block[:4], "little") in UF2_MAGICS
    except OSError:
        return False


def _download_once(url: str, dst: Path) -> tuple[bool, str]:
    """Single download attempt. Returns (success, error_message)."""
    try:
        urlretrieve(url, dst)
        size = dst.stat().st_size
        if size <= 1024 or not validate_uf2(dst):
            dst.unlink(missing_ok=True)
            return False, f"bad file ({size} bytes, invalid UF2 magic)"
        return True, ""
    except URLError as e:
        return False, f"network error — {e.reason}"
    except socket.timeout:
        return False, "timed out after 30s"
    except Exception as e:
        return False, str(e)


def download_firmware(board_id: str, retries: int = 3) -> bool:
    """Download RP2350 firmware UF2 from community repo, with retries and validation."""
    fname = UF2_FILES.get(board_id)
    if not fname:
        print(err(f"Unknown board ID: {board_id}"))
        log_error(f"Unknown board ID for firmware: {board_id}")
        return False

    url = f"{FW_REPO}/{fname}"
    dst = FW_DIR / fname
    tmp = FW_DIR / f"{fname}.part"
    FW_DIR.mkdir(parents=True, exist_ok=True)

    print(info(f"Downloading {fname}..."))
    print(f"    {C.DIM}{url}{C.NC}")
    log_step(f"Downloading UF2: {url}")

    socket.setdefaulttimeout(30)
    try:
        for attempt in range(1, retries + 1):
            if attempt > 1:
                delay = 1.5 * (attempt - 1)
                print(info(f"Retry {attempt}/{retries} in {delay:.1f}s..."))
                time.sleep(delay)

            success, msg = _download_once(url, tmp)
            if success:
                tmp.replace(dst)
                size = dst.stat().st_size
                print(ok(f"Downloaded + verified {fname} ({size:,} bytes)"))
                log_info(f"Firmware downloaded: {fname} ({size} bytes)")
                return True

            tmp.unlink(missing_ok=True)
            print(warn(f"Attempt {attempt}/{retries} failed: {msg}"))
            log_warn(f"UF2 download attempt {attempt}/{retries} failed: {msg}")

        print(err(f"All {retries} download attempts failed — check your internet connection"))
        log_error(f"UF2 download failed after {retries} attempts: {url}")
        return False
    finally:
        socket.setdefaulttimeout(None)


def show_wiring(board: dict):
    """Display wiring diagram in ASCII art."""
    print(section(f"Wiring — {board['name']}"))
    print()

    pins = board.get("pins", {})

    if board.get("soldering", True):
        print(f"  {C.AMB}${C.NC} Cut a Lightning-to-USB-A cable. Verify wires with a multimeter!")
        print(f"  {C.AMB}${C.NC} Colors may vary — always test continuity before soldering.")
        print()
        print(f"  {C.SNOW}Lightning Cable  ──────→  {board['name']}{C.NC}")
        print()
        for signal, gpio in pins.items():
            color = {"D+": C.GRN, "D-": C.FROST, "VBUS": C.AMB, "GND": C.DIM}.get(signal, C.NC)
            print(f"    {color}{signal:<6}{C.NC} → {C.EYE}{gpio}{C.NC}")
        print()
        print(f"  {C.DIM}Tip: Use heat-shrink tubing on each solder joint for durability.{C.NC}")
    else:
        print(f"  {C.GRN}No soldering needed!{C.NC} Just plug your Lightning cable into the USB-A port.")
        print()


def show_led_guide(board: dict):
    """Display LED indicator meanings."""
    print(section("LED Indicators"))
    print()
    print(f"  {C.SNOW}RGB LED boards:{C.NC}")
    print(f"    {C.AMB}Blinking orange{C.NC}  → booting (~2s)")
    print(f"    {C.AMB}Steady orange{C.NC}    → idle, ready")
    print(f"    {C.EYE}Blue{C.NC}              → exploit in progress")
    print(f"    {C.GRN}Green{C.NC}             → exploit SUCCEEDED (device is now PWND)")
    print(f"    {C.RED}Red{C.NC}               → exploit FAILED (reset board, try again)")
    print()
    print(f"  {C.SNOW}Single-color LED boards:{C.NC}")
    print(f"    {C.DIM}Slow blink (200ms){C.NC} → booting")
    print(f"    {C.DIM}Breathing{C.NC}          → idle, ready")
    print(f"    {C.EYE}Rapid blink (100ms){C.NC} → exploit in progress")
    print(f"    {C.GRN}Steady ON{C.NC}          → exploit SUCCEEDED")
    print(f"    {C.RED}OFF{C.NC}                → exploit FAILED")


def show_troubleshooting():
    """Common issues and fixes."""
    print(section("Troubleshooting"))
    print()
    issues = [
        ("LED turns off after exploit", "Reboot RP2350 (reset button or power cycle), re-enter DFU on iPhone, try again."),
        ("DFU but no PWND:[...] serial", "Check D+/D- aren't swapped. Check cable is USB-A (not USB-C). Verify UF2 matches your board."),
        ("RP2350 not detected by PC", "Hold BOOTSEL while plugging in, drag UF2 to RPI-RP2 drive. After flash, unplug and reconnect."),
        ("Device in DFU mode?", "Volume Down + Power for 3s, then release Power while holding Volume Down for 10s. Screen should be black."),
        ("Exploit works but fails intermittently", "RP2350 timing is tight. Try a shorter Lightning cable (<30cm). Remove USB hubs."),
        ("A13 device (iPhone 11/SE2) fails", "RP2040 does NOT work with A13. You MUST use an RP2350 board."),
    ]
    for problem, solution in issues:
        print(f"  {C.AMB}?{C.NC} {C.SNOW}{problem}{C.NC}")
        print(f"    {C.DIM}→ {solution}{C.NC}")
        print()


class QuitSetup(Exception):
    """Raised when the user asks to exit the guided setup."""


def _ask(prompt_text: str, default: str = "", valid: tuple = None, retries: int = 3) -> str:
    """Input with validation and retries. 'quit' or Ctrl-C exits the setup."""
    for attempt in range(retries):
        try:
            ans = input(prompt(prompt_text) or default).strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            raise QuitSetup
        if ans in ("quit", "q"):
            print()
            raise QuitSetup
        if valid is None or ans in valid or ans == default:
            return ans
        print(warn(f"Invalid choice '{ans}' — try again ({retries - attempt - 1} left)"))
    return default


def _confirm(prompt_text: str, default: str = "y") -> bool:
    return _ask(prompt_text, default, valid=("y", "n", "yes", "no", "")) in ("y", "yes", "")


def _pick_board() -> dict:
    """Board selection with retry loop. Returns a BOARDS entry."""
    print(section("Step 1 — Select Your Board"))
    print()
    for i, b in enumerate(BOARDS):
        icon = "★" if not b["soldering"] else " "
        soldering_note = f"  {C.GRN}{icon} no soldering{C.NC}" if not b["soldering"] else f"  {C.AMB}{icon} requires soldering{C.NC}"
        print(f"  {C.EYE}[{i + 1}]{C.NC} {C.SNOW}{b['name']}{C.NC}  {soldering_note}")
        print(f"     {C.DIM}{b['note']}{C.NC}")
        print()
    print(f"  {C.EYE}[m]{C.NC} More info on all supported boards")
    print()

    while True:
        choice = _ask("Choose board [1]: ", "1")
        if choice == "m":
            print(section("All Supported Boards"))
            for b in BOARDS:
                print(f"  {C.EYE}{b['name']}{C.NC}")
                print(f"    {C.DIM}{b['note']}{C.NC}")
                print()
            continue
        try:
            idx = int(choice) - 1
        except ValueError:
            print(warn("Please enter a number between 1 and %d" % len(BOARDS)))
            continue
        if 0 <= idx < len(BOARDS):
            return BOARDS[idx]
        print(warn(f"Board {idx + 1} does not exist — pick 1-{len(BOARDS)}"))


def _wait_rp2350(attempts: int = 3, timeout: float = 15.0) -> bool:
    """Poll for RP2350 USB device; let the user retry between attempts."""
    from pwn_utils import detect_rp2350
    for attempt in range(1, attempts + 1):
        print(info(f"Scanning for RP2350 (attempt {attempt}/{attempts}, {timeout:.0f}s)..."))
        log_step(f"RP2350 scan attempt {attempt}/{attempts}")
        start = time.time()
        found = None
        while time.time() - start < timeout:
            found = detect_rp2350()
            if found:
                break
            time.sleep(0.5)
        if found:
            print(ok(f"RP2350 detected: bus {found['bus']}, addr {found['address']}, serial={found.get('serial', '?')[:40]}"))
            log_info(f"RP2350 detected: bus={found['bus']} addr={found['address']}")
            return True
        print(warn("No RP2350 board detected — check USB cable and power"))
        if attempt < attempts:
            ans = _ask("Reconnect the board and press Enter to retry, [s]kip: ", "r", valid=("", "r", "s", "skip"))
            if ans in ("s", "skip"):
                break
    return False


def _test_pwn(attempts: int = 3, timeout: int = 60) -> bool:
    """Live PWN test with retries and troubleshooting hints."""
    from pwn_utils import wait_for_pwn
    for attempt in range(1, attempts + 1):
        print(info(f"PWN test attempt {attempt}/{attempts} — plug iPhone into RP2350 and enter DFU"))
        if wait_for_pwn(timeout=timeout):
            return True
        if attempt < attempts:
            print(warn("PWN not detected. Common fixes:"))
            print(f"    {C.DIM}→ Hold Volume Down + Power for 3s, release Power, keep Volume Down 10s{C.NC}")
            print(f"    {C.DIM}→ Check LED: orange=idle, blue=exploiting, green=success, red=failed (reset board){C.NC}")
            print(f"    {C.DIM}→ Use a short cable (<30cm), remove USB hubs{C.NC}")
            ans = _ask("Press Enter to retry, [s]kip: ", "r", valid=("", "r", "s", "skip"))
            if ans in ("s", "skip"):
                break
    return False


def guided_setup():
    """Guided, beginner-friendly setup walkthrough with checks and retries."""
    try:
        _guided_setup_impl()
    except QuitSetup:
        print(info("Setup cancelled — returning to menu"))
    except KeyboardInterrupt:
        print()
        print(info("Setup cancelled (Ctrl+C) — returning to menu"))
    finally:
        print()


def _guided_setup_impl():
    print(header("Guided Setup — usbliter8-arctic"))
    print()
    print(f"  {C.AMB}★ Recommended for beginners{C.NC} — hardware, firmware and first PWN, step by step")
    print(f"  {C.DIM}Resumable: re-run anytime. Progress is saved to config.yaml{C.NC}")
    print(f"  {C.DIM}Type 'quit' at any prompt to exit safely.{C.NC}")
    print()

    # Step 0 — dependencies
    print(section("Step 0 — Dependencies"))
    print()
    from deps import check_dependencies, install_dependencies
    results = check_dependencies()
    for mod, pkg in (("usb", "pyusb"), ("yaml", "pyyaml")):
        key = f"pkg_{pkg}"
        print(key_value(f"py {pkg}", f"{C.GRN}installed{C.NC}" if results[key] else f"{C.RED}missing{C.NC}"))
    print(key_value("libusb-1.0", f"{C.GRN}found{C.NC}" if results["libusb"] else f"{C.RED}missing{C.NC}"))
    if not all(results.values()):
        print()
        if _confirm("Some dependencies are missing. Install them now? [Y/n]: ", "y"):
            install_dependencies()
        else:
            print(warn("Continuing without dependencies — USB detection will not work"))
    print()

    # Step 1 — board selection
    board = _pick_board()
    print()
    print(ok(f"Selected: {board['name']}"))
    _save_config({"selected_board": board["id"]})
    log_info(f"Guided setup: board selected {board['id']}")
    print()

    # Step 2 — wiring
    print(section("Step 2 — Wiring"))
    print()
    show_wiring(board)

    # Step 3 — firmware
    print(section("Step 3 — Firmware"))
    print()
    board_id = board["id"]
    fname = UF2_FILES[board_id]
    fw_path = FW_DIR / fname

    if check_firmware(board_id):
        print(ok(f"Firmware ready: {fname} ({fw_path.stat().st_size:,} bytes, verified)"))
    else:
        if fw_path.exists():
            print(warn(f"Existing {fname} is corrupt/incomplete — will re-download"))
        print(info(f"No valid firmware for {board['name']}"))
        if _confirm("Download firmware from Octopus1633/usbliter8-firmware? [Y/n]: ", "y"):
            if download_firmware(board_id, retries=3):
                print()
                print(f"  {C.SNOW}To flash:{C.NC}")
                print(f"    1. Hold {C.EYE}BOOTSEL{C.NC} button on {board['name']}")
                print(f"    2. Plug USB into your computer (RPI-RP2 drive should appear)")
                print(f"    3. Drag {C.FROST}{fname}{C.NC} onto the RPI-RP2 drive")
                print(f"    4. Board will reboot — LED should start blinking")
                print()
            else:
                print(err("Firmware download failed — fix your network and re-run Guided Setup"))
        else:
            print(info("Skipping firmware download. Re-run Guided Setup anytime."))
    print()

    # Step 4 — connection & PWN test
    print(section("Step 4 — Connect & Verify"))
    print()
    from pwn_utils import check_pyusb_installed
    if check_pyusb_installed():
        if _confirm("Board plugged in? Check USB detection now? [Y/n]: ", "y"):
            _wait_rp2350(attempts=3)
        print()
        if _confirm("Test the exploit now (PWN DFU)? [Y/n]: ", "y"):
            _test_pwn(attempts=3)
    else:
        print(warn("pyusb not installed — USB verification skipped (install via Step 0)"))
    print()

    # Step 5 — final checklist
    print(section("Step 5 — Ready to Exploit"))
    print()
    checklist = [
        f"Flash the UF2 firmware to your {board['name']}",
        "Connect Lightning cable to iPhone/iPad",
        "Put iPhone in DFU mode (Vol Down + Power → release Power)",
        "Connect RP2350 to your computer via USB",
        "Wait for LED: steady green (RGB) or steady ON (single-color)",
        "Run [8] Check PWN Status from the main menu to verify",
    ]
    for i, item in enumerate(checklist, 1):
        print(f"  {C.GRN}{i}.{C.NC} {item}")
    print()

    show_led_guide(board)
    print()
    show_troubleshooting()

    try:
        input(prompt("Press Enter to return to menu..."))
    except (EOFError, KeyboardInterrupt):
        print()


# Backward-compatible alias
interactive_hardware_setup = guided_setup


def run_health_check() -> dict[str, bool]:
    """Run comprehensive hardware readiness check."""
    print(header("Hardware Health Check"))
    print()

    results = {}

    # 1. Board config
    cfg = _load_config()
    board_id = cfg.get("selected_board", "unknown")
    board_name = {b["id"]: b["name"] for b in BOARDS}.get(board_id, board_id)
    print(key_value("Board", board_name))
    results["board_configured"] = board_id != "unknown"
    if not results["board_configured"]:
        print(warn("No board selected — run [1] Guided Setup first"))

    # 2. Firmware
    fw_ok = check_firmware(board_id)
    fw_name = UF2_FILES.get(board_id, "N/A")
    print(key_value("Firmware", f"{fw_name} {'(' + C.GRN + 'present' + C.NC + ')' if fw_ok else '(' + C.RED + 'missing' + C.NC + ')'}"))
    results["firmware_present"] = fw_ok

    # 3. Tools
    from log_utils import check_command
    required = ["usbliter8ctl"]
    tools = {t: (TOOLS_DIR / t).exists() or check_command(t) for t in required}
    for t, ok_val in tools.items():
        color = C.GRN if ok_val else C.RED
        print(key_value(f"Tool: {t}", f"{color}{'found' if ok_val else 'NOT FOUND'}{C.NC}"))
    results["tools_ready"] = all(tools.values())

    # 4. RP2350
    from pwn_utils import check_pyusb_installed, detect_rp2350
    pyusb_ok = check_pyusb_installed()
    print(key_value("pyusb", f"{C.GRN}installed{C.NC}" if pyusb_ok else f"{C.AMB}not installed{C.NC}"))
    results["pyusb_available"] = pyusb_ok

    if pyusb_ok:
        rp = detect_rp2350()
        if rp:
            print(ok(f"RP2350 connected: bus {rp['bus']}, addr {rp['address']}"))
            results["rp2350_detected"] = True
        else:
            print(warn("No RP2350 detected — connect board to USB"))
            results["rp2350_detected"] = False
    else:
        results["rp2350_detected"] = False

    # 5. Tools directory check
    tools_ok = TOOLS_DIR.exists() and list(TOOLS_DIR.glob("*"))
    print(key_value("Tool dir", f"{C.GRN}ready ({len(list(TOOLS_DIR.glob('*')))}){C.NC}" if tools_ok else f"{C.RED}empty/missing{C.NC}"))
    results["tool_dir_ready"] = tools_ok

    # Summary
    print()
    all_ok = all(results.values())
    if all_ok:
        print(ok("All checks passed — ready to exploit"))
    else:
        failed = [k for k, v in results.items() if not v]
        print(warn(f"{len(failed)} check(s) need attention: {', '.join(failed)}"))

    log_info(f"Health check: {'ALL OK' if all_ok else f'FAILURES: {failed}'}")
    return results


def verify_board_for_exploit() -> bool:
    """Pre-flash verification checklist. Returns True if ready."""
    print(header("Pre-Flash Verification"))
    print()

    checks = [
        ("Board configured", _load_config().get("selected_board") is not None),
        ("Firmware downloaded", any(
            check_firmware(bid) for bid in UF2_FILES
        )),
        ("usbliter8ctl available", (TOOLS_DIR / "usbliter8ctl").exists()),
        ("RP2350 tools present", TOOLS_DIR.exists() and list(TOOLS_DIR.glob("*"))),
    ]

    all_pass = True
    for name, result in checks:
        if result:
            print(ok(name))
        else:
            print(err(name))
            all_pass = False

    print()
    if all_pass:
        print(ok("Verification passed — ready to proceed"))
    else:
        print(err("Some checks failed — resolve before flashing"))

    return all_pass


if __name__ == "__main__":
    interactive_hardware_setup()
