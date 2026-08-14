"""Hardware setup guide for usbliter8-arctic.

Wiring diagrams, RP2350 board selection, firmware download/flash,
status/health checks, and pre-flash verification.
"""

import sys
import socket
from pathlib import Path
from urllib.request import urlretrieve, URLError

import yaml

from colors import C, ok, err, warn, info, section, key_value, header, divider, prompt
from log_utils import log_info, log_warn, log_error, log_step

TOOLS_DIR = Path(__file__).parent.parent.parent / ".w0lfsword" / "usbliter8" / "tools"
FW_DIR = Path(__file__).parent.parent.parent / ".w0lfsword" / "usbliter8" / "firmware"
CONFIG_PATH = Path(__file__).parent.parent.parent / ".w0lfsword" / "usbliter8" / "config.yaml"

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
    """Check if firmware UF2 exists for the given board."""
    fname = UF2_FILES.get(board_id)
    if not fname:
        return False
    return (FW_DIR / fname).exists()


def download_firmware(board_id: str) -> bool:
    """Download RP2350 firmware UF2 from community repo."""
    fname = UF2_FILES.get(board_id)
    if not fname:
        print(err(f"Unknown board ID: {board_id}"))
        log_error(f"Unknown board ID for firmware: {board_id}")
        return False

    url = f"{FW_REPO}/{fname}"
    dst = FW_DIR / fname
    FW_DIR.mkdir(parents=True, exist_ok=True)

    print(info(f"Downloading {fname}..."))
    print(f"    {C.DIM}{url}{C.NC}")
    log_step(f"Downloading UF2: {url}")

    socket.setdefaulttimeout(30)
    try:
        urlretrieve(url, dst)
        size = dst.stat().st_size
        if size > 1024:
            print(ok(f"Downloaded {fname} ({size:,} bytes)"))
            log_info(f"Firmware downloaded: {fname} ({size} bytes)")
            return True
        else:
            dst.unlink(missing_ok=True)
            print(err(f"Downloaded file too small ({size} bytes) — may be a 404 page"))
            log_error(f"Firmware download too small: {fname} ({size} bytes)")
            return False
    except URLError as e:
        print(err(f"Download failed: network error — {e.reason}"))
        log_error(f"UF2 download network error: {e}")
        return False
    except socket.timeout:
        print(err("Download timed out after 30s — check your internet connection"))
        log_error(f"UF2 download timeout: {url}")
        return False
    except Exception as e:
        print(err(f"Download failed: {e}"))
        log_error(f"UF2 download exception: {e}")
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


def interactive_hardware_setup():
    """Full interactive hardware setup walkthrough."""
    print(header("Hardware Setup — usbliter8-arctic"))
    print()
    print(f"  {C.SNOW}You need:{C.NC}")
    print(f"    1. An RP2350-based microcontroller board")
    print(f"    2. A Lightning-to-USB-A cable (NOT USB-C)")
    print(f"    3. {C.DIM}(if using non-USB-A board){C.NC} Soldering iron + multimeter")
    print()

    # Board selection
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

    choice = input(prompt("Choose board [1]: ") or "1").strip().lower()

    if choice == "m":
        print(section("All Supported Boards"))
        for b in BOARDS:
            print(f"  {C.EYE}{b['name']}{C.NC}")
            print(f"    {C.DIM}{b['note']}{C.NC}")
            print()
        choice = input(prompt(f"Choose board [1]: ") or "1").strip()

    try:
        idx = int(choice) - 1
        if idx < 0 or idx >= len(BOARDS):
            idx = 0
    except ValueError:
        idx = 0

    board = BOARDS[idx]
    print()
    print(ok(f"Selected: {board['name']}"))
    _save_config({"selected_board": board["id"]})

    # Wiring
    show_wiring(board)

    # Firmware
    print(section("Step 2 — Firmware"))
    print()

    board_id = board["id"]
    if check_firmware(board_id):
        fname = UF2_FILES[board_id]
        print(ok(f"Firmware already downloaded: {fname}"))
    else:
        print(info(f"No firmware found for {board['name']}"))
        ans = input(prompt("Download firmware from Octopus1633/usbliter8-firmware? [Y/n]: ") or "y")
        if ans.lower() in ("y", "yes", ""):
            if download_firmware(board_id):
                fname = UF2_FILES[board_id]
                print()
                print(f"  {C.SNOW}To flash:{C.NC}")
                print(f"    1. Hold {C.EYE}BOOTSEL{C.NC} button on {board['name']}")
                print(f"    2. Plug USB into your computer (RPI-RP2 drive should appear)")
                print(f"    3. Drag {C.FROST}{fname}{C.NC} onto the RPI-RP2 drive")
                print(f"    4. Board will reboot — LED should start blinking")
                print()
        else:
            print(info("Skipping firmware download. You can download later from the main menu."))

    # LED guide
    show_led_guide(board)

    # Final checklist
    print(section("Step 3 — Ready to Exploit"))
    print()
    print(f"  {C.GRN}1.{C.NC} Flash the UF2 firmware to your {board['name']}")
    print(f"  {C.GRN}2.{C.NC} Connect Lightning cable to iPhone/iPad")
    print(f"  {C.GRN}3.{C.NC} Put iPhone in DFU mode (Vol Down + Power → release Power)")
    print(f"  {C.GRN}4.{C.NC} Connect RP2350 to your computer via USB")
    print(f"  {C.GRN}5.{C.NC} Wait for LED to turn steady {C.GRN}green{C.NC} (RGB) or stay ON (single-color)")
    print(f"  {C.GRN}6.{C.NC} Run {C.EYE}[Check PWN]{C.NC} from the main menu to verify")
    print()

    show_troubleshooting()

    input(prompt("Press Enter to return to menu..."))


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
        print(warn("No board selected — run [1] Hardware Setup first"))

    # 2. Firmware
    fw_ok = check_firmware(board_id)
    fw_name = UF2_FILES.get(board_id, "N/A")
    print(key_value("Firmware", f"{fw_name} {'(' + C.GRN + 'present' + C.NC + ')' if fw_ok else '(' + C.RED + 'missing' + C.NC + ')'}"))
    results["firmware_present"] = fw_ok

    # 3. Tools
    from log_utils import check_tools
    required = ["usbliter8ctl"]
    tools = check_tools(required)
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
