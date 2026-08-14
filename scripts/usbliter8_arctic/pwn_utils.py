"""PWN DFU USB utilities for usbliter8-arctic.

Detects RP2350 microcontroller, Apple DFU/WTF/restore devices,
verifies PWN DFU mode via USB serial number check, handles retries,
and polls for device state changes.
"""

import sys
import time
import subprocess
from colors import C, ok, err, warn, info
from log_utils import log_info, log_warn, log_error, log_step


RP2350_VID = 0x2E8A
RP2350_PID = 0x0003
APPLE_DFU_VID = 0x05AC
APPLE_DFU_PID = 0x1227
APPLE_WTF_PID = 0x1280    # WTF mode (pre-DFU)
APPLE_RESTORE_PID = 0x1281  # restore mode
APPLE_RECOVERY_PID = 0x1281  # same as restore

RP2350_DFU_PID = 0x000f     # RP2350 in BOOTSEL (UF2 flash drive)


def _get_usb() -> object | None:
    try:
        import usb.core
        return usb.core
    except ImportError:
        return None


def detect_rp2350() -> dict | None:
    """Find an RP2350 board connected via USB. Returns {vid, pid, serial, bus, address} or None."""
    usb = _get_usb()
    if not usb:
        return None
    try:
        dev = usb.find(idVendor=RP2350_VID, idProduct=RP2350_PID)
        if dev:
            return {
                "vid": hex(RP2350_VID),
                "pid": hex(RP2350_PID),
                "serial": getattr(dev, 'serial_number', 'N/A'),
                "bus": dev.bus,
                "address": dev.address,
            }
    except Exception:
        pass
    return None


def detect_apple_dfu() -> dict | None:
    """Find an Apple device in DFU or WTF mode. Returns {vid, pid, mode, serial, bus, address} or None."""
    usb = _get_usb()
    if not usb:
        return None
    try:
        dfu_pids = {APPLE_DFU_PID: "DFU", APPLE_WTF_PID: "WTF", APPLE_RESTORE_PID: "restore"}
        for pid, mode in dfu_pids.items():
            dev = usb.core.find(idVendor=APPLE_DFU_VID, idProduct=pid)
            if dev:
                return {
                    "vid": hex(APPLE_DFU_VID),
                    "pid": hex(pid),
                    "mode": mode,
                    "serial": getattr(dev, 'serial_number', 'N/A'),
                    "bus": dev.bus,
                    "address": dev.address,
                }
    except Exception as e:
        log_warn(f"USB enumeration error: {e}")
    return None


def detect_device_state() -> dict:
    """Detect all connected devices and their states. Returns comprehensive status dict."""
    result = {
        "rp2350": detect_rp2350(),
        "apple_dfu": detect_apple_dfu(),
        "pyusb_available": check_pyusb_installed(),
    }
    result["pwned"] = verify_pwn_mode()[0] if result["apple_dfu"] else False
    return result


def verify_pwn_mode() -> tuple[bool, str]:
    """Check if connected Apple device has PWND:[usbliter8] in its serial.

    Returns (is_pwned, serial_string_or_error_message).
    """
    dfu = detect_apple_dfu()
    if not dfu:
        return False, "No Apple device in DFU mode detected"

    serial = dfu.get("serial", "")
    if not serial:
        return False, "DFU device has no serial number"

    if "PWND:[" in serial:
        return True, serial
    return False, f"Device in DFU but not PWND (serial: {serial})"


def wait_for_pwn(timeout: int = 30, poll_interval: float = 0.5) -> bool:
    """Poll until PWN DFU is detected or timeout expires. Returns True if successful."""
    print(info(f"Waiting for PWN DFU mode (timeout: {timeout}s)..."))
    log_step(f"wait_for_pwn start (timeout={timeout}s)")
    start = time.time()

    while time.time() - start < timeout:
        # Retry USB enumeration a few times (laptops can be slow)
        for attempt in range(3):
            is_pwned, msg = verify_pwn_mode()
            if is_pwned:
                elapsed = time.time() - start
                print()
                print(ok(f"PWN DFU detected after {elapsed:.1f}s: {msg}"))
                log_info(f"PWN DFU detected: {msg} (elapsed={elapsed:.1f}s)")
                return True
            time.sleep(0.1)

        elapsed = time.time() - start
        dots_count = int((elapsed % 2) * 4) % 4
        sys.stdout.write(f"\r  {C.EYE}{'.' * dots_count}{' ' * (3 - dots_count)}{C.NC} waiting for PWND...  ({int(elapsed)}s)")
        sys.stdout.flush()
        time.sleep(poll_interval)

    print()
    elapsed = time.time() - start
    print(warn(f"Timeout: no PWN DFU after {elapsed:.1f}s. Check RP2350 connection and try again."))
    log_error(f"wait_for_pwn timeout after {elapsed:.1f}s")
    return False


def check_pyusb_installed() -> bool:
    """Check if pyusb is available."""
    return _get_usb() is not None


def print_device_status():
    """Print a human-readable status of all connected devices."""
    print(f"  {C.GREY}── device scan ──{C.NC}")

    rp = detect_rp2350()
    if rp:
        serial = rp.get("serial", "?")
        print(ok(f"RP2350 board: bus {rp['bus']} addr {rp['address']}  serial={serial[:40]}"))
    else:
        print(err("No RP2350 board detected (VID/PID: 2E8A:0003)"))

    dfu = detect_apple_dfu()
    if dfu:
        mode = dfu.get("mode", "?")
        serial = dfu.get("serial", "")[:60]
        print(ok(f"Apple {mode}: bus {dfu['bus']} addr {dfu['address']}  serial={serial}"))
    else:
        print(err("No Apple device in DFU/WTF mode (VID/PID: 05AC:1227/1280)"))

    is_pwned, msg = verify_pwn_mode()
    if is_pwned:
        print(ok(f"PWN CONFIRMED: {msg}"))
    else:
        print(info("Not in PWN DFU — plug into RP2350 and enter DFU mode"))


def wait_for_dfu(timeout: int = 30) -> bool:
    """Wait for any Apple device to enter DFU mode. Returns True if found."""
    print(info(f"Waiting for Apple DFU device (timeout: {timeout}s)..."))
    log_step(f"wait_for_dfu start (timeout={timeout}s)")
    start = time.time()

    while time.time() - start < timeout:
        dfu = detect_apple_dfu()
        if dfu:
            elapsed = time.time() - start
            print()
            print(ok(f"Apple {dfu['mode']} detected after {elapsed:.1f}s"))
            log_info(f"Apple DFU detected: mode={dfu['mode']} (elapsed={elapsed:.1f}s)")
            return True
        elapsed = time.time() - start
        dots = int(elapsed % 3)
        sys.stdout.write(f"\r  {C.EYE}{'.' * dots}{' ' * (2 - dots)}{C.NC} waiting for DFU...  ({int(elapsed)}s)")
        sys.stdout.flush()
        time.sleep(0.5)

    print()
    print(warn(f"Timeout: no Apple device in DFU after {timeout}s"))
    log_warn(f"wait_for_dfu timeout after {timeout}s")
    return False


# ── CLI ──

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print_device_status()
    elif sys.argv[1] == "wait":
        wait_for_pwn(timeout=int(sys.argv[2]) if len(sys.argv) > 2 else 30)
    elif sys.argv[1] == "wait_dfu":
        wait_for_dfu(timeout=int(sys.argv[2]) if len(sys.argv) > 2 else 30)
    elif sys.argv[1] == "check":
        is_pwned, msg = verify_pwn_mode()
        print(f"PWNED={is_pwned}  serial={msg}")
    elif sys.argv[1] == "scan":
        print_device_status()
    else:
        print_device_status()
