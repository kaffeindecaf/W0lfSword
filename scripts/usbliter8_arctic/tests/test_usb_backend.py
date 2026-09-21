"""Tests for the USB layer in `pwn_utils.py`.

The old helper returned the `usb.core` *module* while its name promised the
`usb` package, and `detect_apple_dfu()` then did `usb.core.find(...)` on it:
`AttributeError: module 'usb.core' has no attribute 'core'`, swallowed by a bare
`except Exception`. DFU/WTF/PWN detection therefore never worked anywhere, which
is what the Windows reporter hit (issue #4). These tests pin the fixed
behaviour, including the libusb backend diagnostics Windows users need.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import pwn_utils  # noqa: E402


class FakeDevice:
    def __init__(self, vid, pid, serial="SERIAL123"):
        self.idVendor, self.idProduct = vid, pid
        self.serial_number, self.bus, self.address = serial, 1, 7


class FakeCore:
    """Stand-in for the usb.core module."""

    def __init__(self, devices=None, error=None, backend_seen=None):
        self.devices = devices or []
        self.error = error
        self.backend_seen = backend_seen

    def find(self, backend=None, **kwargs):
        if self.backend_seen is not None:
            self.backend_seen.append(backend)
        if self.error:
            raise self.error
        for dev in self.devices:
            if dev.idVendor == kwargs.get("idVendor") and dev.idProduct == kwargs.get("idProduct"):
                return dev
        return None


@pytest.fixture(autouse=True)
def fresh_usb_state(monkeypatch):
    """Each test starts with an unresolved backend so the cache cannot leak."""
    monkeypatch.setattr(pwn_utils, "_USB", {"resolved": False, "backend": None,
                                            "note": "", "problem": ""})
    yield


# ── detection works at all (the regression) ─────────────────────────

def test_detect_apple_dfu_finds_a_device(monkeypatch):
    """Issue #4: `usb.core.find` on the already-narrowed module raised."""
    core = FakeCore([FakeDevice(pwn_utils.APPLE_DFU_VID, pwn_utils.APPLE_DFU_PID,
                                serial="PWND:[usbliter8]")])
    monkeypatch.setattr(pwn_utils, "usb_core", lambda: core)
    monkeypatch.setattr(pwn_utils, "usb_backend", lambda: (None, "test"))

    found = pwn_utils.detect_apple_dfu()
    assert found is not None
    assert found["mode"] == "DFU"
    assert found["serial"] == "PWND:[usbliter8]"
    assert found["pid"] == hex(pwn_utils.APPLE_DFU_PID)


def test_verify_pwn_mode_reads_the_serial(monkeypatch):
    core = FakeCore([FakeDevice(pwn_utils.APPLE_DFU_VID, pwn_utils.APPLE_DFU_PID,
                                serial="PWND:[usbliter8] xyz")])
    monkeypatch.setattr(pwn_utils, "usb_core", lambda: core)
    monkeypatch.setattr(pwn_utils, "usb_backend", lambda: (None, "test"))
    is_pwned, message = pwn_utils.verify_pwn_mode()
    assert is_pwned is True and "PWND" in message


def test_verify_pwn_mode_reports_a_plain_dfu_device(monkeypatch):
    core = FakeCore([FakeDevice(pwn_utils.APPLE_DFU_VID, pwn_utils.APPLE_DFU_PID,
                                serial="CPID:8030")])
    monkeypatch.setattr(pwn_utils, "usb_core", lambda: core)
    monkeypatch.setattr(pwn_utils, "usb_backend", lambda: (None, "test"))
    is_pwned, message = pwn_utils.verify_pwn_mode()
    assert is_pwned is False and "not PWND" in message


def test_detect_apple_dfu_recognises_wtf_and_restore(monkeypatch):
    for pid, mode in ((pwn_utils.APPLE_WTF_PID, "WTF"),
                      (pwn_utils.APPLE_RESTORE_PID, "restore")):
        core = FakeCore([FakeDevice(pwn_utils.APPLE_DFU_VID, pid)])
        monkeypatch.setattr(pwn_utils, "usb_core", lambda c=core: c)
        monkeypatch.setattr(pwn_utils, "usb_backend", lambda: (None, "test"))
        found = pwn_utils.detect_apple_dfu()
        assert found is not None and found["mode"] == mode


def test_detect_rp2350_finds_the_board(monkeypatch):
    core = FakeCore([FakeDevice(pwn_utils.RP2350_VID, pwn_utils.RP2350_PID, serial="E66")])
    monkeypatch.setattr(pwn_utils, "usb_core", lambda: core)
    monkeypatch.setattr(pwn_utils, "usb_backend", lambda: (None, "test"))
    board = pwn_utils.detect_rp2350()
    assert board is not None and board["pid"] == hex(pwn_utils.RP2350_PID)


def test_detect_returns_none_with_no_devices(monkeypatch):
    monkeypatch.setattr(pwn_utils, "usb_core", lambda: FakeCore([]))
    monkeypatch.setattr(pwn_utils, "usb_backend", lambda: (None, "test"))
    assert pwn_utils.detect_apple_dfu() is None
    assert pwn_utils.detect_rp2350() is None


# ── backend diagnostics ─────────────────────────────────────────────

def test_missing_libusb_backend_explains_itself(monkeypatch):
    core = FakeCore(error=RuntimeError("No backend available"))
    monkeypatch.setattr(pwn_utils, "usb_core", lambda: core)
    monkeypatch.setattr(pwn_utils, "usb_backend", lambda: (None, "none found"))
    assert pwn_utils.detect_apple_dfu() is None
    problem = pwn_utils.usb_problem()
    assert "No backend available" in problem
    assert "zadig" in problem.lower() and "libusb-1.0-0" in problem


def test_missing_pyusb_points_at_pip(monkeypatch):
    monkeypatch.setattr(pwn_utils, "usb_core", lambda: None)
    monkeypatch.setattr(pwn_utils, "usb_backend",
                        lambda: (None, pwn_utils._USB.setdefault("problem", "")) if False
                        else _pyusb_missing())
    assert pwn_utils.detect_apple_dfu() is None
    assert "pip install pyusb" in pwn_utils.usb_problem()


def _pyusb_missing():
    pwn_utils._USB["problem"] = (f"pyusb is not installed - run: python3 -m pip install "
                                 f"pyusb\n{pwn_utils.USB_HELP}")
    return None, pwn_utils._USB["problem"]


def test_usb_status_shape(monkeypatch):
    monkeypatch.setattr(pwn_utils, "usb_core", lambda: FakeCore([]))
    monkeypatch.setattr(pwn_utils, "usb_backend", lambda: (None, "test backend"))
    status = pwn_utils.usb_status()
    assert status["pyusb"] is True
    assert status["backend"] == "test backend"
    assert status["ready"] is True
    assert status["problem"] == ""


def test_usb_status_reports_a_problem(monkeypatch):
    monkeypatch.setattr(pwn_utils, "usb_core", lambda: FakeCore(error=RuntimeError("boom")))
    monkeypatch.setattr(pwn_utils, "usb_backend", lambda: (None, "nope"))
    pwn_utils.usb_status()
    pwn_utils.detect_apple_dfu()
    assert pwn_utils.usb_status()["ready"] is False


def test_backend_is_passed_to_find(monkeypatch):
    seen = []
    core = FakeCore([FakeDevice(pwn_utils.APPLE_DFU_VID, pwn_utils.APPLE_DFU_PID)],
                    backend_seen=seen)
    backend = object()
    monkeypatch.setattr(pwn_utils, "usb_core", lambda: core)
    monkeypatch.setattr(pwn_utils, "usb_backend", lambda: (backend, "test"))
    assert pwn_utils.detect_apple_dfu() is not None
    assert seen and seen[0] is backend


def test_usb_backend_prefers_a_pip_installed_libusb(monkeypatch):
    """`libusb-package` is the answer for Windows users without Zadig."""
    class FakeBackend:
        pass

    seen = {}

    def get_backend(find_library=None):
        seen["find_library"] = find_library
        return FakeBackend() if find_library else None

    import types

    fake_libusb1 = types.ModuleType("usb.backend.libusb1")
    fake_libusb1.get_backend = get_backend
    fake_backend_pkg = types.ModuleType("usb.backend")
    fake_backend_pkg.libusb1 = fake_libusb1
    fake_usb = types.ModuleType("usb")
    fake_usb.backend = fake_backend_pkg
    fake_package = types.ModuleType("libusb_package")
    fake_package.get_library_path = lambda: "/pkg/libusb-1.0.dll"

    monkeypatch.setitem(sys.modules, "usb", fake_usb)
    monkeypatch.setitem(sys.modules, "usb.backend", fake_backend_pkg)
    monkeypatch.setitem(sys.modules, "usb.backend.libusb1", fake_libusb1)
    monkeypatch.setitem(sys.modules, "libusb_package", fake_package)
    monkeypatch.setattr(pwn_utils, "usb_core", lambda: FakeCore([]))

    backend, note = pwn_utils.usb_backend()
    assert backend is not None and note == "libusb-package"
    assert seen["find_library"]("/whatever") == "/pkg/libusb-1.0.dll"


def test_windows_candidates_include_the_usual_locations():
    candidates = pwn_utils._windows_libusb_candidates()
    assert any("System32" in c for c in candidates)
    assert any("Zadig" in c or "Program Files" in c for c in candidates)


def test_usb_core_is_the_real_module_or_none():
    core = pwn_utils.usb_core()
    if core is None:
        assert pwn_utils.check_pyusb_installed() is False
    else:
        assert hasattr(core, "find")
        assert pwn_utils._get_usb() is core            # compatibility alias
