from pathlib import Path
import subprocess

import pytest

from scripts import panic_usb


@pytest.fixture
def usb_tools(monkeypatch):
    state = {
        "devices": b"phone-one\n",
        "options": b"--keep --filter",
        "transfer": lambda _: (0, b""),
        "calls": [],
    }

    def run(args, *, cwd, capture_output, timeout):
        assert capture_output and timeout <= 60
        state["calls"].append(args)
        if args == ["idevice_id", "-l"]:
            return subprocess.CompletedProcess(args, 0, state["devices"], b"")
        if args == ["idevicecrashreport", "--help"]:
            return subprocess.CompletedProcess(args, 0, state["options"], b"")
        status, stderr = state["transfer"](Path(cwd))
        return subprocess.CompletedProcess(args, status, b"", stderr)

    monkeypatch.setattr(panic_usb.subprocess, "run", run)
    return state


def test_transfer_retains_device_reports_and_deduplicates(tmp_path, usb_tools):
    def transfer(scratch):
        report = b'{"bug_type":"210"}\n{"panicString":"synthetic test"}\n'
        (scratch / "panic-full-first.ips").write_bytes(report)
        (scratch / "alias").mkdir()
        (scratch / "alias" / "panic-full-second.ips.synced").write_bytes(report)
        (scratch / "panic-full-link.ips").symlink_to("panic-full-first.ips")
        (scratch / "unrelated.ips").write_bytes(b"unrelated report")
        return 0, b""

    usb_tools["transfer"] = transfer
    assert panic_usb.import_usb_reports(tmp_path, None) == (1, 1)
    assert usb_tools["calls"][-1] == [
        "idevicecrashreport", "--keep", "--filter", "panic-full", "--udid", "phone-one", ".",
    ]
    assert panic_usb.import_usb_reports(tmp_path, None) == (0, 2)
    report, = tmp_path.iterdir()
    assert report.name.startswith("panic-full-usb-")
    assert report.stat().st_mode & 0o777 == 0o600
    assert b"synthetic test" in report.read_bytes()


def test_empty_device_result(tmp_path, usb_tools):
    assert panic_usb.import_usb_reports(tmp_path, None) == (0, 0)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize(
    ("devices", "requested", "message"),
    [
        (b"", None, "no USB device"),
        (b"phone-one\nphone-two\n", None, "multiple USB devices"),
        (b"phone-one\n", "phone-two", "not connected over USB"),
    ],
)
def test_ambiguous_or_missing_device_stops_before_transfer(
    tmp_path, usb_tools, devices, requested, message,
):
    usb_tools["devices"] = devices
    with pytest.raises(panic_usb.PanicImportError, match=message):
        panic_usb.import_usb_reports(tmp_path, requested)
    assert usb_tools["calls"] == [["idevice_id", "-l"]]


def test_explicit_device_selected(tmp_path, usb_tools):
    usb_tools["devices"] = b"phone-one\nphone-two\n"
    assert panic_usb.import_usb_reports(tmp_path, "phone-two") == (0, 0)
    assert usb_tools["calls"][-1][-3:] == ["--udid", "phone-two", "."]


def test_tool_without_filter_refused(tmp_path, usb_tools):
    usb_tools["options"] = b"--keep"
    with pytest.raises(panic_usb.PanicImportError, match="both --keep and --filter"):
        panic_usb.import_usb_reports(tmp_path, None)
    assert len(usb_tools["calls"]) == 2


@pytest.mark.parametrize(("status", "stderr"), [(1, b""), (0, b"File size mismatch")])
def test_failed_transfer_discards_staged_files(tmp_path, usb_tools, status, stderr):
    def transfer(scratch):
        (scratch / "panic-full-partial.ips").write_bytes(b"partial")
        return status, stderr

    usb_tools["transfer"] = transfer
    with pytest.raises(panic_usb.PanicImportError, match="reported an error"):
        panic_usb.import_usb_reports(tmp_path, None)
    assert list(tmp_path.iterdir()) == []


def test_timed_out_transfer_discards_staged_files(tmp_path, usb_tools):
    def transfer(scratch):
        (scratch / "panic-full-partial.ips").write_bytes(b"partial")
        raise subprocess.TimeoutExpired("idevicecrashreport", 60)

    usb_tools["transfer"] = transfer
    with pytest.raises(panic_usb.PanicImportError, match="timed out"):
        panic_usb.import_usb_reports(tmp_path, None)
    assert list(tmp_path.iterdir()) == []
