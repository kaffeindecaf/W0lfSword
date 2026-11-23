#!/usr/bin/env python3
"""Copy iOS panic-full reports over USB while retaining the phone's copies."""

import argparse
import filecmp
import hashlib
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile


PANIC_REPORT = re.compile(r"panic-full(?:-[a-zA-Z0-9._-]+)?\.ips(?:\.synced)?")


class PanicImportError(Exception):
    """The USB importer could not complete the requested operation."""


def run_usb_tool(args, *, timeout, cwd=None):
    tool = args[0]
    try:
        result = subprocess.run(args, cwd=cwd, capture_output=True, timeout=timeout)
    except FileNotFoundError as exc:
        raise PanicImportError(f"{tool} is required from libimobiledevice") from exc
    except subprocess.TimeoutExpired as exc:
        raise PanicImportError(f"{tool} timed out after {timeout} seconds") from exc
    if result.returncode or result.stderr:
        # Some versions emit file transfer errors on stderr and still exit 0.
        # Avoid echoing device paths and report names from the diagnostics.
        raise PanicImportError(f"{tool} reported an error (exit {result.returncode})")
    return result.stdout


def select_usb_device(requested):
    devices = set(run_usb_tool(["idevice_id", "-l"], timeout=5).decode().split())
    if not devices:
        raise PanicImportError("no USB device found; connect and unlock the iPhone")
    if requested:
        if requested not in devices:
            raise PanicImportError("the requested device is not connected over USB")
        return requested
    if len(devices) > 1:
        raise PanicImportError("multiple USB devices found; pass a UDID from idevice_id -l")
    return devices.pop()


def archive_report(report, archive):
    digest = hashlib.sha256()
    with report.open("rb") as stream:
        for block in iter(lambda: stream.read(65536), b""):
            digest.update(block)
    destination = archive / f"panic-full-usb-{digest.hexdigest()}.ips"
    report.chmod(0o600)
    try:
        os.link(report, destination)
    except FileExistsError:
        if destination.is_symlink() or not destination.is_file() or not filecmp.cmp(
            report, destination, shallow=False
        ):
            raise PanicImportError("an archive entry conflicts with an imported report")
        return False
    return True


def import_usb_reports(archive, requested):
    udid = select_usb_device(requested)
    options = run_usb_tool(["idevicecrashreport", "--help"], timeout=5)
    if b"--keep" not in options or b"--filter" not in options:
        raise PanicImportError("idevicecrashreport must support both --keep and --filter")

    archive.mkdir(mode=0o700, parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".usb-", dir=archive) as scratch:
        # Keep the tool's destination argument short even in deep checkouts.
        run_usb_tool(
            ["idevicecrashreport", "--keep", "--filter", "panic-full", "--udid", udid, "."],
            timeout=60,
            cwd=scratch,
        )
        reports = [
            Path(directory) / name
            for directory, _, names in os.walk(scratch)
            for name in names
            if PANIC_REPORT.fullmatch(name)
        ]
        reports = [path for path in reports if not path.is_symlink() and path.is_file()]
        if any(not path.stat().st_size for path in reports):
            raise PanicImportError("an empty panic report was received")
        saved = sum(archive_report(path, archive) for path in reports)
    return saved, len(reports) - saved


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path, help="local panic-report directory")
    parser.add_argument("udid", nargs="?", help="USB device to select if several are connected")
    args = parser.parse_args()
    try:
        saved, existing = import_usb_reports(args.archive, args.udid)
    except (PanicImportError, OSError) as exc:
        print(f"panic usb: {exc}", file=sys.stderr)
        return 1
    if saved or existing:
        print(f"Saved {saved} new report(s), {existing} already archived in {args.archive}")
    else:
        print("No panic-full reports were returned by the connected device.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
