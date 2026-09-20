"""Tests for the ranged IPSW reader (kczip.py).

Everything runs against a local HTTP server that honours Range requests, so
the tests are hermetic: no Apple CDN, no multi-GB download. They cover the
EOCD scan (classic + zip64), zip64 extra resolution, central-directory
parsing, pattern matching, range fetch and CRC verification.
"""

import http.server
import socketserver
import struct
import sys
import threading
import zipfile
import zlib
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import kczip  # noqa: E402


class _RangeHandler(http.server.SimpleHTTPRequestHandler):
    """SimpleHTTPRequestHandler plus single-range support (stdlib lacks it)."""

    def send_head(self):
        rng = self.headers.get("Range")
        if not rng or not rng.startswith("bytes="):
            return super().send_head()
        path = self.translate_path(self.path)
        try:
            data = Path(path).read_bytes()
        except OSError:
            self.send_error(404)
            return None
        start_s, _, end_s = rng[6:].partition("-")
        start = int(start_s)
        end = int(end_s) if end_s else len(data) - 1
        chunk = data[start:end + 1]
        self.send_response(206)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(chunk)))
        self.send_header("Content-Range", f"bytes {start}-{end}/{len(data)}")
        self.end_headers()
        return _BytesIO(chunk)

    def do_HEAD(self):
        path = self.translate_path(self.path)
        try:
            size = Path(path).stat().st_size
        except OSError:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Length", str(size))
        self.end_headers()

    def log_message(self, *args):  # keep pytest output clean
        pass

    def handle_one_request(self):
        try:
            super().handle_one_request()
        except (ConnectionResetError, BrokenPipeError):
            self.close_connection = True


class _BytesIO:
    def __init__(self, data):
        self._data = data

    def read(self, n=-1):
        return self._data if n < 0 else self._data[:n]

    def close(self):
        pass


@pytest.fixture(scope="module")
def ipsw_server(tmp_path_factory):
    """A local zip exposed over HTTP with Range support."""
    root = tmp_path_factory.mktemp("ipsw")
    zip_path = root / "Fake_27.0_24A437_Restore.ipsw"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("Firmware/dfu/iBSS.n104.RELEASE.im4p", b"IBSS" * 4000)
        zf.writestr("Firmware/dfu/iBEC.n104.RELEASE.im4p", b"IBEC" * 3000)
        zf.writestr("Firmware/txm.iphoneos.release.im4p", b"TXM" * 500)
        zf.writestr("kernelcache.release.iphone12b", b"KERN" * 20000)
        zf.writestr("kernelcache.research.iphone12b", b"RSCH" * 200)

    handler = lambda *a, **k: _RangeHandler(*a, directory=str(root), **k)  # noqa: E731
    httpd = socketserver.TCPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}/{zip_path.name}"
    httpd.shutdown()


def test_total_size_and_central_directory(ipsw_server, tmp_path):
    size = kczip.total_size(ipsw_server)
    assert size > 0
    entries = kczip.central_directory(ipsw_server)
    names = {e["name"] for e in entries}
    assert "Firmware/dfu/iBSS.n104.RELEASE.im4p" in names
    assert "kernelcache.release.iphone12b" in names
    assert len(entries) == 5


def test_match_entries_requires_all_literals(ipsw_server):
    entries = kczip.central_directory(ipsw_server)
    ibss = kczip.match_entries(entries, [("iBSS.n104", ".im4p")])
    assert [e["name"] for e in ibss] == ["Firmware/dfu/iBSS.n104.RELEASE.im4p"]
    kc = kczip.match_entries(entries, ["kernelcache.release."])
    assert len(kc) == 1
    assert kczip.match_entries(entries, [("iBSS.", "d79")]) == []


def test_locate_entry_by_prefix(ipsw_server):
    entry = kczip.locate_entry(ipsw_server, prefix="kernelcache.release.")
    assert entry["name"] == "kernelcache.release.iphone12b"
    assert entry["ucsize"] == 4 * 20000


def test_fetch_entry_verifies_crc(ipsw_server, tmp_path):
    entry = kczip.locate_entry(ipsw_server, prefix="Firmware/dfu/iBSS.")
    out = tmp_path / "ibss.im4p"
    _, n = kczip.fetch_entry(ipsw_server, entry, out)
    assert n == 4 * 4000
    assert out.read_bytes() == b"IBSS" * 4000


def test_fetch_entry_rejects_bad_crc(ipsw_server, tmp_path):
    entry = dict(kczip.locate_entry(ipsw_server, prefix="Firmware/txm"))
    entry["crc32"] ^= 0xFFFFFFFF
    with pytest.raises(RuntimeError, match="CRC32 mismatch"):
        kczip.fetch_entry(ipsw_server, entry, tmp_path / "txm.im4p")


def test_fetch_entry_stored_uncompressed(tmp_path):
    """method=0 (stored) entries are written as-is (zip64 IPSWs store .aea)."""
    path = tmp_path / "stored.ipsw"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("stored.bin", b"PLAIN" * 64)
    entry = {"name": "stored.bin", "csize": 320, "ucsize": 320, "lho": 0,
             "crc32": zlib.crc32(b"PLAIN" * 64) & 0xFFFFFFFF, "method": 0}
    # locate the real local-header offset from the file itself
    with open(path, "rb") as fh:
        blob = fh.read()
    entry["lho"] = blob.index(b"PK\x03\x04")
    out = tmp_path / "stored.out"
    _, n = kczip.fetch_entry(str(path), entry, out, decompress=True)
    assert n == 320 and out.read_bytes() == b"PLAIN" * 64


def test_find_eocd_classic_and_zip64():
    payload = b"x" * 128
    cd = b"PK\x01\x02" + b"\x00" * 44
    classic = payload + cd + b"PK\x05\x06" + struct.pack("<HHHHIIH", 0, 0, 1, 1, len(cd), 128, 0)
    kind, cd_size, cd_offset = kczip.find_eocd(classic)
    assert kind == "classic" and cd_size == len(cd) and cd_offset == 128

    # real zip64 layout: ... payload, central directory, zip64 EOCD record,
    # zip64 EOCD locator (20 bytes), classic EOCD holding 0xFFFFFFFF markers
    z64_off = len(payload) + len(cd)
    z64_eocd = b"PK\x06\x06" + struct.pack("<QHHIIQQQQ", 44, 45, 45, 0, 0, 1, 1, len(cd), 128)
    locator = b"PK\x06\x07" + struct.pack("<IQI", 0, z64_off, 1)
    eocd = b"PK\x05\x06" + struct.pack("<HHHHIIH", 0, 0, 1, 1, 0xFFFFFFFF, 0xFFFFFFFF, 0)
    tail = payload + cd + z64_eocd + locator + eocd
    kind, eocd_pos = kczip.find_eocd(tail)
    assert kind == "zip64"
    assert tail[eocd_pos - 20:eocd_pos - 16] == b"PK\x06\x07"
    assert struct.unpack_from("<Q", tail, eocd_pos - 20 + 8)[0] == z64_off


def test_zip64_entry_sizes_resolution():
    extra = struct.pack("<HHQQQ", 0x0001, 24, 0x1122334455, 0x66778899AA, 0xAABBCCDDEE)
    ucsize, csize, lho = kczip._zip64_entry_sizes(extra, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF)
    assert (ucsize, csize, lho) == (0x1122334455, 0x66778899AA, 0xAABBCCDDEE)


def test_find_eocd_raises_without_record():
    with pytest.raises(RuntimeError, match="no valid EOCD"):
        kczip.find_eocd(b"not a zip" * 10)
