"""Tests for `img4wrap.py` (IMG4/IM4P container handling).

Firmware components in an IPSW are DER-encoded containers whose payload is
usually lzfse-compressed, and the profile's offsets index into the
decompressed payload. Getting this wrong is what made preflight block a valid
build on Windows (issue #4), so both the decoder and the writer are pinned here,
including the "no decoder installed" path that must fail loudly instead of
guessing.
"""

from __future__ import annotations

import bz2
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import img4wrap  # noqa: E402

PAYLOAD = bytes.fromhex("1f2003d5000080d2c0035fd6") * 200
BIG_PAYLOAD = bytes(range(256)) * 400            # > 64 KiB, exercises long DER lengths


@pytest.fixture
def no_pyimg4(monkeypatch):
    """Simulate a machine where pyimg4 is not installed."""
    monkeypatch.setitem(sys.modules, "pyimg4", None)
    return None


# ── detection ───────────────────────────────────────────────────────

def test_raw_payload_is_not_mistaken_for_a_container():
    assert img4wrap.looks_like_container(PAYLOAD) is False
    assert img4wrap.unwrap(PAYLOAD).payload == PAYLOAD
    assert img4wrap.unwrap(PAYLOAD).via == "raw"


def test_wrapped_payload_is_detected():
    container = img4wrap.wrap(PAYLOAD, "ibss", "mBoot-test")
    assert img4wrap.looks_like_container(container) is True
    assert container[:1] == b"\x30" and b"IM4P" in container[:64]


# ── reading ─────────────────────────────────────────────────────────

def test_round_trip_with_pyimg4():
    """The preferred backend; skipped where pyimg4 is not installed (CI installs it)."""
    pytest.importorskip("pyimg4")
    container = img4wrap.wrap(PAYLOAD, "ibss", "mBoot-20457.0.77.0.2")
    result = img4wrap.unwrap(container)
    assert result.payload == PAYLOAD
    assert result.fourcc == "ibss"
    assert result.description.startswith("mBoot-2045")
    assert result.via == "pyimg4"


def test_round_trip_without_pyimg4_uses_the_stdlib_parser(no_pyimg4):
    container = img4wrap.wrap(PAYLOAD, "ibss", "mBoot")
    result = img4wrap.unwrap(container)
    assert result.payload == PAYLOAD
    assert result.via == "der"
    assert result.fourcc == "ibss"


def test_long_der_lengths_round_trip(no_pyimg4):
    """Payloads over 64 KiB need multi-byte DER lengths."""
    container = img4wrap.wrap(BIG_PAYLOAD, "krnl", "")
    result = img4wrap.unwrap(container)
    assert result.payload == BIG_PAYLOAD


def test_bzip2_payload_is_decompressed_with_stdlib(no_pyimg4):
    compressed = bz2.compress(PAYLOAD)
    container = img4wrap.wrap(compressed, "ibss", "")
    result = img4wrap.unwrap(container)
    assert result.payload == PAYLOAD
    assert result.compression == "bzip2"


def test_lzfse_without_a_decoder_refuses_loudly(no_pyimg4, monkeypatch):
    """No pyimg4, no lzfse module: refuse with the install hint, never guess."""
    monkeypatch.setitem(sys.modules, "lzfse", None)
    container = img4wrap.wrap(PAYLOAD, "ibss", "")
    # make the payload a bvx2 lzfse stream without needing the encoder
    container = container.replace(b"\x04", b"\x04", 1)
    container = bytes(container).replace(PAYLOAD[:4], b"bvx2", 1)
    with pytest.raises(img4wrap.Unsupported) as exc:
        img4wrap.unwrap(container)
    assert "pip install pyimg4" in str(exc.value)


def test_corrupt_bzip2_payload_is_reported_not_raised(no_pyimg4):
    container = img4wrap.wrap(b"BZh9garbage-not-really-bzip2", "ibss", "")
    with pytest.raises(img4wrap.Unsupported) as exc:
        img4wrap.unwrap(container)
    assert "corrupt" in str(exc.value)


def test_der_data_without_im4p_magic_passes_through_as_raw(no_pyimg4):
    """Only genuine IM4P containers are decoded; anything else is raw bytes."""
    body = b"\x16\x04nope\x16\x04test\x16\x00\x04\x04abcd"
    container = b"\x30" + bytes([len(body)]) + body
    assert img4wrap.looks_like_container(container) is False
    assert img4wrap.unwrap(container).payload == container


def test_container_without_payload_is_rejected(no_pyimg4):
    body = b"\x16\x04IM4P\x16\x04ibss\x16\x00"
    container = b"\x30" + bytes([len(body)]) + body
    with pytest.raises(img4wrap.Unsupported):
        img4wrap.unwrap(container)


def test_compressed_wrap_without_decoder_refuses(no_pyimg4, monkeypatch):
    monkeypatch.setitem(sys.modules, "lzfse", None)
    with pytest.raises(img4wrap.Unsupported):
        img4wrap.wrap(PAYLOAD, "trxm", compress="lzfse")


def test_unknown_compression_is_a_value_error():
    with pytest.raises(ValueError):
        img4wrap.wrap(PAYLOAD, "ibss", compress="zstd")


# ── files and health ────────────────────────────────────────────────

def test_unwrap_file_and_payload_of(tmp_path):
    container = img4wrap.wrap(PAYLOAD, "ibss", "mBoot")
    im4p = tmp_path / "iBSS.n104.RELEASE.im4p"
    im4p.write_bytes(container)
    assert img4wrap.unwrap_file(im4p).payload == PAYLOAD
    assert img4wrap.payload_of(im4p) == PAYLOAD
    assert img4wrap.unwrap_file(im4p).via == im4p.name

    raw = tmp_path / "ibss.raw"
    raw.write_bytes(PAYLOAD)
    assert img4wrap.payload_of(raw) == PAYLOAD


def test_decoder_available_reports_something_useful():
    available, note = img4wrap.decoder_available()
    assert isinstance(available, bool)
    assert note


def test_cli_unwraps_a_directory(tmp_path, capsys):
    im4p = tmp_path / "iBSS.n104.RELEASE.im4p"
    im4p.write_bytes(img4wrap.wrap(PAYLOAD, "ibss", "mBoot"))
    out = tmp_path / "raw"
    assert img4wrap.main([str(im4p), "-o", str(out)]) == 0
    assert (out / "iBSS.n104.RELEASE.raw").read_bytes() == PAYLOAD
    assert "iBSS.n104.RELEASE.im4p" in capsys.readouterr().out


def test_cli_reports_an_undecodable_file(tmp_path, capsys, monkeypatch):
    """A real container whose payload needs a decoder that is missing."""
    monkeypatch.setitem(sys.modules, "pyimg4", None)
    monkeypatch.setitem(sys.modules, "lzfse", None)
    broken = tmp_path / "iBSS.n104.RELEASE.im4p"
    payload = b"bvx2" + b"\x00" * 32
    body = (b"\x16\x04IM4P" + b"\x16\x04ibss" + b"\x16\x00"
            + b"\x04" + bytes([len(payload)]) + payload)
    broken.write_bytes(b"\x30" + bytes([len(body)]) + body)

    assert img4wrap.main([str(broken)]) == 1
    out = capsys.readouterr().out
    assert "pip install pyimg4" in out
