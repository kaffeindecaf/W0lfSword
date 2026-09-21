#!/usr/bin/env python3
"""IMG4 / IM4P container reading and writing.

Firmware components inside an IPSW are NOT raw binaries: they are DER-encoded
IMG4 containers, and the payload is usually lzfse-compressed. The raw offsets in
an offset profile index into the *decompressed payload*, so anything that reads
a component straight out of an IPSW - or out of a `*.im4p` file - has to unwrap
it first. Comparing profile offsets against container bytes produces a wall of
bogus "does not match" results and blocks a perfectly fine build, which is
exactly what happened on Windows (issue #4).

Container layout (the part we need):

    SEQUENCE {
        OCTET STRING "IM4P"          magic
        OCTET STRING "ibss"          fourcc
        OCTET STRING "mBoot-20457"   description (build metadata, may be empty)
        OCTET STRING <payload>       optionally compressed with a 4-byte magic:
                                     bvx2 = lzfse, bvxn/bvx- = lzvn,
                                     complzss = Apple LZSS, BZh = bzip2
    }

`pyimg4` (pip installable, pure Python, wheels for Linux/macOS/Windows including
its lzfse/pylzss deps) does the whole job, so it is the preferred backend. When
it is missing we still decode what stdlib can do (bzip2 payloads, and containers
whose payload is stored plain) and refuse the rest with an actionable message
instead of guessing, because guessing here means patching compressed bytes.

Writing: `wrap()` builds a container for a patched payload. The device is pwned
when these are used, so no signature/manifest is attached - same as the
`img4tool -c <out> -t <fourcc> <raw>` step this replaces.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import log_utils

MAGIC = b"IM4P"
COMPRESSION = {
    b"bvx2": "lzfse",
    b"bvxn": "lzvn",
    b"bvx-": "lzvn",
    b"complzss": "lzss",
    b"BZh": "bzip2",
    b"\x1f\x8b": "gzip",
}


class Unsupported(Exception):
    """The container cannot be decoded with what is installed here."""


@dataclass
class Unwrapped:
    payload: bytes
    fourcc: str = ""
    description: str = ""
    compression: str = ""
    encrypted: bool = False
    via: str = ""

    @property
    def size(self) -> int:
        return len(self.payload)


def looks_like_container(data: bytes) -> bool:
    """True for a DER IMG4/IM4P container (the form IPSW components ship in)."""
    head = data[:64]
    return data[:1] == b"\x30" and MAGIC in head


def _der_items(data: bytes) -> list[bytes]:
    """Return the OCTET STRINGs of a DER SEQUENCE (one level, no schema)."""
    if not data or data[0] != 0x30:
        raise Unsupported("not a DER SEQUENCE")
    offset = 1
    length, offset = _der_length(data, offset)
    end = min(len(data), offset + length)
    items: list[bytes] = []
    while offset < end:
        tag = data[offset]
        offset += 1
        item_len, offset = _der_length(data, offset)
        items.append(data[offset:offset + item_len] if tag in (0x04, 0x16) else b"")
        offset += item_len
    return items


def _der_length(data: bytes, offset: int) -> tuple[int, int]:
    first = data[offset]
    offset += 1
    if first < 0x80:
        return first, offset
    count = first & 0x7F
    if count == 0 or count > 4 or offset + count > len(data):
        raise Unsupported("unsupported DER length encoding")
    return int.from_bytes(data[offset:offset + count], "big"), offset + count


def _install_hint(compression: str) -> str:
    return (f"payload is {compression}-compressed and no decoder is installed; "
            f"run: python3 -m pip install pyimg4")


def _decompress(payload: bytes) -> tuple[bytes, str]:
    """Decompress a component payload, using stdlib where it can."""
    kind = ""
    for size in (6, 5, 4, 3, 2):                 # bvx2/bvxn/complzss/BZh/\x1f\x8b
        kind = COMPRESSION.get(payload[:size], "")
        if kind:
            break
    if not kind:
        return payload, ""
    if kind == "bzip2":
        import bz2
        try:
            return bz2.decompress(payload), kind
        except OSError as exc:
            raise Unsupported(f"{kind} payload is corrupt: {exc}") from exc
    if kind == "gzip":
        import gzip
        try:
            return gzip.decompress(payload), kind
        except OSError as exc:
            raise Unsupported(f"{kind} payload is corrupt: {exc}") from exc
    if kind == "lzfse":
        try:
            import lzfse
        except ImportError:
            raise Unsupported(_install_hint(kind)) from None
        try:
            return lzfse.decompress(payload), kind
        except Exception as exc:                              # noqa: BLE001
            raise Unsupported(f"{kind} payload could not be decompressed: {exc}") from exc
    raise Unsupported(_install_hint(kind))


def unwrap(data: bytes, *, via: str = "") -> Unwrapped:
    """Decode an IMG4 container into its decompressed payload.

    Data that is not a container at all is passed through unchanged (callers
    point this at `<section>.raw` files too). Raises Unsupported when the data
    IS a container but needs a decoder that is not installed, so callers report
    "cannot check this component" instead of a false mismatch.
    """
    if not looks_like_container(data):
        # already a raw payload (or something else entirely)
        return Unwrapped(payload=bytes(data), via=via or "raw")

    try:
        import pyimg4

        image = pyimg4.IM4P(data)
        if image.payload is None:
            raise Unsupported("container has no payload")
        payload = bytes(image.payload.data)
        compression = {1: "lzfse", 2: "lzfse", 3: "lzss"}.get(
            getattr(image.payload, "compression", 0), "")
        if getattr(image.payload, "compression", 0):
            image.payload.decompress()
            payload = bytes(image.payload.data)
        return Unwrapped(payload=payload, fourcc=str(image.fourcc or ""),
                         description=str(getattr(image, "description", "") or ""),
                         compression=compression,
                         encrypted=bool(getattr(image.payload, "encrypted", False)),
                         via=via or "pyimg4")
    except ImportError:
        pass
    except Exception as exc:                                  # noqa: BLE001
        raise Unsupported(f"pyimg4 could not read the container: {exc}") from exc

    items = _der_items(data)
    if not items or items[0] != MAGIC:
        raise Unsupported("unrecognised container (no IM4P magic) - "
                          "run: python3 -m pip install pyimg4")
    fourcc = items[1].decode("ascii", "replace") if len(items) > 1 else ""
    description = items[2].decode("ascii", "replace") if len(items) > 2 else ""
    if len(items) < 4:
        raise Unsupported("container has no payload - "
                          "run: python3 -m pip install pyimg4")
    payload, compression = _decompress(items[3])
    return Unwrapped(payload=payload, fourcc=fourcc, description=description,
                     compression=compression, via=via or "der")


def _der_item(payload: bytes) -> bytes:
    length = len(payload)
    if length < 0x80:
        return bytes([length]) + payload
    for count in (1, 2, 3, 4):
        if length < (1 << (8 * count)):
            return bytes([0x80 | count]) + length.to_bytes(count, "big") + payload
    raise ValueError("payload too large for DER")


def wrap(payload: bytes, fourcc: str, description: str = "",
         compress: str = "") -> bytes:
    """Build an IMG4 container for a patched payload (no signature: pwned boot).

    `compress` accepts "lzfse" or "" (stored); compression is optional, so a
    container written without a decoder installed is still valid.
    """
    if compress:
        if compress == "lzfse":
            try:
                import lzfse
                payload = lzfse.compress(payload)
            except ImportError:
                raise Unsupported(_install_hint(compress)) from None
        elif compress == "bzip2":
            import bz2
            payload = bz2.compress(payload)
        else:
            raise ValueError(f"unknown compression: {compress}")

    body = (b"\x16" + _der_item(MAGIC) + b"\x16" + _der_item(fourcc.encode())
            + b"\x16" + _der_item(description.encode()) + b"\x04" + _der_item(payload))
    return b"\x30" + _der_item(body)


def unwrap_file(path: Path | str) -> Unwrapped:
    return unwrap(Path(path).read_bytes(), via=Path(path).name)


def payload_of(path: Path | str) -> bytes:
    """Raw payload bytes for a component file (raw files pass through)."""
    return unwrap_file(path).payload


def decoder_available() -> tuple[bool, str]:
    """(can decode everything, human note) - for health checks."""
    try:
        import pyimg4                                          # noqa: F401
        return True, "pyimg4"
    except ImportError:
        pass
    try:
        import lzfse                                           # noqa: F401
        return True, "lzfse module (no IM4P writer)"
    except ImportError:
        return False, "no IMG4 decoder installed - run: python3 -m pip install pyimg4"


def main(argv: list[str] | None = None) -> int:
    import argparse
    import sys

    ap = argparse.ArgumentParser(description="Unwrap IMG4/IM4P containers to raw payloads")
    ap.add_argument("files", nargs="+", help="*.im4p files (or a component directory)")
    ap.add_argument("-o", "--out-dir", help="write <name>.raw next to this directory")
    args = ap.parse_args(argv if argv is not None else sys.argv[1:])

    from colors import C, err, ok

    status = 0
    for name in args.files:
        path = Path(name)
        try:
            result = unwrap_file(path)
        except (Unsupported, OSError) as exc:
            print(err(f"{path.name}: {exc}"))
            status = 1
            continue
        note = f"{len(result.payload):,} B"
        if result.compression:
            note += f" ({result.compression})"
        if result.fourcc:
            note += f" fourcc={result.fourcc}"
        print(ok(f"{path.name}: {note} via {result.via}"))
        if args.out_dir:
            dest = Path(args.out_dir) / f"{path.stem}.raw"
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(result.payload)
            print(f"    {C.DIM}wrote {dest}{C.NC}")
    return status


if __name__ == "__main__":
    import log_utils
    log_utils.install()          # usbliter8.log + unhandled-exception logging
    import sys
    sys.exit(log_utils.guard(main))
