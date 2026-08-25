#!/usr/bin/env python3
"""kczip.py — zip64-aware remote range reader for IPSWs (kcwatch core).

Reads a single entry out of a large zip (like an IPSW) over HTTP Range:
pull the tail (EOCD / zip64 EOCD locator), fetch the central directory,
locate the entry, fetch exactly its compressed bytes, verify CRC32, and
optionally raw-deflate decompress. Never downloads the whole file.

Proven against >4GB Apple CDN IPSWs (zip64) — see fetch_kernelcache.py
and kcwatch.py. Pure stdlib.
"""
import struct
import time
import urllib.request
import zlib

RETRIES = 3
BACKOFF = 2.0          # seconds, exponential
RANGE_TIMEOUT = 60
HEAD_TIMEOUT = 30
TAIL_SIZE = 262144     # bytes pulled from the end to find the EOCD


def fetch_range(url, start, length, retries=RETRIES, timeout=RANGE_TIMEOUT):
    """Fetch url[start:start+length] with exponential-backoff retries."""
    last = None
    for attempt in range(retries):
        try:
            req = urllib.request.Request(
                url, headers={"Range": "bytes=%d-%d" % (start, start + length - 1)})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read()
        except Exception as e:          # noqa: BLE001 — retry everything
            last = e
            time.sleep(BACKOFF * (attempt + 1))
    raise RuntimeError("range fetch %d+%d failed after %d tries: %s"
                       % (start, length, retries, last))


def total_size(url):
    with urllib.request.urlopen(urllib.request.Request(url, method="HEAD"),
                                timeout=HEAD_TIMEOUT) as r:
        return int(r.headers["Content-Length"])


def find_eocd(tail):
    """Return (kind, *fields) locating the central directory.
    kind == 'classic' → (cd_size, cd_offset); 'zip64' → zip64 EOCD offset."""
    for i in range(len(tail) - 22, 0, -1):
        if tail[i:i + 4] == b"PK\x05\x06":
            comment_len = struct.unpack_from("<H", tail, i + 20)[0]
            if i + 22 + comment_len == len(tail):
                cd_size, cd_offset = struct.unpack_from("<II", tail, i + 12)
                if cd_offset == 0xFFFFFFFF or cd_size == 0xFFFFFFFF:
                    return ("zip64", i)
                return ("classic", cd_size, cd_offset)
    raise RuntimeError("no valid EOCD record in the %d-byte tail" % len(tail))


def _zip64_entry_sizes(extra, ucsize, csize, lho):
    """Resolve 0xFFFFFFFF placeholders via the entry's zip64 extra (ID 0x0001).
    Fields appear in order ucsize, csize, lho — only those that were 0xFFFFFFFF."""
    epos = 0
    while epos + 4 <= len(extra):
        eid, esz = struct.unpack_from("<HH", extra, epos)
        if eid == 0x0001:
            eo = epos + 4
            if ucsize == 0xFFFFFFFF:
                ucsize = struct.unpack_from("<Q", extra, eo)[0]
                eo += 8
            if csize == 0xFFFFFFFF:
                csize = struct.unpack_from("<Q", extra, eo)[0]
                eo += 8
            if lho == 0xFFFFFFFF:
                lho = struct.unpack_from("<Q", extra, eo)[0]
            return ucsize, csize, lho
        epos += 4 + esz
    raise RuntimeError("zip64 placeholders present but no zip64 extra found")


def locate_entry(url, prefix="kernelcache.release.", tail_size=TAIL_SIZE):
    """Return an entry dict for the first central-directory entry whose
    name starts with prefix: {name, csize, ucsize, lho, crc32, method}."""
    total = total_size(url)
    tail = fetch_range(url, total - tail_size, tail_size)
    kind, *rest = find_eocd(tail)
    if kind == "zip64":
        loc = rest[0] - 20
        z64_off = struct.unpack_from("<Q", tail, loc + 8)[0]
        chunk = fetch_range(url, z64_off, 96)
        cd_size = struct.unpack_from("<Q", chunk, 40)[0]
        cd_offset = struct.unpack_from("<Q", chunk, 48)[0]
    else:
        cd_size, cd_offset = rest
    cds = fetch_range(url, cd_offset, cd_size)
    pos = 0
    while pos < len(cds) - 46:
        if cds[pos:pos + 4] != b"PK\x01\x02":
            pos += 1
            continue
        name_len, extra_len, comment_len = struct.unpack_from("<HHH", cds, pos + 28)
        name = cds[pos + 46:pos + 46 + name_len].decode("utf-8", "replace")
        if name.startswith(prefix):
            crc32 = struct.unpack_from("<I", cds, pos + 16)[0]
            method = struct.unpack_from("<H", cds, pos + 10)[0]
            ucsize = struct.unpack_from("<I", cds, pos + 24)[0]
            csize = struct.unpack_from("<I", cds, pos + 20)[0]
            lho = struct.unpack_from("<I", cds, pos + 42)[0]
            extra = cds[pos + 46 + name_len:pos + 46 + name_len + extra_len]
            if 0xFFFFFFFF in (ucsize, csize, lho):
                ucsize, csize, lho = _zip64_entry_sizes(extra, ucsize, csize, lho)
            return {"name": name, "csize": csize, "ucsize": ucsize,
                    "lho": lho, "crc32": crc32, "method": method}
        pos += 46 + name_len + extra_len + comment_len
    raise RuntimeError("no entry starting with %r in the central directory" % prefix)


def fetch_entry(url, entry, out_path, decompress=True):
    """Fetch entry bytes (Range to its data span), verify CRC32, optionally
    raw-deflate decompress (zip method 8), and write to out_path.
    Returns (out_path, byte_count_written).
    NOTE: the zip CRC-32 covers the UNCOMPRESSED data — decompress first,
    then verify (deflate entries with the data-descriptor flag set are the
    norm in Apple IPSWs; stored entries verify as-is)."""
    lh = fetch_range(url, entry["lho"], 64)
    lname_len, lextra_len = struct.unpack_from("<HH", lh, 26)
    data_start = entry["lho"] + 30 + lname_len + lextra_len
    data = fetch_range(url, data_start, entry["csize"])
    if decompress:
        if entry["method"] == 8:
            data = zlib.decompressobj(-15).decompress(data)
        elif entry["method"] != 0:
            raise RuntimeError("unsupported compression method %d" % entry["method"])
    if (zlib.crc32(data) & 0xFFFFFFFF) != entry["crc32"]:
        raise RuntimeError("CRC32 mismatch for %s (got %08x want %08x)"
                           % (entry["name"], zlib.crc32(data) & 0xFFFFFFFF,
                              entry["crc32"]))
    with open(out_path, "wb") as fh:
        fh.write(data)
    return out_path, len(data)
