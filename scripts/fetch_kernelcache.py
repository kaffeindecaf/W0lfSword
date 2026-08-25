#!/usr/bin/env python3
"""fetch_kernelcache.py — ranged kernelcache fetcher (kcwatch method).

Pull just the kernelcache.release.<board> bytes out of a full IPSW over
HTTP Range — no 6-8GB download. Zero-risk: reads Apple's CDN only.
Uses kczip.py (zip64-aware, retries, CRC32 verify). The kernelcache
entry is deflate-wrapped in the zip; it is decompressed to the raw IMG4
before saving (feed that straight into tools/xpf-cli).

Usage:
    fetch_kernelcache.py <ipsw-url> [output.img4]

Proven 2026-08-24/25: iPhone12,8_18.4.1_22E252_Restore.ipsw (8.45GB)
-> 19.2MB kernelcache.release.iphone12c, resolved by tools/xpf-cli.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import kczip  # noqa: E402


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    ipsw = sys.argv[1]
    out = sys.argv[2] if len(sys.argv) > 2 else "/tmp/kernelcache.img4"

    total = kczip.total_size(ipsw)
    print("IPSW size: %.2f GB" % (total / 1e9))

    entry = kczip.locate_entry(ipsw)
    print("found: %s  csize=%d  ucsize=%d  crc32=%08x" % (
        entry["name"], entry["csize"], entry["ucsize"], entry["crc32"]))

    path, n = kczip.fetch_entry(ipsw, entry, out)
    print("saved %s (%.1f MB, %s)" % (
        path, n / 1e6, "decompressed" if entry["method"] == 8 else "stored"))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:          # noqa: BLE001
        print("ERROR: %s" % e)
        sys.exit(1)
