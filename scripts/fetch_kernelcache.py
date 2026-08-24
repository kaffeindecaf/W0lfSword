#!/usr/bin/env python3
"""Ranged kernelcache fetcher (kcwatch method).

Pull just the kernelcache.release.<board> bytes out of a full IPSW over
HTTP Range — no 6-8GB download. Zero-risk: reads Apple's CDN only.

Usage:
    fetch_kernelcache.py <ipsw-url> [output.img4]
    # auto-detects the kernelcache.release.* entry via the zip central dir
    # (handles zip64 EOCD + zip64 local-header offsets)

Proven 2026-08-24: iPhone12,8_18.4.1_22E252_Restore.ipsw (8.45GB) -> 19.2MB
kernelcache.release.iphone12c, resolved by tools/xpf-cli (see its README).
"""
import struct, sys, urllib.request

def fetch_range(url, start, length):
    req = urllib.request.Request(url, headers={"Range": f"bytes={start}-{start+length-1}"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read()

def find_eocd(tail):
    """Return (offset_of_eocd_in_tail, cd_size, cd_offset), handling zip64."""
    # EOCD signature 0x06054b50. Valid record: comment_len field must
    # make the record end exactly at the buffer end (avoids false
    # positives from the signature appearing in file data).
    for i in range(len(tail) - 22, 0, -1):
        if tail[i:i+4] == b"PK\x05\x06":
            comment_len = struct.unpack_from("<H", tail, i + 20)[0]
            if i + 22 + comment_len == len(tail):
                # EOCD layout: sig(4) disk(2) cddisk(2) n1(2) n2(2)
                # cdsize(4 @+12) cdoffset(4 @+16) commentlen(2 @+20)
                cd_size, cd_offset = struct.unpack_from("<II", tail, i + 12)
                if cd_offset == 0xFFFFFFFF or cd_size == 0xFFFFFFFF:
                    return ("zip64", i)
                return ("classic", cd_size, cd_offset)
    raise RuntimeError("no valid EOCD found in tail")

def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    ipsw = sys.argv[1]
    out = sys.argv[2] if len(sys.argv) > 2 else "/tmp/kernelcache.img4"

    with urllib.request.urlopen(urllib.request.Request(ipsw, method="HEAD"), timeout=30) as r:
        total = int(r.headers["Content-Length"])
    print(f"IPSW size: {total/1e9:.2f} GB")

    tail = fetch_range(ipsw, total - 262144, 262144)
    kind, *rest = find_eocd(tail)
    if kind == "zip64":
        # zip64 EOCD locator sits right before EOCD: sig(4) disk(4) z64off(8)
        eocd = rest[0]
        loc = eocd - 20
        z64_off = struct.unpack_from("<Q", tail, loc + 8)[0]
        print(f"zip64 EOCD @ {z64_off}")
        # zip64 EOCD record: sig(4) recsize(8) ver(2+2) disks(4+4)
        # entries(8+8) cdsize(8 @40) cdoffset(8 @48)
        chunk = fetch_range(ipsw, z64_off, 96)
        cd_size = struct.unpack_from("<Q", chunk, 40)[0]
        cd_offset = struct.unpack_from("<Q", chunk, 48)[0]
        print(f"zip64 central dir @ {cd_offset} size {cd_size}")
    else:
        cd_size, cd_offset = rest
        print(f"central dir @ {cd_offset} size {cd_size}")

    # fetch central directory, find the kernelcache entry
    cds = fetch_range(ipsw, cd_offset, cd_size)
    pos = 0
    while pos < len(cds) - 46:
        if cds[pos:pos+4] != b"PK\x01\x02":
            pos += 1
            continue
        name_len, extra_len, comment_len = struct.unpack_from("<HHH", cds, pos + 28)
        name = cds[pos+46:pos+46+name_len].decode("utf-8", "replace")
        if name.startswith("kernelcache.release."):
            csize = struct.unpack_from("<I", cds, pos + 20)[0]
            lho = struct.unpack_from("<I", cds, pos + 42)[0]
            # zip64: 0xFFFFFFFF placeholders resolved via entry extra field
            # (ID 0x0001: only fields that were 0xFFFFFFFF appear, in order:
            #  csize(8) [if placeholder] then lho(8) [if placeholder])
            extra = cds[pos+46+name_len:pos+46+name_len+extra_len]
            if lho == 0xFFFFFFFF or csize == 0xFFFFFFFF:
                epos = 0
                while epos + 4 <= len(extra):
                    eid, esz = struct.unpack_from("<HH", extra, epos)
                    if eid == 0x0001:
                        eo = epos + 4
                        if csize == 0xFFFFFFFF:
                            csize = struct.unpack_from("<Q", extra, eo)[0]
                            eo += 8
                        if lho == 0xFFFFFFFF:
                            lho = struct.unpack_from("<Q", extra, eo)[0]
                        break
                    epos += 4 + esz
            print(f"found: {name}  csize={csize}  local_header_offset={lho}")
            # local header: name/extra lengths may differ from central dir
            lh = fetch_range(ipsw, lho, 64)
            lname_len, lextra_len = struct.unpack_from("<HH", lh, 26)
            data_start = lho + 30 + lname_len + lextra_len
            print(f"data starts @ {data_start}, fetching {csize} bytes...")
            data = fetch_range(ipsw, data_start, csize)
            with open(out, "wb") as f:
                f.write(data)
            print(f"saved {out} ({len(data)/1e6:.1f} MB)")
            print("NOTE: entry is deflate-compressed in the zip — decompress")
            print("      with: python3 -c \"import zlib;open('kc.dec','wb').write(")
            print("      zlib.decompressobj(-15).decompress(open('%s','rb').read()))\"" % out)
            return 0
        pos += 46 + name_len + extra_len + comment_len
    raise RuntimeError("kernelcache.release.* not found in central directory")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"ERROR: {e}")
        sys.exit(1)
