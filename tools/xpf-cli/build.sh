#!/bin/bash
# build.sh — build the XPF offset-resolver CLI on Linux (K4.1 tooling)
#
# Compiles XPF (repo: XPF/src) + ChOma (XPF/external/ChOma) for the HOST
# (Linux x86_64) using small header shims for Apple-only headers
# (xpc, mach-o, libkern, compression, CommonCrypto, os/log).
#
# Needs: clang, liblzfse-dev, libblocksruntime-dev, libssl-dev (apt-get /
# apt-get download + dpkg-deb -x works without root, see notes).
#
# Usage:
#   ./build.sh                → ./xpf-cli
#   ./xpf-cli kernelcache.img4            # print all resolved offsets
#   ./xpf-cli kernelcache.img4 dump.macho # decompress kernel to raw Mach-O
#
# Notes:
#   - Feed it the IMG4 kernelcache (encrypted ones need firmware keys first;
#     the iPhone18,1 26.x kernelcaches from the Apple CDN are unencrypted).
#   - The local xpf_patched.c copy makes the LC_UNIXTHREAD entry-point check
#     non-fatal and skips xpf_ppl_init() on SPTM devices (PPL text is absent).
#   - Each item is resolved under a SIGSEGV guard: finders that crash on
#     SPTM kernels print [UNRESOLVED/crash] instead of aborting.
set -e
cd "$(dirname "$0")"
REPO="$(cd ../.. && pwd)"

XPF_SRC="$REPO/XPF/src"
CHOMA_SRC="$REPO/XPF/external/ChOma/src"
CHOMA_INC="$REPO/XPF/external/ChOma/include"

CHOMA_FILES="BufferedStream Fat MachO MachOLoadCommand PatchFinder PatchFinder_arm64 arm64 Util Host FileStream MemoryStream CSBlob CodeDirectory DyldSharedCache"
CHOMA_OBJS=""
for f in $CHOMA_FILES; do CHOMA_OBJS="$CHOMA_OBJS $CHOMA_SRC/$f.c"; done

# Apple-header shim deps: if you build on a distro without these, fetch the
# .debs into deps/ and point the paths below (see K4.1 notes in ROADMAP).
LZFSE_DIR="${LZFSE_DIR:-/usr}"
BLK_DIR="${BLK_DIR:-/usr}"
[ -d /tmp/opencode/kc26/lzfse_lib/usr ] && LZFSE_DIR=/tmp/opencode/kc26/lzfse_lib/usr
[ -d /tmp/opencode/kc26/blk/usr ] && BLK_DIR=/tmp/opencode/kc26/blk/usr

clang -O2 -fblocks -o xpf-cli \
    main.c xpf_patched.c \
    "$XPF_SRC/common.c" "$XPF_SRC/decompress.c" "$XPF_SRC/non_ppl.c" \
    "$XPF_SRC/ppl.c" "$XPF_SRC/bad_recovery.c" \
    $CHOMA_OBJS \
    -I "$XPF_SRC" -I "$CHOMA_INC" -I shims \
    -I "$LZFSE_DIR/include" -I "$BLK_DIR/include" \
    -include stdint.h -include stdarg.h -include stddef.h \
    -include stdbool.h -include string.h -include stdlib.h -include stdio.h \
    -L "$LZFSE_DIR/lib/x86_64-linux-gnu" -Wl,-rpath,"$LZFSE_DIR/lib/x86_64-linux-gnu" \
    -L "$BLK_DIR/lib/x86_64-linux-gnu" -Wl,-rpath,"$BLK_DIR/lib/x86_64-linux-gnu" \
    -llzfse -lBlocksRuntime -lcrypto -lm

echo "Built ./xpf-cli"
