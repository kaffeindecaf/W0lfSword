#!/usr/bin/env bash
# L2.2 — engine extraction: compile kexploit/sandbox/SSV/utils/kpf/XPF into
# libw0lfengine.a (standalone static lib, same CFLAGS as the tweak).
#
# Excluded by design (tweak-only, per ROADMAP L2.2):
#   Tweak.m, TweakExploit.m, FilzaPadlockBypass.xm
#
# Usage: THEOS=~/theos bash scripts/build_libengine.sh
# Output: .theos/libengine/libw0lfengine.a

set -euo pipefail
cd "$(dirname "$0")/.."

THEOS="${THEOS:-$HOME/theos}"
OUT=".theos/libengine"
mkdir -p "$OUT"
: > "$OUT/build.log"

# toolchain + sdk (linux + macosx layouts)
CC=""
for cand in "$THEOS/toolchain/linux/iphone/bin/clang" "$THEOS/toolchain/macosx/iphone/bin/clang"; do
    [ -x "$cand" ] && CC="$cand" && break
done
[ -n "$CC" ] || { echo "no theos clang found under $THEOS/toolchain"; exit 1; }
AR=""
for cand in "$THEOS/toolchain/linux/iphone/bin/ar" "$THEOS/toolchain/macosx/iphone/bin/ar"; do
    [ -x "$cand" ] && AR="$cand" && break
done
SDK="$(ls -d "$THEOS"/sdks/iPhoneOS*.sdk 2>/dev/null | head -1)"
[ -n "$SDK" ] || { echo "no iPhoneOS sdk under $THEOS/sdks"; exit 1; }

CFLAGS="-target arm64-apple-ios15.0 -isysroot $SDK -arch arm64 -miphoneos-version-min=15.0 \
  -I$(pwd) -I$(pwd)/XPF/src -I$(pwd)/XPF/external/ChOma/include \
  -Wno-unused-function -Wno-unused-variable -Wno-unused-but-set-variable \
  -Wno-incompatible-pointer-types -Wno-incompatible-pointer-types-discards-qualifiers \
  -Wno-deprecated-declarations -Wno-nonportable-include-path -Wno-format -DDEBUG"

SOURCES="sandbox_escape.m \
  kexploit/kexploit_opa334.m kexploit/krw.m kexploit/kutils.m kexploit/offsets.m \
  kexploit/vnode.m kexploit/file.m kexploit/vnode_research.m kexploit/sandbox.m \
  kexploit/Exception.m kexploit/Thread.m kexploit/VM.m kexploit/MigFilterBypassThread.m \
  kexploit/RemoteCall.m kexploit/PAC.m kexploit/mcm_bridge.m kexploit/container_access.m \
  kexploit/bad_query_escape.m \
  SSV/SSVUtils.m \
  utils/hexdump.c utils/process.c utils/permission_utils.m utils/state.m utils/tweak_log.m \
  kpf/patchfinder.m \
  XPF/src/xpf.c XPF/src/common.c XPF/src/decompress.c XPF/src/bad_recovery.c XPF/src/non_ppl.c XPF/src/ppl.c \
  XPF/external/ChOma/src/arm64.c XPF/external/ChOma/src/Base64.c XPF/external/ChOma/src/BufferedStream.c \
  XPF/external/ChOma/src/CodeDirectory.c XPF/external/ChOma/src/CSBlob.c XPF/external/ChOma/src/DER.c \
  XPF/external/ChOma/src/DyldSharedCache.c XPF/external/ChOma/src/Entitlements.c XPF/external/ChOma/src/Fat.c \
  XPF/external/ChOma/src/FileStream.c XPF/external/ChOma/src/Host.c XPF/external/ChOma/src/MachO.c \
  XPF/external/ChOma/src/MachOLoadCommand.c XPF/external/ChOma/src/MemoryStream.c \
  XPF/external/ChOma/src/PatchFinder.c XPF/external/ChOma/src/PatchFinder_arm64.c \
  XPF/external/ChOma/src/Util.c"

OBJS=""
for src in $SOURCES; do
    obj="$OUT/$(echo "$src" | tr '/' '_').o"
    if ! "$CC" $CFLAGS -c "$src" -o "$obj" >>"$OUT/build.log" 2>&1; then
        echo "FAILED: $src"
        tail -8 "$OUT/build.log"
        exit 1
    fi
    OBJS="$OBJS $obj"
done

"$AR" rcs "$OUT/libw0lfengine.a" $OBJS
echo "OK: $OUT/libw0lfengine.a ($(du -h "$OUT/libw0lfengine.a" | cut -f1), $(echo $OBJS | wc -w | tr -d ' ') objects)"
