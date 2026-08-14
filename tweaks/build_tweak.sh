#!/bin/bash
# build_tweak.sh <tweak-id> — compile a catalog tweak from its Logos template
# into a .deb targeting SpringBoard (K3.2 tweak installer backend).
#
# Usage:
#   ./tweaks/build_tweak.sh five_icon_dock
#   ./tweaks/build_tweak.sh list
#
# Reads tweaks/catalog.json, uses the entry's dylib_template + substrate_target,
# generates a Theos project in tweaks/.build/<id>/, builds with
# FINALPACKAGE=1 DEBUG=0, and copies the .deb to tweaks/packages/.
#
# Works on Linux and macOS (THEOS auto-detected, see BUILD.md).
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
TWEAK_ID="${1:-}"
CATALOG="$PROJECT_DIR/tweaks/catalog.json"
BUILD_ROOT="$PROJECT_DIR/tweaks/.build"
OUT_DIR="$PROJECT_DIR/tweaks/packages"

if [ -z "$TWEAK_ID" ] || [ "$TWEAK_ID" = "list" ]; then
    python3 - "$CATALOG" <<'PYEOF'
import json, sys
d = json.load(open(sys.argv[1]))
print("Available tweak templates:")
for t in d['tweaks']:
    mark = "●" if t.get('dylib_template') else "◌"
    print(f"  {mark} {t['id']:<16} {t['name']}  [{t['status']}]")
PYEOF
    exit 0
fi

# ── THEOS auto-detect (same paths as W0lfSword check_theos) ────
if [ -z "${THEOS:-}" ]; then
    for d in "$HOME/theos" /opt/theos /usr/local/theos "$PROJECT_DIR/.theos" \
             /opt/homebrew/theos /opt/homebrew/share/theos /usr/local/share/theos; do
        if [ -d "$d/makefiles" ]; then export THEOS="$d"; break; fi
    done
fi
[ -n "${THEOS:-}" ] || { echo "[ERROR] THEOS not found — export THEOS=/path/to/theos or run ./W0lfSword setup" >&2; exit 1; }
command -v dpkg-deb >/dev/null 2>&1 || { echo "[ERROR] dpkg-deb not found (brew install dpkg / apt install dpkg)" >&2; exit 1; }
command -v clang >/dev/null 2>&1 || { echo "[ERROR] clang not found (Xcode CLT on macOS, apt clang on Linux)" >&2; exit 1; }

# ── Catalog lookup ────────────────────────────────────────────
META=$(python3 - "$CATALOG" "$TWEAK_ID" <<'PYEOF'
import json, sys
catalog, want = sys.argv[1], sys.argv[2]
d = json.load(open(catalog))
t = next((x for x in d['tweaks'] if x['id'] == want), None)
if not t:
    sys.exit(1)
print("\x1f".join([
    t['id'],
    t['name'],
    t.get('ios_min', '17.0'),
    t.get('dylib_template', ''),
    t.get('substrate_target', 'com.apple.springboard'),
]))
PYEOF
) || { echo "[ERROR] No such tweak in catalog: $TWEAK_ID" >&2; echo "       Run './tweaks/build_tweak.sh list' to see ids." >&2; exit 1; }

IFS=$'\x1f' read -r ID NAME IOS_MIN TPL_REL SUBSTRATE_TARGET <<< "$META"
[ -n "$TPL_REL" ] || { echo "[ERROR] '$ID' has no dylib_template yet (status: planned)" >&2; exit 1; }

TPL_PATH="$PROJECT_DIR/tweaks/$TPL_REL"
[ -f "$TPL_PATH" ] || { echo "[ERROR] Template missing: $TPL_REL" >&2; exit 1; }

# ── Theos project layout ──────────────────────────────────────
# Debian package names: lowercase alnums + "-+." only (no underscores).
PKG_SUFFIX="${ID//_/-}"
PACKAGE_ID="com.kaffeindecaf.w0lfsword.tweak.$PKG_SUFFIX"
TWEAK_NAME="W0lfSwordTweak${ID}"
WORK="$BUILD_ROOT/$ID"
rm -rf "$WORK"
mkdir -p "$WORK"

cp "$TPL_PATH" "$WORK/Tweak.xm"

cat > "$WORK/Makefile" <<EOF
TARGET := iphone:clang:latest:15.0
ARCHS = arm64

include \$(THEOS)/makefiles/common.mk

TWEAK_NAME = $TWEAK_NAME

${TWEAK_NAME}_FILES = Tweak.xm
${TWEAK_NAME}_FRAMEWORKS = UIKit Foundation

include \$(THEOS_MAKE_PATH)/tweak.mk
EOF

cat > "$WORK/control" <<EOF
Package: $PACKAGE_ID
Name: W0lfSword — $NAME
Version: 1.0.0
Architecture: iphoneos-arm64
Depends: mobilesubstrate
Description: $NAME — installed by W0lfSword (tweak catalog)
Maintainer: kaffeindecaf <github.com/kaffeindecaf>
Author: kaffeindecaf
Section: Tweaks
EOF

# Theos copies this to <TWEAK_NAME>.plist in the staging dir (tweak.mk).
cat > "$WORK/Filter.plist" <<EOF
{ Filter = { Bundles = ( "$SUBSTRATE_TARGET" ); }; }
EOF

# ── Build ─────────────────────────────────────────────────────
echo "[1/3] Building $NAME ($ID) — THEOS=$THEOS"
echo "      Template: $TPL_REL   Target: $SUBSTRATE_TARGET   iOS: $IOS_MIN+"
if ! make -C "$WORK" messages=no package FINALPACKAGE=1 DEBUG=0 >/dev/null; then
    echo "[ERROR] Build failed — run manually for details:" >&2
    echo "        make -C $WORK messages=yes package FINALPACKAGE=1 DEBUG=0" >&2
    exit 1
fi

DEB=$(ls -t "$WORK/packages/"*.deb 2>/dev/null | head -1)
[ -n "$DEB" ] || { echo "[ERROR] No .deb produced" >&2; exit 1; }

mkdir -p "$OUT_DIR"
cp "$DEB" "$OUT_DIR/"
echo "[2/3] Package: $(basename "$DEB") ($(du -h "$DEB" | cut -f1))"
echo "      Copied to $OUT_DIR/$(basename "$DEB")"

# ── Verify contents ───────────────────────────────────────────
DYLIB_CNT=$(dpkg-deb -c "$DEB" 2>/dev/null | grep -c "DynamicLibraries/.*\.dylib" || true)
PLIST_CNT=$(dpkg-deb -c "$DEB" 2>/dev/null | grep -c "DynamicLibraries/.*\.plist" || true)
[ "$DYLIB_CNT" -ge 1 ] && [ "$PLIST_CNT" -ge 1 ] \
    && echo "[3/3] Package verified: dylib + Substrate filter plist ($SUBSTRATE_TARGET) present" \
    || { echo "[WARN] Package verification odd: dylib=$DYLIB_CNT plist=$PLIST_CNT" >&2; exit 1; }

echo ""
echo "Done. Install with: ./W0lfSword tweaks install $ID"
