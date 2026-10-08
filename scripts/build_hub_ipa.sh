#!/usr/bin/env bash
# L2.5 — build the W0lfSword Hub .ipa from pocs/hub_shell:
#   Theos build → entitlements (L2.3) → ldid sign (L2.4) → .ipa assemble →
#   optional version bump → verify (unzip -l + ldid -h/-e).
#
# Usage:
#   bash scripts/build_hub_ipa.sh [sideload|trollstore] [version] [--release]
#     sideload  (default): get-task-allow only — plain sideload installs
#     trollstore: adds platform-application (TrollStore grants it anyway;
#                 kept explicit so the signing is self-documenting)
#     --release: L8.3 release build. Rebuilds the engine archive with
#                 DEBUG=0 (-DNDEBUG, KPRINTF address-leak logging compiled
#                 out) into .theos/libengine-release, builds the app with
#                 FINALPACKAGE=1, and refuses to hand over an ipa whose
#                 shipped binary still carries a KPRINTF marker. The debug
#                 archive (.theos/libengine/) is left untouched.
#
# Output: .w0lfsword/dist/W0lfSwordHub-<version>-<mode>[-release].ipa
set -euo pipefail
cd "$(dirname "$0")/.."

MODE=sideload
VERSION=1.0
RELEASE=0
for arg in "$@"; do
  case "$arg" in
    sideload|trollstore) MODE="$arg" ;;
    --release)           RELEASE=1 ;;
    -*)                  echo "unknown flag: $arg"; exit 1 ;;
    *)                   VERSION="$arg" ;;
  esac
done

APP_NAME=W0lfSwordHubShell
OUT_APP=W0lfSwordHub.app
DIST=".w0lfsword/dist"
mkdir -p "$DIST"
SUFFIX=""
[ "$RELEASE" = 1 ] && SUFFIX="-release"
IPA="$DIST/W0lfSwordHub-$VERSION-$MODE$SUFFIX.ipa"

THEOS="${THEOS:-$HOME/theos}"
[ -d "$THEOS" ] || { echo "no theos at $THEOS"; exit 1; }
[ -x scripts/ldid ] || { echo "scripts/ldid (Procursus) missing"; exit 1; }

if [ "$RELEASE" = 1 ]; then
  echo "== 1/5 release engine archive (DEBUG=0, NDEBUG) =="
  # Separate OUT: the host suite pins the debug archive's sha256 (AUD.11), so a
  # release build must never rewrite .theos/libengine/libw0lfengine.a.
  DEBUG=0 OUT=.theos/libengine-release THEOS="$THEOS" bash scripts/build_libengine.sh
  ENGINE_LIB=../../.theos/libengine-release/libw0lfengine.a
  echo "== 2/5 theos build (pocs/hub_shell, FINALPACKAGE=1) =="
  ( cd pocs/hub_shell && THEOS="$THEOS" make clean >/dev/null 2>&1 || true
    THEOS="$THEOS" make FINALPACKAGE=1 ENGINE_LIB="$ENGINE_LIB" >/dev/null 2>&1 ) \
    || { echo "build failed"; exit 1; }
else
  echo "== 1/5 theos build (pocs/hub_shell) =="
  ( cd pocs/hub_shell && THEOS="$THEOS" make clean >/dev/null 2>&1 || true
    THEOS="$THEOS" make >/dev/null 2>&1 ) || { echo "build failed"; exit 1; }
fi
# debug builds land in .theos/obj/debug/, release in .theos/obj/ - pick the
# shallowest match so the staged copy is the packaged one, not the per-arch one.
APP="$(find pocs/hub_shell/.theos/obj -maxdepth 2 -name '*.app' -type d 2>/dev/null \
       | awk -F/ '{print NF"\t"$0}' | sort -n | head -1 | cut -f2-)"
[ -n "$APP" ] || { echo "built .app not found"; exit 1; }

echo "== 3/5 entitlements ($MODE) =="
ENT="$DIST/ent-$MODE.plist"
cat > "$ENT" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>get-task-allow</key>
	<true/>
EOF
[ "$MODE" = trollstore ] && printf '\t<key>platform-application</key>\n\t<true/>\n' >> "$ENT"
printf '%s\n' '</dict>' '</plist>' >> "$ENT"

echo "== 4/5 assemble Payload/$OUT_APP + sign + version bump =="
rm -rf "$DIST/Payload"
mkdir -p "$DIST/Payload/$OUT_APP"
cp -R "$APP/." "$DIST/Payload/$OUT_APP/"
./scripts/ldid -S"$ENT" "$DIST/Payload/$OUT_APP/$APP_NAME"
python3 - "$DIST/Payload/$OUT_APP/Info.plist" "$VERSION" <<'EOF'
import plistlib, sys
path, ver = sys.argv[1], sys.argv[2]
with open(path, "rb") as f:
    p = plistlib.load(f)
p["CFBundleShortVersionString"] = ver
p["CFBundleVersion"] = ver.split("-")[0]
with open(path, "wb") as f:
    plistlib.dump(p, f)
EOF

echo "== 5/5 package .ipa =="
( cd "$DIST" && rm -f "$(basename "$IPA")" && zip -qr "$(basename "$IPA")" Payload )

echo ""
echo "== verify =="
# No `... | head` under pipefail: unzip exits on SIGPIPE when head stops
# reading, which turns a successful build into rc=141. sed reads to EOF.
unzip -l "$IPA" | sed -n '1,8p'
echo "  code signature:"
./scripts/ldid -h "$DIST/Payload/$OUT_APP/$APP_NAME" 2>&1 | grep -m 2 -E 'CodeDirectory|Identifier'
echo "  entitlements:"
./scripts/ldid -e "$DIST/Payload/$OUT_APP/$APP_NAME"
if [ "$RELEASE" = 1 ]; then
  echo "  KPRINTF markers (must be 0 in a release build):"
  # Address-leak / diagnostic literals that only exist when DEBUG is defined.
  MARKERS="Kernel base: 0x|spray released \(%lu sockets|mach_vm_map keeps failing with kr="
  LEAKS="$(strings -a "$DIST/Payload/$OUT_APP/$APP_NAME" | grep -cE "$MARKERS" || true)"
  echo "    $LEAKS"
  [ "$LEAKS" = 0 ] || { echo "FAIL: release binary still carries KPRINTF strings"; exit 1; }
fi
echo ""
echo "OK: $IPA"
