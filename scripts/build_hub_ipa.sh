#!/usr/bin/env bash
# L2.5 — build the W0lfSword Hub .ipa from pocs/hub_shell:
#   Theos build → entitlements (L2.3) → ldid sign (L2.4) → .ipa assemble →
#   optional version bump → verify (unzip -l + ldid -h/-e).
#
# Usage:
#   bash scripts/build_hub_ipa.sh [sideload|trollstore] [version]
#     sideload  (default): get-task-allow only — plain sideload installs
#     trollstore: adds platform-application (TrollStore grants it anyway;
#                 kept explicit so the signing is self-documenting)
#
# Output: .w0lfsword/dist/W0lfSwordHub-<version>-<mode>.ipa
set -euo pipefail
cd "$(dirname "$0")/.."

MODE="${1:-sideload}"
VERSION="${2:-1.0}"
case "$MODE" in sideload|trollstore) ;; *) echo "mode must be sideload|trollstore"; exit 1;; esac

APP_NAME=W0lfSwordHubShell
OUT_APP=W0lfSwordHub.app
DIST=".w0lfsword/dist"
mkdir -p "$DIST"
IPA="$DIST/W0lfSwordHub-$VERSION-$MODE.ipa"

THEOS="${THEOS:-$HOME/theos}"
[ -d "$THEOS" ] || { echo "no theos at $THEOS"; exit 1; }
[ -x scripts/ldid ] || { echo "scripts/ldid (Procursus) missing"; exit 1; }

echo "== 1/5 theos build (pocs/hub_shell) =="
( cd pocs/hub_shell && THEOS="$THEOS" make clean >/dev/null 2>&1 || true
  THEOS="$THEOS" make >/dev/null 2>&1 ) || { echo "build failed"; exit 1; }
APP="$(ls -d pocs/hub_shell/.theos/obj/debug/*.app 2>/dev/null | head -1)"
[ -n "$APP" ] || { echo "built .app not found"; exit 1; }

echo "== 2/5 entitlements ($MODE) =="
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

echo "== 3/5 assemble Payload/$OUT_APP =="
rm -rf "$DIST/Payload"
mkdir -p "$DIST/Payload/$OUT_APP"
cp -R "$APP/." "$DIST/Payload/$OUT_APP/"

echo "== 4/5 sign + version bump =="
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
unzip -l "$IPA" | head -8
echo "  code signature:"
./scripts/ldid -h "$DIST/Payload/$OUT_APP/$APP_NAME" 2>&1 | grep -E 'CodeDirectory|Identifier' | head -2
echo "  entitlements:"
./scripts/ldid -e "$DIST/Payload/$OUT_APP/$APP_NAME"
echo ""
echo "OK: $IPA"
