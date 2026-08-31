#!/bin/bash
# ═══════════════════════════════════════════════════════════════════
#  re-sign_mha.sh — K4.12 MobileHouseArrest identity re-sign
#
#  Produces a Filza IPA whose bundle + CodeDirectory identifier is
#  com.apple.mobile.MobileHouseArrest, with the W0lfSword tweak dylib
#  injected. containermanagerd trusts that identity, so container
#  leases activate WITHOUT any kernel exploit (works iOS 18–27b).
#
#  Usage: scripts/re-sign_mha.sh <Filza.ipa> <tweak.dylib> [out.ipa]
#  Requires: ldid, python3, unzip, zip
# ═══════════════════════════════════════════════════════════════════
set -euo pipefail

# Bundle ID for the re-signed app. Default = MHA identity (K4.12 research /
# TrollStore path, where Apple registration is never involved).
# Pass a 4th arg (or BUNDLE_ID=) for Apple-ID sideloading: Apple refuses to
# register ANY com.apple.* App ID for third parties (Developer API error
# 9400), so PlumeImpactor/AltStore installs need a registerable ID like
# com.kaffeindecaf.w0lfsword.filza. The kernel R/W works from any bundle ID.
MHA_ID="com.apple.mobile.MobileHouseArrest"
DEFAULT_ID="com.kaffeindecaf.w0lfsword.filza"
BUNDLE_ID="${4:-${BUNDLE_ID:-$MHA_ID}}"
DIR="$(cd "$(dirname "$0")" && pwd)"
ADD_LC="$DIR/add-load-dylib.py"

IPA="${1:-}"
DYLIB="${2:-}"
OUT="${3:-Filza-MHA.ipa}"
[ -n "$IPA" ] && [ -f "$IPA" ] || { echo "  ✗ usage: re-sign_mha.sh <Filza.ipa> <tweak.dylib> [out.ipa] [bundle-id]"; echo "    bundle-id default: $MHA_ID (MHA identity, TrollStore path)"; echo "    for Apple-ID sideloading pass a registerable id, e.g. $DEFAULT_ID"; exit 1; }
[ -f "$DYLIB" ] || { echo "  ✗ tweak dylib not found: $DYLIB (build first: make package, then extract W0lfSword.dylib)"; exit 1; }

command -v ldid    >/dev/null || { echo "  ✗ ldid not found — install: apt install ldid (Linux) / brew install ldid (macOS)"; exit 1; }
command -v python3 >/dev/null || { echo "  ✗ python3 not found"; exit 1; }
command -v unzip   >/dev/null || { echo "  ✗ unzip not found"; exit 1; }
command -v zip     >/dev/null || { echo "  ✗ zip not found"; exit 1; }

TMP="$(mktemp -d /tmp/mha_resign_XXXXXX)"
trap 'rm -rf "$TMP"' EXIT
DYLIB_NAME="$(basename "$DYLIB")"

echo "╔════════════════════════════════════════════════════════════╗"
echo "║  W0lfSword Filza re-sign + dylib injection                  ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo "  identity: $BUNDLE_ID"
echo "  ipa:      $IPA"
echo "  dylib:    $DYLIB_NAME"
echo ""

# 1. Extract
[ -f "$DYLIB" ] || { echo "  ✗ tweak dylib not found: $DYLIB (build first: make package, then extract W0lfSword.dylib)"; exit 1; }
# Guard: the injected dylib must be SUBSTRATE-FREE. A plain `make package`
# (build/quick/adderall) rebuilds the shared .theos dylib WITH
# FilzaPadlockBypass.xm, which reintroduces the /var/jb CydiaSubstrate load
# command — dyld then kills Filza at launch on a non-jailbroken device
# ("Library not loaded: /var/jb/.../CydiaSubstrate"). Only the
# MHA_IDENTITY=1 build drops the .xm. Fail loudly instead of shipping a
# broken IPA.
if python3 - "$DYLIB" <<'PYEOF'
import struct, sys
data = open(sys.argv[1], 'rb').read()
ncmds, _ = struct.unpack('<II', data[16:24])
off = 32
for _ in range(ncmds):
    cmd, cs = struct.unpack('<II', data[off:off+8])
    if cmd == 0xc:  # LC_LOAD_DYLIB
        no = struct.unpack('<I', data[off+8:off+12])[0]
        if b'CydiaSubstrate' in data[off+no:off+cs]:
            sys.exit(1)
    off += cs
sys.exit(0)
PYEOF
then
    echo "  ✓ dylib substrate-free (no /var/jb CydiaSubstrate dependency)"
else
    echo "  ✗ dylib links CydiaSubstrate from /var/jb — a plain 'make package' overwrote the MHA build."
    echo "    Rebuild with:  make package MHA_IDENTITY=1   (or: ./W0lfSword nojailbreak)"
    echo "    Then re-run this re-sign."
    exit 1
fi
echo "[1/6] Extracting IPA..."
( cd "$TMP" && unzip -q "$(cd "$(dirname "$IPA")" && pwd)/$(basename "$IPA")" )
APP="$(find "$TMP" -maxdepth 3 -name '*.app' -type d | head -1)"
[ -n "$APP" ] || { echo "  ✗ no .app bundle in IPA"; exit 1; }
BIN="$APP/$(basename "$APP" .app)"
[ -f "$BIN" ] || BIN="$(find "$APP" -maxdepth 1 -type f -perm -u+x | head -1)"
[ -f "$BIN" ] || { echo "  ✗ main binary not found in $APP"; exit 1; }
echo "  bundle: $(basename "$APP")  binary: $(basename "$BIN")"

# 2. Strip any stale W0lfSword injection from a previous re-sign pass, then
#    inject the fresh tweak dylib. The source IPA may already carry an old
#    @executable_path/Frameworks/FilzaApplySandboxExt.dylib (with a hard
#    /var/jb CydiaSubstrate link) — stacking a second load command would make
#    dyld try to load BOTH on a non-jailbroken device. Idempotent re-sign:
echo "[2/6] Stripping stale injections, then injecting $DYLIB_NAME..."
python3 "$ADD_LC" --strip "$BIN" "$BIN.clean" "FilzaApplySandboxExt.dylib"
mv "$BIN.clean" "$BIN"
rm -f "$APP/Frameworks/FilzaApplySandboxExt.dylib"
rmdir "$APP/Frameworks" 2>/dev/null || true
cp "$DYLIB" "$APP/$DYLIB_NAME"
python3 "$ADD_LC" "$BIN" "$BIN.patched" "@executable_path/$DYLIB_NAME"
mv "$BIN.patched" "$BIN"

# 3. Re-bundle
echo "[3/6] Setting bundle identifier → $BUNDLE_ID"
python3 - "$APP/Info.plist" "$BUNDLE_ID" <<'PYEOF'
import plistlib, sys
path, ident = sys.argv[1], sys.argv[2]
with open(path, "rb") as f:
    d = plistlib.load(f)
old = d.get("CFBundleIdentifier", "?")
d["CFBundleIdentifier"] = ident
with open(path, "wb") as f:
    plistlib.dump(d, f)
print(f"  CFBundleIdentifier: {old} -> {ident}")
PYEOF

# 3b. App-extension bundle IDs must be rewritten too. PlumeImpactor/AltStore
# register EVERY bundle ID in the IPA with Apple's developer portal; the
# stock Filza's PlugIns/Sharing.appex still carries com.tigisoftware.Filza.Sharing,
# which Apple rejects (Developer API error 9401: "An App ID ... is not
# available") because Tigisoftware's own team owns that identifier. Extensions
# must be prefixed with the parent app's ID, so derive
# <parent>.<suffix> from each extension.
for ext_plist in "$APP"/PlugIns/*.appex/Info.plist; do
    [ -f "$ext_plist" ] || continue
    python3 - "$ext_plist" "$BUNDLE_ID" <<'PYEOF'
import plistlib, sys
path, prefix = sys.argv[1], sys.argv[2]
with open(path, "rb") as f:
    d = plistlib.load(f)
old = d.get("CFBundleIdentifier", "")
suffix = old.rsplit(".", 1)[-1] if "." in old else ""
new = f"{prefix}.{suffix}" if suffix else prefix
d["CFBundleIdentifier"] = new
with open(path, "wb") as f:
    plistlib.dump(d, f)
print(f"  extension CFBundleIdentifier: {old} -> {new}")
PYEOF
done

# 4. Re-sign (CodeDirectory identifier must match the bundle id)
# NOTE: -I takes the value ATTACHED (this ldid build rejects "-I <id>").
echo "[4/6] Re-signing with ldid (identifier $BUNDLE_ID)..."
# adhoc-sign the whole bundle FIRST (default identifiers), then re-sign the
# main binary + every extension binary with -I so their CodeDirectory
# identifiers match their (rewritten) bundle IDs. Order matters: a plain
# `ldid -S` at the end would clobber the -I identifiers.
find "$APP" -type f -perm -u+x -exec ldid -S {} \; 2>/dev/null || true
ldid -S -I"$BUNDLE_ID" "$BIN"
ldid -S "$APP/$DYLIB_NAME"
for ext_plist in "$APP"/PlugIns/*.appex/Info.plist; do
    [ -f "$ext_plist" ] || continue
    ext_dir="$(dirname "$ext_plist")"
    ext_id=$(python3 -c "import plistlib; print(plistlib.load(open('$ext_plist','rb')).get('CFBundleIdentifier',''))" 2>/dev/null)
    ext_exec=$(python3 -c "import plistlib; print(plistlib.load(open('$ext_plist','rb')).get('CFBundleExecutable',''))" 2>/dev/null)
    ext_bin="$ext_dir/$ext_exec"
    if [ -n "$ext_id" ] && [ -n "$ext_exec" ] && [ -f "$ext_bin" ]; then
        ldid -S -I"$ext_id" "$ext_bin"
        echo "  re-signed extension: $(basename "$ext_dir") -> $ext_id"
    else
        echo "  ⚠ extension binary not found for $ext_plist (id=$ext_id exec=$ext_exec)"
    fi
done

# 5. Repackage
echo "[5/6] Repackaging..."
OUTDIR="$(cd "$(dirname "$OUT")" 2>/dev/null && pwd || echo .)"
OUTABS="$OUTDIR/$(basename "$OUT")"
( cd "$TMP" && zip -q -r -y "$OUTABS" Payload )
echo "  wrote: $OUTABS"
OUT="$OUTABS"

# 6. Verify + instructions
echo "[6/6] Verify:"
echo "  $(ls -lh "$OUT" | awk '{print $5}')  $(python3 - "$OUT" <<'PYEOF'
import plistlib, sys, zipfile
z = zipfile.ZipFile(sys.argv[1])
name = [n for n in z.namelist() if n.endswith('.app/Info.plist')][0]
d = plistlib.loads(z.read(name))
print("bundle id:", d.get("CFBundleIdentifier"))
PYEOF
)"
echo ""
echo "  Install on the phone (TrollStore or Sileo):"
echo "    open Filza-MHA.ipa in TrollStore, or: scp $OUT root@<ip>:/var/mobile/ && ssh root@<ip> 'installer ...'"
echo "  After launch, Filza runs with the MHA identity — check /tmp/FilzaTweak.log for"
echo "  '[MCM] *** CONTAINER ACCESS ACTIVE' (pre-exploit container access, K4.12)."
