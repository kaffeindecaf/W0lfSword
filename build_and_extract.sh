#!/bin/bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  W0lfSword — Build + Dylib Extractor                         ║
# ║  Made by kaffeindecaf — github.com/kaffeindecaf              ║
# ╚══════════════════════════════════════════════════════════════╝
#
# Usage: ./build_and_extract.sh [--keep-temp]
#   Compiles the tweak via Theos, then extracts the .dylib from
#   the resulting .deb package for inspection or standalone use.

set -e

KEEP_TEMP=0
if [ "$1" = "--keep-temp" ]; then
    KEEP_TEMP=1
fi

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$PROJECT_DIR"

echo "╔════════════════════════════════════════╗"
echo "║  FilzaJailedDS-SSV-Bypass Build Tool  ║"
echo "╚════════════════════════════════════════╝"
echo ""

# Check THEOS
if [ -z "$THEOS" ]; then
    if [ -d "$HOME/theos" ]; then
        export THEOS="$HOME/theos"
        echo "[!] THEOS not set, using $THEOS"
    else
        echo "[ERROR] THEOS environment variable not set and ~/theos not found."
        echo "        Install Theos: https://theos.dev/"
        exit 1
    fi
fi

# Check dpkg-deb
if ! command -v dpkg-deb &>/dev/null; then
    echo "[ERROR] dpkg-deb not found. Install: brew install dpkg (macOS) or apt install dpkg (Linux)"
    exit 1
fi

# Step 1: Build
echo "[1/5] Building tweak..."
make package 2>&1 | tail -3
echo ""

# Step 2: Find the .deb
DEB=$(ls -t packages/*.deb 2>/dev/null | head -1)
if [ -z "$DEB" ]; then
    echo "[ERROR] No .deb found in packages/ after build"
    exit 1
fi
echo "[2/5] Found package: $(basename "$DEB") ($(du -h "$DEB" | cut -f1))"

# Step 3: Extract
EXTRACT_DIR="/tmp/filza_extract_$$"
mkdir -p "$EXTRACT_DIR"
echo "[3/5] Extracting to $EXTRACT_DIR..."

dpkg-deb -x "$DEB" "$EXTRACT_DIR/" 2>/dev/null
dpkg-deb -e "$DEB" "$EXTRACT_DIR/DEBIAN/" 2>/dev/null

# Step 4: Find and copy the dylib
DYLIB=$(find "$EXTRACT_DIR" -name '*.dylib' -type f 2>/dev/null | head -1)
if [ -z "$DYLIB" ]; then
    echo "[ERROR] No .dylib found in extracted package"
    [ $KEEP_TEMP -eq 0 ] && rm -rf "$EXTRACT_DIR"
    exit 1
fi

cp "$DYLIB" "$PROJECT_DIR/FilzaApplySandboxExt.dylib"
echo "[4/5] Dylib copied: FilzaApplySandboxExt.dylib ($(du -h "$PROJECT_DIR/FilzaApplySandboxExt.dylib" | cut -f1))"

# Step 5: Print info
echo "[5/5] Dylib info:"
echo "      Path:     $PROJECT_DIR/FilzaApplySandboxExt.dylib"
echo "      Size:     $(ls -lh "$PROJECT_DIR/FilzaApplySandboxExt.dylib" | awk '{print $5}')"
echo "      Type:     $(file "$PROJECT_DIR/FilzaApplySandboxExt.dylib" | cut -d: -f2-)"

# Show linked libraries (macOS only)
if command -v otool &>/dev/null; then
    echo "      Linked:"
    otool -L "$PROJECT_DIR/FilzaApplySandboxExt.dylib" | tail -n +2 | sed 's/^/        /'
elif command -v llvm-objdump &>/dev/null; then
    echo "      Linked:"
    llvm-objdump -p "$PROJECT_DIR/FilzaApplySandboxExt.dylib" 2>/dev/null | grep NEEDED | sed 's/^/        /'
fi

# Cleanup
if [ $KEEP_TEMP -eq 0 ]; then
    rm -rf "$EXTRACT_DIR"
    echo ""
    echo "      (temp dir cleaned. Use --keep-temp to preserve)"
else
    echo ""
    echo "      Extraction kept at: $EXTRACT_DIR"
fi

echo ""
echo "Done — ready to inject into Filza IPA."
