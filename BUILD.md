# BUILD.md — Compilation & Extraction Guide

---

## What is Theos?

**Theos** is a cross-platform build system for iOS tweak development. It's a collection of Makefiles and scripts that:

1. **Cross-compiles** Objective-C/C/C++/Logos code for iOS (arm64/arm64e) from macOS, Linux, or even iOS itself
2. **Links** against iOS SDKs (UIKit, Foundation, IOKit, etc.) and private frameworks (IOSurface)
3. **Packages** the compiled dylib + plist into a `.deb` (Debian package) that can be installed on jailbroken devices
4. **Handles Logos preprocessing** — `.xm` files (like `FilzaPadlockBypass.xm`) use `%hook`/`%orig`/`%log` syntax which Theos translates into MobileSubstrate hook code before compilation

Think of it as `make` + `dpkg-deb` + a Logos preprocessor, all specialized for iOS tweak development.

The key parts in our `Makefile`:
- `TARGET := iphone:clang:latest:15.0` — build for iPhone, use Clang, target iOS 15.0+
- `TWEAK_NAME = FilzaApplySandboxExt` — output dylib name
- `FilzaApplySandboxExt_INSTALL_TARGET_PROCESSES = Filza` — inject into Filza process only
- `include $(THEOS_MAKE_PATH)/tweak.mk` — Theos's tweak build rules

---

## Prerequisites

### On macOS (recommended)

```bash
# 1. Install Xcode Command Line Tools
xcode-select --install

# 2. Install Theos
bash -c "$(curl -fsSL https://raw.githubusercontent.com/theos/theos/master/bin/install-theos)"

# 3. Add Theos to your shell
echo 'export THEOS=~/theos' >> ~/.zshrc
source ~/.zshrc

# 4. Get an iOS SDK (already in Xcode, or download)
# Theos looks for SDKs in $THEOS/sdks/
# Xcode ships them at: /Applications/Xcode.app/.../iPhoneOS.sdk
# For iOS 26.0, you need Xcode 26+ or a manually placed SDK

# 5. Install dpkg (for .deb packaging)
brew install dpkg
```

### On Linux

```bash
# 1. Install Theos (same install script)
bash -c "$(curl -fsSL https://raw.githubusercontent.com/theos/theos/master/bin/install-theos)"
echo 'export THEOS=~/theos' >> ~/.bashrc
source ~/.bashrc

# 2. You need an iOS SDK since Linux has no Xcode
# Download patched sdks from: https://github.com/theos/sdks
# Place them in $THEOS/sdks/

# 3. Install dependencies
sudo apt install dpkg fakeroot clang ldid
```

### On iOS (yes, you can build on-device)

```bash
# Install Theos via a package manager (Sileo/Cydia)
# Add: https://repo.theos.dev/
# Install: org.theos.theos

# Or install manually:
# https://github.com/theos/theos/wiki/Installation-iOS
```

---

## Quick Build

```bash
cd FilzaJailedDS-SSV-Bypass

# Build + create .deb
make package

# Output:
#   .theos/obj/debug/arm64/FilzaApplySandboxExt.dylib  (raw dylib)
#   packages/com.local.filzaescaped_0.7.6-1+debug_iphoneos-arm64.deb  (installable)
```

### Build variants

```bash
# Build only (no packaging)
make

# Build + package for debugging
make package DEBUG=1

# Build for release (strips debug symbols)
make package FINALPACKAGE=1

# Clean build artifacts
make clean

# Clean everything including packages
make clean-packages
```

---

## Auto-Extract the .dylib

The compiled dylib is inside the `.deb`. This script builds, extracts, and copies it:

```bash
#!/bin/bash
# build_and_extract.sh — Compile the tweak and extract the dylib
set -e

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$PROJECT_DIR"

echo "=== Building ==="
make package

DEB=$(ls -t packages/*.deb 2>/dev/null | head -1)
if [ -z "$DEB" ]; then
    echo "ERROR: No .deb found in packages/"
    exit 1
fi

echo "=== Extracting $DEB ==="
EXTRACT_DIR="/tmp/filza_extract_$$"
mkdir -p "$EXTRACT_DIR"

# Extract .deb contents
dpkg-deb -x "$DEB" "$EXTRACT_DIR/"
dpkg-deb -e "$DEB" "$EXTRACT_DIR/DEBIAN/"

# Find the dylib
DYLIB=$(find "$EXTRACT_DIR" -name '*.dylib' | head -1)
if [ -z "$DYLIB" ]; then
    echo "ERROR: No .dylib found in extracted .deb"
    rm -rf "$EXTRACT_DIR"
    exit 1
fi

# Copy to a convenient location
cp "$DYLIB" "$PROJECT_DIR/FilzaApplySandboxExt.dylib"
cp "$(dirname "$DYLIB")"/*.plist "$PROJECT_DIR/" 2>/dev/null || true

echo "=== Done ==="
echo "Dylib: $(ls -lh "$PROJECT_DIR/FilzaApplySandboxExt.dylib" | awk '{print $5, $NF}')"
echo "Extracted to: $PROJECT_DIR/FilzaApplySandboxExt.dylib"

# Optional: keep extracted dir for inspection
# rm -rf "$EXTRACT_DIR"
echo "Full extraction kept at: $EXTRACT_DIR"
```

Save this as `build_and_extract.sh`, make it executable:

```bash
chmod +x build_and_extract.sh
./build_and_extract.sh
```

---

## Manual .dylib Extraction (no build)

If you already have a `.deb` in `packages/`:

```bash
# Extract files
dpkg-deb -x packages/com.local.filzaescaped_*.deb /tmp/filza_out/
dpkg-deb -e packages/com.local.filzaescaped_*.deb /tmp/filza_out/DEBIAN/

# The dylib is at:
#   /tmp/filza_out/Library/MobileSubstrate/DynamicLibraries/FilzaApplySandboxExt.dylib

# Inspect it
file /tmp/filza_out/Library/MobileSubstrate/DynamicLibraries/FilzaApplySandboxExt.dylib
# Output: Mach-O 64-bit arm64 dynamically linked shared library

# Check linked libraries
otool -L /tmp/filza_out/Library/MobileSubstrate/DynamicLibraries/FilzaApplySandboxExt.dylib
# Or on Linux: llvm-objdump -p /tmp/.../FilzaApplySandboxExt.dylib | grep NEEDED
```

---

## Install on Device

```bash
# Copy .deb to jailbroken iPhone
scp packages/com.local.filzaescaped_*.deb root@<device-ip>:/tmp/

# SSH in and install
ssh root@<device-ip>
dpkg -i /tmp/com.local.filzaescaped_*.deb
killall -9 Filza

# Or use a package manager (Sileo/Zebra) to install the .deb file
```

---

## What Goes Into the .deb

```
com.local.filzaescaped_0.7.6_iphoneos-arm64.deb
│
├── DEBIAN/
│   ├── control          ← package metadata (name, version, dependencies)
│   ├── preinst          ← (optional) runs before install
│   └── postinst         ← (optional) runs after install
│
└── Library/
    └── MobileSubstrate/
        └── DynamicLibraries/
            ├── FilzaApplySandboxExt.dylib    ← the compiled tweak
            └── FilzaApplySandboxExt.plist    ← filter: only inject into Filza
```

The `.plist` `{ Filter = { Bundles = ( "com.tigisoftware.Filza" ); } }` tells MobileSubstrate: *"only load this dylib when the Filza app is running"*.

---

## Troubleshooting

| Error | Fix |
|-------|-----|
| `theos/makefiles/common.mk: No such file` | `THEOS` env var not set → `export THEOS=~/theos` |
| `iPhoneOS.sdk not found` | Missing SDK → download from [theos/sdks](https://github.com/theos/sdks), place in `$THEOS/sdks/` |
| `dpkg-deb: command not found` | `brew install dpkg` (macOS) or `apt install dpkg` (Linux) |
| `Logos: %hook syntax error` | `.xm` files need Logos preprocessor → make sure `$THEOS/bin/logos` exists |
| `Undefined symbols for architecture arm64` | Missing framework/library → check Makefile `_FRAMEWORKS`/`_LIBRARIES` |
| `clang: error: no such file or directory: '.../XPF/src/xpf.c'` | XPF submodule not initialized → `git submodule update --init` if XPF is a submodule |
