#!/bin/bash
# build.sh — Build the Extract Key SwiftUI app for Intel Macs.
#
# On an Apple Silicon Mac (M1/M2/M3/M4), this cross-compiles for x86_64.
# The resulting binary runs natively on Intel Macs.
#
# Usage:
#   cd tools/extract-key-app
#   ./build.sh
#   # Binary:  .build/release/ExtractKeyApp
#   # App:     ExtractKey.app/

set -euo pipefail
cd "$(dirname "$0")"

# 1. Assemble the XNU encrypt function for x86_64 macOS
echo "Assembling XNU encrypt function..."
ENCRYPT_S="../../rustpush/open-absinthe/src/asm/encrypt.s"
mkdir -p .build/lib

# Patch the assembly for Mach-O:
#   - Underscore prefix for global symbol (Mach-O convention)
#   - Section directives (ELF → Mach-O)
#   - Alignment directives (absolute → power-of-2)
sed \
    -e 's/\.global sub_ffffff8000ec7320/.globl _sub_ffffff8000ec7320/' \
    -e 's/sub_ffffff8000ec7320:/_sub_ffffff8000ec7320:/' \
    -e 's/^\.section \.data/.data/' \
    -e 's/^\.section \.text/.text/' \
    -e 's/\.align 0x100/.p2align 8/' \
    -e 's/\.align 0x10$/.p2align 4/' \
    "$ENCRYPT_S" > .build/encrypt_macos.s

# Assemble for x86_64 (target 11.0 to match deployment target)
clang -c -arch x86_64 -mmacosx-version-min=10.15 -o .build/encrypt.o .build/encrypt_macos.s

# Create static library
ar rcs .build/lib/libxnu_encrypt.a .build/encrypt.o
echo "  Built .build/lib/libxnu_encrypt.a"

# 2. Build the Swift app
echo ""
# Build for x86_64 regardless of host architecture
echo "Building ExtractKeyApp for x86_64 (Intel)..."
ARCH=$(uname -m)
if [ "$ARCH" = "x86_64" ]; then
    swift build -c release
else
    swift build -c release --arch x86_64
fi

BINARY=".build/release/ExtractKeyApp"
if [ ! -f "$BINARY" ]; then
    # SPM may place it in an arch-specific subdirectory
    BINARY=$(find .build -name ExtractKeyApp -type f -perm +111 2>/dev/null | head -1)
fi

if [ ! -f "$BINARY" ]; then
    echo "ERROR: Build succeeded but binary not found"
    exit 1
fi

echo ""
echo "Binary: $BINARY"
file "$BINARY"

# 3. Wrap in .app bundle
APP="ExtractKey.app"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS"
cp "$BINARY" "$APP/Contents/MacOS/ExtractKeyApp"

cat > "$APP/Contents/Info.plist" << 'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>com.lrhodin.extract-key</string>
    <key>CFBundleName</key>
    <string>Extract Key</string>
    <key>CFBundleDisplayName</key>
    <string>Hardware Key Extractor</string>
    <key>CFBundleExecutable</key>
    <string>ExtractKeyApp</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleVersion</key>
    <string>1.0</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0</string>
    <key>LSMinimumSystemVersion</key>
    <string>10.15</string>
    <key>NSHighResolutionCapable</key>
    <true/>
</dict>
</plist>
PLIST

# Ad-hoc sign (required for Gatekeeper on recent macOS)
codesign --force --sign - "$APP" 2>/dev/null || true

echo ""
echo "App bundle: $(pwd)/$APP"
echo ""
echo "To run on this Mac (under Rosetta if Apple Silicon):"
echo "  open $APP"
echo ""
echo "To run on an Intel Mac:"
echo "  Copy $APP to the Intel Mac and double-click it."
