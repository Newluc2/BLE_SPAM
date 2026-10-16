#!/bin/bash
# Build script for BLE Spam FAP (Flipper Application Package)
# Tested on: Ubuntu 20.04 LTS, macOS 11+, WSL2 Windows
# Requires: a Flipper firmware checkout with FBT

set -e  # Exit on error

PROJECT_NAME="ble_spam"
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIST_DIR="$PROJECT_DIR/dist"

echo "=================================================="
echo "🔨 BLE Spam FAP Builder v7.0"
echo "=================================================="
echo ""
echo "📁 Project: $PROJECT_NAME"
echo "📂 Source:  $PROJECT_DIR"
echo "🏗️  Firmware: $FLIPPER_DEV_TOOLS"
echo ""

mkdir -p "$DIST_DIR"

# Build with the official Flipper Build Tool (FBT).
if [ -z "${FLIPPER_DEV_TOOLS:-}" ] || [ ! -f "$FLIPPER_DEV_TOOLS/fbt" ]; then
    echo "❌ FLIPPER_DEV_TOOLS must point to a Flipper firmware checkout."
    exit 1
fi

echo "🔨 Building FAP..."
cd "$FLIPPER_DEV_TOOLS"
./fbt fap_ble_spam "APPSRC=$PROJECT_DIR"

# Check if build succeeded
FAP_FILE="$(find "$FLIPPER_DEV_TOOLS" -type f -name "$PROJECT_NAME.fap" -print -quit)"
if test -n "$FAP_FILE"
then
    echo ""
    echo "✅ Build successful!"
    echo "📦 Package: $DIST_DIR/$PROJECT_NAME.fap"
    
    # Copy to dist
    cp "$FAP_FILE" "$DIST_DIR/$PROJECT_NAME.fap"
    
    # Show file info
    ls -lh "$DIST_DIR/$PROJECT_NAME.fap"
    
    echo ""
    echo "🎉 Ready for deployment!"
    echo ""
    echo "Next steps:"
    echo "1. Connect Flipper via USB"
    echo "2. Use qFlipper or drag-drop to: /ext/apps/bluetooth/"
    echo "3. Launch: Apps → Bluetooth → BLE Spam"
    echo ""
else
    echo ""
    echo "❌ Build failed!"
    echo "Check the error messages above."
    exit 1
fi
