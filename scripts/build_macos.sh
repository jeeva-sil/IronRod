#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────
# Build IronRod for macOS — produces .app bundle + .dmg installer
# Auto-detects architecture (Intel x86_64 / Apple Silicon arm64)
# ──────────────────────────────────────────────────────────────
set -euo pipefail

APP_NAME="IronRod"
VERSION="1.0"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="$PROJECT_DIR/dist"

# ── Detect architecture ──
ARCH="$(uname -m)"
if [ "$ARCH" = "arm64" ]; then
    ARCH_LABEL="Apple Silicon"
    ARCH_TAG="arm64"
elif [ "$ARCH" = "x86_64" ]; then
    ARCH_LABEL="Intel"
    ARCH_TAG="x86_64"
else
    ARCH_LABEL="$ARCH"
    ARCH_TAG="$ARCH"
fi

DMG_NAME="${APP_NAME}-${VERSION}-macOS-${ARCH_TAG}.dmg"

echo "════════════════════════════════════════════════════════════"
echo "  🍎  Building ${APP_NAME} v${VERSION} for macOS (${ARCH_LABEL})"
echo "════════════════════════════════════════════════════════════"
echo

cd "$PROJECT_DIR"

# ── 1. Python virtual environment ──
if [ ! -d "build_env" ]; then
    echo "📦 Creating build virtual environment..."
    python3 -m venv build_env
fi
source build_env/bin/activate

echo "📦 Installing dependencies..."
pip install --upgrade pip setuptools wheel > /dev/null
pip install -r requirements.txt > /dev/null 2>&1 || true
pip install -r requirements-build.txt > /dev/null

# ── 2. Generate icons ──
if [ ! -f "assets/icon.icns" ]; then
    echo "🎨 Generating app icons..."
    python assets/generate_icons.py
fi

# ── 3. Build with PyInstaller ──
echo "🔨 Building application (${ARCH_LABEL})..."
pyinstaller IronRod.spec --noconfirm --clean

# ── 4. Create DMG ──
echo "📀 Creating DMG installer (${ARCH_TAG})..."
DMG_TEMP="$BUILD_DIR/dmg_temp"
rm -rf "$DMG_TEMP"
mkdir -p "$DMG_TEMP"

# Copy .app bundle into staging area
cp -R "$BUILD_DIR/${APP_NAME}.app" "$DMG_TEMP/"

# Create Applications symlink for drag-and-drop install
ln -s /Applications "$DMG_TEMP/Applications"

# Create DMG
if command -v create-dmg &> /dev/null; then
    # Fancy DMG with create-dmg (brew install create-dmg)
    create-dmg \
        --volname "${APP_NAME}" \
        --volicon "assets/icon.icns" \
        --window-pos 200 120 \
        --window-size 600 400 \
        --icon-size 100 \
        --icon "${APP_NAME}.app" 150 190 \
        --hide-extension "${APP_NAME}.app" \
        --app-drop-link 450 190 \
        --no-internet-enable \
        "$BUILD_DIR/$DMG_NAME" \
        "$DMG_TEMP/" \
    || {
        # Fallback to hdiutil if create-dmg fails
        echo "  Falling back to hdiutil..."
        hdiutil create -volname "${APP_NAME}" \
            -srcfolder "$DMG_TEMP" \
            -ov -format UDZO \
            "$BUILD_DIR/$DMG_NAME"
    }
else
    hdiutil create -volname "${APP_NAME}" \
        -srcfolder "$DMG_TEMP" \
        -ov -format UDZO \
        "$BUILD_DIR/$DMG_NAME"
fi

rm -rf "$DMG_TEMP"

# ── 5. Summary ──
echo
echo "════════════════════════════════════════════════════════════"
echo "  ✅  macOS build complete! (${ARCH_LABEL})"
echo "════════════════════════════════════════════════════════════"
echo
echo "  Architecture: ${ARCH_LABEL} (${ARCH_TAG})"
echo "  App bundle:   $BUILD_DIR/${APP_NAME}.app"
echo "  Installer:    $BUILD_DIR/$DMG_NAME"
echo "  Size:         $(du -sh "$BUILD_DIR/$DMG_NAME" | cut -f1)"
echo
echo "  Users install by opening the .dmg and dragging"
echo "  ${APP_NAME}.app into their Applications folder."
echo
echo "  ⚠  Note: Raw disk access requires running with sudo:"
echo "     sudo /Applications/${APP_NAME}.app/Contents/MacOS/${APP_NAME}"
echo
echo "  💡 To build for the other architecture, run this script"
echo "     on a Mac with that chip (or use GitHub Actions CI/CD)."
echo

deactivate
