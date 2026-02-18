#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────
# Build IronRod for Linux — produces AppImage + .deb + .tar.gz
# ──────────────────────────────────────────────────────────────
set -euo pipefail

APP_NAME="IronRod"
VERSION="1.0"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="$PROJECT_DIR/dist"
APPIMAGE_NAME="${APP_NAME}-${VERSION}-Linux-x86_64.AppImage"
DEB_NAME="${APP_NAME,,}_${VERSION}_amd64.deb"
TARBALL_NAME="${APP_NAME}-${VERSION}-Linux-x86_64.tar.gz"

echo "════════════════════════════════════════════════════════════"
echo "  🐧  Building ${APP_NAME} v${VERSION} for Linux"
echo "════════════════════════════════════════════════════════════"
echo

cd "$PROJECT_DIR"

# ── 0. System dependencies check ──
echo "🔍 Checking system dependencies..."
MISSING=""
command -v python3 &>/dev/null || MISSING="$MISSING python3"
python3 -c "import tkinter" 2>/dev/null || {
    echo "  ⚠  tkinter not found. Install with:"
    echo "     sudo apt install python3-tk       (Debian/Ubuntu)"
    echo "     sudo dnf install python3-tkinter  (Fedora)"
    echo
}

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
if [ ! -f "assets/icon.png" ]; then
    echo "🎨 Generating app icons..."
    python assets/generate_icons.py
fi

# ── 3. Build with PyInstaller ──
echo "🔨 Building application..."
pyinstaller IronRod.spec --noconfirm --clean

# ── 4. Create .tar.gz portable bundle ──
echo "📦 Creating portable tarball..."
cd "$BUILD_DIR"
tar czf "$TARBALL_NAME" "${APP_NAME}/"
cd "$PROJECT_DIR"

# ── 5. Create .deb package ──
echo "📦 Creating .deb package..."
DEB_ROOT="$BUILD_DIR/deb_build"
rm -rf "$DEB_ROOT"
mkdir -p "$DEB_ROOT/DEBIAN"
mkdir -p "$DEB_ROOT/opt/${APP_NAME,,}"
mkdir -p "$DEB_ROOT/usr/local/bin"
mkdir -p "$DEB_ROOT/usr/share/applications"
mkdir -p "$DEB_ROOT/usr/share/icons/hicolor/256x256/apps"

# Copy application files
cp -R "$BUILD_DIR/${APP_NAME}/"* "$DEB_ROOT/opt/${APP_NAME,,}/"

# Create launcher symlink
cat > "$DEB_ROOT/usr/local/bin/${APP_NAME,,}" << 'LAUNCHER'
#!/bin/bash
# IronRod Data Recovery launcher
# Raw disk access requires: sudo ironrod
exec /opt/ironrod/IronRod "$@"
LAUNCHER
chmod +x "$DEB_ROOT/usr/local/bin/${APP_NAME,,}"

# Copy icon
if [ -f "assets/icon.png" ]; then
    cp "assets/icon.png" "$DEB_ROOT/usr/share/icons/hicolor/256x256/apps/${APP_NAME,,}.png"
fi

# Desktop entry
cat > "$DEB_ROOT/usr/share/applications/${APP_NAME,,}.desktop" << EOF
[Desktop Entry]
Name=IronRod Data Recovery
Comment=Recover deleted photos, videos, and files from any storage device
Exec=pkexec /opt/ironrod/IronRod
Icon=${APP_NAME,,}
Terminal=false
Type=Application
Categories=Utility;System;FileTools;
Keywords=recovery;undelete;carve;disk;photo;video;
EOF

# DEBIAN/control
INSTALLED_SIZE=$(du -sk "$DEB_ROOT/opt/${APP_NAME,,}" | cut -f1)
cat > "$DEB_ROOT/DEBIAN/control" << EOF
Package: ${APP_NAME,,}
Version: ${VERSION}
Section: utils
Priority: optional
Architecture: amd64
Installed-Size: ${INSTALLED_SIZE}
Depends: libc6 (>= 2.17), libx11-6, python3-tk
Maintainer: IronRod Team <support@ironrod.dev>
Description: Universal Data Recovery Tool
 Recover deleted photos, videos, documents and more from
 any storage device using raw binary file-signature carving.
 Supports SSD, HDD, USB, SD cards across all major filesystems.
Homepage: https://github.com/ironrod/ironrod
EOF

# DEBIAN/postinst
cat > "$DEB_ROOT/DEBIAN/postinst" << 'EOF'
#!/bin/bash
set -e
chmod +x /opt/ironrod/IronRod
update-desktop-database /usr/share/applications/ 2>/dev/null || true
gtk-update-icon-cache /usr/share/icons/hicolor/ 2>/dev/null || true
EOF
chmod 755 "$DEB_ROOT/DEBIAN/postinst"

# Build .deb
if command -v dpkg-deb &>/dev/null; then
    dpkg-deb --build "$DEB_ROOT" "$BUILD_DIR/$DEB_NAME"
    echo "  ✅ .deb package created"
else
    echo "  ⚠  dpkg-deb not found — skipping .deb creation"
fi

rm -rf "$DEB_ROOT"

# ── 6. Create AppImage (if appimagetool available) ──
echo "📦 Creating AppImage..."
APPDIR="$BUILD_DIR/AppDir"
rm -rf "$APPDIR"
mkdir -p "$APPDIR/usr/bin"
mkdir -p "$APPDIR/usr/share/applications"
mkdir -p "$APPDIR/usr/share/icons/hicolor/256x256/apps"

cp -R "$BUILD_DIR/${APP_NAME}/"* "$APPDIR/usr/bin/"

if [ -f "assets/icon.png" ]; then
    cp "assets/icon.png" "$APPDIR/${APP_NAME,,}.png"
    cp "assets/icon.png" "$APPDIR/usr/share/icons/hicolor/256x256/apps/${APP_NAME,,}.png"
fi

cat > "$APPDIR/${APP_NAME,,}.desktop" << EOF
[Desktop Entry]
Name=IronRod Data Recovery
Exec=IronRod
Icon=${APP_NAME,,}
Type=Application
Categories=Utility;System;
EOF
cp "$APPDIR/${APP_NAME,,}.desktop" "$APPDIR/usr/share/applications/"

# AppRun
cat > "$APPDIR/AppRun" << 'APPRUN'
#!/bin/bash
HERE="$(dirname "$(readlink -f "$0")")"
exec "$HERE/usr/bin/IronRod" "$@"
APPRUN
chmod +x "$APPDIR/AppRun"

if command -v appimagetool &>/dev/null; then
    ARCH=x86_64 appimagetool "$APPDIR" "$BUILD_DIR/$APPIMAGE_NAME"
    echo "  ✅ AppImage created"
else
    echo "  ⚠  appimagetool not found — skipping AppImage creation"
    echo "     Download from: https://github.com/AppImage/AppImageKit/releases"
fi

rm -rf "$APPDIR"

# ── 7. Summary ──
echo
echo "════════════════════════════════════════════════════════════"
echo "  ✅  Linux build complete!"
echo "════════════════════════════════════════════════════════════"
echo
echo "  Portable:   $BUILD_DIR/$TARBALL_NAME"
[ -f "$BUILD_DIR/$DEB_NAME" ] && echo "  Debian:     $BUILD_DIR/$DEB_NAME"
[ -f "$BUILD_DIR/$APPIMAGE_NAME" ] && echo "  AppImage:   $BUILD_DIR/$APPIMAGE_NAME"
echo
echo "  Install .deb:     sudo dpkg -i $DEB_NAME"
echo "  Run AppImage:     chmod +x $APPIMAGE_NAME && ./$APPIMAGE_NAME"
echo "  Run portable:     tar xzf $TARBALL_NAME && ./${APP_NAME}/${APP_NAME}"
echo
echo "  ⚠  Note: Raw disk access requires running with sudo."
echo

deactivate
