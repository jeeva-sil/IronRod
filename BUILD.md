# Building IronRod — Cross-Platform Installers

This document explains how to build IronRod as a standalone installable application for **macOS**, **Windows**, and **Linux**.

---

## Prerequisites

- **Python 3.10+**
- **pip** (Python package manager)

Install build dependencies:
```bash
pip install -r requirements-build.txt
```

---

## 🍎 macOS — DMG Installer

### Quick Build
```bash
chmod +x scripts/build_macos.sh
./scripts/build_macos.sh
```

### Output
| File | Description |
|------|-------------|
| `dist/IronRod.app` | macOS application bundle |
| `dist/IronRod-1.0.0-macOS.dmg` | Drag-and-drop DMG installer |

### Install
1. Open the `.dmg`
2. Drag **IronRod** into **Applications**
3. For raw disk access: `sudo /Applications/IronRod.app/Contents/MacOS/IronRod`

### Optional
- Install `create-dmg` for a polished DMG: `brew install create-dmg`

---

## 🪟 Windows — EXE Installer + Portable ZIP

### Quick Build
```cmd
scripts\build_windows.bat
```

### Output
| File | Description |
|------|-------------|
| `dist\IronRod\` | Portable application folder |
| `dist\IronRod-1.0.0-Windows-Portable.zip` | Portable ZIP (no install needed) |
| `dist\IronRod-1.0.0-Windows-Setup.exe` | NSIS installer (requires NSIS) |

### Install
- **Portable**: Extract ZIP → run `IronRod.exe`
- **Installer**: Run the Setup EXE → installs to Program Files, adds Start Menu & Desktop shortcuts

### Optional
- Install [NSIS](https://nsis.sourceforge.io/) for the Setup EXE installer
- Run as Administrator for raw disk access

---

## 🐧 Linux — AppImage + .deb + Portable Tarball

### Quick Build
```bash
chmod +x scripts/build_linux.sh
./scripts/build_linux.sh
```

### System Dependencies
```bash
# Debian/Ubuntu
sudo apt install python3-tk python3-venv

# Fedora
sudo dnf install python3-tkinter
```

### Output
| File | Description |
|------|-------------|
| `dist/IronRod-1.0.0-Linux-x86_64.tar.gz` | Portable tarball |
| `dist/ironrod_1.0.0_amd64.deb` | Debian/Ubuntu package |
| `dist/IronRod-1.0.0-Linux-x86_64.AppImage` | Universal AppImage |

### Install
```bash
# AppImage (any distro)
chmod +x IronRod-1.0.0-Linux-x86_64.AppImage
./IronRod-1.0.0-Linux-x86_64.AppImage

# Debian/Ubuntu
sudo dpkg -i ironrod_1.0.0_amd64.deb

# Portable
tar xzf IronRod-1.0.0-Linux-x86_64.tar.gz
./IronRod/IronRod
```

### Optional
- Install [appimagetool](https://github.com/AppImage/AppImageKit/releases) for AppImage creation

---

## 🔄 Automated CI/CD Builds (GitHub Actions)

The repository includes a GitHub Actions workflow that **automatically builds for all platforms** when you push a version tag:

```bash
git tag v1.0.0
git push origin v1.0.0
```

This triggers builds on:
- macOS (Intel + Apple Silicon)
- Windows (x64)
- Linux (x64)

All artifacts are attached to a **draft GitHub Release** for review and publishing.

### Manual Trigger
You can also trigger builds manually from the GitHub Actions tab → "Build & Release" → "Run workflow".

---

## 🎨 App Icon

Generate icons for all platforms:
```bash
python assets/generate_icons.py                  # Auto-generated icon
python assets/generate_icons.py my_logo.png      # Custom logo
```

This creates:
- `assets/icon.png` — Linux / source (1024×1024)
- `assets/icon.ico` — Windows (multi-size)
- `assets/icon.icns` — macOS

---

## Project Structure (Build Files)

```
IronRod.spec                    # PyInstaller build specification
requirements-build.txt          # Build-time dependencies
BUILD.md                        # This file
assets/
  generate_icons.py             # Icon generator script
  icon.png / .ico / .icns       # App icons (generated)
scripts/
  build_macos.sh                # macOS build script
  build_windows.bat             # Windows build script
  build_linux.sh                # Linux build script
  installer.nsi                 # Windows NSIS installer script
.github/
  workflows/
    build-release.yml           # CI/CD for all platforms
```

---

## Troubleshooting

### "python: command not found" under sudo
Use `python3` explicitly, or use the full path:
```bash
sudo $(which python3) main.py
```

### tkinter not found
```bash
# macOS — comes with Python from python.org; if using brew:
brew install python-tk

# Ubuntu/Debian
sudo apt install python3-tk

# Fedora
sudo dnf install python3-tkinter
```

### PyInstaller "hidden import" errors
If a module isn't found at runtime, add it to `hiddenimports` in `IronRod.spec`.

### macOS Gatekeeper blocks the app
Since the app isn't code-signed, users may need:
```bash
xattr -cr /Applications/IronRod.app
```
Or: System Preferences → Security & Privacy → "Open Anyway"

### Windows SmartScreen warning
Without code-signing, Windows will show a SmartScreen warning. Users click "More info" → "Run anyway". For production, consider purchasing an EV code-signing certificate.
