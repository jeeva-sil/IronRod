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

## 🪟 Windows — MSIX (Verified) + EXE Installer + Portable ZIP

### Quick Build (all formats)
```cmd
scripts\build_windows.bat
```

### Output
| File | Description |
|------|-------------|
| `dist\IronRod\` | Portable application folder |
| `dist\IronRod-1.0-Windows-Portable.zip` | Portable ZIP (no install needed) |
| `dist\IronRod-1.0-Windows-Setup.exe` | NSIS installer (requires NSIS) |
| `dist\IronRod-1.0-Windows.msix` | **MSIX package — clean verified install** |

### Install
- **MSIX** *(recommended)*: Double-click `.msix` → clean Windows installer, no SmartScreen warning (with trusted cert)
- **Portable**: Extract ZIP → run `IronRod.exe`
- **Installer**: Run the Setup EXE → installs to Program Files, adds Start Menu & Desktop shortcuts

---

## 🔏 MSIX Code Signing (Removing "Unverified App" Warning)

Windows shows an "unverified app" warning when an MSIX isn't signed with a **trusted certificate**.
There are two paths to eliminate it:

---

### Option A — Self-Signed Certificate (Dev / Testing only)

Works **only on machines where the certificate is manually installed**. Good for internal testing.

**Step 1: Create and install the dev certificate** *(run once on each test machine)*
```powershell
# Run in PowerShell as Administrator
powershell -ExecutionPolicy Bypass -File scripts\create_cert.ps1
```

**Step 2: Build the app**
```cmd
scripts\build_windows.bat
```

**Step 3: Build the MSIX** *(auto-uses dev cert)*
```cmd
scripts\build_msix.bat
```
Or via PowerShell directly:
```powershell
powershell -ExecutionPolicy Bypass -File scripts\package_msix.ps1
```

**To trust on another machine**, copy `msix\ironrod_dev_cert.cer` there and run:
```powershell
powershell -ExecutionPolicy Bypass -File scripts\create_cert.ps1 -InstallOnly
```

---

### Option B — Trusted Code Signing Certificate (Production — no warning for anyone)

Purchase an **EV Code Signing Certificate** from a CA. This immediately removes the SmartScreen
warning for **all users worldwide**, no cert installation needed.

| Provider | Link | ~Cost/year |
|----------|------|-----------|
| DigiCert EV | https://www.digicert.com/signing/code-signing-certificates | $499 |
| Sectigo EV | https://sectigo.com/ssl-certificates-tls/code-signing | $299 |
| GlobalSign EV | https://www.globalsign.com/en/code-signing-certificate | $349 |

> **Standard OV certificates** (~$100–200/year) also work but may need SmartScreen reputation
> to build before the warning disappears. EV certs skip this entirely.

**Step 1: Update `msix/AppxManifest.xml`** — set `Publisher` to match your cert's Subject:
```xml
<Identity
  Name="IronRod.DataRecovery"
  Publisher="CN=Your Company LLC, O=Your Company, C=US"
  Version="1.0.0.0"
  ProcessorArchitecture="x64" />
```

**Step 2: Build**
```cmd
scripts\build_windows.bat
```

**Step 3: Sign with PFX file**
```cmd
scripts\build_msix.bat /cert:"C:\path\to\yourcert.pfx" /pass:"pfx_password"
```

**Or sign with an EV cert on a hardware token** (USB dongle):
```powershell
# Find your cert thumbprint first
Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Subject -like "*YourCompany*" }

# Then sign
powershell -ExecutionPolicy Bypass -File scripts\package_msix.ps1 -CertThumbprint "ABCDEF1234..."
```

---

### Option C — Microsoft Store

Submit to the [Microsoft Store](https://partner.microsoft.com/dashboard) — Microsoft signs and
distributes the app. Free for individuals, $19 one-time registration for companies.
The app is then installable from the Store with zero warnings.

---

### MSIX Build Files Structure

```
msix/
  AppxManifest.xml          ← MSIX package manifest (edit Publisher here)
  Assets/                   ← Generated icon assets (auto-created by build)
  ironrod_dev_cert.pfx      ← Dev certificate (created by create_cert.ps1, git-ignored)
  ironrod_dev_cert.cer      ← Public key for distribution to test machines
scripts/
  build_msix.bat            ← One-step MSIX build + sign script
  package_msix.ps1          ← PowerShell MSIX packager (more options)
  create_cert.ps1           ← Create/install self-signed dev certificate
  generate_msix_assets.py   ← Generate required icon sizes for MSIX
```

### Prerequisites for MSIX
- **Windows SDK** — for `MakeAppx.exe` and `SignTool.exe`
  Download: https://developer.microsoft.com/windows/downloads/windows-sdk/
- **Python + Pillow** — for icon asset generation (`pip install Pillow`)

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
msix/
  AppxManifest.xml              # MSIX package manifest
  Assets/                       # MSIX icon assets (generated)
  ironrod_dev_cert.pfx/.cer     # Dev signing cert (git-ignored)
scripts/
  build_macos.sh                # macOS build script
  build_windows.bat             # Windows build script (EXE + MSIX)
  build_linux.sh                # Linux build script
  build_msix.bat                # MSIX-only build + sign script
  package_msix.ps1              # PowerShell MSIX packager (advanced)
  create_cert.ps1               # Self-signed dev certificate creator
  generate_msix_assets.py       # MSIX icon asset generator
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

### Windows "unverified app" / SmartScreen warning
Use the MSIX packaging workflow above. For public distribution without any warning, purchase an
EV Code Signing certificate and sign the MSIX with it. See the **MSIX Code Signing** section above.

### MSIX install error: "The app couldn't be installed because the app publisher is not trusted"
The signing certificate is not trusted on that machine. Either:
1. Install the dev certificate: `powershell -ExecutionPolicy Bypass -File scripts\create_cert.ps1 -InstallOnly`
2. Or use a trusted EV certificate for signing (see Option B above)

### MSIX error: "The Publisher in the manifest does not match the signing certificate"
The `Publisher` in `msix\AppxManifest.xml` must be an **exact match** (case-sensitive) to the
Subject of the signing certificate. Check both and make them identical.
