@echo off
REM ──────────────────────────────────────────────────────────────
REM Build IronRod for Windows — produces portable EXE + NSIS installer
REM ──────────────────────────────────────────────────────────────

set APP_NAME=IronRod
set VERSION=1.0
set SCRIPT_DIR=%~dp0
set PROJECT_DIR=%SCRIPT_DIR%..
set BUILD_DIR=%PROJECT_DIR%\dist
set INSTALLER_NAME=%APP_NAME%-%VERSION%-Windows-Setup.exe

echo ════════════════════════════════════════════════════════════
echo   🪟  Building %APP_NAME% v%VERSION% for Windows
echo ════════════════════════════════════════════════════════════
echo.

cd /d "%PROJECT_DIR%"

REM ── 1. Python virtual environment ──
if not exist "build_env" (
    echo 📦 Creating build virtual environment...
    python -m venv build_env
)
call build_env\Scripts\activate.bat

echo 📦 Installing dependencies...
pip install --upgrade pip setuptools wheel > NUL 2>&1
pip install -r requirements.txt > NUL 2>&1
pip install -r requirements-build.txt > NUL 2>&1

REM ── 2. Generate icons ──
if not exist "assets\icon.ico" (
    echo 🎨 Generating app icons...
    python assets\generate_icons.py
)

REM ── 3. Build with PyInstaller ──
echo 🔨 Building application...
pyinstaller IronRod.spec --noconfirm --clean

REM ── 4. Create NSIS installer (if NSIS is installed) ──
where makensis >nul 2>&1
if %ERRORLEVEL% equ 0 (
    echo 📀 Creating NSIS installer...
    makensis /DVERSION=%VERSION% /DOUTFILE="%BUILD_DIR%\%INSTALLER_NAME%" scripts\installer.nsi
) else (
    echo ⚠  NSIS not found — skipping installer creation.
    echo    Install NSIS from https://nsis.sourceforge.io/
    echo    Or distribute the portable folder: %BUILD_DIR%\%APP_NAME%\
)

REM ── 5. Create portable ZIP ──
echo 📦 Creating portable ZIP...
cd "%BUILD_DIR%"
if exist "%APP_NAME%-%VERSION%-Windows-Portable.zip" del "%APP_NAME%-%VERSION%-Windows-Portable.zip"
powershell -Command "Compress-Archive -Path '%APP_NAME%' -DestinationPath '%APP_NAME%-%VERSION%-Windows-Portable.zip' -Force"
cd /d "%PROJECT_DIR%"

REM ── 6. Build MSIX package (requires Windows SDK) ──
echo 📦 Building MSIX package...
powershell -ExecutionPolicy Bypass -File scripts\package_msix.ps1
if %ERRORLEVEL% neq 0 (
    echo ⚠  MSIX packaging failed or Windows SDK not found.
    echo    Install Windows SDK: https://developer.microsoft.com/windows/downloads/windows-sdk/
    echo    Then run: scripts\build_msix.bat
)

REM ── 7. Summary ──
echo.
echo ════════════════════════════════════════════════════════════
echo   ✅  Windows build complete!
echo ════════════════════════════════════════════════════════════
echo.
echo   Portable:   %BUILD_DIR%\%APP_NAME%-%VERSION%-Windows-Portable.zip
if exist "%BUILD_DIR%\%INSTALLER_NAME%" (
    echo   Installer:  %BUILD_DIR%\%INSTALLER_NAME%
)
if exist "%BUILD_DIR%\%APP_NAME%-%VERSION%-Windows.msix" (
    echo   MSIX:       %BUILD_DIR%\%APP_NAME%-%VERSION%-Windows.msix
)
echo.
echo   ⚠  Note: Raw disk access requires running as Administrator.
echo      Right-click → Run as Administrator
echo.
echo   ℹ  For a verified (no SmartScreen warning) MSIX:
echo      1. Get an EV Code Signing cert from DigiCert/Sectigo
echo      2. Run: scripts\build_msix.bat /cert:"C:\path\to.pfx" /pass:"password"
echo.

call deactivate
