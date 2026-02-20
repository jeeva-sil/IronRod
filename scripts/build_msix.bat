@echo off
REM ══════════════════════════════════════════════════════════════
REM  IronRod — MSIX Package Builder
REM  Produces a signed MSIX installer that Windows trusts.
REM
REM  Prerequisites:
REM    1. Run build_windows.bat first (to build dist\IronRod\)
REM    2. Windows SDK installed (for MakeAppx.exe + SignTool.exe)
REM       https://developer.microsoft.com/windows/downloads/windows-sdk/
REM    3. A signing certificate (see scripts\create_cert.ps1 for dev cert)
REM
REM  Usage:
REM    scripts\build_msix.bat
REM    scripts\build_msix.bat /cert:"C:\path\to\cert.pfx" /pass:"pfx_password"
REM
REM  Output:
REM    dist\IronRod-1.0.0-Windows.msix   ← signed MSIX package
REM ══════════════════════════════════════════════════════════════
setlocal EnableDelayedExpansion

set APP_NAME=IronRod
set VERSION=1.0.0.0
set VERSION_SHORT=1.0
set PUBLISHER_NAME=IronRod Team
set PUBLISHER_CN=CN=IronRod Team

set SCRIPT_DIR=%~dp0
set PROJECT_DIR=%SCRIPT_DIR%..
set DIST_DIR=%PROJECT_DIR%\dist
set MSIX_STAGING=%PROJECT_DIR%\dist\msix_staging
set MSIX_OUT=%DIST_DIR%\%APP_NAME%-%VERSION_SHORT%-Windows.msix

REM ── Parse optional arguments ──────────────────────────────────
set CERT_PFX=
set CERT_PASS=
:parse_args
if "%~1"=="" goto done_args
if /i "%~1"=="/cert" (set CERT_PFX=%~2& shift & shift & goto parse_args)
if /i "%~1"=="/pass" (set CERT_PASS=%~2& shift & shift & goto parse_args)
shift & goto parse_args
:done_args

echo.
echo ════════════════════════════════════════════════════════════
echo   📦  Building %APP_NAME% MSIX v%VERSION_SHORT%
echo ════════════════════════════════════════════════════════════
echo.

cd /d "%PROJECT_DIR%"

REM ── 1. Verify PyInstaller output exists ───────────────────────
if not exist "%DIST_DIR%\%APP_NAME%\%APP_NAME%.exe" (
    echo ❌  Error: %DIST_DIR%\%APP_NAME%\%APP_NAME%.exe not found.
    echo     Run scripts\build_windows.bat first to build the app.
    exit /b 1
)
echo ✅  PyInstaller build found: %DIST_DIR%\%APP_NAME%\

REM ── 2. Find Windows SDK tools ─────────────────────────────────
call :FindSDKTools
if "%MAKEAPPX%"=="" (
    echo ❌  MakeAppx.exe not found. Install Windows SDK:
    echo     https://developer.microsoft.com/windows/downloads/windows-sdk/
    echo.
    echo     Or run MSIX packaging via PowerShell:
    echo       powershell -ExecutionPolicy Bypass -File scripts\package_msix.ps1
    exit /b 1
)
echo ✅  MakeAppx.exe: %MAKEAPPX%
echo ✅  SignTool.exe:  %SIGNTOOL%

REM ── 3. Generate MSIX assets if missing ───────────────────────
if not exist "%PROJECT_DIR%\msix\Assets\Square150x150Logo.png" (
    echo 🎨  Generating MSIX icon assets...
    python scripts\generate_msix_assets.py
    if errorlevel 1 (
        echo ⚠   Asset generation failed. Using fallback icons.
    )
)

REM ── 4. Prepare staging directory ─────────────────────────────
echo 📁  Preparing MSIX staging directory...
if exist "%MSIX_STAGING%" rmdir /s /q "%MSIX_STAGING%"
mkdir "%MSIX_STAGING%"

REM  Copy app files from PyInstaller dist
xcopy /s /e /q "%DIST_DIR%\%APP_NAME%\*" "%MSIX_STAGING%\"
if errorlevel 1 (
    echo ❌  Failed to copy app files to staging.
    exit /b 1
)

REM  Copy MSIX manifest
copy /y "%PROJECT_DIR%\msix\AppxManifest.xml" "%MSIX_STAGING%\AppxManifest.xml"
if errorlevel 1 (
    echo ❌  Failed to copy AppxManifest.xml
    exit /b 1
)

REM  Copy MSIX assets folder
if exist "%PROJECT_DIR%\msix\Assets" (
    xcopy /s /e /q "%PROJECT_DIR%\msix\Assets\*" "%MSIX_STAGING%\Assets\"
) else (
    echo ⚠   No msix\Assets\ folder found. Run: python scripts\generate_msix_assets.py
    mkdir "%MSIX_STAGING%\Assets"
    REM  Use the main icon as a fallback for all asset slots
    copy /y "%PROJECT_DIR%\assets\icon.ico" "%MSIX_STAGING%\Assets\icon.ico" >nul 2>&1
)

echo ✅  Staging ready: %MSIX_STAGING%

REM ── 5. Pack MSIX ─────────────────────────────────────────────
echo 📦  Packing MSIX...
if exist "%MSIX_OUT%" del /q "%MSIX_OUT%"

"%MAKEAPPX%" pack /d "%MSIX_STAGING%" /p "%MSIX_OUT%" /nv /o
if errorlevel 1 (
    echo ❌  MakeAppx.exe failed. Check the staging directory for issues.
    exit /b 1
)
echo ✅  MSIX packed: %MSIX_OUT%

REM ── 6. Sign MSIX ─────────────────────────────────────────────
echo 🔏  Signing MSIX...

if "%CERT_PFX%"=="" (
    REM  No cert provided — look for auto-generated dev cert
    set DEV_CERT=%PROJECT_DIR%\msix\ironrod_dev_cert.pfx
    if exist "!DEV_CERT!" (
        set CERT_PFX=!DEV_CERT!
        set CERT_PASS=IronRodDev
        echo ℹ   Using dev certificate: !DEV_CERT!
    ) else (
        echo.
        echo ⚠   No signing certificate found.
        echo.
        echo     For DEV testing (self-signed):
        echo       powershell -ExecutionPolicy Bypass -File scripts\create_cert.ps1
        echo       Then re-run this script.
        echo.
        echo     For PRODUCTION (trusted on all PCs):
        echo       Purchase an EV Code Signing cert from DigiCert or Sectigo.
        echo       Then run:
        echo         scripts\build_msix.bat /cert:"C:\path\to\cert.pfx" /pass:"password"
        echo.
        goto done_nosign
    )
)

if "%CERT_PASS%"=="" (
    "%SIGNTOOL%" sign /fd SHA256 /a /f "%CERT_PFX%" /tr http://timestamp.digicert.com /td SHA256 "%MSIX_OUT%"
) else (
    "%SIGNTOOL%" sign /fd SHA256 /f "%CERT_PFX%" /p "%CERT_PASS%" /tr http://timestamp.digicert.com /td SHA256 "%MSIX_OUT%"
)

if errorlevel 1 (
    echo ❌  Signing failed. Verify the certificate matches the Publisher in AppxManifest.xml
    echo     Publisher in manifest: %PUBLISHER_CN%
    exit /b 1
)
echo ✅  MSIX signed successfully.

:done_nosign

REM ── 7. Cleanup staging ───────────────────────────────────────
rmdir /s /q "%MSIX_STAGING%"

REM ── 8. Summary ───────────────────────────────────────────────
echo.
echo ════════════════════════════════════════════════════════════
echo   ✅  MSIX build complete!
echo ════════════════════════════════════════════════════════════
echo.
echo   Output: %MSIX_OUT%
echo.

if "%CERT_PFX%"=="" (
    echo   ⚠  UNSIGNED — install will show certificate warning.
    echo.
) else (
    echo   Installation:
    echo     Double-click the .msix file — Windows will show a clean
    echo     installer without SmartScreen warning (if cert is trusted).
    echo.
    echo   For DEV cert: install the cert to Trusted Root first:
    echo     powershell -ExecutionPolicy Bypass -File scripts\create_cert.ps1 -InstallOnly
    echo.
)
echo   Note: Raw disk access requires running as Administrator.
echo.
goto :eof

REM ════════════════════════════════════════════════════════════
REM  Subroutine: Find Windows SDK tools (MakeAppx + SignTool)
REM ════════════════════════════════════════════════════════════
:FindSDKTools
set MAKEAPPX=
set SIGNTOOL=

REM Try PATH first
where makeappx.exe >nul 2>&1
if %ERRORLEVEL%==0 (
    set MAKEAPPX=makeappx.exe
    set SIGNTOOL=signtool.exe
    goto :eof
)

REM Search Windows Kits
set SDK_ROOT=C:\Program Files (x86)\Windows Kits\10\bin
if not exist "%SDK_ROOT%" set SDK_ROOT=C:\Program Files\Windows Kits\10\bin

REM Find newest SDK version (sort descending)
set NEWEST_SDK=
for /d %%D in ("%SDK_ROOT%\10.*") do set NEWEST_SDK=%%D

if "%NEWEST_SDK%"=="" goto :eof

REM Check x64 first, then x86
if exist "%NEWEST_SDK%\x64\makeappx.exe" (
    set MAKEAPPX=%NEWEST_SDK%\x64\makeappx.exe
    set SIGNTOOL=%NEWEST_SDK%\x64\signtool.exe
    goto :eof
)
if exist "%NEWEST_SDK%\x86\makeappx.exe" (
    set MAKEAPPX=%NEWEST_SDK%\x86\makeappx.exe
    set SIGNTOOL=%NEWEST_SDK%\x86\signtool.exe
)
goto :eof
