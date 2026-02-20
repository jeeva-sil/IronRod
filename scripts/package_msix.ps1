#Requires -Version 5.1
<#
.SYNOPSIS
    IronRod MSIX Packager — builds and signs an MSIX package using MakeAppx + SignTool.

.DESCRIPTION
    This script is a PowerShell alternative to build_msix.bat with better error reporting
    and flexibility. It handles:
      - Locating Windows SDK tools automatically
      - Staging app files + manifest + assets
      - Creating the MSIX with MakeAppx.exe
      - Signing with a PFX certificate or cert from store
      - Optionally opening the output folder when done

.PARAMETER CertPfx
    Path to PFX certificate file for signing.
    Leave empty to use msix\ironrod_dev_cert.pfx (created by create_cert.ps1).

.PARAMETER CertPassword
    Password for the PFX file. Not needed if using cert from the Windows cert store.

.PARAMETER CertThumbprint
    Thumbprint of a certificate already installed in the Windows cert store.
    Use this instead of CertPfx if you have an EV cert on a hardware token.

.PARAMETER SkipSign
    Create the MSIX without signing (for testing manifest/structure only).

.PARAMETER OpenFolder
    Open the dist\ folder in Explorer when done.

.EXAMPLE
    # Dev build with self-signed cert
    powershell -ExecutionPolicy Bypass -File scripts\package_msix.ps1

    # Production build with EV cert from store (hardware token)
    powershell -ExecutionPolicy Bypass -File scripts\package_msix.ps1 `
        -CertThumbprint "ABCDEF1234567890..."

    # Production build with PFX file
    powershell -ExecutionPolicy Bypass -File scripts\package_msix.ps1 `
        -CertPfx "C:\certs\mycompany.pfx" -CertPassword "MyP@ssword"
#>

param(
    [string]$CertPfx        = "",
    [string]$CertPassword   = "",
    [string]$CertThumbprint = "",
    [switch]$SkipSign,
    [switch]$OpenFolder
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Configuration ─────────────────────────────────────────────
$AppName       = "IronRod"
$Version       = "1.0.0.0"
$VersionShort  = "1.0"
$PublisherCN   = "CN=IronRod Team"
$TimestampUrl  = "http://timestamp.digicert.com"

$ProjectDir    = Split-Path $PSScriptRoot -Parent
$DistDir       = Join-Path $ProjectDir "dist"
$AppDir        = Join-Path $DistDir $AppName
$StagingDir    = Join-Path $DistDir "msix_staging"
$ManifestSrc   = Join-Path $ProjectDir "msix\AppxManifest.xml"
$AssetsSrc     = Join-Path $ProjectDir "msix\Assets"
$MsixOut       = Join-Path $DistDir "$AppName-$VersionShort-Windows.msix"
$DevCertPfx    = Join-Path $ProjectDir "msix\ironrod_dev_cert.pfx"
$DevCertPass   = "IronRodDev"

# ── Banner ────────────────────────────────────────────────────
Write-Host ""
Write-Host "════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "   📦  IronRod MSIX Packager v$VersionShort" -ForegroundColor Cyan
Write-Host "════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

# ── Step 1: Find Windows SDK tools ───────────────────────────
function Find-SdkTool {
    param([string]$ToolName)

    # Try PATH first
    $inPath = Get-Command $ToolName -ErrorAction SilentlyContinue
    if ($inPath) { return $inPath.Source }

    # Search Windows Kits directories
    $sdkRoots = @(
        "C:\Program Files (x86)\Windows Kits\10\bin",
        "C:\Program Files\Windows Kits\10\bin"
    )
    foreach ($root in $sdkRoots) {
        if (-not (Test-Path $root)) { continue }
        # Get newest SDK version
        $versions = Get-ChildItem $root -Directory | Where-Object { $_.Name -match "^10\." } |
                    Sort-Object Name -Descending
        foreach ($ver in $versions) {
            foreach ($arch in @("x64","x86","arm64")) {
                $p = Join-Path $ver.FullName "$arch\$ToolName"
                if (Test-Path $p) { return $p }
            }
        }
    }
    return $null
}

$MakeAppx = Find-SdkTool "makeappx.exe"
$SignTool  = Find-SdkTool "signtool.exe"

if (-not $MakeAppx) {
    Write-Host "❌  MakeAppx.exe not found." -ForegroundColor Red
    Write-Host "    Install Windows SDK: https://developer.microsoft.com/windows/downloads/windows-sdk/" -ForegroundColor Yellow
    exit 1
}
Write-Host "✅  MakeAppx : $MakeAppx"
Write-Host "✅  SignTool  : $($SignTool ?? '(not found)')"

# ── Step 2: Verify PyInstaller output ────────────────────────
$AppExe = Join-Path $AppDir "$AppName.exe"
if (-not (Test-Path $AppExe)) {
    Write-Host "❌  $AppExe not found." -ForegroundColor Red
    Write-Host "    Run: scripts\build_windows.bat first." -ForegroundColor Yellow
    exit 1
}
Write-Host "✅  App build : $AppDir"

# ── Step 3: Generate MSIX assets if missing ───────────────────
if (-not (Test-Path (Join-Path $AssetsSrc "Square150x150Logo.png"))) {
    Write-Host "🎨  Generating MSIX icon assets..."
    $iconScript = Join-Path $PSScriptRoot "generate_msix_assets.py"
    & python $iconScript
    if ($LASTEXITCODE -ne 0) {
        Write-Host "⚠   Asset generation failed. Continuing without scaled assets." -ForegroundColor Yellow
    }
}

# ── Step 4: Prepare staging directory ────────────────────────
Write-Host "📁  Preparing staging directory..."
if (Test-Path $StagingDir) { Remove-Item $StagingDir -Recurse -Force }
New-Item -ItemType Directory -Path $StagingDir | Out-Null

# Copy app files
Copy-Item "$AppDir\*" $StagingDir -Recurse -Force

# Copy manifest
if (-not (Test-Path $ManifestSrc)) {
    Write-Host "❌  AppxManifest.xml not found at: $ManifestSrc" -ForegroundColor Red
    exit 1
}
Copy-Item $ManifestSrc (Join-Path $StagingDir "AppxManifest.xml") -Force

# Copy MSIX assets
$stagingAssets = Join-Path $StagingDir "Assets"
New-Item -ItemType Directory -Path $stagingAssets -Force | Out-Null
if (Test-Path $AssetsSrc) {
    Copy-Item "$AssetsSrc\*" $stagingAssets -Recurse -Force
} else {
    Write-Host "⚠   msix\Assets\ not found. Run: python scripts\generate_msix_assets.py" -ForegroundColor Yellow
}

Write-Host "✅  Staging: $StagingDir"

# ── Step 5: Pack MSIX ─────────────────────────────────────────
Write-Host "📦  Packing MSIX..."
if (Test-Path $MsixOut) { Remove-Item $MsixOut -Force }

& $MakeAppx pack /d $StagingDir /p $MsixOut /nv /o
if ($LASTEXITCODE -ne 0) {
    Write-Host "❌  MakeAppx failed. Check staging directory for issues." -ForegroundColor Red
    exit 1
}
Write-Host "✅  Packed: $MsixOut"

# ── Step 6: Sign MSIX ─────────────────────────────────────────
if ($SkipSign) {
    Write-Host "⚠   Skipping signing (--SkipSign specified)." -ForegroundColor Yellow
} elseif (-not $SignTool) {
    Write-Host "⚠   SignTool not found — MSIX will be unsigned." -ForegroundColor Yellow
} else {
    Write-Host "🔏  Signing MSIX..."

    $signArgs = @("sign", "/fd", "SHA256")

    if ($CertThumbprint) {
        # Sign using cert from Windows cert store (best for EV on hardware token)
        $signArgs += @("/sha1", $CertThumbprint, "/sm")
        Write-Host "    Using cert store thumbprint: $CertThumbprint"
    } elseif ($CertPfx) {
        # Sign using provided PFX
        $signArgs += @("/f", $CertPfx)
        if ($CertPassword) { $signArgs += @("/p", $CertPassword) }
        Write-Host "    Using PFX: $CertPfx"
    } elseif (Test-Path $DevCertPfx) {
        # Fallback to dev cert
        $signArgs += @("/f", $DevCertPfx, "/p", $DevCertPass)
        Write-Host "    Using dev cert: $DevCertPfx" -ForegroundColor Yellow
    } else {
        Write-Host ""
        Write-Host "⚠   No certificate found for signing." -ForegroundColor Yellow
        Write-Host "    Create a dev cert:   powershell -ExecutionPolicy Bypass -File scripts\create_cert.ps1" -ForegroundColor Cyan
        Write-Host "    Use a PFX:           -CertPfx 'path.pfx' -CertPassword 'pass'" -ForegroundColor Cyan
        Write-Host "    Use store cert:      -CertThumbprint 'ABCDEF...'" -ForegroundColor Cyan
        Write-Host ""
        goto done
    }

    # Timestamp for long-lived signature
    $signArgs += @("/tr", $TimestampUrl, "/td", "SHA256")
    $signArgs += $MsixOut

    & $SignTool @signArgs
    if ($LASTEXITCODE -ne 0) {
        Write-Host "❌  Signing failed." -ForegroundColor Red
        Write-Host "    Ensure the Publisher in AppxManifest.xml matches the cert Subject:" -ForegroundColor Yellow
        Write-Host "    Expected: $PublisherCN" -ForegroundColor Yellow
        exit 1
    }
    Write-Host "✅  Signed successfully."
}

:done

# ── Step 7: Cleanup staging ───────────────────────────────────
Remove-Item $StagingDir -Recurse -Force

# ── Step 8: Summary ───────────────────────────────────────────
$sizeMB = [math]::Round((Get-Item $MsixOut).Length / 1MB, 1)
Write-Host ""
Write-Host "════════════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host "   ✅  MSIX build complete!" -ForegroundColor Green
Write-Host "════════════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host ""
Write-Host "   Output : $MsixOut"
Write-Host "   Size   : $sizeMB MB"
Write-Host ""
Write-Host "   Install: Double-click the .msix file" -ForegroundColor Cyan
Write-Host "            (No SmartScreen warning if signed with trusted cert)" -ForegroundColor Cyan
Write-Host ""
Write-Host "   ⚠  Raw disk access still requires running as Administrator." -ForegroundColor Yellow
Write-Host ""

if ($OpenFolder) { Start-Process explorer.exe $DistDir }
