#Requires -Version 5.1
<#
.SYNOPSIS
    Creates a self-signed code signing certificate for MSIX development/testing.

.DESCRIPTION
    For DEVELOPMENT / TESTING:
      This script creates a self-signed certificate, exports it as a PFX,
      and optionally installs it to the Trusted Root store so Windows trusts it.

    For PRODUCTION (verifying app for all users, no warning):
      Purchase an EV Code Signing certificate from a trusted CA:
        ● DigiCert EV Code Signing  – https://www.digicert.com/signing/code-signing-certificates
        ● Sectigo EV Code Signing   – https://sectigo.com/ssl-certificates-tls/code-signing
        ● GlobalSign EV Signing     – https://www.globalsign.com/en/code-signing-certificate
      Cost: ~$300–500/year for EV. EV certs immediately bypass SmartScreen for everyone.
      Standard OV certs (~$100–200/year) remove the "unknown publisher" dialog from MSIX
      but may still require SmartScreen reputation building.

    After creating a production cert, update msix\AppxManifest.xml:
      Publisher="CN=Your Company, O=Your Company LLC, L=City, S=State, C=US"

.PARAMETER CertSubject
    The Subject (CN) for the certificate. Must match Publisher in AppxManifest.xml.

.PARAMETER OutputDir
    Directory to save the PFX and CER files. Defaults to msix\ folder.

.PARAMETER Password
    Password for the exported PFX file.

.PARAMETER InstallOnly
    Skip creation, just install an existing cert to Trusted Root (for other machines).

.PARAMETER CertFile
    Path to an existing CER file to install (used with -InstallOnly).

.EXAMPLE
    # Create dev cert and install it locally
    powershell -ExecutionPolicy Bypass -File scripts\create_cert.ps1

    # Create dev cert only (no install — for CI)
    powershell -ExecutionPolicy Bypass -File scripts\create_cert.ps1 -NoInstall

    # Install existing cert on another machine
    powershell -ExecutionPolicy Bypass -File scripts\create_cert.ps1 `
        -InstallOnly -CertFile "msix\ironrod_dev_cert.cer"
#>

param(
    [string]$CertSubject = "CN=IronRod Team",
    [string]$OutputDir   = "",
    [string]$Password    = "IronRodDev",
    [switch]$InstallOnly,
    [switch]$NoInstall,
    [string]$CertFile    = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ProjectDir = Split-Path $PSScriptRoot -Parent
if (-not $OutputDir) { $OutputDir = Join-Path $ProjectDir "msix" }

$PfxPath = Join-Path $OutputDir "ironrod_dev_cert.pfx"
$CerPath = Join-Path $OutputDir "ironrod_dev_cert.cer"

Write-Host ""
Write-Host "════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "   🔐  IronRod Code Signing Certificate Manager" -ForegroundColor Cyan
Write-Host "════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

# ═══════════════════════════════════════════════════════════════
#  INSTALL ONLY mode — install existing CER to Trusted Root
# ═══════════════════════════════════════════════════════════════
if ($InstallOnly) {
    $target = if ($CertFile) { $CertFile } else { $CerPath }
    if (-not (Test-Path $target)) {
        Write-Host "❌  Certificate file not found: $target" -ForegroundColor Red
        exit 1
    }

    Write-Host "🔒  Installing certificate to Trusted Root..." -ForegroundColor Yellow
    Write-Host "    (Requires Administrator — you may see a UAC prompt)" -ForegroundColor Gray

    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($target)
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store(
        [System.Security.Cryptography.X509Certificates.StoreName]::Root,
        [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine
    )
    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
    $store.Add($cert)
    $store.Close()

    Write-Host "✅  Certificate installed to Local Machine Trusted Root." -ForegroundColor Green
    Write-Host "    Windows will now trust MSIX packages signed with this cert." -ForegroundColor Green
    exit 0
}

# ═══════════════════════════════════════════════════════════════
#  CREATE a new self-signed certificate
# ═══════════════════════════════════════════════════════════════
Write-Host "📋  Certificate Subject : $CertSubject"
Write-Host "📁  Output directory    : $OutputDir"
Write-Host ""
Write-Host "⚠   SELF-SIGNED CERTIFICATE — for development/testing only." -ForegroundColor Yellow
Write-Host "    For production distribution, use an EV Code Signing cert from a CA." -ForegroundColor Yellow
Write-Host ""

# Create output dir if needed
if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory $OutputDir | Out-Null }

# Check if cert already exists in store
$existing = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Subject -eq $CertSubject }
if ($existing) {
    Write-Host "ℹ   Found existing cert in store: $($existing.Thumbprint)"
    $cert = $existing[0]
} else {
    Write-Host "🔑  Creating self-signed code signing certificate..."
    $cert = New-SelfSignedCertificate `
        -Subject          $CertSubject `
        -Type             CodeSigningCert `
        -KeyAlgorithm     RSA `
        -KeyLength        4096 `
        -HashAlgorithm    SHA256 `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -KeyExportPolicy  Exportable `
        -NotAfter         (Get-Date).AddYears(3) `
        -TextExtension    @("2.5.29.37={text}1.3.6.1.5.5.7.3.3")

    Write-Host "✅  Certificate created: $($cert.Thumbprint)"
}

# Export PFX (with private key, for signing)
Write-Host "💾  Exporting PFX (with private key)..."
$securePass = ConvertTo-SecureString $Password -AsPlainText -Force
Export-PfxCertificate -Cert $cert -FilePath $PfxPath -Password $securePass | Out-Null
Write-Host "✅  PFX saved: $PfxPath"
Write-Host "    Password : $Password"

# Export CER (public key only, for distributing to other machines)
Write-Host "💾  Exporting CER (public key, for distribution)..."
Export-Certificate -Cert $cert -FilePath $CerPath | Out-Null
Write-Host "✅  CER saved: $CerPath"

Write-Host ""

# Install to Trusted Root (so this machine trusts it)
if (-not $NoInstall) {
    Write-Host "🔒  Installing to Local Machine Trusted Root..." -ForegroundColor Yellow
    Write-Host "    (May require Administrator privileges)" -ForegroundColor Gray

    try {
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store(
            [System.Security.Cryptography.X509Certificates.StoreName]::Root,
            [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine
        )
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        $store.Add($cert)
        $store.Close()
        Write-Host "✅  Installed to Trusted Root. This PC will trust signed MSIX packages." -ForegroundColor Green
    } catch {
        Write-Host "⚠   Could not install to LocalMachine (run as Admin)." -ForegroundColor Yellow
        Write-Host "    Installing to CurrentUser instead..." -ForegroundColor Gray
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store(
            [System.Security.Cryptography.X509Certificates.StoreName]::Root,
            [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser
        )
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        $store.Add($cert)
        $store.Close()
        Write-Host "✅  Installed to CurrentUser Trusted Root." -ForegroundColor Green
    }
}

Write-Host ""
Write-Host "════════════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host "   ✅  Certificate ready!" -ForegroundColor Green
Write-Host "════════════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host ""
Write-Host "   Thumbprint : $($cert.Thumbprint)"
Write-Host "   PFX file   : $PfxPath"
Write-Host "   PFX pass   : $Password"
Write-Host ""
Write-Host "   Next steps:" -ForegroundColor Cyan
Write-Host "   1. Build the app:   scripts\build_windows.bat"
Write-Host "   2. Build MSIX:      scripts\build_msix.bat"
Write-Host "      (auto-uses $PfxPath)"
Write-Host ""
Write-Host "   To trust on OTHER machines, run there:" -ForegroundColor Cyan
Write-Host "   powershell -ExecutionPolicy Bypass -File scripts\create_cert.ps1 -InstallOnly"
Write-Host "   (copy ironrod_dev_cert.cer to that machine first)"
Write-Host ""
Write-Host "   ⚠  Self-signed certs only work on machines where the cert is trusted." -ForegroundColor Yellow
Write-Host "      For public distribution without warnings, purchase an EV cert:" -ForegroundColor Yellow
Write-Host "      https://www.digicert.com/signing/code-signing-certificates" -ForegroundColor Yellow
Write-Host ""
