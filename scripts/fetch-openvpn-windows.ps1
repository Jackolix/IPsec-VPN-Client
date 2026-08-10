<#
.SYNOPSIS
  Vendor the OpenVPN Windows binaries into out\openvpn, so the app can bundle
  its own openvpn.exe instead of depending on one being installed on the host.

.DESCRIPTION
  Sophos "SSL VPN" is stock OpenVPN; the broker drives a real openvpn process to
  carry it (see crates/vpn-broker/src/openvpn.rs). Rather than build openvpn from
  source, this downloads the official community Windows MSI (pinned by version
  and SHA-256), does an administrative extract (msiexec /a -- lays out the files
  only, no install, no driver, no elevation), and assembles the minimal runtime
  set into out\openvpn:

    openvpn.exe                  the client
    tapctl.exe                   creates the dedicated wintun adapter (openvpn
                                 reuses an existing adapter, it does not make
                                 one; the broker pre-creates it with this)
    libssl-3-x64.dll             OpenSSL 3 (TLS)
    libcrypto-3-x64.dll          OpenSSL 3 (crypto)
    libpkcs11-helper-1.dll       imported by openvpn.exe
    vcruntime140.dll             MSVC runtime
    ssl\modules\legacy.dll       OpenSSL 3 legacy provider (older ciphers)
    wintun.dll                   the TUN driver (reused from the strongSwan
                                 build) -- openvpn is launched with
                                 --windows-driver wintun, so no TAP install

  The layout mirrors out\strongswan-windows: the broker finds it in dev via its
  ..\..\out\openvpn fallback, and a release bundles it beside the broker as
  openvpn\.

.PARAMETER OutDir
  Where to place the assembled tree. Default: out\openvpn.

.PARAMETER Version
  OpenVPN version to vendor. Default: 2.6.22.

.EXAMPLE
  .\scripts\fetch-openvpn-windows.ps1
#>
[CmdletBinding()]
param(
    [string]$OutDir  = "out\openvpn",
    [string]$Version = "2.6.22"
)

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo

# Pinned artifacts. Add an entry when bumping $Version; the SHA-256 guards
# against a tampered or truncated download.
$Pinned = @{
    "2.6.22" = @{
        Url    = "https://build.openvpn.net/downloads/releases/OpenVPN-2.6.22-I001-amd64.msi"
        Sha256 = "1e1bb9a712990d1b2b961de7e8df3384964e4fb6f6776a100840f0d9a82ed507"
    }
}
if (-not $Pinned.ContainsKey($Version)) {
    throw "no pinned URL/checksum for OpenVPN $Version -- add one to `$Pinned"
}
$url    = $Pinned[$Version].Url
$sha    = $Pinned[$Version].Sha256

# wintun.dll is not a loose file in the MSI; reuse the one the strongSwan build
# already produced (same driver charon loads).
$wintun = Join-Path $repo "out\strongswan-windows\wintun.dll"
if (-not (Test-Path $wintun)) {
    throw "wintun.dll not found at $wintun -- run scripts\build-strongswan-windows.ps1 first"
}

$work = Join-Path ([IO.Path]::GetTempPath()) ("openvpn-vendor-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $work | Out-Null
try {
    $msi = Join-Path $work "openvpn.msi"
    Write-Host "==> Downloading OpenVPN $Version" -ForegroundColor Cyan
    Invoke-WebRequest -Uri $url -OutFile $msi

    $got = (Get-FileHash -Algorithm SHA256 $msi).Hash.ToLower()
    if ($got -ne $sha.ToLower()) {
        throw "SHA-256 mismatch for $url`n  expected $sha`n  got      $got"
    }
    Write-Host "    checksum OK" -ForegroundColor DarkGray

    Write-Host "==> Extracting (administrative install, no driver/elevation)" -ForegroundColor Cyan
    $extract = Join-Path $work "extract"
    $p = Start-Process msiexec -ArgumentList "/a `"$msi`" /qn TARGETDIR=`"$extract`"" -Wait -PassThru
    if ($p.ExitCode -ne 0) { throw "msiexec /a failed ($($p.ExitCode))" }

    $bin = (Get-ChildItem -Recurse $extract -Filter openvpn.exe | Select-Object -First 1).Directory.FullName
    if (-not $bin) { throw "openvpn.exe not found in the extracted MSI" }
    $legacy = Get-ChildItem -Recurse $extract -Filter legacy.dll -ErrorAction SilentlyContinue | Select-Object -First 1

    if (Test-Path $OutDir) { Remove-Item -Recurse -Force $OutDir }
    New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

    $need = "openvpn.exe","tapctl.exe","libssl-3-x64.dll","libcrypto-3-x64.dll","libpkcs11-helper-1.dll","vcruntime140.dll"
    foreach ($n in $need) {
        $src = Join-Path $bin $n
        if (-not (Test-Path $src)) { throw "expected file missing from MSI: $n" }
        Copy-Item $src $OutDir
    }
    if ($legacy) {
        $mod = Join-Path $OutDir "ssl\modules"
        New-Item -ItemType Directory -Force -Path $mod | Out-Null
        Copy-Item $legacy.FullName $mod
    }
    Copy-Item $wintun $OutDir

    # Prove the assembled binary runs (all DLLs resolve) before declaring success.
    $ver = & (Join-Path $OutDir "openvpn.exe") --version 2>&1 | Select-Object -First 1
    Write-Host "`n==> Done. $ver" -ForegroundColor Green
    Get-ChildItem -Recurse $OutDir -File | Select-Object -ExpandProperty FullName | Sort-Object
} finally {
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}
