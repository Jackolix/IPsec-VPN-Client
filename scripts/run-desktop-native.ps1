<#
.SYNOPSIS
  Launch the desktop GUI against the NATIVE Windows backend (charon-svc on the
  host via WFP) instead of the Linux dev container.

.DESCRIPTION
  No container is started. The app targets vici on 127.0.0.1:4502 (charon-svc's
  Windows default) and can start/stop the native daemon itself from the sidebar
  "Start" / "Stop" button (each raises a UAC prompt, since the Windows Filtering
  Platform needs Administrator). Build the daemon first with
  scripts\build-strongswan-windows.ps1.

.PARAMETER ProfileDir
  Directory scanned for .ini profiles. Default: repo root.
#>
param(
    [string] $ProfileDir = (Split-Path -Parent $PSScriptRoot)
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

if (-not (Test-Path "out\strongswan-windows\charon-svc.exe")) {
    Write-Warning "out\strongswan-windows\charon-svc.exe not found - run scripts\build-strongswan-windows.ps1 first."
}

# No VPN_VICI_TCP => the app defaults to the native daemon (127.0.0.1:4502).
Remove-Item Env:\VPN_VICI_TCP -ErrorAction SilentlyContinue
$env:VPN_PROFILE_DIR   = $ProfileDir
$env:VPN_CHARON_SCRIPT = (Join-Path $root "scripts\run-charon-windows.ps1")

Write-Host "Launching desktop app (native backend; profiles: $ProfileDir)"
Write-Host "Use the sidebar Start button (or just Connect) to bring up charon-svc."
cargo run -p vpn-desktop
