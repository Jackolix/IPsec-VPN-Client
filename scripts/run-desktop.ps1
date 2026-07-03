# Launch the desktop GUI against a dev VPN backend.
#
# Starts a strongSwan container whose vici control socket is published on
# 127.0.0.1:45022, then runs the Tauri app pointed at it and at a profiles
# directory. The app parses profiles and pushes the connection + PSK to
# charon over vici; charon (in the container) brings up the actual tunnel.
#
# Usage:
#   .\scripts\run-desktop.ps1                        # profiles from repo root
#   .\scripts\run-desktop.ps1 -ProfileDir C:\vpn     # custom profiles dir

param(
    [string] $ProfileDir = (Split-Path -Parent $PSScriptRoot),
    [int] $Port = 45022
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot

docker build -t vpn-vici-tcp -f (Join-Path $root "docker\vici-tcp\Dockerfile") $root
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

docker rm -f vpn-backend 2>$null | Out-Null
docker run -d --name vpn-backend --cap-add NET_ADMIN -p "127.0.0.1:${Port}:45022" vpn-vici-tcp | Out-Null
Write-Host "VPN backend (charon) running; vici on 127.0.0.1:$Port"

try {
    $env:VPN_VICI_TCP = "127.0.0.1:$Port"
    $env:VPN_PROFILE_DIR = $ProfileDir
    Write-Host "Launching desktop app (profiles: $ProfileDir)"
    cargo run -p vpn-desktop
}
finally {
    docker rm -f vpn-backend 2>$null | Out-Null
    Write-Host "VPN backend stopped."
}
