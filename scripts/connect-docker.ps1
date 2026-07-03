# Phase 1 test drive: build the vpn-agent image and bring up the tunnel from
# a strongSwan container, driving charon over vici (no swanctl.conf on disk).
#
# Usage:
#   .\scripts\connect-docker.ps1 -Profile .\TEST-1.ini -Gateway 192.168.100.10
#
# -Gateway is required on purpose so nobody accidentally connects to the
# production gateway baked into a profile.

param(
    [Parameter(Mandatory = $true)] [string] $Profile,
    [Parameter(Mandatory = $true)] [string] $Gateway
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$profileFull = (Resolve-Path $Profile).Path

docker build -t vpn-agent -f (Join-Path $root "docker\agent\Dockerfile") $root
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

docker rm -f vpn-agent 2>$null | Out-Null

# NET_ADMIN: charon installs XFRM policies and routes in the container netns.
docker run --rm -it `
    --name vpn-agent `
    --cap-add NET_ADMIN `
    -e PROFILE=/profile.ini `
    -e GATEWAY_OVERRIDE=$Gateway `
    -v "${profileFull}:/profile.ini:ro" `
    vpn-agent
