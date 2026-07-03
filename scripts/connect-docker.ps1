# Phase 0 test drive: generate swanctl config from an NCP profile and bring
# up the tunnel from a strongSwan container against a test responder.
#
# Usage:
#   .\scripts\connect-docker.ps1 -Profile .\EFA_MDT_42.ini -Gateway 192.168.100.10
#
# -Gateway is required on purpose: it forces an explicit decision about what
# you are connecting to, so nobody accidentally hits the production gateway
# baked into the profile.

param(
    [Parameter(Mandatory = $true)] [string] $Profile,
    [Parameter(Mandatory = $true)] [string] $Gateway
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$outDir = Join-Path $root "out"

cargo run --manifest-path (Join-Path $root "Cargo.toml") -p vpn-cli -- `
    generate $Profile --out-dir $outDir --gateway-override $Gateway
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

docker build -t vpn-initiator (Join-Path $root "docker\initiator")
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

# NET_ADMIN + /dev/net/tun: charon needs to install XFRM policies and routes
# inside the container's own network namespace.
docker run --rm -it `
    --cap-add NET_ADMIN `
    -v "${outDir}:/config:ro" `
    vpn-initiator
