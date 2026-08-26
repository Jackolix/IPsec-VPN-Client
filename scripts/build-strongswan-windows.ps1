<#
.SYNOPSIS
  Cross-build strongSwan's native Windows daemon (charon-svc.exe) and export
  the artifacts to out\strongswan-windows.

.DESCRIPTION
  Wraps docker/strongswan-windows/Dockerfile (a MinGW-w64 cross build of
  OpenSSL + strongSwan on Linux). The result is a self-contained tree of
  Windows .exe/.dll files that terminate the IPsec tunnel on the Windows host
  itself -- no container, no WSL. ESP runs in userland (libipsec) over a Wintun
  adapter, so wintun.dll ships alongside charon-svc.exe. The desktop app drives
  the daemon over vici on 127.0.0.1:45023, exactly as it drives the Linux dev
  container.

.PARAMETER OutDir
  Where to place the exported tree. Default: out\strongswan-windows.

.PARAMETER Tag
  Docker image tag to build. Default: ss-win.

.EXAMPLE
  .\scripts\build-strongswan-windows.ps1
#>
[CmdletBinding()]
param(
    [string]$OutDir = "out\strongswan-windows",
    [string]$Tag    = "ss-win"
)

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo

# Remove a container that may not exist, without letting that end the script.
#
# Under $ErrorActionPreference='Stop' a native command writing to stderr becomes
# a terminating error — in Windows PowerShell 5.1 as a NativeCommandError, and in
# PowerShell 7.3+ via $PSNativeCommandUseErrorActionPreference. On a clean
# machine the export container does not exist yet, so `docker rm -f` says so on
# stderr and the script dies *after* the very long image build has succeeded.
# Failure here is genuinely uninteresting; where it isn't, $LASTEXITCODE is
# checked explicitly.
function Remove-ContainerQuietly([string]$Name) {
    try { docker rm -f $Name 2>&1 | Out-Null } catch { }
}

$dockerfile = "docker/strongswan-windows/Dockerfile"
$confSrc    = "docker/strongswan-windows/strongswan.conf"

Write-Host "==> Building $Tag from $dockerfile (long cross-compile)..." -ForegroundColor Cyan
docker build -t $Tag -f $dockerfile .
if ($LASTEXITCODE -ne 0) { throw "docker build failed ($LASTEXITCODE)" }

# Export /dist out of a throwaway container.
$container = "$Tag-export"
Remove-ContainerQuietly $container
docker create --name $container $Tag | Out-Null
try {
    if (Test-Path $OutDir) { Remove-Item -Recurse -Force $OutDir }
    New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

    Write-Host "==> Exporting /dist -> $OutDir" -ForegroundColor Cyan
    docker cp "${container}:/dist/." $OutDir
    if ($LASTEXITCODE -ne 0) { throw "docker cp failed ($LASTEXITCODE)" }
} finally {
    Remove-ContainerQuietly $container
}

# Drop the Windows strongswan.conf into etc\ (the daemon reads etc\strongswan.conf
# relative to its prefix / the STRONGSWAN_CONF env var the run script sets).
$etc = Join-Path $OutDir "etc"
New-Item -ItemType Directory -Force -Path $etc | Out-Null
Copy-Item -Force $confSrc (Join-Path $etc "strongswan.conf")

Write-Host "`n==> Done. Windows artifacts in $OutDir" -ForegroundColor Green
Get-ChildItem -Recurse $OutDir -Include *.exe,*.dll |
    Select-Object -ExpandProperty FullName |
    Sort-Object
