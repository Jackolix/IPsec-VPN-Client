<#
.SYNOPSIS
  Run the native Windows strongSwan daemon (charon-svc.exe) in the foreground
  so the desktop app / vpn-agent can drive a real host tunnel over vici.

.DESCRIPTION
  charon-svc installs IPsec SAs through the Windows Filtering Platform, so it
  MUST run elevated (Administrator). This script:
    * verifies elevation,
    * locates charon-svc.exe in out\strongswan-windows,
    * writes an effective strongswan.conf with an absolute filelog path,
    * points STRONGSWAN_CONF at it and launches charon-svc in the console.

  Stop with Ctrl+C. The vici socket comes up on 127.0.0.1:4502 (charon-svc's
  Windows default), which vpn-desktop / vpn-agent --tcp 127.0.0.1:4502 target.

.PARAMETER Dist
  The exported artifact tree. Default: out\strongswan-windows.

.PARAMETER Install
  Instead of running in the console, install charon-svc as a Windows service
  (sc.exe). Requires elevation. Use -Uninstall to remove it.
#>
[CmdletBinding()]
param(
    [string]$Dist = "out\strongswan-windows",
    [switch]$Install,
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
        throw "charon-svc needs the Windows Filtering Platform: run this in an elevated (Administrator) PowerShell."
    }
}

$distFull = (Resolve-Path $Dist).Path

# Locate the daemon wherever `make install` put it.
$svc = Get-ChildItem -Recurse -Path $distFull -Filter "charon-svc.exe" -ErrorAction SilentlyContinue |
       Select-Object -First 1
if (-not $svc) { throw "charon-svc.exe not found under $distFull - run scripts\build-strongswan-windows.ps1 first." }

$svcExe = $svc.FullName
$svcDir = $svc.DirectoryName
$logDir = Join-Path $env:APPDATA "ipsec-vpn"
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
$logPath = Join-Path $logDir "charon.log"

# Materialize an effective strongswan.conf with absolute paths. The daemon is
# built --enable-monolithic, so all plugins are compiled into charon itself --
# there is no separate plugin directory or load_path to configure.
$confTemplate = Join-Path $distFull "etc\strongswan.conf"
if (-not (Test-Path $confTemplate)) { throw "missing $confTemplate (packaging step didn't run?)" }
$conf = Get-Content -Raw $confTemplate
# Absolute, forward-slashed log path (charon parses backslashes as escapes).
$logFwd = $logPath -replace '\\','/'
$conf = $conf -replace 'path = charon\.log', "path = $logFwd"
$effConf = Join-Path $logDir "strongswan.effective.conf"
Set-Content -Path $effConf -Value $conf -Encoding ASCII

# charon-svc has no Windows default config location (its compiled-in path is a
# Unix path), so it MUST be told via the STRONGSWAN_CONF env var. Set it on the
# process so the child charon-svc inherits it.
[Environment]::SetEnvironmentVariable("STRONGSWAN_CONF", $effConf, "Process")
$env:STRONGSWAN_CONF = $effConf

$svcConsole = Join-Path $logDir "charon-console.log"

Write-Host "charon-svc : $svcExe"  -ForegroundColor Cyan
Write-Host "config     : $effConf (exists: $(Test-Path $effConf))" -ForegroundColor Cyan
Write-Host "log        : $logPath" -ForegroundColor Cyan
Write-Host "console    : $svcConsole" -ForegroundColor Cyan
Write-Host "STRONGSWAN_CONF = $($env:STRONGSWAN_CONF)" -ForegroundColor DarkGray

if ($Uninstall) {
    Assert-Admin
    sc.exe stop  "ipsec-vpn-charon" 2>$null | Out-Null
    sc.exe delete "ipsec-vpn-charon"
    return
}

if ($Install) {
    Assert-Admin
    # charon-svc supports Windows service control; register it.
    sc.exe create "ipsec-vpn-charon" binPath= "`"$svcExe`"" start= demand DisplayName= "IPsec VPN (strongSwan charon)"
    Write-Host "Service 'ipsec-vpn-charon' installed. Start with: sc.exe start ipsec-vpn-charon" -ForegroundColor Green
    return
}

Assert-Admin
Write-Host "==> launching charon-svc (Ctrl+C to stop). vici on 127.0.0.1:4502" -ForegroundColor Green
# Run from the daemon's own dir so it finds its sibling DLLs, and capture its
# native stdout/stderr to a file (charon-svc's early messages predate the
# filelog; -RedirectStandardOutput captures them reliably). STRONGSWAN_CONF is
# already set on this process, so the child inherits it.
# Flushed startup diagnostic (the console is buffered while charon-svc blocks).
@(
    "when=$(Get-Date -Format o)",
    "whoami=$(whoami)",
    "svcExe=$svcExe",
    "STRONGSWAN_CONF=$($env:STRONGSWAN_CONF)",
    "effConf.exists=$(Test-Path $effConf)"
) | Set-Content -LiteralPath (Join-Path $logDir "run-diag.txt") -Encoding ASCII

$p = Start-Process -FilePath $svcExe -WorkingDirectory $svcDir -NoNewWindow -PassThru `
        -RedirectStandardOutput $svcConsole -RedirectStandardError "$svcConsole.err"
Write-Host "charon-svc PID: $($p.Id).  Ctrl+C or close this window to stop." -ForegroundColor Green
try {
    $p.WaitForExit()
} finally {
    if (-not $p.HasExited) { $p.Kill() }
}
