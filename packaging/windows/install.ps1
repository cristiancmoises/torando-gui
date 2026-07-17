# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 Cristian Cezar Moisés — AGPL-3.0-only
#
# Install the Torando Control ALL-IN-ONE on Windows. Ships its own Python and
# Tor, so nothing needs to be pre-installed. Registers two boot-time Scheduled
# Tasks running as SYSTEM (the bundled Tor, and the root daemon that drives the
# firewall / system proxy / DNS) and seeds the config.
#
# Run from an elevated PowerShell:
#   powershell -ExecutionPolicy Bypass -File install.ps1
#
param([string]$InstallDir = "$env:ProgramFiles\torando-gui")
$ErrorActionPreference = "Stop"

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $pr = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $pr.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
        throw "install.ps1 must be run as Administrator."
    }
}
Assert-Admin

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Write-Host "Installing Torando Control (all-in-one) to $InstallDir"
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
foreach ($d in @("python", "tor", "lib")) {
    Copy-Item -Recurse -Force "$here\$d" $InstallDir
}
foreach ($f in @("torando-guid.cmd", "torando-gui.cmd", "torrc.template", "uninstall.ps1")) {
    Copy-Item -Force "$here\$f" $InstallDir
}

$torExe = Join-Path $InstallDir "tor\tor.exe"
$daemon = Join-Path $InstallDir "python\pythonw.exe"

# Config directory, tor data directory, torrc (from the template).
$cfgDir = "$env:ProgramData\torando-gui"
$torData = Join-Path $cfgDir "tor-data"
New-Item -ItemType Directory -Force -Path $cfgDir, $torData | Out-Null

$torrc = Get-Content (Join-Path $InstallDir "torrc.template") -Raw
$torrc = $torrc.Replace("@@DATADIR@@", $torData).
                Replace("@@GEOIP@@",  (Join-Path $InstallDir "tor\data\geoip")).
                Replace("@@GEOIP6@@", (Join-Path $InstallDir "tor\data\geoip6"))
$torrcPath = Join-Path $cfgDir "torrc"
Set-Content -Path $torrcPath -Value $torrc -Encoding ASCII
Write-Host "Wrote $torrcPath"

# Seed config.json (machine-wide killswitch; Tor is bundled so manage_torrc off).
$cfgFile = Join-Path $cfgDir "config.json"
if (-not (Test-Path $cfgFile)) {
    $cfg = [ordered]@{
        host            = "127.0.0.1"
        port            = 8088
        socks_port      = 9050
        dns_port        = 53
        manage_torrc    = $false
        lock_resolv     = $true
        ipv6_killswitch = $true
        tor_path        = $torExe
    }
    ($cfg | ConvertTo-Json) | Set-Content -Encoding UTF8 $cfgFile
    Write-Host "Seeded $cfgFile"
}

# Boot-time Scheduled Tasks (SYSTEM, highest privileges).
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
                -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) `
                -ExecutionTimeLimit ([TimeSpan]::Zero)
$trigger   = New-ScheduledTaskTrigger -AtStartup

# 1) the bundled Tor
$torAction = New-ScheduledTaskAction -Execute $torExe -Argument "-f `"$torrcPath`"" -WorkingDirectory (Join-Path $InstallDir "tor")
Register-ScheduledTask -TaskName "TorandoGUI-Tor" -Action $torAction -Trigger $trigger `
    -Principal $principal -Settings $settings -Force | Out-Null

# 2) the root daemon
$daemonAction = New-ScheduledTaskAction -Execute $daemon -Argument "-m torando_gui" -WorkingDirectory $InstallDir
Register-ScheduledTask -TaskName "TorandoGUI-Daemon" -Action $daemonAction -Trigger $trigger `
    -Principal $principal -Settings $settings -Force | Out-Null

Start-ScheduledTask -TaskName "TorandoGUI-Tor"
Start-Sleep -Seconds 2
Start-ScheduledTask -TaskName "TorandoGUI-Daemon"

Write-Host ""
Write-Host "Installed. Tor and the daemon run at boot as SYSTEM — nothing else to install."
Write-Host "Open the app:  $InstallDir\torando-gui.cmd"
Write-Host "(A desktop/Start shortcut to that .cmd is convenient to create.)"
