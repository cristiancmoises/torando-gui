# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 Cristian Cezar Moisés — AGPL-3.0-only
#
# Install Torando Control on Windows: register the root daemon as a boot-time
# Scheduled Task running as SYSTEM (so it can drive the firewall, the system
# SOCKS proxy and interface DNS), and seed its config.
#
# Run from an elevated PowerShell:
#   powershell -ExecutionPolicy Bypass -File install.ps1 [-TorPath C:\path\to\tor.exe]
#
param(
    [string]$TorPath = "",
    [string]$InstallDir = "$env:ProgramFiles\torando-gui"
)
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
Write-Host "Installing Torando Control to $InstallDir"
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Copy-Item -Recurse -Force "$here\lib" $InstallDir
Copy-Item -Force "$here\torando-guid.cmd" $InstallDir
Copy-Item -Force "$here\torando-gui.cmd" $InstallDir

# Config directory + a seed config.json (loopback only, machine-wide killswitch).
$cfgDir = "$env:ProgramData\torando-gui"
New-Item -ItemType Directory -Force -Path $cfgDir | Out-Null
$cfgFile = "$cfgDir\config.json"
if (-not (Test-Path $cfgFile)) {
    $tor = $TorPath
    if ($tor -eq "") {
        $found = (Get-Command tor.exe -ErrorAction SilentlyContinue)
        if ($found) { $tor = $found.Source }
    }
    $cfg = @{
        host          = "127.0.0.1"
        port          = 8088
        socks_port    = 9050
        dns_port      = 53
        manage_torrc  = $false
        lock_resolv   = $true
        ipv6_killswitch = $true
    }
    if ($tor -ne "") { $cfg["tor_path"] = $tor }
    ($cfg | ConvertTo-Json) | Set-Content -Encoding UTF8 $cfgFile
    Write-Host "Seeded $cfgFile"
}

# Boot-time Scheduled Task for the daemon (SYSTEM, highest privileges).
$daemon = "$InstallDir\torando-guid.cmd"
$action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c `"$daemon`""
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
Register-ScheduledTask -TaskName "TorandoGUI-Daemon" -Action $action -Trigger $trigger `
    -Principal $principal -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName "TorandoGUI-Daemon"

Write-Host ""
Write-Host "Installed. The daemon runs at boot as SYSTEM."
Write-Host "Start the app with:  $InstallDir\torando-gui.cmd"
Write-Host "NOTE: install a Tor Expert Bundle and set tor_path in $cfgFile if not already set."
