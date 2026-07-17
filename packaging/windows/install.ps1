# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 Cristian Cezar Moisés — AGPL-3.0-only
#
# Install the Torando Control ALL-IN-ONE on Windows. Ships its own Python and
# Tor, so nothing needs to be pre-installed.
#
#   * Tor runs as a boot-time SYSTEM Scheduled Task (needs no user).
#   * The daemon runs as YOU, elevated, at logon — because the WinINET system
#     proxy is per-user (HKCU): a SYSTEM daemon would set it in the wrong hive
#     and your browser would never see it. Running as your elevated account lets
#     it set your proxy AND drive the firewall/DNS.
#
# Run from an elevated PowerShell **as the account you'll use the desktop with**:
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

if ($env:USERNAME -eq "SYSTEM") {
    throw "Run install.ps1 from your own (elevated) account, not as SYSTEM — the daemon must run as the desktop user to set the per-user proxy."
}
# Identify the desktop user by SID — works for local, Microsoft-account and
# Entra/AzureAD logins where USERDOMAIN\USERNAME does not resolve for a task.
$currentSid  = ([Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
$currentUser = "$env:USERDOMAIN\$env:USERNAME"

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Write-Host "Installing Torando Control (all-in-one) to $InstallDir  [daemon user: $currentUser]"

# If an old install exists, stop its tasks and remove the payload dirs FIRST.
# Otherwise Copy-Item -Recurse into an existing folder NESTS (python\python\...),
# leaving the stale, broken files in place — so a reinstall-to-fix does nothing.
foreach ($t in @("TorandoGUI-Daemon", "TorandoGUI-Tor")) {
    Stop-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue
}
Start-Sleep -Milliseconds 500
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
foreach ($d in @("python", "tor", "lib", "boot")) {
    $dest = Join-Path $InstallDir $d
    Remove-Item -Recurse -Force $dest -ErrorAction SilentlyContinue
    Copy-Item -Recurse -Force "$here\$d" $dest
}
foreach ($f in @("torando-guid.cmd", "torando-gui.cmd", "torrc.template", "uninstall.ps1")) {
    Copy-Item -Force "$here\$f" $InstallDir
}

$torExe   = Join-Path $InstallDir "tor\tor.exe"
$pyw      = Join-Path $InstallDir "python\pythonw.exe"
$daemonPy = Join-Path $InstallDir "boot\daemon.py"

# Config dir, tor data dir, log dir, torrc (from the template).
$cfgDir  = "$env:ProgramData\torando-gui"
$torData = Join-Path $cfgDir "tor-data"
$logDir  = Join-Path $cfgDir "logs"
New-Item -ItemType Directory -Force -Path $cfgDir, $torData, $logDir | Out-Null

$torrc = Get-Content (Join-Path $InstallDir "torrc.template") -Raw
$torrc = $torrc.Replace("@@DATADIR@@", $torData).
                Replace("@@GEOIP@@",  (Join-Path $InstallDir "tor\data\geoip")).
                Replace("@@GEOIP6@@", (Join-Path $InstallDir "tor\data\geoip6"))
$torrcPath = Join-Path $cfgDir "torrc"
Set-Content -Path $torrcPath -Value $torrc -Encoding ASCII
Write-Host "Wrote $torrcPath"

# Seed config.json (machine-wide killswitch; bundled Tor owns its torrc; no
# ControlPort in that torrc, so don't attempt control-port auth).
$cfgFile = Join-Path $cfgDir "config.json"
if (-not (Test-Path $cfgFile)) {
    $cfg = [ordered]@{
        host                = "127.0.0.1"
        port                = 8088
        socks_port          = 9050
        dns_port            = 53
        manage_torrc        = $false
        enable_control_port = $false
        lock_resolv         = $true
        ipv6_killswitch     = $true
        tor_path            = $torExe
    }
    # Write UTF-8 WITHOUT a BOM — PowerShell's `Set-Content -Encoding UTF8` adds
    # one, which makes the daemon's json.loads fail and drop the whole config.
    [System.IO.File]::WriteAllText($cfgFile, ($cfg | ConvertTo-Json), (New-Object System.Text.UTF8Encoding($false)))
    Write-Host "Seeded $cfgFile"
}

$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
                -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) `
                -ExecutionTimeLimit ([TimeSpan]::Zero)

# 1) Tor — SYSTEM, at boot (no user needed).
$torPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$torAction = New-ScheduledTaskAction -Execute $torExe -Argument "-f `"$torrcPath`"" `
                -WorkingDirectory (Join-Path $InstallDir "tor")
Register-ScheduledTask -TaskName "TorandoGUI-Tor" -Action $torAction `
    -Trigger (New-ScheduledTaskTrigger -AtStartup) -Principal $torPrincipal -Settings $settings -Force | Out-Null

# 2) Daemon — YOU, elevated, at logon (so it sets your per-user proxy). Use the
#    SID so it resolves for local / Microsoft-account / Entra logins alike.
$daemonPrincipal = New-ScheduledTaskPrincipal -UserId $currentSid -LogonType Interactive -RunLevel Highest
$daemonAction = New-ScheduledTaskAction -Execute $pyw -Argument "`"$daemonPy`"" -WorkingDirectory $InstallDir
Register-ScheduledTask -TaskName "TorandoGUI-Daemon" -Action $daemonAction `
    -Trigger (New-ScheduledTaskTrigger -AtLogOn -User $currentSid) `
    -Principal $daemonPrincipal -Settings $settings -Force | Out-Null

Start-ScheduledTask -TaskName "TorandoGUI-Tor"
Start-Sleep -Seconds 2
Start-ScheduledTask -TaskName "TorandoGUI-Daemon"

function Test-Port($p) {
    try { $c = New-Object Net.Sockets.TcpClient; $c.Connect("127.0.0.1", $p); $c.Close(); return $true }
    catch { return $false }
}

# Health check: wait for BOTH the daemon (8088) and bundled Tor's SocksPort (9050).
Write-Host -NoNewline "Waiting for the daemon and Tor"
$daemonUp = $false; $torUp = $false
foreach ($i in 1..24) {
    Start-Sleep -Milliseconds 750
    Write-Host -NoNewline "."
    if (-not $daemonUp) { $daemonUp = Test-Port 8088 }
    if (-not $torUp)    { $torUp    = Test-Port 9050 }
    if ($daemonUp -and $torUp) { break }
}
Write-Host ""
if ($daemonUp -and $torUp) {
    Write-Host "Installed and running (daemon + Tor up). Open the app:  $InstallDir\torando-gui.cmd"
} else {
    if (-not $daemonUp) {
        Write-Warning "The daemon did not answer on 127.0.0.1:8088."
        Write-Warning "Check the log:  $logDir\daemon.log"
    }
    if (-not $torUp) {
        Write-Warning "Tor did not open its SocksPort on 127.0.0.1:9050 (check that port 53/9050 are free)."
    }
    Write-Host "You can still try:  $InstallDir\torando-gui.cmd"
}
