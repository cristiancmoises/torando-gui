# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 Cristian Cezar Moisés — AGPL-3.0-only
#
# Remove Torando Control from Windows. Restores the firewall/proxy/DNS to their
# captured state first (via the daemon's own teardown), then deletes the task
# and files. Run from an elevated PowerShell.
#
param([string]$InstallDir = "$env:ProgramFiles\torando-gui")
$ErrorActionPreference = "SilentlyContinue"

# Best-effort: let the daemon restore firewall policy, system proxy and DNS
# (via the bundled Python + bootstrap, so this works with no system Python).
$pyw = "$InstallDir\python\pythonw.exe"
$boot = "$InstallDir\boot\daemon.py"
if ((Test-Path $pyw) -and (Test-Path $boot)) {
    & $pyw $boot --restore-dns | Out-Null
    Start-Sleep -Seconds 1
}

# Delete any residual firewall rules and re-allow outbound (safety net if the
# daemon could not run its own teardown).
foreach ($name in @("TorandoGUI-Tor-Out","TorandoGUI-Loopback4-Out",
                    "TorandoGUI-Loopback6-Out","TorandoGUI-DHCP-Out","TorandoGUI-LAN-Out")) {
    netsh advfirewall firewall delete rule name="$name" | Out-Null
}
foreach ($p in @("domainprofile","privateprofile","publicprofile")) {
    netsh advfirewall set $p firewallpolicy blockinbound,allowoutbound | Out-Null
}

# Stop and remove both boot tasks (the daemon and the bundled Tor).
foreach ($t in @("TorandoGUI-Daemon", "TorandoGUI-Tor")) {
    Stop-ScheduledTask -TaskName $t
    Unregister-ScheduledTask -TaskName $t -Confirm:$false
}
Remove-Item -Recurse -Force $InstallDir
Write-Host "Removed Torando Control. Your config under %ProgramData%\torando-gui was left in place."
