# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 Cristian Cezar Moisés — AGPL-3.0-only
#
# Remove Torando Control from Windows. Restores the firewall/proxy/DNS to their
# captured state first (via the daemon's own teardown), then deletes the task
# and files. Run from an elevated PowerShell.
#
param([string]$InstallDir = "$env:ProgramFiles\torando-gui")
$ErrorActionPreference = "SilentlyContinue"

# Best-effort: let the daemon restore firewall policy, system proxy and DNS.
$daemon = "$InstallDir\torando-guid.cmd"
if (Test-Path $daemon) {
    & cmd.exe /c "`"$daemon`" --restore-dns" | Out-Null
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

Unregister-ScheduledTask -TaskName "TorandoGUI-Daemon" -Confirm:$false
Unregister-ScheduledTask -TaskName "TorandoGUI-Tor" -Confirm:$false
Remove-Item -Recurse -Force $InstallDir
Write-Host "Removed Torando Control. Your config under %ProgramData%\torando-gui was left in place."
