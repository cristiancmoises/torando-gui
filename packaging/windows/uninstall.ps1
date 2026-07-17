# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 Cristian Cezar Moises -- AGPL-3.0-only
#
# Remove Torando Control from Windows. Does a FULL teardown first -- restores the
# firewall policy, the WinINET system proxy AND DNS -- so removal never leaves the
# browser pointed at a now-deleted SOCKS proxy. Run from an elevated PowerShell,
# ideally from the same account you installed with (the proxy is per-user).
#
param([string]$InstallDir = "$env:ProgramFiles\torando-gui")
$ErrorActionPreference = "SilentlyContinue"

# 1) Full teardown via the daemon (bundled Python; restores firewall + proxy + DNS).
$pyw = "$InstallDir\python\pythonw.exe"
$boot = "$InstallDir\boot\daemon.py"
if ((Test-Path $pyw) -and (Test-Path $boot)) {
    & $pyw $boot --disconnect | Out-Null
    Start-Sleep -Seconds 2
    & $pyw $boot --restore-dns | Out-Null   # belt-and-braces for DNS
    Start-Sleep -Seconds 1
}

# 2) Safety net if the daemon could not run: clear our rules, re-allow outbound,
#    and forcibly disable the WinINET proxy so the browser regains connectivity.
foreach ($name in @("TorandoGUI-Tor-Out","TorandoGUI-Loopback4-Out",
                    "TorandoGUI-Loopback6-Out","TorandoGUI-DHCP-Out","TorandoGUI-LAN-Out")) {
    netsh advfirewall firewall delete rule name="$name" | Out-Null
}
foreach ($p in @("domainprofile","privateprofile","publicprofile")) {
    netsh advfirewall set $p firewallpolicy blockinbound,allowoutbound | Out-Null
}
$inet = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
if ((Get-ItemProperty -Path $inet -Name ProxyServer).ProxyServer -like "*127.0.0.1:9050*") {
    Set-ItemProperty -Path $inet -Name ProxyEnable -Value 0
}

# 3) Stop and remove both tasks, wait for the daemon process to exit, then delete.
foreach ($t in @("TorandoGUI-Daemon", "TorandoGUI-Tor")) {
    Stop-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $t -Confirm:$false -ErrorAction SilentlyContinue
}
foreach ($i in 1..10) {
    $busy = Get-Process pythonw, tor -ErrorAction SilentlyContinue |
            Where-Object { $_.Path -and $_.Path.StartsWith($InstallDir) }
    if (-not $busy) { break }
    Start-Sleep -Milliseconds 500
}
Remove-Item -Recurse -Force $InstallDir
Write-Host "Removed Torando Control. Your config under %ProgramData%\torando-gui was left in place."
