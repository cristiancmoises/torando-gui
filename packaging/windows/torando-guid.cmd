@echo off
REM SPDX-License-Identifier: AGPL-3.0-only
REM Copyright (c) 2026 Cristian Cezar Moisés — AGPL-3.0-only
REM Torando Control root daemon launcher for Windows.
REM Must run elevated (Administrator): it changes the Windows Firewall policy,
REM the system SOCKS proxy and the interface DNS servers.
setlocal
set "HERE=%~dp0"
set "PYTHONPATH=%HERE%lib;%PYTHONPATH%"
where pythonw.exe >nul 2>&1 && (set "PY=pythonw.exe") || (set "PY=python.exe")
"%PY%" -m torando_gui %*
