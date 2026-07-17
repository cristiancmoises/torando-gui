@echo off
REM SPDX-License-Identifier: AGPL-3.0-only
REM Copyright (c) 2026 Cristian Cezar Moises - AGPL-3.0-only
REM Torando Control root daemon, run by the bundled Python (no system Python
REM needed). Must run elevated: it changes the firewall, system proxy and DNS.
setlocal
set "HERE=%~dp0"
"%HERE%python\pythonw.exe" "%HERE%boot\daemon.py" %*
