@echo off
REM SPDX-License-Identifier: AGPL-3.0-only
REM Copyright (c) 2026 Cristian Cezar Moises - AGPL-3.0-only
REM Torando Control front end, run by the bundled Python. Opens the UI in your
REM browser; has no privileges of its own.
setlocal
set "HERE=%~dp0"
"%HERE%python\python.exe" "%HERE%boot\gui.py" %*
