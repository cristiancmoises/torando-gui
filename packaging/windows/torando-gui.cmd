@echo off
REM SPDX-License-Identifier: AGPL-3.0-only
REM Copyright (c) 2026 Cristian Cezar Moisés — AGPL-3.0-only
REM Torando Control front end for Windows (opens the UI; no privileges of its own).
setlocal
set "HERE=%~dp0"
set "PYTHONPATH=%HERE%lib;%PYTHONPATH%"
python.exe -m torando_gui.launcher %*
