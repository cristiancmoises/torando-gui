#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 Cristian Cezar Moisés — AGPL-3.0-only
# Executable inside "Torando Control.app/Contents/MacOS". Launches the front end,
# which starts (or reaches) the root daemon and opens the UI. No privileges here.
PY="$(command -v python3 || echo /usr/bin/python3)"
export PYTHONPATH="/usr/local/lib/torando-gui${PYTHONPATH:+:$PYTHONPATH}"
exec "$PY" -m torando_gui.launcher "$@"
