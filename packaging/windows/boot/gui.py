# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 Cristian Cezar Moisés — AGPL-3.0-only
"""Bootstrap the Torando Control front end from the all-in-one bundle.

Puts the bundled ``lib\\`` on ``sys.path`` explicitly (no reliance on the
embeddable ``._pth``), then hands off to the normal launcher, which opens the UI
in the browser. Runs under ``python.exe`` so any error is visible in the console.
"""

from __future__ import annotations

import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_ROOT, "lib"))

if __name__ == "__main__":
    from torando_gui.launcher import main

    sys.exit(main(sys.argv[1:]))
