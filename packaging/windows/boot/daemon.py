# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 Cristian Cezar Moisés — AGPL-3.0-only
"""Bootstrap the Torando Control root daemon from the all-in-one bundle.

Why a bootstrap instead of ``pythonw -m torando_gui``:

* It puts the bundled ``lib\\`` on ``sys.path`` **explicitly**, so importing the
  package never depends on the embeddable Python's ``._pth`` resolving a relative
  ``..\\lib`` entry (which is easy to get wrong and impossible to see fail).
* The daemon runs under ``pythonw.exe`` with no console, so it redirects output
  to ``%ProgramData%\\torando-gui\\logs\\daemon.log`` and logs any startup
  exception — otherwise a failure is completely silent and the GUI just reports
  "backend not reachable".
"""

from __future__ import annotations

import datetime
import os
import sys
import traceback

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_ROOT, "lib"))


def _log_path() -> str:
    base = os.environ.get("PROGRAMDATA", r"C:\ProgramData")
    for d in (os.path.join(base, "torando-gui", "logs"), os.path.join(_ROOT, "logs")):
        try:
            os.makedirs(d, exist_ok=True)
            return os.path.join(d, "daemon.log")
        except OSError:
            continue
    return os.path.join(_ROOT, "daemon.log")


def main() -> int:
    # Intentionally kept open for the process lifetime — it is stdout/stderr.
    log = open(_log_path(), "a", buffering=1, encoding="utf-8", errors="replace")  # noqa: SIM115
    sys.stdout = log
    sys.stderr = log
    stamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"\n--- {stamp} starting torando-guid (pid {os.getpid()}) ---", flush=True)
    try:
        from torando_gui.__main__ import main as daemon_main

        return daemon_main(sys.argv[1:])
    except SystemExit as exc:
        return int(exc.code) if isinstance(exc.code, int) else 0
    except BaseException:  # noqa: BLE001 — log everything, this is the top frame
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
