# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 Cristian Cezar Moisés — AGPL-3.0-only
"""Desktop launcher.

Opens the Torando Control UI in the default browser. The backend needs root
(it edits netfilter, torrc and resolv.conf), so this launcher does not start it
directly when run unprivileged: it asks systemd to start the system service —
which polkit can authorize for a desktop user — then waits for the local
endpoint to answer and opens it. The session token is injected into the page by
the server, so the launcher never needs to read or handle it.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
import webbrowser

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8088


def _url() -> str:
    host = os.environ.get("TORANDO_HOST", DEFAULT_HOST)
    port = os.environ.get("TORANDO_PORT", str(DEFAULT_PORT))
    return f"http://{host}:{port}/"


def _reachable(url: str, timeout: float = 1.5) -> bool:
    try:
        # URL is always http on loopback (built from host/port); not user-controlled.
        with urllib.request.urlopen(url, timeout=timeout):  # noqa: S310
            return True
    except (urllib.error.URLError, OSError):
        return False


def _start_service() -> str:
    """Ask systemd (via polkit) to start the daemon. Returns any error text."""
    if shutil.which("systemctl") is None:
        return "systemctl not found"
    # User invocation triggers polkit; the shipped policy authorizes it.
    # systemctl is resolved via PATH so this works across FHS distros and Guix.
    proc = subprocess.run(
        ["systemctl", "start", "torando-gui.service"],  # noqa: S607
        check=False,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        return (proc.stderr or proc.stdout or "systemctl start failed").strip()
    return ""


def main(argv: list[str] | None = None) -> int:
    url = _url()
    start_error = ""
    if not _reachable(url):
        start_error = _start_service()
        for _ in range(20):
            if _reachable(url):
                break
            time.sleep(0.5)
    if not _reachable(url):
        detail = f"systemctl: {start_error}\n" if start_error else ""
        sys.stderr.write(
            "Torando Control backend is not reachable at "
            f"{url}\n{detail}Start it with:  sudo systemctl start torando-gui.service\n"
        )
        return 1
    webbrowser.open(url)
    sys.stdout.write(f"Torando Control: {url}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
