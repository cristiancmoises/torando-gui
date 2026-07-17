# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 Cristian Cezar Moisés — AGPL-3.0-only
"""Desktop launcher / entry point for the user-facing GUI.

``main`` opens the **native desktop window** (GTK4 + WebKitGTK — see
``desktop.py``); if the GUI toolkit isn't installed it falls back to opening the
UI in the default browser. Either way it first makes sure the root daemon is
running: the backend needs root (it edits netfilter, torrc and resolv.conf), so
an unprivileged launch asks the init system to start the system service (systemd
via polkit, or — on Guix System — the Shepherd service), waits for the loopback
endpoint to answer, and then shows it. The session token is injected into the
page by the server, so the launcher never reads or handles it.
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

from . import platform as _plat

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
    """Ask the init system to start the daemon. Returns any error text.

    Only the systemd path can start the daemon without an interactive prompt
    (via the shipped polkit policy). On the other platforms elevation needs a
    password/consent the launcher can't supply, so it returns a hint instead.
    """
    if _plat.CURRENT == _plat.LINUX and shutil.which("systemctl"):
        # User invocation triggers polkit; the shipped policy authorizes it.
        proc = subprocess.run(
            ["systemctl", "start", "torando-gui.service"],  # noqa: S607
            check=False,
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0:
            return (proc.stderr or proc.stdout or "systemctl start failed").strip()
        return ""
    return "daemon not running"


def _start_hint() -> str:
    """A platform-appropriate 'how to start the daemon' message."""
    p = _plat.CURRENT
    if p == _plat.WINDOWS:
        return (
            "Start the daemon as Administrator:  torando-guid\n"
            "(or install the boot task from packaging\\windows\\install.ps1)"
        )
    if p == _plat.MACOS:
        return (
            "Start the daemon as root:  sudo torando-guid\n"
            "(or load the LaunchDaemon: sudo launchctl load "
            "/Library/LaunchDaemons/co.securityops.torando-gui.plist)"
        )
    if _plat.is_bsd(p):
        if shutil.which("rcctl"):
            return "Start it with:  doas rcctl start torando-gui   (OpenBSD)"
        return "Start it with:  sudo service torando-gui start   (FreeBSD)"
    if shutil.which("systemctl"):
        return "Start it with:  sudo systemctl start torando-gui.service"
    if shutil.which("herd"):
        return "Start it with:  sudo herd start torando-gui   (Guix System)"
    return "Start the daemon as root:  sudo torando-guid"


def ensure_daemon() -> tuple[bool, str]:
    """Make a best effort to have the daemon reachable. Returns (reachable, hint)."""
    url = _url()
    start_error = ""
    if not _reachable(url):
        start_error = _start_service()
        for _ in range(20):
            if _reachable(url):
                break
            time.sleep(0.5)
    if _reachable(url):
        return True, ""
    hint = _start_hint()
    if start_error and start_error != "daemon not running":
        hint = f"{start_error}\n{hint}"
    return False, hint


def open_in_browser(argv: list[str] | None = None) -> int:
    """Fallback path: ensure the daemon is up and open the UI in a browser."""
    url = _url()
    ok, hint = ensure_daemon()
    if not ok:
        sys.stderr.write(f"Torando Control backend is not reachable at {url}\n{hint}\n")
        return 1
    webbrowser.open(url)
    sys.stdout.write(f"Torando Control: {url}\n")
    return 0


def main(argv: list[str] | None = None) -> int:
    """Open the native desktop window; fall back to the browser if GTK/WebKit
    is unavailable, or if --browser is passed."""
    args = list(argv if argv is not None else sys.argv[1:])
    if "--browser" in args:
        return open_in_browser(args)
    from . import desktop

    return desktop.run(args)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
