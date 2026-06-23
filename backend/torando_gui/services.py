# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 Cristian Cezar Moisés — AGPL-3.0-only
"""Thin wrappers around systemctl and the local account database.

Used for: showing/controlling the Tor system service, and listing the human
accounts the GUI can offer as the torification target.
"""

from __future__ import annotations

import pwd
import shutil
import subprocess
from collections.abc import Callable

Runner = Callable[[list[str]], "subprocess.CompletedProcess[str]"]

# Tor ships under different unit names across distros; first hit wins.
TOR_UNITS = ("tor.service", "tor@default.service", "tor@default")

# Login shells that indicate "not a real interactive user".
_NOLOGIN = {"/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false"}


def _default_runner(argv: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, capture_output=True, text=True, check=False)  # noqa: S603


def tor_installed() -> bool:
    return shutil.which("tor") is not None


def _is_active(unit: str, run: Runner) -> bool:
    return run(["systemctl", "is-active", "--quiet", unit]).returncode == 0


def tor_service_status(runner: Runner | None = None) -> dict[str, object]:
    run = runner or _default_runner
    if shutil.which("systemctl") is None:
        return {"installed": tor_installed(), "active": None, "unit": None, "note": "no systemctl"}
    for unit in TOR_UNITS:
        if _is_active(unit, run):
            return {"installed": True, "active": True, "unit": unit, "note": ""}
    return {"installed": tor_installed(), "active": False, "unit": TOR_UNITS[0], "note": ""}


def _act(action: str, runner: Runner | None) -> dict[str, object]:
    run = runner or _default_runner
    last = None
    for unit in TOR_UNITS:
        res = run(["systemctl", action, unit])
        if res.returncode == 0:
            return {"ok": True, "unit": unit, "error": ""}
        last = res.stderr.strip()
    return {"ok": False, "unit": TOR_UNITS[0], "error": last or f"systemctl {action} failed"}


def start_tor(runner: Runner | None = None) -> dict[str, object]:
    return _act("start", runner)


def stop_tor(runner: Runner | None = None) -> dict[str, object]:
    return _act("stop", runner)


def reload_tor(runner: Runner | None = None) -> dict[str, object]:
    return _act("reload-or-restart", runner)


def candidate_users(min_uid: int = 1000, max_uid: int = 60000) -> list[dict[str, object]]:
    """Human accounts the GUI may torify: uid in range and a real login shell."""
    out: list[dict[str, object]] = []
    for ent in pwd.getpwall():
        if min_uid <= ent.pw_uid <= max_uid and ent.pw_shell not in _NOLOGIN:
            out.append({"uid": ent.pw_uid, "name": ent.pw_name})
    out.sort(key=lambda e: e["uid"])
    return out
