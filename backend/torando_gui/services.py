# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 Cristian Cezar Moisés — AGPL-3.0-only
"""Thin wrappers around the init system and the local account database.

Used for: showing/controlling the Tor system service, and listing the human
accounts the GUI can offer as the torification target. Both are per-platform —
systemd on most Linux, ``service``/``rcctl`` on the BSDs, ``brew services`` on
macOS, and a Scheduled Task on Windows — so this module hides the differences
behind :func:`tor_service_status`, :func:`reload_tor` and :func:`candidate_users`.
"""

from __future__ import annotations

import shutil
import subprocess
from collections.abc import Callable

from . import platform as _plat

try:
    import pwd  # POSIX-only; absent on Windows.
except ImportError:  # pragma: no cover - exercised only on Windows
    pwd = None  # type: ignore[assignment]

Runner = Callable[[list[str]], "subprocess.CompletedProcess[str]"]

# Tor ships under different unit names across distros; first hit wins.
TOR_UNITS = ("tor.service", "tor@default.service", "tor@default")

# Login shells that indicate "not a real interactive user".
_NOLOGIN = {"/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false"}


def _default_runner(argv: list[str]) -> subprocess.CompletedProcess[str]:
    return _plat.run_argv(argv)  # routes through CREATE_NO_WINDOW on Windows


def tor_installed() -> bool:
    return shutil.which("tor") is not None or shutil.which("tor.exe") is not None


def _is_active(unit: str, run: Runner) -> bool:
    return run(["systemctl", "is-active", "--quiet", unit]).returncode == 0


def _systemd_status(run: Runner) -> dict[str, object]:
    for unit in TOR_UNITS:
        if _is_active(unit, run):
            return {"installed": True, "active": True, "unit": unit, "note": ""}
    return {"installed": tor_installed(), "active": False, "unit": TOR_UNITS[0], "note": ""}


def _bsd_service_status(run: Runner, name: str = "tor") -> dict[str, object]:
    # FreeBSD/NetBSD `service tor status`; OpenBSD `rcctl check tor`.
    if shutil.which("rcctl"):
        res = run(["rcctl", "check", name])
        return {
            "installed": tor_installed(),
            "active": res.returncode == 0,
            "unit": name,
            "note": "",
        }
    if shutil.which("service"):
        res = run(["service", name, "status"])
        return {
            "installed": tor_installed(),
            "active": res.returncode == 0,
            "unit": name,
            "note": "",
        }
    return {"installed": tor_installed(), "active": None, "unit": name, "note": "no service tool"}


def _macos_status(run: Runner) -> dict[str, object]:
    if shutil.which("brew"):
        res = run(["brew", "services", "list"])
        for line in (res.stdout or "").splitlines():
            cols = line.split()
            if cols and cols[0] == "tor":
                active = len(cols) > 1 and cols[1].lower() in ("started", "running")
                return {"installed": True, "active": active, "unit": "tor (brew)", "note": ""}
    return {"installed": tor_installed(), "active": None, "unit": "tor (brew)", "note": ""}


def _windows_status(run: Runner) -> dict[str, object]:
    # Tor runs from the Expert Bundle under our Scheduled Task; probe the task.
    res = run(["schtasks", "/Query", "/TN", "TorandoGUI-Tor"])
    active = res.returncode == 0 and "Running" in (res.stdout or "")
    installed = res.returncode == 0 or tor_installed()
    return {"installed": installed, "active": active, "unit": "TorandoGUI-Tor (task)", "note": ""}


def tor_service_status(runner: Runner | None = None) -> dict[str, object]:
    run = runner or _default_runner
    p = _plat.CURRENT
    if p == _plat.LINUX or shutil.which("systemctl"):
        if shutil.which("systemctl"):
            return _systemd_status(run)
        return {"installed": tor_installed(), "active": None, "unit": None, "note": "no systemctl"}
    if _plat.is_bsd(p):
        return _bsd_service_status(run)
    if p == _plat.MACOS:
        return _macos_status(run)
    if p == _plat.WINDOWS:
        return _windows_status(run)
    return {"installed": tor_installed(), "active": None, "unit": None, "note": "unknown platform"}


def _systemd_act(action: str, run: Runner) -> dict[str, object]:
    last = None
    for unit in TOR_UNITS:
        res = run(["systemctl", action, unit])
        if res.returncode == 0:
            return {"ok": True, "unit": unit, "error": ""}
        last = res.stderr.strip()
    return {"ok": False, "unit": TOR_UNITS[0], "error": last or f"systemctl {action} failed"}


def _act(action: str, runner: Runner | None) -> dict[str, object]:
    run = runner or _default_runner
    p = _plat.CURRENT
    if shutil.which("systemctl"):
        return _systemd_act(action, run)
    if _plat.is_bsd(p):
        if shutil.which("rcctl"):
            res = run(["rcctl", "restart" if action == "reload-or-restart" else action, "tor"])
        else:
            verb = "restart" if action == "reload-or-restart" else action
            res = run(["service", "tor", verb])
        return {"ok": res.returncode == 0, "unit": "tor", "error": res.stderr.strip()}
    if p == _plat.MACOS and shutil.which("brew"):
        verb = "restart" if action in ("reload-or-restart", "reload") else action
        res = run(["brew", "services", verb, "tor"])
        return {"ok": res.returncode == 0, "unit": "tor (brew)", "error": res.stderr.strip()}
    if p == _plat.WINDOWS:
        # The Scheduled Task owns tor.exe; a "reload" is a task restart.
        run(["schtasks", "/End", "/TN", "TorandoGUI-Tor"])
        res = run(["schtasks", "/Run", "/TN", "TorandoGUI-Tor"])
        return {
            "ok": res.returncode == 0,
            "unit": "TorandoGUI-Tor (task)",
            "error": res.stderr.strip(),
        }
    return {"ok": False, "unit": "tor", "error": "no service manager for this platform"}


def start_tor(runner: Runner | None = None) -> dict[str, object]:
    return _act("start", runner)


def stop_tor(runner: Runner | None = None) -> dict[str, object]:
    return _act("stop", runner)


def reload_tor(runner: Runner | None = None) -> dict[str, object]:
    return _act("reload-or-restart", runner)


def candidate_users(min_uid: int = 1000, max_uid: int = 60000) -> list[dict[str, object]]:
    """Human accounts the GUI may torify.

    On POSIX: uid in range with a real login shell. macOS starts human UIDs at
    501, so the floor is lowered there. Windows has no per-UID model (the
    killswitch is machine-wide), so this returns the current account purely for
    display — selection isn't required to connect.
    """
    if pwd is None:  # Windows
        import getpass

        try:
            name = getpass.getuser()
        except Exception:  # noqa: BLE001
            name = "current user"
        return [{"uid": 0, "name": f"{name} (machine-wide)"}]

    floor = 500 if _plat.CURRENT == _plat.MACOS else min_uid
    out: list[dict[str, object]] = []
    for ent in pwd.getpwall():
        if floor <= ent.pw_uid <= max_uid and ent.pw_shell not in _NOLOGIN:
            out.append({"uid": ent.pw_uid, "name": ent.pw_name})
    out.sort(key=lambda e: e["uid"])
    return out
