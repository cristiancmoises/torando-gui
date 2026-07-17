# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 Cristian Cezar Moisés — AGPL-3.0-only
"""Per-platform DNS pinning.

"Pin DNS to 127.0.0.1" means something different on each OS:

* **Linux / *BSD** — rewrite ``/etc/resolv.conf`` to ``nameserver 127.0.0.1`` and
  make it immutable (``chattr +i`` on Linux, ``chflags schg`` on the BSDs) so
  dhclient/resolvconf/resolvd can't clobber it. This is the file-based path in
  :mod:`torando_gui.netcfg`.
* **macOS** — ``/etc/resolv.conf`` is a compatibility stub that most apps ignore;
  the real setting is per network service via ``networksetup -setdnsservers``.
* **Windows** — per interface via ``netsh interface ipv4 set dnsservers``.

Each pinner captures the prior resolver so ``restore`` puts it back, and reports
``is_pinned``/``nameserver`` for the status view. The Linux behaviour is
unchanged; the others are new in 1.2.0.
"""

from __future__ import annotations

import contextlib
import json
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Protocol

from . import netcfg
from . import platform as _plat
from .config import Config, atomic_write_text

Runner = Callable[[list[str]], "subprocess.CompletedProcess[str]"]

LOOPBACK = "127.0.0.1"


def _default_runner(argv: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, capture_output=True, text=True, check=False)  # noqa: S603


class DnsPinner(Protocol):
    def lock(self, cfg: Config) -> dict[str, object]: ...
    def restore(self, cfg: Config) -> dict[str, object]: ...
    def is_pinned(self, cfg: Config) -> bool: ...
    def nameserver(self, cfg: Config) -> str: ...


class FileDns:
    """resolv.conf-based pinning for Linux and the BSDs (immutability via
    ``chattr`` or ``chflags`` depending on platform)."""

    def __init__(self, platform_id: str | None = None, runner: Runner | None = None) -> None:
        self._p = platform_id or _plat.CURRENT
        self._run = runner or _default_runner
        if _plat.is_bsd(self._p) or self._p == _plat.MACOS:
            self._set = netcfg.CHFLAGS_SET
            self._clear = netcfg.CHFLAGS_CLEAR
        else:
            self._set = netcfg.CHATTR_SET
            self._clear = netcfg.CHATTR_CLEAR

    def lock(self, cfg: Config) -> dict[str, object]:
        return netcfg.lock_resolv(
            cfg, runner=self._run, set_immutable=self._set, clear_immutable=self._clear
        )

    def restore(self, cfg: Config) -> dict[str, object]:
        return netcfg.restore_resolv(cfg, runner=self._run, clear_immutable=self._clear)

    def is_pinned(self, cfg: Config) -> bool:
        return netcfg.resolv_is_pinned(cfg)

    def nameserver(self, cfg: Config) -> str:
        try:
            for line in Path(cfg.resolv_path).read_text(encoding="utf-8").splitlines():
                s = line.strip()
                if s.startswith("nameserver"):
                    parts = s.split()
                    return parts[1] if len(parts) > 1 else ""
        except OSError:
            return ""
        return ""


# --- macOS networksetup ------------------------------------------------------
def parse_network_services(text: str) -> list[str]:
    """Enabled service names from ``networksetup -listallnetworkservices``.

    The first line is an informational header; a leading ``*`` marks a disabled
    service (excluded).
    """
    out: list[str] = []
    for line in text.splitlines()[1:]:
        name = line.strip()
        if name and not name.startswith("*"):
            out.append(name)
    return out


def parse_dns_servers(text: str) -> list[str]:
    """DNS servers from ``networksetup -getdnsservers``.

    Returns [] when DHCP-supplied (the tool prints "There aren't any DNS Servers
    set on <service>." in that case).
    """
    servers = []
    for line in text.splitlines():
        s = line.strip()
        if not s or "aren't any" in s or "There aren" in s:
            continue
        servers.append(s)
    return servers


class MacDns:
    """DNS pinning via ``networksetup`` (per network service)."""

    def __init__(self, runner: Runner | None = None, state_dir: Path | None = None) -> None:
        self._run = runner or _default_runner
        self._state_dir = state_dir or Path("/etc/torando-gui")

    def _state_file(self) -> Path:
        return self._state_dir / "macos_dns_state.json"

    def _load_state(self) -> dict | None:
        try:
            return json.loads(self._state_file().read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None

    def _services(self) -> list[str]:
        res = self._run(["networksetup", "-listallnetworkservices"])
        return parse_network_services(res.stdout or "") if res.returncode == 0 else []

    def _current(self, service: str) -> list[str]:
        res = self._run(["networksetup", "-getdnsservers", service])
        return parse_dns_servers(res.stdout or "") if res.returncode == 0 else []

    def lock(self, cfg: Config) -> dict[str, object]:
        services = self._services()
        # Capture ONCE. If a state file already exists (a prior session that
        # didn't tear down), keep the original real resolver — re-capturing now
        # would record our own 127.0.0.1 pin and lose the user's DNS forever.
        if self._load_state() is None:
            captured: dict[str, list[str]] = {}
            for svc in services:
                cur = self._current(svc)
                # never snapshot our own pin as the "real" resolver
                captured[svc] = [] if cur == [LOOPBACK] else cur
            atomic_write_text(self._state_file(), json.dumps(captured, indent=2) + "\n", mode=0o600)
        for svc in services:
            self._run(["networksetup", "-setdnsservers", svc, LOOPBACK])
        return {"path": "networksetup", "immutable": False, "note": "", "services": len(services)}

    def restore(self, cfg: Config) -> dict[str, object]:
        state = self._load_state()
        if state is None:
            # Nothing we pinned — do NOT reset every service to DHCP, which would
            # wipe a user's manually-configured DNS on a never-connected machine.
            return {"path": "networksetup", "restored": False, "note": "no saved DNS state"}
        for svc, prior in state.items():
            if prior:
                self._run(["networksetup", "-setdnsservers", svc, *prior])
            else:
                self._run(["networksetup", "-setdnsservers", svc, "Empty"])
        with contextlib.suppress(OSError):
            self._state_file().unlink()
        return {"path": "networksetup", "restored": True, "note": ""}

    def is_pinned(self, cfg: Config) -> bool:
        services = self._services()
        if not services:
            return False
        return all(self._current(svc) == [LOOPBACK] for svc in services)

    def nameserver(self, cfg: Config) -> str:
        for svc in self._services():
            cur = self._current(svc)
            if cur:
                return cur[0]
        return ""


# --- Windows netsh -----------------------------------------------------------
def parse_interface_names(text: str) -> list[str]:
    """Interface names from ``netsh interface ipv4 show interfaces``.

    LOCALE-INDEPENDENT: the header and the ``State`` column are translated on
    non-English Windows, so we key only on the numeric ``Idx`` column (the first
    token being an integer marks a data row) and take the name from the 5th
    column on. We deliberately do NOT filter on ``State`` — setting DNS on a
    down adapter is harmless, and filtering on the (localized) State word is
    exactly what caused a total DNS outage on non-English Windows. Loopback is
    skipped.
    """
    names: list[str] = []
    for line in text.splitlines():
        cols = line.split()
        if len(cols) < 5 or not cols[0].isdigit():
            continue
        name = " ".join(cols[4:])
        if name and "loopback" not in name.lower():
            names.append(name)
    return names


def parse_dns_config(text: str) -> dict:
    """Parse ``netsh interface ipv4 show dnsservers name="X"`` into
    ``{"dhcp": bool, "servers": [ip, ...]}``.

    The ``DNS servers configured through DHCP`` line is authoritative: when it is
    present the interface is DHCP and its servers must NOT be captured as static
    (netsh prints the DHCP-assigned server on that same line, and treating it as
    static would permanently freeze the adapter onto that resolver on restore).
    Only ``Statically Configured DNS Servers`` are captured as static.
    """
    if "through DHCP" in text or "through dhcp" in text.lower():
        return {"dhcp": True, "servers": []}
    servers: list[str] = []
    for line in text.splitlines():
        for tok in line.replace(":", " ").split():
            parts = tok.split(".")
            if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
                servers.append(tok)
    return {"dhcp": False, "servers": servers}


class WindowsDns:
    """DNS pinning via ``netsh interface ipv4``.

    Complementary to the firewall killswitch (which already blocks port-53
    egress): pinning the interface resolver to 127.0.0.1 routes lookups through
    Tor's DNSPort. The prior per-interface config is captured so restore puts
    back exactly what was there (static servers or DHCP), never blindly DHCP.
    """

    def __init__(self, runner: Runner | None = None, state_dir: Path | None = None) -> None:
        self._run = runner or _default_runner
        self._state_dir = state_dir or Path(_programdata()) / "torando-gui"

    def _state_file(self) -> Path:
        return self._state_dir / "windows_dns_state.json"

    def _load_state(self) -> dict | None:
        try:
            return json.loads(self._state_file().read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None

    def _interfaces(self) -> list[str]:
        res = self._run(["netsh", "interface", "ipv4", "show", "interfaces"])
        return parse_interface_names(res.stdout or "") if res.returncode == 0 else []

    def _dns_config(self, name: str) -> dict:
        res = self._run(["netsh", "interface", "ipv4", "show", "dnsservers", f"name={name}"])
        return (
            parse_dns_config(res.stdout or "")
            if res.returncode == 0
            else {"dhcp": True, "servers": []}
        )

    def lock(self, cfg: Config) -> dict[str, object]:
        ifaces = self._interfaces()
        if not ifaces:
            # Localized Windows or no connected adapter: pin nothing and record
            # nothing, so is_pinned() won't falsely claim DNS is routed via Tor.
            return {
                "path": "netsh",
                "immutable": False,
                "note": "no interfaces to pin",
                "interfaces": 0,
            }
        # Capture ONCE (crash-safe): keep the original config if a state file
        # already exists, otherwise snapshot each interface's real DNS config.
        if self._load_state() is None:
            captured = {name: self._dns_config(name) for name in ifaces}
            atomic_write_text(self._state_file(), json.dumps(captured, indent=2) + "\n", mode=0o600)
        for name in ifaces:
            self._run(
                [
                    "netsh",
                    "interface",
                    "ipv4",
                    "set",
                    "dnsservers",
                    f"name={name}",
                    "static",
                    LOOPBACK,
                    "primary",
                ]
            )
        return {"path": "netsh", "immutable": False, "note": "", "interfaces": len(ifaces)}

    def restore(self, cfg: Config) -> dict[str, object]:
        state = self._load_state()
        if state is None:
            return {"path": "netsh", "restored": False, "note": "no saved DNS state"}
        all_ok = True
        for name, cfgd in state.items():
            servers = cfgd.get("servers") if isinstance(cfgd, dict) else None
            if servers and not (len(servers) == 1 and servers[0] == LOOPBACK):
                ok = self._run_ok(
                    [
                        "netsh",
                        "interface",
                        "ipv4",
                        "set",
                        "dnsservers",
                        f"name={name}",
                        "static",
                        servers[0],
                        "primary",
                    ]
                )
                for idx, extra in enumerate(servers[1:], start=2):
                    self._run(
                        [
                            "netsh",
                            "interface",
                            "ipv4",
                            "add",
                            "dnsservers",
                            f"name={name}",
                            extra,
                            f"index={idx}",
                        ]
                    )
            else:
                ok = self._run_ok(
                    [
                        "netsh",
                        "interface",
                        "ipv4",
                        "set",
                        "dnsservers",
                        f"name={name}",
                        "source=dhcp",
                    ]
                )
            all_ok = all_ok and ok
        if all_ok:
            with contextlib.suppress(OSError):
                self._state_file().unlink()
            return {"path": "netsh", "restored": True, "note": ""}
        # Keep the state file so a retry (or --restore-dns) can finish the job.
        return {"path": "netsh", "restored": False, "note": "some interfaces failed to restore"}

    def _run_ok(self, argv: list[str]) -> bool:
        return self._run(argv).returncode == 0

    def is_pinned(self, cfg: Config) -> bool:
        # Cheap proxy: our state file exists only while pinned.
        return self._state_file().exists()

    def nameserver(self, cfg: Config) -> str:
        return LOOPBACK if self.is_pinned(cfg) else ""


def _programdata() -> str:
    import os

    return os.environ.get("PROGRAMDATA", r"C:\ProgramData")


def make_dns(platform_id: str | None = None, runner: Runner | None = None) -> DnsPinner:
    """Return the DNS pinner for *platform_id* (default: this host)."""
    p = platform_id or _plat.CURRENT
    if p == _plat.MACOS:
        return MacDns(runner=runner)
    if p == _plat.WINDOWS:
        return WindowsDns(runner=runner)
    return FileDns(platform_id=p, runner=runner)
