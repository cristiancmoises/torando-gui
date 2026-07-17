# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 Cristian Cezar Moisés — AGPL-3.0-only
"""Windows firewall + system-proxy backend.

Windows has no driverless way to transparently redirect one process's outbound
TCP into Tor (that needs a WFP/NDIS kernel driver such as WinDivert, which this
stdlib-only tool deliberately avoids). So the Windows model is the honest one:

* a **system SOCKS proxy** (WinINET registry) points cooperating apps at Tor's
  ``SocksPort``; and
* a **default-block-outbound Windows Firewall killswitch** that whitelists only
  ``tor.exe`` and loopback — so an app that ignores the proxy is *blocked*, never
  leaked around Tor.

This is machine-wide, not per-UID: ``target_uid`` is meaningless here. The prior
firewall policy is captured before we change it and restored on disconnect, and
only our own named rules are added/removed — we never run ``netsh advfirewall
reset``, which would wipe the user's existing rules.

Command *generation* is pure and unit-tested on any OS. Only :class:`WindowsFirewall`
touches ``netsh``/``winreg``/``ctypes``, all imported lazily.
"""

from __future__ import annotations

import contextlib
import json
import re
import shutil
import subprocess
from collections.abc import Callable
from pathlib import Path

from . import platform as _plat
from .config import Config, atomic_write_text

Runner = Callable[[list[str]], "subprocess.CompletedProcess[str]"]

RULE_PREFIX = "TorandoGUI-"
RULE_TOR = RULE_PREFIX + "Tor-Out"
RULE_LOOPBACK4 = RULE_PREFIX + "Loopback4-Out"
RULE_LOOPBACK6 = RULE_PREFIX + "Loopback6-Out"
RULE_DHCP = RULE_PREFIX + "DHCP-Out"
RULE_LAN = RULE_PREFIX + "LAN-Out"

PROFILES = ("domainprofile", "privateprofile", "publicprofile")

# WinINET registry surface for the per-user system proxy.
_INET_KEY = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
# InternetSetOption option codes used to broadcast a proxy change.
_INTERNET_OPTION_SETTINGS_CHANGED = 39
_INTERNET_OPTION_REFRESH = 37


def _default_runner(argv: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, capture_output=True, text=True, check=False)  # noqa: S603


# --- pure command generation (unit-tested) ----------------------------------
def set_policy_cmd(profile: str, inbound: str, outbound: str) -> list[str]:
    """netsh argv to set one profile's firewall policy (e.g. block outbound)."""
    return ["netsh", "advfirewall", "set", profile, "firewallpolicy", f"{inbound},{outbound}"]


def allow_program_cmd(name: str, program: str) -> list[str]:
    return [
        "netsh",
        "advfirewall",
        "firewall",
        "add",
        "rule",
        f"name={name}",
        "dir=out",
        "action=allow",
        f"program={program}",
        "enable=yes",
        "profile=any",
    ]


def allow_remoteip_cmd(
    name: str,
    remoteip: str,
    *,
    protocol: str | None = None,
    localport: str | None = None,
    remoteport: str | None = None,
) -> list[str]:
    argv = [
        "netsh",
        "advfirewall",
        "firewall",
        "add",
        "rule",
        f"name={name}",
        "dir=out",
        "action=allow",
        f"remoteip={remoteip}",
    ]
    if protocol:
        argv.append(f"protocol={protocol}")
    if localport:
        argv.append(f"localport={localport}")
    if remoteport:
        argv.append(f"remoteport={remoteport}")
    argv += ["enable=yes", "profile=any"]
    return argv


def delete_rule_cmd(name: str) -> list[str]:
    return ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"]


def proxy_server_value(host: str, port: int) -> str:
    """The WinINET ProxyServer string that forces ALL protocols through SOCKS."""
    return f"socks={host}:{port}"


def parse_firewall_policy(show_output: str) -> dict[str, str]:
    """Parse ``netsh advfirewall show allprofiles`` into {profile: 'In,Out'}.

    The output has three sections (Domain/Private/Public Profile Settings) each
    with a ``Firewall Policy`` line like ``BlockInbound,AllowOutbound``. Returns a
    mapping keyed by the netsh profile token (domainprofile/…). Missing sections
    are simply absent from the result.
    """
    out: dict[str, str] = {}
    section_to_profile = {
        "Domain Profile": "domainprofile",
        "Private Profile": "privateprofile",
        "Public Profile": "publicprofile",
    }
    current: str | None = None
    for raw in show_output.splitlines():
        line = raw.strip()
        for label, token in section_to_profile.items():
            if line.startswith(label):
                current = token
                break
        m = re.match(r"Firewall Policy\s+(\S+)", line)
        if m and current:
            # value like 'BlockInbound,AllowOutbound' -> keep as 'In,Out' tokens
            out[current] = m.group(1)
            current = None
    return out


class WindowsFirewall:
    """Arms/disarms the machine-wide killswitch and the WinINET SOCKS proxy."""

    def __init__(self, runner: Runner | None = None, state_dir: Path | None = None) -> None:
        self._run = runner or _default_runner
        self._state_dir = state_dir or (Path(_plat_env_programdata()) / "torando-gui")

    # --- discovery -------------------------------------------------------
    def available(self) -> bool:
        if not _plat.is_windows():
            return False
        return shutil.which("netsh") is not None

    def _tor_path(self, cfg: Config) -> str:
        if cfg.tor_path:
            return cfg.tor_path
        found = shutil.which("tor") or shutil.which("tor.exe")
        if found:
            return found
        raise _fw_error(
            "tor.exe not found — set tor_path in the config to the Tor Expert "
            "Bundle's tor.exe so the firewall can whitelist it."
        )

    def _state_file(self) -> Path:
        return self._state_dir / "windows_fw_state.json"

    # --- apply / remove --------------------------------------------------
    def _run_ok(self, argv: list[str]) -> bool:
        return self._run(argv).returncode == 0

    def apply(self, cfg: Config) -> None:
        from .firewall import FirewallError

        tor = self._tor_path(cfg)
        # 1) Capture the prior policy + proxy ONCE. If a state file already
        #    exists (a prior session that didn't tear down — crash/reboot), keep
        #    the ORIGINAL captured state; re-capturing now would record our own
        #    blockoutbound/proxy as the "prior" and make restore a permanent
        #    lockout. This mirrors the resolv.conf capture-once guard.
        existing = self._load_state()
        if existing and existing.get("policy"):
            prior = existing["policy"]
            prior_proxy = existing.get("proxy")
        else:
            prior = self._capture_policy()
            prior_proxy = self._capture_proxy()
            self._save_state({"policy": prior, "proxy": prior_proxy})

        # 2) Whitelist the traffic that must survive the block FIRST — Tor,
        #    loopback, optionally DHCP/LAN — checking each rule was accepted.
        rules = [
            allow_program_cmd(RULE_TOR, tor),
            allow_remoteip_cmd(RULE_LOOPBACK4, "127.0.0.1"),
            allow_remoteip_cmd(RULE_LOOPBACK6, "::1"),
        ]
        if cfg.allow_dhcp:
            rules.append(
                allow_remoteip_cmd(
                    RULE_DHCP, "any", protocol="UDP", localport="68", remoteport="67"
                )
            )
        if cfg.allow_lan:
            rules.append(allow_remoteip_cmd(RULE_LAN, "LocalSubnet"))
        for r in rules:
            if not self._run_ok(r):
                # A whitelist rule failed — do NOT proceed to block outbound (that
                # would lock the machine out). Undo and fail so connect() rolls back.
                self._teardown(cfg)
                raise FirewallError(f"failed to add firewall rule: {' '.join(r)}")

        # 3) Flip outbound to block on every profile (preserve inbound direction).
        for profile in PROFILES:
            inbound = _inbound_token(prior.get(profile, "BlockInbound,AllowOutbound"))
            if not self._run_ok(set_policy_cmd(profile, inbound, "blockoutbound")):
                self._teardown(cfg)
                raise FirewallError(f"failed to block outbound on {profile}")

        # 4) Point the system proxy at Tor's SocksPort.
        self._set_proxy(enable=True, server=proxy_server_value(cfg.host_socks(), cfg.socks_port))

    def remove(self, cfg: Config) -> None:
        from .firewall import FirewallError

        state = self._load_state() or {}
        prior = state.get("policy", {})
        # Restore each profile's captured policy, checking it took. If ANY
        # restore fails we must NOT delete the whitelist rules or the state file
        # — that would leave the machine blocking outbound with Tor no longer
        # whitelisted and no record of how to recover.
        all_restored = True
        for profile in PROFILES:
            captured = prior.get(profile)
            if captured and "," in captured:
                inbound, outbound = captured.split(",", 1)
            else:
                inbound, outbound = _inbound_token(captured or ""), "allowoutbound"
            if not self._run_ok(set_policy_cmd(profile, inbound, outbound)):
                all_restored = False

        self._restore_proxy(state.get("proxy"))
        if not all_restored:
            raise FirewallError(
                "could not restore the firewall policy on every profile; leaving the "
                "Tor/loopback allow rules and saved state in place. Retry disconnect, or "
                "restore manually with: netsh advfirewall set allprofiles firewallpolicy "
                "blockinbound,allowoutbound"
            )
        # Only now that outbound is allowed again is it safe to drop our rules.
        for name in (RULE_TOR, RULE_LOOPBACK4, RULE_LOOPBACK6, RULE_DHCP, RULE_LAN):
            self._run(delete_rule_cmd(name))
        with contextlib.suppress(OSError):
            self._state_file().unlink(missing_ok=True)

    def _teardown(self, cfg: Config) -> None:
        """Best-effort undo used when apply() fails mid-way: restore policy and
        proxy and delete our rules, so a failed connect never leaves the machine
        blocking outbound."""
        state = self._load_state() or {}
        prior = state.get("policy", {})
        for profile in PROFILES:
            captured = prior.get(profile)
            if captured and "," in captured:
                inbound, outbound = captured.split(",", 1)
            else:
                inbound, outbound = _inbound_token(captured or ""), "allowoutbound"
            self._run(set_policy_cmd(profile, inbound, outbound))
        for name in (RULE_TOR, RULE_LOOPBACK4, RULE_LOOPBACK6, RULE_DHCP, RULE_LAN):
            self._run(delete_rule_cmd(name))
        self._restore_proxy(state.get("proxy"))
        with contextlib.suppress(OSError):
            self._state_file().unlink(missing_ok=True)

    def status(self, cfg: Config) -> dict[str, object]:
        current = self._capture_policy()
        blocked = all("BlockOutbound" in current.get(p, "") for p in PROFILES) and bool(current)
        proxied = self._proxy_is_ours(proxy_server_value(cfg.host_socks(), cfg.socks_port))
        active = blocked and proxied
        return {
            "rules_total": len(PROFILES),
            "rules_present": sum(1 for p in PROFILES if "BlockOutbound" in current.get(p, "")),
            "active": active,
            "killswitch": blocked,
        }

    # --- helpers ---------------------------------------------------------
    def _capture_policy(self) -> dict[str, str]:
        res = self._run(["netsh", "advfirewall", "show", "allprofiles"])
        if res.returncode != 0:
            return {}
        return parse_firewall_policy(res.stdout or "")

    def _save_state(self, data: dict) -> None:
        atomic_write_text(self._state_file(), json.dumps(data, indent=2) + "\n", mode=0o600)

    def _load_state(self) -> dict | None:
        try:
            return json.loads(self._state_file().read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None

    # --- WinINET system proxy (winreg + ctypes broadcast) ----------------
    def _set_proxy(self, *, enable: bool, server: str) -> None:
        try:
            import winreg  # noqa: PLC0415 — Windows-only, imported lazily
        except ImportError:
            return
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, _INET_KEY, 0, winreg.KEY_SET_VALUE)
        try:
            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1 if enable else 0)
            if enable:
                winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, server)
        finally:
            winreg.CloseKey(key)
        self._broadcast_proxy_change()

    def _capture_proxy(self) -> dict | None:
        """Snapshot the user's current WinINET proxy so restore is exact. Returns
        None off Windows / if the key can't be read."""
        try:
            import winreg  # noqa: PLC0415
        except ImportError:
            return None
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, _INET_KEY)
        except OSError:
            return {"enable": 0, "server": None}
        try:
            try:
                enable, _ = winreg.QueryValueEx(key, "ProxyEnable")
            except OSError:
                enable = 0
            try:
                server, _ = winreg.QueryValueEx(key, "ProxyServer")
            except OSError:
                server = None
        finally:
            winreg.CloseKey(key)
        return {"enable": int(enable), "server": server}

    def _restore_proxy(self, prior: dict | None) -> None:
        """Put back the captured proxy. If there was none, just disable ours."""
        if not prior:
            self._set_proxy(enable=False, server="")
            return
        try:
            import winreg  # noqa: PLC0415
        except ImportError:
            return
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, _INET_KEY, 0, winreg.KEY_SET_VALUE)
        try:
            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, int(prior.get("enable", 0)))
            server = prior.get("server")
            if server is not None:
                winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, server)
        finally:
            winreg.CloseKey(key)
        self._broadcast_proxy_change()

    def _proxy_is_ours(self, server: str) -> bool:
        try:
            import winreg  # noqa: PLC0415
        except ImportError:
            return False
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, _INET_KEY)
            try:
                enabled, _ = winreg.QueryValueEx(key, "ProxyEnable")
                value, _ = winreg.QueryValueEx(key, "ProxyServer")
            finally:
                winreg.CloseKey(key)
        except OSError:
            return False
        return bool(enabled) and value == server

    def _broadcast_proxy_change(self) -> None:
        # Best-effort: apps also pick the proxy up on next launch.
        with contextlib.suppress(Exception):
            import ctypes  # noqa: PLC0415

            wininet = ctypes.windll.wininet  # type: ignore[attr-defined]
            wininet.InternetSetOptionW(0, _INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)
            wininet.InternetSetOptionW(0, _INTERNET_OPTION_REFRESH, 0, 0)


def _plat_env_programdata() -> str:
    import os

    return os.environ.get("PROGRAMDATA", r"C:\ProgramData")


def _inbound_token(policy: str) -> str:
    """Return the inbound half of a captured 'In,Out' policy (default block)."""
    if policy and "," in policy:
        return policy.split(",", 1)[0]
    return "blockinbound"


def _fw_error(msg: str) -> Exception:
    from .firewall import FirewallError

    return FirewallError(msg)


def is_admin() -> bool:
    """True if the current Windows process is elevated (stdlib-only check)."""
    try:
        import ctypes  # noqa: PLC0415

        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001
        return False
