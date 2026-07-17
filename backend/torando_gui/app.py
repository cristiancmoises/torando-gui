# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 Cristian Cezar Moisés — AGPL-3.0-only
"""Application core: orchestrates engine, tor control, config and netfilter.

A ``Backend`` is the seam between the orchestration logic and the host. The
real one (:class:`SystemBackend`) touches iptables/tor/files. The mock one
(:class:`MockBackend`) keeps believable in-memory state so the UI can be run
and screenshotted with no root and no Tor — it is never used unless ``--mock``
is passed. Both share the exact same orchestration in :class:`App`.
"""

from __future__ import annotations

import contextlib
import threading
import time
from collections import deque
from collections.abc import Iterator
from pathlib import Path
from queue import Empty, Queue
from typing import Protocol

from . import dns as dnsmod
from . import geoip, netcfg, netcheck, services
from . import platform as _plat
from .config import Config, save
from .engine import RULE_COUNT, resolve_uid
from .firewall import make_firewall
from .netcheck import ExitInfo
from .torctl import Bootstrap, TorControl

# Sentinel distinguishing "geoip not yet loaded" from "loaded, but unavailable".
_UNSET: object = object()


class Backend(Protocol):
    def firewall_available(self) -> bool: ...
    def apply_rules(self, cfg: Config) -> None: ...
    def remove_rules(self, cfg: Config) -> None: ...
    def rules_status(self, cfg: Config) -> dict[str, object]: ...
    def tor_status(self) -> dict[str, object]: ...
    def reload_tor(self) -> dict[str, object]: ...
    def control_bootstrap(self) -> Bootstrap | None: ...
    def control_available(self) -> bool: ...
    def new_identity(self) -> None: ...
    def circuit_count(self) -> int: ...
    def check_exit(self, host: str, port: int, url: str) -> ExitInfo: ...
    def apply_torrc(self, cfg: Config) -> None: ...
    def lock_resolv(self, cfg: Config) -> dict[str, object]: ...
    def unlock_resolv(self, cfg: Config) -> dict[str, object]: ...
    def resolv_is_pinned(self, cfg: Config) -> bool: ...
    def resolv_nameserver(self, cfg: Config) -> str: ...
    def candidate_users(self) -> list[dict[str, object]]: ...


class SystemBackend:
    """Real backend. Every method here changes or reads actual system state.

    The firewall and DNS mechanisms are chosen for the host platform at
    construction (iptables/ip6tables on Linux, ``pf`` on macOS/BSD, ``netsh`` +
    WinINET on Windows); the orchestration in :class:`App` is identical for all.
    """

    def __init__(self, control_host: str, control_port: int) -> None:
        self._firewall = make_firewall()
        self._dns = dnsmod.make_dns()
        self._ctl_host = control_host
        self._ctl_port = control_port
        self._geoip_cache: object = _UNSET
        self._city_cache: object = _UNSET

    def _ctl(self) -> TorControl:
        return TorControl(self._ctl_host, self._ctl_port)

    def firewall_available(self) -> bool:
        return self._firewall.available()

    def apply_rules(self, cfg: Config) -> None:
        self._firewall.apply(cfg)

    def remove_rules(self, cfg: Config) -> None:
        self._firewall.remove(cfg)

    def rules_status(self, cfg: Config) -> dict[str, object]:
        return self._firewall.status(cfg)

    def tor_status(self) -> dict[str, object]:
        return services.tor_service_status()

    def reload_tor(self) -> dict[str, object]:
        return services.reload_tor()

    def control_available(self) -> bool:
        return self._ctl().is_available()

    def control_bootstrap(self) -> Bootstrap | None:
        try:
            with self._ctl() as c:
                return c.bootstrap()
        except OSError:
            return None

    def new_identity(self) -> None:
        with self._ctl() as c:
            c.new_identity()

    def circuit_count(self) -> int:
        try:
            with self._ctl() as c:
                return c.circuit_count()
        except OSError:
            return 0

    def check_exit(self, host: str, port: int, url: str) -> ExitInfo:
        info = netcheck.check_exit(host, port, url)
        if info.ip and info.country is None:
            geo = self._geoip()
            if geo is not None:
                info.country = geo.lookup(info.ip)
        if info.ip and info.lat is None:
            city = self._city()
            if city is not None:
                rec = city.lookup(info.ip)
                if rec is not None:
                    info.lat = rec["lat"]
                    info.lon = rec["lon"]
                    info.city = rec["city"]
                    if info.country is None and rec["country"]:
                        info.country = rec["country"]
        return info

    def _geoip(self) -> geoip.GeoIP | None:
        if self._geoip_cache is _UNSET:
            self._geoip_cache = geoip.load_default()
        return self._geoip_cache

    def _city(self) -> geoip.CityDB | None:
        if self._city_cache is _UNSET:
            self._city_cache = geoip.load_city_default()
        return self._city_cache

    def apply_torrc(self, cfg: Config) -> None:
        netcfg.apply_torrc(cfg)

    def lock_resolv(self, cfg: Config) -> dict[str, object]:
        return self._dns.lock(cfg)

    def unlock_resolv(self, cfg: Config) -> dict[str, object]:
        return self._dns.restore(cfg)

    def resolv_is_pinned(self, cfg: Config) -> bool:
        return self._dns.is_pinned(cfg)

    def resolv_nameserver(self, cfg: Config) -> str:
        return self._dns.nameserver(cfg)

    def candidate_users(self) -> list[dict[str, object]]:
        return services.candidate_users()


class MockBackend:
    """In-memory fake for UI preview/testing. No privileges, no Tor."""

    def __init__(self) -> None:
        self._active = False
        self._t0 = 0.0

    def firewall_available(self) -> bool:
        return True

    def apply_rules(self, cfg: Config) -> None:
        self._active = True
        self._t0 = time.monotonic()

    def remove_rules(self, cfg: Config) -> None:
        self._active = False

    def rules_status(self, cfg: Config) -> dict[str, object]:
        n = RULE_COUNT if self._active else 0
        return {
            "rules_total": RULE_COUNT,
            "rules_present": n,
            "active": self._active,
            "killswitch": self._active,
        }

    def tor_status(self) -> dict[str, object]:
        return {"installed": True, "active": True, "unit": "tor.service (mock)", "note": ""}

    def reload_tor(self) -> dict[str, object]:
        return {"ok": True, "unit": "tor.service (mock)", "error": ""}

    def control_available(self) -> bool:
        return True

    def control_bootstrap(self) -> Bootstrap | None:
        if not self._active:
            return Bootstrap(0, "starting", "idle")
        pct = min(100, int((time.monotonic() - self._t0) * 55))
        tag = "done" if pct >= 100 else "conn_or_circuit"
        summ = "Done" if pct >= 100 else "Building circuits"
        return Bootstrap(pct, tag, summ)

    def new_identity(self) -> None:
        self._t0 = time.monotonic()

    def circuit_count(self) -> int:
        return 6 if self._active else 0

    def check_exit(self, host: str, port: int, url: str) -> ExitInfo:
        if not self._active:
            return ExitInfo(False, "203.0.113.7", None, None)
        return ExitInfo(
            True, "185.220.101.47", None, "se", lat=57.7065, lon=11.967, city="Göteborg"
        )

    def apply_torrc(self, cfg: Config) -> None:
        return None

    def lock_resolv(self, cfg: Config) -> dict[str, object]:
        return {"path": cfg.resolv_path, "immutable": True, "note": ""}

    def unlock_resolv(self, cfg: Config) -> dict[str, object]:
        return {"path": cfg.resolv_path, "restored": True}

    def resolv_is_pinned(self, cfg: Config) -> bool:
        return self._active

    def resolv_nameserver(self, cfg: Config) -> str:
        return "127.0.0.1" if self._active else "192.168.1.1"

    def candidate_users(self) -> list[dict[str, object]]:
        return [{"uid": 1000, "name": "cristian"}, {"uid": 1001, "name": "guest"}]


class _LogBus:
    """Ring buffer of recent log lines plus live fan-out to SSE subscribers."""

    def __init__(self, capacity: int = 500) -> None:
        self._lock = threading.Lock()
        self._buf: deque[dict[str, object]] = deque(maxlen=capacity)
        self._subs: set[Queue[dict[str, object]]] = set()

    def emit(self, level: str, msg: str) -> None:
        rec = {"ts": time.time(), "level": level, "msg": msg}
        with self._lock:
            self._buf.append(rec)
            subs = list(self._subs)
        for q in subs:
            q.put(rec)

    def recent(self) -> list[dict[str, object]]:
        with self._lock:
            return list(self._buf)

    def subscribe(self) -> Queue[dict[str, object]]:
        q: Queue[dict[str, object]] = Queue(maxsize=256)
        with self._lock:
            self._subs.add(q)
        return q

    def unsubscribe(self, q: Queue[dict[str, object]]) -> None:
        with self._lock:
            self._subs.discard(q)


class App:
    """Holds config + backend and exposes the operations the server calls."""

    def __init__(
        self,
        cfg: Config,
        backend: Backend,
        token: str,
        *,
        mock: bool,
        config_path: Path,
    ) -> None:
        self.cfg = cfg
        self.backend = backend
        self.token = token
        self.mock = mock
        self._config_path = config_path
        self._oplock = threading.Lock()
        self.log = _LogBus()
        # On Windows the killswitch is machine-wide (no per-UID redirect exists
        # without a driver), so a target user is neither required nor meaningful.
        self.machine_wide = _plat.is_windows()

    # --- read paths ----------------------------------------------------
    def status(self) -> dict[str, object]:
        cfg = self.cfg
        uid = cfg.target_uid
        rules = (
            self.backend.rules_status(cfg)
            if uid is not None or self.machine_wide
            else {
                "rules_total": RULE_COUNT,
                "rules_present": 0,
                "active": False,
                "killswitch": False,
            }
        )
        boot = self.backend.control_bootstrap()
        ctl = self.backend.control_available()
        tor = self.backend.tor_status()
        ns = self.backend.resolv_nameserver(cfg)
        return {
            "mock": self.mock,
            "active": bool(rules["active"]),
            "rules": rules,
            "tor": tor,
            "control": {
                "available": ctl,
                "bootstrap": (
                    {"progress": boot.progress, "tag": boot.tag, "summary": boot.summary}
                    if boot
                    else None
                ),
                "circuits": self.backend.circuit_count() if ctl else 0,
            },
            "dns": {
                "nameserver": ns,
                "via_tor": ns == "127.0.0.1" and bool(rules["killswitch"]),
            },
            "target_uid": uid,
            "config": cfg.sanitized(),
        }

    def users(self) -> list[dict[str, object]]:
        return self.backend.candidate_users()

    def check_exit(self) -> dict[str, object]:
        info = self.backend.check_exit(
            self.cfg.host_socks(), self.cfg.socks_port, self.cfg.check_url
        )
        return info.as_dict()

    # --- write paths (serialized) -------------------------------------
    def connect(self) -> dict[str, object]:
        with self._oplock:
            cfg = self.cfg
            if cfg.target_uid is None and not self.machine_wide:
                raise ValueError("no target user selected")
            if not self.backend.firewall_available():
                raise RuntimeError("firewall tooling not available")
            target = "the whole machine" if self.machine_wide else f"uid {cfg.target_uid}"
            self.log.emit("info", f"routing {target} through Tor")
            rules_applied = False
            try:
                # 1) Tor config (inert until reload; never fatal on Guix where
                #    torrc is store-managed and management is disabled). On Linux
                #    this also (re)starts tor; on Windows the bundled Tor task
                #    owns the torrc so this is skipped.
                if cfg.manage_torrc:
                    self.backend.apply_torrc(cfg)
                    self.log.emit("info", "torrc managed block written")
                    res = self.backend.reload_tor()
                    self.log.emit("info" if res["ok"] else "warn", f"tor reload: {res}")
                # 1b) Tor MUST be listening before we arm anything. Arming the
                #    killswitch + system proxy while Tor is down would leave the
                #    host with no working egress and no DNS — the worst outcome.
                if not self._tor_listening(cfg):
                    raise RuntimeError(
                        f"Tor is not listening on {cfg.host_socks()}:{cfg.socks_port} — "
                        "start Tor first (Windows: the TorandoGUI-Tor task), then Connect."
                    )
                # 2) Firewall FIRST: this arms the killswitch (and, on Linux, the
                #    DNS redirect), so by the time resolv.conf points at 127.0.0.1
                #    the path to Tor's DNSPort is already live.
                self.backend.apply_rules(cfg)
                rules_applied = True
                self.log.emit("info", "firewall rules applied (killswitch armed)")
                # 3) Pin DNS LAST. If anything above failed, DNS was never
                #    touched, so a failed connect never degrades host DNS.
                if cfg.lock_resolv:
                    r = self.backend.lock_resolv(cfg)
                    self.log.emit(
                        "info", f"DNS pinned -> 127.0.0.1 (immutable={r.get('immutable')})"
                    )
            except Exception:
                # Roll everything back so a failed connect leaves the host
                # exactly as it found it: rules removed, DNS restored.
                with contextlib.suppress(Exception):
                    if cfg.lock_resolv:
                        self.backend.unlock_resolv(cfg)
                    if rules_applied:
                        self.backend.remove_rules(cfg)
                    self.log.emit("warn", "connect failed; rolled back rules + DNS")
                raise
            return self.status()

    def disconnect(self) -> dict[str, object]:
        with self._oplock:
            cfg = self.cfg
            # Restore DNS FIRST and unconditionally (even if target_uid changed
            # or rules are already gone) so the user always regains a working
            # resolver — the #1 thing that must never be left broken.
            r = self.backend.unlock_resolv(cfg)
            note = f"; {r['note']}" if r.get("note") else ""
            self.log.emit("info", f"DNS restored (restored={r.get('restored')}{note})")
            if cfg.target_uid is not None or self.machine_wide:
                self.backend.remove_rules(cfg)
                self.log.emit("info", "firewall rules removed")
            return self.status()

    def recover_orphaned_dns(self) -> None:
        """At startup, if resolv.conf is still pinned to our loopback entry but
        we are not actually routing (rules gone after a crash/kill/reboot),
        restore the real resolver. Safe no-op when genuinely connected."""
        cfg = self.cfg
        try:
            if not self.backend.resolv_is_pinned(cfg):
                return
            routing = False
            if cfg.target_uid is not None or self.machine_wide:
                st = self.backend.rules_status(cfg)
                routing = bool(st.get("killswitch"))
            if routing:
                return  # genuinely connected — leave the pin in place
            res = self.backend.unlock_resolv(cfg)
            self.log.emit("warn", f"recovered DNS from an orphaned session: {res}")
        except Exception as exc:  # noqa: BLE001 — recovery must never crash startup
            self.log.emit("warn", f"DNS recovery check failed: {exc}")

    def _tor_listening(self, cfg: Config) -> bool:
        """True if Tor's SocksPort accepts a connection. Mock mode is always OK
        (no Tor). Retries briefly so a just-(re)started tor has time to open the
        port. Used to refuse arming the killswitch while Tor is down."""
        if self.mock:
            return True
        import socket
        import time

        for attempt in range(6):  # ~6 x 0.5s = 3s
            try:
                with socket.create_connection((cfg.host_socks(), cfg.socks_port), timeout=2):
                    return True
            except OSError:
                if attempt < 5:
                    time.sleep(0.5)
        return False

    def new_identity(self) -> dict[str, object]:
        with self._oplock:
            try:
                self.backend.new_identity()
            except OSError as exc:
                # No ControlPort (e.g. the bundled Windows Tor) or Tor down —
                # don't 500 the UI; report it and move on.
                self.log.emit("warn", f"new identity unavailable: {exc}")
                return {"ok": False, "error": "Tor control port not available"}
            self.log.emit("info", "requested new Tor identity (NEWNYM)")
            return {"ok": True}

    # Fields that define which rules are installed; changing them while routing
    # would orphan the active killswitch (the GUI would target a different UID/
    # ports and could never remove the old rules → a stranded user).
    _ROUTING_FIELDS = ("target_uid", "trans_port", "dns_port")

    def update_config(self, patch: dict[str, object]) -> dict[str, object]:
        with self._oplock:
            merged = self.cfg.sanitized()
            merged.update(patch)
            new = Config.from_dict(merged)
            _validate(new)
            if new.target_uid is not None and not self.machine_wide:
                resolve_uid(new.target_uid)  # raises if not a real account
            # Refuse routing-relevant changes while connected: disconnect first.
            if self._is_routing():
                changed = [
                    f for f in self._ROUTING_FIELDS if getattr(new, f) != getattr(self.cfg, f)
                ]
                if changed:
                    raise RuntimeError(
                        f"disconnect before changing {', '.join(changed)} "
                        "(those define the active killswitch rules)"
                    )
            self.cfg = new
            save(new, self._config_path)
            self.log.emit("info", "configuration updated")
            return self.status()

    def _is_routing(self) -> bool:
        cfg = self.cfg
        if cfg.target_uid is None and not self.machine_wide:
            return False
        try:
            st = self.backend.rules_status(cfg)
            return bool(st.get("killswitch"))
        except Exception:  # noqa: BLE001 — never block a config edit on a probe error
            return False

    # --- SSE -----------------------------------------------------------
    def events(self, stop: threading.Event) -> Iterator[dict[str, object]]:
        for rec in self.log.recent():
            yield {"type": "log", **rec}
        q = self.log.subscribe()
        try:
            last_status = 0.0
            while not stop.is_set():
                try:
                    rec = q.get(timeout=1.0)
                    yield {"type": "log", **rec}
                except Empty:
                    pass
                now = time.monotonic()
                if now - last_status >= 2.0:
                    last_status = now
                    yield {"type": "status", "data": self.status()}
        finally:
            self.log.unsubscribe(q)


def _validate(cfg: Config) -> None:
    for name, port in (
        ("port", cfg.port),
        ("trans_port", cfg.trans_port),
        ("dns_port", cfg.dns_port),
        ("socks_port", cfg.socks_port),
        ("control_port", cfg.control_port),
    ):
        if not 1 <= int(port) <= 65535:
            raise ValueError(f"{name} out of range: {port}")
    if cfg.exit_country and not cfg.exit_country.strip().isalpha():
        raise ValueError("exit_country must be an ISO letter code")
