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

from . import geoip, netcfg, netcheck, services
from .config import Config, save
from .engine import Engine, resolve_uid
from .netcheck import ExitInfo
from .torctl import Bootstrap, TorControl

# Sentinel distinguishing "geoip not yet loaded" from "loaded, but unavailable".
_UNSET: object = object()


class Backend(Protocol):
    def iptables_available(self) -> bool: ...
    def apply_rules(self, uid: int, trans: int, dns: int) -> None: ...
    def remove_rules(self, uid: int, trans: int, dns: int) -> None: ...
    def rules_status(self, uid: int, trans: int, dns: int) -> dict[str, object]: ...
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
    def resolv_nameserver(self, path: str) -> str: ...
    def candidate_users(self) -> list[dict[str, object]]: ...


class SystemBackend:
    """Real backend. Every method here changes or reads actual system state."""

    def __init__(self, control_host: str, control_port: int) -> None:
        self._engine = Engine()
        self._ctl_host = control_host
        self._ctl_port = control_port
        self._geoip_cache: object = _UNSET
        self._city_cache: object = _UNSET

    def _ctl(self) -> TorControl:
        return TorControl(self._ctl_host, self._ctl_port)

    def iptables_available(self) -> bool:
        return self._engine.available()

    def apply_rules(self, uid: int, trans: int, dns: int) -> None:
        self._engine.apply(uid, trans, dns)

    def remove_rules(self, uid: int, trans: int, dns: int) -> None:
        self._engine.remove(uid, trans, dns)

    def rules_status(self, uid: int, trans: int, dns: int) -> dict[str, object]:
        return self._engine.status(uid, trans, dns)

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
        return netcfg.lock_resolv(cfg)

    def unlock_resolv(self, cfg: Config) -> dict[str, object]:
        return netcfg.unlock_resolv(cfg)

    def resolv_nameserver(self, path: str) -> str:
        try:
            for line in Path(path).read_text(encoding="utf-8").splitlines():
                s = line.strip()
                if s.startswith("nameserver"):
                    return s.split(None, 1)[1] if len(s.split()) > 1 else ""
        except OSError:
            return ""
        return ""

    def candidate_users(self) -> list[dict[str, object]]:
        return services.candidate_users()


class MockBackend:
    """In-memory fake for UI preview/testing. No privileges, no Tor."""

    def __init__(self) -> None:
        self._active = False
        self._t0 = 0.0

    def iptables_available(self) -> bool:
        return True

    def apply_rules(self, uid: int, trans: int, dns: int) -> None:
        self._active = True
        self._t0 = time.monotonic()

    def remove_rules(self, uid: int, trans: int, dns: int) -> None:
        self._active = False

    def rules_status(self, uid: int, trans: int, dns: int) -> dict[str, object]:
        n = 5 if self._active else 0
        return {
            "rules_total": 5,
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

    def resolv_nameserver(self, path: str) -> str:
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

    # --- read paths ----------------------------------------------------
    def status(self) -> dict[str, object]:
        cfg = self.cfg
        uid = cfg.target_uid
        rules = (
            self.backend.rules_status(uid, cfg.trans_port, cfg.dns_port)
            if uid is not None
            else {"rules_total": 5, "rules_present": 0, "active": False, "killswitch": False}
        )
        boot = self.backend.control_bootstrap()
        ctl = self.backend.control_available()
        tor = self.backend.tor_status()
        ns = self.backend.resolv_nameserver(cfg.resolv_path)
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
            if cfg.target_uid is None:
                raise ValueError("no target user selected")
            if not self.backend.iptables_available():
                raise RuntimeError("iptables not available")
            self.log.emit("info", f"routing uid {cfg.target_uid} through Tor")
            resolv_locked = False
            try:
                if cfg.manage_torrc:
                    self.backend.apply_torrc(cfg)
                    self.log.emit("info", "torrc managed block written")
                    res = self.backend.reload_tor()
                    self.log.emit("info" if res["ok"] else "warn", f"tor reload: {res}")
                if cfg.lock_resolv:
                    r = self.backend.lock_resolv(cfg)
                    resolv_locked = True
                    self.log.emit("info", f"resolv.conf -> 127.0.0.1 (immutable={r['immutable']})")
                self.backend.apply_rules(cfg.target_uid, cfg.trans_port, cfg.dns_port)
                self.log.emit("info", "netfilter rules applied (killswitch armed)")
            except Exception:
                # resolv.conf is pinned to 127.0.0.1 *before* the rules go in. If
                # rule application then fails, leaving the pin in place would point
                # the host's DNS at a local resolver that is not being fed by Tor
                # (killswitch never armed) — breaking name resolution system-wide.
                # Roll the pin back so a failed connect never degrades host DNS.
                if resolv_locked:
                    with contextlib.suppress(Exception):
                        self.backend.unlock_resolv(cfg)
                        self.log.emit("warn", "connect failed; resolv.conf restored")
                raise
            return self.status()

    def disconnect(self) -> dict[str, object]:
        with self._oplock:
            cfg = self.cfg
            if cfg.target_uid is not None:
                self.backend.remove_rules(cfg.target_uid, cfg.trans_port, cfg.dns_port)
                self.log.emit("info", "netfilter rules removed")
            if cfg.lock_resolv:
                r = self.backend.unlock_resolv(cfg)
                self.log.emit("info", f"resolv.conf restored (restored={r['restored']})")
            return self.status()

    def new_identity(self) -> dict[str, object]:
        with self._oplock:
            self.backend.new_identity()
            self.log.emit("info", "requested new Tor identity (NEWNYM)")
            return {"ok": True}

    def update_config(self, patch: dict[str, object]) -> dict[str, object]:
        with self._oplock:
            merged = self.cfg.sanitized()
            merged.update(patch)
            new = Config.from_dict(merged)
            _validate(new)
            if new.target_uid is not None:
                resolve_uid(new.target_uid)  # raises if not a real account
            self.cfg = new
            save(new, self._config_path)
            self.log.emit("info", "configuration updated")
            return self.status()

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
