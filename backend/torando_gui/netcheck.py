# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 Cristian Cezar Moisés — AGPL-3.0-only
"""Verify that egress actually leaves through a Tor exit.

We perform a real HTTPS request to the Tor Project's check endpoint *through*
Tor's SocksPort and report exactly what it says. The verdict is never
fabricated: on any error we return ``is_tor=None`` with the error string so the
UI shows "unknown", not a false "secured".
"""

from __future__ import annotations

import json
import socket
import ssl
from dataclasses import dataclass
from urllib.parse import urlsplit

from .socks import socks5_connect


@dataclass
class ExitInfo:
    is_tor: bool | None
    ip: str | None
    error: str | None = None
    country: str | None = None  # ISO-3166-1 alpha-2, lower-case, if resolvable
    lat: float | None = None
    lon: float | None = None
    city: str | None = None

    def as_dict(self) -> dict[str, object]:
        return {
            "is_tor": self.is_tor,
            "ip": self.ip,
            "error": self.error,
            "country": self.country,
            "lat": self.lat,
            "lon": self.lon,
            "city": self.city,
        }


def _http_get_over(sock: socket.socket, host: str, path: str, timeout: float) -> bytes:
    sock.settimeout(timeout)
    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "User-Agent: torando-gui\r\n"
        "Accept: application/json\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii")
    sock.sendall(req)
    chunks = bytearray()
    while True:
        data = sock.recv(8192)
        if not data:
            break
        chunks += data
        if len(chunks) > 1 << 20:  # 1 MiB hard cap; the endpoint is tiny
            break
    return bytes(chunks)


def _split_body(raw: bytes) -> bytes:
    sep = raw.find(b"\r\n\r\n")
    return raw[sep + 4 :] if sep != -1 else raw


def check_exit(
    socks_host: str,
    socks_port: int,
    url: str,
    timeout: float = 15.0,
) -> ExitInfo:
    parts = urlsplit(url)
    host = parts.hostname or ""
    port = parts.port or (443 if parts.scheme == "https" else 80)
    path = parts.path or "/"
    if parts.query:
        path = f"{path}?{parts.query}"
    try:
        tunnel = socks5_connect(socks_host, socks_port, host, port, timeout=timeout)
    except Exception as exc:  # noqa: BLE001 — surfaced to UI as "unknown"
        return ExitInfo(None, None, f"socks: {exc}")
    try:
        if parts.scheme == "https":
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(tunnel, server_hostname=host) as tls:
                raw = _http_get_over(tls, host, path, timeout)
        else:
            with tunnel:
                raw = _http_get_over(tunnel, host, path, timeout)
    except Exception as exc:  # noqa: BLE001
        return ExitInfo(None, None, f"http: {exc}")

    body = _split_body(raw)
    try:
        doc = json.loads(body.decode("utf-8", "replace"))
    except json.JSONDecodeError:
        return ExitInfo(None, None, "could not parse check response")
    is_tor = doc.get("IsTor")
    ip = doc.get("IP")
    return ExitInfo(bool(is_tor) if is_tor is not None else None, ip)
