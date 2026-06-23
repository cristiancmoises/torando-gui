# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 Cristian Cezar Moisés — AGPL-3.0-only
"""Loopback HTTP server exposing the control API and the embedded SPA.

Security posture for a single-user localhost daemon:
  * bind 127.0.0.1 only (enforced by the caller / config);
  * Host header must match the bound origin -> defeats DNS-rebinding;
  * cross-origin reads are impossible: no Access-Control-Allow-Origin is ever
    sent, so a foreign page's JS cannot read the token embedded in '/';
  * every /api/* call requires the session token in X-Torando-Token, compared
    in constant time (hmac.compare_digest) to avoid a timing oracle;
  * mutating (POST) calls additionally require an Origin/Referer that matches;
  * a strict CSP plus COOP/CORP/frame-ancestors locks the document down.
This is sufficient for "other local users / a browser tab the user has open".
It is NOT a defence against a compromised root account (see THREAT_MODEL.md).

Static assets (app.js/app.css/worldmap.js/favicon) are read, gzip-compressed,
and fingerprinted once at startup, then served with an immutable Cache-Control
and a strong ETag (304 on revalidation). The token-injected index is never
cached and never compressed.
"""

from __future__ import annotations

import gzip
import hashlib
import hmac
import json
import threading
import time
from collections.abc import Callable
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from urllib.parse import parse_qs, urlsplit

from .app import App

_STATIC = {
    "/app.css": "text/css; charset=utf-8",
    "/app.js": "application/javascript; charset=utf-8",
    "/worldmap.js": "application/javascript; charset=utf-8",
    "/favicon.svg": "image/svg+xml",
    "/securityops-logo.svg": "image/svg+xml",
}

_CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; "
    "connect-src 'self'; img-src 'self' data:; font-src 'self'; "
    "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)

# Applied to every response. Cache policy is set per-response: dynamic bodies
# (index, API, SSE) use no-store; versioned static assets use immutable.
_SECURITY_HEADERS = (
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "no-referrer"),
    ("X-Frame-Options", "DENY"),
    ("Cross-Origin-Opener-Policy", "same-origin"),
    ("Cross-Origin-Resource-Policy", "same-origin"),
    ("Permissions-Policy", "geolocation=(), camera=(), microphone=(), usb=(), payment=()"),
    ("Content-Security-Policy", _CSP),
)

_IMMUTABLE = "public, max-age=31536000, immutable"


def _read_asset(name: str) -> bytes:
    return (resources.files("torando_gui") / "webroot" / name).read_bytes()


def _build_static_cache() -> dict[str, tuple[bytes, bytes, str, str]]:
    """Read, gzip, and fingerprint each static asset once at startup.

    Returns path -> (raw, gzipped, etag, content_type).
    """
    cache: dict[str, tuple[bytes, bytes, str, str]] = {}
    for path, ctype in _STATIC.items():
        raw = _read_asset(path.lstrip("/"))
        gz = gzip.compress(raw, 9)
        etag = '"' + hashlib.blake2b(raw, digest_size=16).hexdigest() + '"'
        cache[path] = (raw, gz, etag, ctype)
    return cache


def make_server(app: App, host: str, port: int) -> ThreadingHTTPServer:
    allowed_hosts = {f"{host}:{port}", f"localhost:{port}", f"127.0.0.1:{port}"}
    allowed_origins = {f"http://{h}" for h in allowed_hosts}
    static_cache = _build_static_cache()

    class Handler(BaseHTTPRequestHandler):
        server_version = "torando-gui"
        protocol_version = "HTTP/1.1"

        # --- helpers ---------------------------------------------------
        def _host_ok(self) -> bool:
            return self.headers.get("Host", "") in allowed_hosts

        def _token_ok(self) -> bool:
            # Constant-time comparison: a secret is being checked per request.
            supplied = self.headers.get("X-Torando-Token", "")
            if supplied and hmac.compare_digest(supplied, app.token):
                return True
            # EventSource cannot set request headers, so the token is allowed in
            # the query string — but ONLY for GET. Mutating verbs (POST) must use
            # the header, so a query-string token can never satisfy a POST whose
            # Origin/Referer is absent (see _origin_ok), keeping CSRF defence
            # header-bound. The SPA already sends the header on every POST.
            if self.command != "GET":
                return False
            q = parse_qs(urlsplit(self.path).query).get("token", [""])[0]
            return bool(q) and hmac.compare_digest(q, app.token)

        def _origin_ok(self) -> bool:
            origin = self.headers.get("Origin")
            if origin is not None:
                return origin in allowed_origins
            ref = self.headers.get("Referer")
            if ref is not None:
                return f"{urlsplit(ref).scheme}://{urlsplit(ref).netloc}" in allowed_origins
            return True  # non-browser client (curl/CLI): token already gates it

        def _security_headers(self, content_type: str) -> None:
            self.send_header("Content-Type", content_type)
            for key, value in _SECURITY_HEADERS:
                self.send_header(key, value)

        def _send_json(self, code: int, payload: object) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(code)
            self._security_headers("application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _send_html(self, code: int, body: bytes) -> None:
            # token is injected here, so this document must never be cached.
            self.send_response(code)
            self._security_headers("text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _send_static(self, path: str) -> None:
            raw, gz, etag, ctype = static_cache[path]
            inm = self.headers.get("If-None-Match", "")
            if inm and any(etag == t.strip() for t in inm.split(",")):
                self.send_response(HTTPStatus.NOT_MODIFIED)
                self._security_headers(ctype)
                self.send_header("ETag", etag)
                self.send_header("Cache-Control", _IMMUTABLE)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            accepts_gzip = "gzip" in self.headers.get("Accept-Encoding", "")
            body = gz if accepts_gzip else raw
            self.send_response(HTTPStatus.OK)
            self._security_headers(ctype)
            self.send_header("ETag", etag)
            self.send_header("Cache-Control", _IMMUTABLE)
            self.send_header("Vary", "Accept-Encoding")
            if accepts_gzip:
                self.send_header("Content-Encoding", "gzip")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _body_json(self) -> dict[str, object]:
            length = int(self.headers.get("Content-Length", "0") or "0")
            if length <= 0:
                return {}
            if length > 1 << 20:
                raise ValueError("request body too large")
            raw = self.rfile.read(length)
            return json.loads(raw.decode("utf-8")) if raw else {}

        def log_message(self, fmt: str, *args: object) -> None:  # quieter default
            redacted = (fmt % args).replace(app.token, "<token>")
            app.log.emit("debug", f"http {self.address_string()} {redacted}")

        # --- index with injected token ---------------------------------
        def _serve_index(self) -> None:
            html = _read_asset("index.html").decode("utf-8")
            html = html.replace("__TORANDO_TOKEN__", app.token)
            self._send_html(HTTPStatus.OK, html.encode("utf-8"))

        # --- SSE -------------------------------------------------------
        def _serve_events(self) -> None:
            self.send_response(HTTPStatus.OK)
            self._security_headers("text/event-stream")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "close")
            self.end_headers()
            if self.command == "HEAD":
                return  # HEAD must not carry a body; never open the event stream
            stop = threading.Event()
            try:
                for event in app.events(stop):
                    chunk = f"data: {json.dumps(event)}\n\n".encode()
                    self.wfile.write(chunk)
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, OSError):
                stop.set()

        # --- verb dispatch ---------------------------------------------
        def do_GET(self) -> None:  # noqa: N802 (stdlib naming)
            if not self._host_ok():
                self._send_json(HTTPStatus.FORBIDDEN, {"error": "bad host"})
                return
            path = urlsplit(self.path).path
            if path in ("/", "/index.html"):
                self._serve_index()
                return
            if path in static_cache:
                self._send_static(path)
                return
            if path.startswith("/api/"):
                if not self._token_ok():
                    self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "bad token"})
                    return
                self._api_get(path)
                return
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})

        def do_HEAD(self) -> None:  # noqa: N802
            self.do_GET()

        def do_POST(self) -> None:  # noqa: N802
            if not self._host_ok():
                self._send_json(HTTPStatus.FORBIDDEN, {"error": "bad host"})
                return
            path = urlsplit(self.path).path
            if not path.startswith("/api/"):
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})
                return
            if not self._token_ok():
                self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "bad token"})
                return
            if not self._origin_ok():
                self._send_json(HTTPStatus.FORBIDDEN, {"error": "bad origin"})
                return
            self._api_post(path)

        # --- API routes ------------------------------------------------
        def _api_get(self, path: str) -> None:
            routes: dict[str, Callable[[], object]] = {
                "/api/health": lambda: {"ok": True, "ts": time.time()},
                "/api/status": app.status,
                "/api/users": app.users,
                "/api/exit": app.check_exit,
            }
            if path == "/api/events":
                self._serve_events()
                return
            fn = routes.get(path)
            if fn is None:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "no such endpoint"})
                return
            try:
                self._send_json(HTTPStatus.OK, fn())
            except Exception as exc:  # noqa: BLE001 — uniform error envelope
                self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": str(exc)})

        def _api_post(self, path: str) -> None:
            try:
                body = self._body_json()
            except ValueError as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                return
            try:
                if path == "/api/connect":
                    self._send_json(HTTPStatus.OK, app.connect())
                elif path == "/api/disconnect":
                    self._send_json(HTTPStatus.OK, app.disconnect())
                elif path == "/api/newnym":
                    self._send_json(HTTPStatus.OK, app.new_identity())
                elif path == "/api/config":
                    self._send_json(HTTPStatus.OK, app.update_config(body))
                else:
                    self._send_json(HTTPStatus.NOT_FOUND, {"error": "no such endpoint"})
            except (ValueError, RuntimeError) as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            except Exception as exc:  # noqa: BLE001
                self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": str(exc)})

    httpd = ThreadingHTTPServer((host, port), Handler)
    httpd.daemon_threads = True
    return httpd
