# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 Cristian Cezar Moisés — AGPL-3.0-only
"""Server tests against a live ThreadingHTTPServer bound to an ephemeral port,
driven through the MockBackend so no privileges or Tor are required.

These lock the three browser-facing defenses:
  * session token required on every /api/* call,
  * Host header allowlist (defeats DNS-rebinding),
  * Origin check on state-changing POSTs (defeats cross-site POST).
"""

from __future__ import annotations

import gzip
import json
import socket
import threading
import urllib.error
import urllib.request

import pytest
from torando_gui.app import App, MockBackend
from torando_gui.config import Config
from torando_gui.server import make_server

TOKEN = "tok_test_DEADBEEF"


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture()
def server(tmp_path):
    port = _free_port()
    app = App(
        Config(port=port),
        MockBackend(),
        TOKEN,
        mock=True,
        config_path=tmp_path / "config.json",
    )
    httpd = make_server(app, "127.0.0.1", port)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        httpd.shutdown()
        t.join(timeout=3)


def _req(url, method="GET", headers=None, data=None):
    req = urllib.request.Request(url, method=method, headers=headers or {}, data=data)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, resp.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8")


def _req_full(url, method="GET", headers=None, data=None):
    """Like _req but returns (status, lowercased-headers, raw bytes)."""
    req = urllib.request.Request(url, method=method, headers=headers or {}, data=data)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, {k.lower(): v for k, v in exc.headers.items()}, exc.read()


def test_index_injects_token(server):
    code, body = _req(server + "/")
    assert code == 200
    assert TOKEN in body
    assert "__TORANDO_TOKEN__" not in body


def test_status_requires_token(server):
    code, _ = _req(server + "/api/status")
    assert code == 401


def test_status_with_header_token(server):
    code, body = _req(server + "/api/status", headers={"X-Torando-Token": TOKEN})
    assert code == 200
    assert json.loads(body)["mock"] is True


def test_status_with_query_token(server):
    # EventSource path: token as query param, no header
    code, body = _req(server + "/api/status?token=" + TOKEN)
    assert code == 200
    assert json.loads(body)["mock"] is True


def test_bad_host_is_forbidden(server):
    # DNS-rebinding attempt: right token, wrong Host
    code, _ = _req(
        server + "/api/status",
        headers={"X-Torando-Token": TOKEN, "Host": "evil.example.com"},
    )
    assert code == 403


def test_static_assets_served(server):
    for path in ("/app.js", "/app.css", "/worldmap.js", "/favicon.svg", "/securityops-logo.svg"):
        code, _ = _req(server + path)
        assert code == 200, path


def test_connect_requires_token(server):
    code, _ = _req(server + "/api/connect", method="POST")
    assert code == 401


def test_post_rejects_cross_origin(server):
    code, _ = _req(
        server + "/api/config",
        method="POST",
        headers={
            "X-Torando-Token": TOKEN,
            "Origin": "http://evil.example.com",
            "Content-Type": "application/json",
        },
        data=b"{}",
    )
    assert code == 403


def test_post_allows_same_origin(server):
    code, body = _req(
        server + "/api/config",
        method="POST",
        headers={"X-Torando-Token": TOKEN, "Origin": server, "Content-Type": "application/json"},
        data=b"{}",
    )
    assert code == 200
    assert json.loads(body)["mock"] is True


def test_unknown_api_route_404(server):
    code, _ = _req(server + "/api/nope", headers={"X-Torando-Token": TOKEN})
    assert code == 404


def test_mock_connect_then_status_active(server):
    # connect in mock flips rules active and yields a Tor exit verdict
    code, body = _req(
        server + "/api/config",
        method="POST",
        headers={"X-Torando-Token": TOKEN, "Origin": server, "Content-Type": "application/json"},
        data=json.dumps({"target_uid": 1000}).encode(),
    )
    assert code == 200
    code, body = _req(
        server + "/api/connect",
        method="POST",
        headers={"X-Torando-Token": TOKEN, "Origin": server},
    )
    assert code == 200
    st = json.loads(body)
    assert st["active"] is True
    assert st["rules"]["killswitch"] is True


def test_wrong_token_rejected(server):
    # exercises the constant-time compare path with a non-matching secret
    code, _ = _req(server + "/api/status", headers={"X-Torando-Token": "tok_wrong_BADBADBA"})
    assert code == 401


def test_security_headers_present(server):
    status, h, _ = _req_full(server + "/")
    assert status == 200
    assert "default-src 'none'" in h.get("content-security-policy", "")
    assert h.get("x-content-type-options") == "nosniff"
    assert h.get("x-frame-options") == "DENY"
    assert h.get("referrer-policy") == "no-referrer"
    assert h.get("cross-origin-opener-policy") == "same-origin"
    assert h.get("cross-origin-resource-policy") == "same-origin"
    assert "geolocation=()" in h.get("permissions-policy", "")
    assert "no-store" in h.get("cache-control", "")


def test_static_gzip_and_etag(server):
    status, h, body = _req_full(server + "/worldmap.js", headers={"Accept-Encoding": "gzip"})
    assert status == 200
    assert h.get("content-encoding") == "gzip"
    assert "immutable" in h.get("cache-control", "")
    assert h.get("etag")
    assert b"TORANDO_MAP" in gzip.decompress(body)


def test_static_etag_revalidation_304(server):
    status, h, _ = _req_full(server + "/app.js")
    assert status == 200
    etag = h["etag"]
    status2, _, body2 = _req_full(server + "/app.js", headers={"If-None-Match": etag})
    assert status2 == 304
    assert body2 == b""


def test_head_on_events_returns_no_body(server):
    # HEAD must not carry a body; the SSE handler must not open the stream.
    status, _, body = _req_full(
        server + "/api/events", method="HEAD", headers={"X-Torando-Token": TOKEN}
    )
    assert status == 200
    assert body == b""


def test_post_with_query_token_only_is_rejected(server):
    # The ?token= shortcut exists for the GET EventSource only; a POST that
    # supplies the token solely in the query string (no header) must be rejected
    # so CSRF defence stays header-bound.
    code, _ = _req(
        server + "/api/config?token=" + TOKEN,
        method="POST",
        headers={"Origin": server, "Content-Type": "application/json"},
        data=b"{}",
    )
    assert code == 401
