# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 Cristian Cezar Moisés — AGPL-3.0-only
"""netcheck tests. The key invariant: a failure NEVER yields a true/false
verdict — it must be is_tor=None so the UI shows 'unknown', not a false
'secured'."""

from __future__ import annotations

from torando_gui import netcheck


class _Dummy:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def close(self):
        pass


def test_split_body_strips_headers():
    raw = b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"IP":"1.2.3.4"}'
    assert netcheck._split_body(raw) == b'{"IP":"1.2.3.4"}'


def test_split_body_without_separator_returns_raw():
    raw = b'{"IP":"1.2.3.4"}'
    assert netcheck._split_body(raw) == raw


def test_check_exit_parses_positive_verdict(monkeypatch):
    monkeypatch.setattr(netcheck, "socks5_connect", lambda *a, **k: _Dummy())
    resp = (
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"
        b'{"IsTor":true,"IP":"185.220.101.47"}'
    )
    monkeypatch.setattr(netcheck, "_http_get_over", lambda *a, **k: resp)
    info = netcheck.check_exit("127.0.0.1", 9050, "http://check.example/api/ip")
    assert info.is_tor is True
    assert info.ip == "185.220.101.47"
    assert info.error is None


def test_check_exit_parses_negative_verdict(monkeypatch):
    monkeypatch.setattr(netcheck, "socks5_connect", lambda *a, **k: _Dummy())
    resp = b"HTTP/1.1 200 OK\r\n\r\n" + b'{"IsTor":false,"IP":"203.0.113.9"}'
    monkeypatch.setattr(netcheck, "_http_get_over", lambda *a, **k: resp)
    info = netcheck.check_exit("127.0.0.1", 9050, "http://check.example/api/ip")
    assert info.is_tor is False
    assert info.ip == "203.0.113.9"


def test_check_exit_socks_failure_is_unknown(monkeypatch):
    def boom(*a, **k):
        raise OSError("connection refused")

    monkeypatch.setattr(netcheck, "socks5_connect", boom)
    info = netcheck.check_exit("127.0.0.1", 9050, "https://check.torproject.org/api/ip")
    assert info.is_tor is None
    assert info.ip is None
    assert info.error.startswith("socks:")


def test_check_exit_bad_json_is_unknown(monkeypatch):
    monkeypatch.setattr(netcheck, "socks5_connect", lambda *a, **k: _Dummy())
    monkeypatch.setattr(
        netcheck, "_http_get_over", lambda *a, **k: b"HTTP/1.1 200 OK\r\n\r\nnot-json"
    )
    info = netcheck.check_exit("127.0.0.1", 9050, "http://check.example/api/ip")
    assert info.is_tor is None
    assert info.error is not None


def test_exitinfo_as_dict_shape():
    d = netcheck.ExitInfo(True, "1.2.3.4").as_dict()
    assert d == {
        "is_tor": True,
        "ip": "1.2.3.4",
        "error": None,
        "country": None,
        "lat": None,
        "lon": None,
        "city": None,
    }
