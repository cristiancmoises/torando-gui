# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 Cristian Cezar Moisés — AGPL-3.0-only
"""geoip tests: parse Tor's low,high,CC ranges and resolve IPs, degrading to
None (never a guessed country) when the file or range is missing."""

from __future__ import annotations

import ipaddress

from torando_gui.geoip import GeoIP, find_default, load_default

# A tiny Tor-format geoip fixture (low,high,CC as 32-bit integers).
SAMPLE = """\
# comment line, ignored
{a},{b},SE
{c},{d},US
{e},{f},??
""".format(
    a=int(ipaddress.IPv4Address("185.220.101.0")),
    b=int(ipaddress.IPv4Address("185.220.101.255")),
    c=int(ipaddress.IPv4Address("8.8.8.0")),
    d=int(ipaddress.IPv4Address("8.8.8.255")),
    e=int(ipaddress.IPv4Address("192.0.2.0")),
    f=int(ipaddress.IPv4Address("192.0.2.255")),
)


def _write(tmp_path, text):
    p = tmp_path / "geoip"
    p.write_text(text)
    return p


def test_lookup_resolves_known_ranges(tmp_path):
    geo = GeoIP.load(_write(tmp_path, SAMPLE))
    assert len(geo) == 3
    assert geo.lookup("185.220.101.47") == "se"
    assert geo.lookup("8.8.8.8") == "us"


def test_lookup_unknown_code_is_none(tmp_path):
    geo = GeoIP.load(_write(tmp_path, SAMPLE))
    assert geo.lookup("192.0.2.10") is None  # mapped to "??" -> no answer


def test_lookup_ip_outside_all_ranges_is_none(tmp_path):
    geo = GeoIP.load(_write(tmp_path, SAMPLE))
    assert geo.lookup("1.1.1.1") is None


def test_lookup_rejects_garbage_ip(tmp_path):
    geo = GeoIP.load(_write(tmp_path, SAMPLE))
    assert geo.lookup("not-an-ip") is None
    assert geo.lookup("") is None


def test_load_sorts_unsorted_input(tmp_path):
    a = int(ipaddress.IPv4Address("8.8.8.0"))
    b = int(ipaddress.IPv4Address("8.8.8.255"))
    c = int(ipaddress.IPv4Address("1.0.0.0"))
    d = int(ipaddress.IPv4Address("1.0.0.255"))
    # US range appears before a numerically-lower AU range
    geo = GeoIP.load(_write(tmp_path, f"{a},{b},US\n{c},{d},AU\n"))
    assert geo.lookup("1.0.0.5") == "au"
    assert geo.lookup("8.8.8.8") == "us"


def test_find_default_returns_none_when_absent(monkeypatch):
    import torando_gui.geoip as g

    monkeypatch.setattr(g, "DEFAULT_PATHS", (g.Path("/nonexistent/torando/geoip"),))
    assert find_default() is None
    assert load_default() is None
