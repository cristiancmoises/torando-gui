# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 Cristian Cezar Moisés — AGPL-3.0-only
"""SOCKS5 byte-framing tests. No live proxy: the pure functions are exercised
directly to lock the wire format (incl. remote DNS / socks5h semantics)."""

from __future__ import annotations

import struct

import pytest
from torando_gui.socks import (
    ATYP_IPV4,
    ATYP_IPV6,
    SocksError,
    build_connect,
    build_greeting,
    parse_connect_reply_head,
    parse_method_reply,
    reply_bound_len,
)


def test_greeting_offers_only_no_auth():
    assert build_greeting() == bytes([0x05, 0x01, 0x00])


def test_method_reply_accepts_no_auth():
    assert parse_method_reply(b"\x05\x00") is None


def test_method_reply_rejects_auth_demand_and_bad_version():
    with pytest.raises(SocksError):
        parse_method_reply(b"\x05\xff")  # would require authentication
    with pytest.raises(SocksError):
        parse_method_reply(b"\x04\x00")  # wrong version
    with pytest.raises(SocksError):
        parse_method_reply(b"\x05")  # short


def test_connect_uses_domain_atyp_for_remote_dns():
    pkt = build_connect("example.com", 443)
    name = b"example.com"
    expected = bytes([0x05, 0x01, 0x00, 0x03, len(name)]) + name + struct.pack("!H", 443)
    assert pkt == expected
    # ATYP must be 0x03 (domain) so the proxy resolves the name, not the client
    assert pkt[3] == 0x03


def test_connect_idna_encodes_non_ascii_host():
    pkt = build_connect("bücher.de", 80)
    assert b"xn--bcher-kva.de" in pkt


def test_connect_rejects_bad_port_and_long_host():
    with pytest.raises(SocksError):
        build_connect("example.com", 0)
    with pytest.raises(SocksError):
        build_connect("example.com", 65536)
    with pytest.raises(SocksError):
        build_connect("a" * 256 + ".com", 443)


def test_reply_head_success_returns_atyp():
    assert parse_connect_reply_head(b"\x05\x00\x00\x01") == ATYP_IPV4


def test_reply_head_maps_error_code():
    with pytest.raises(SocksError, match="connection refused"):
        parse_connect_reply_head(b"\x05\x05\x00\x01")


def test_reply_head_rejects_short_and_bad_version():
    with pytest.raises(SocksError):
        parse_connect_reply_head(b"\x05\x00\x00")
    with pytest.raises(SocksError):
        parse_connect_reply_head(b"\x04\x00\x00\x01")


def test_bound_len_per_atyp():
    assert reply_bound_len(ATYP_IPV4) == 4
    assert reply_bound_len(ATYP_IPV6) == 16
    with pytest.raises(SocksError):
        reply_bound_len(0x03)  # domain not expected in a reply
