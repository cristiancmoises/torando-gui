# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 Cristian Cezar Moisés — AGPL-3.0-only
"""A minimal SOCKS5 client, just enough to CONNECT through Tor's SocksPort.

Domain names are sent to the proxy (ATYP=0x03), i.e. remote DNS / "socks5h"
semantics, so name resolution also happens inside Tor and never leaks locally.
The byte-framing is factored into pure functions so it can be unit-tested with
no live proxy.
"""

from __future__ import annotations

import socket
import struct

SOCKS_VERSION = 0x05
NO_AUTH = 0x00
CMD_CONNECT = 0x01
ATYP_IPV4 = 0x01
ATYP_DOMAIN = 0x03
ATYP_IPV6 = 0x04

_REPLY = {
    0x00: "succeeded",
    0x01: "general SOCKS server failure",
    0x02: "connection not allowed by ruleset",
    0x03: "network unreachable",
    0x04: "host unreachable",
    0x05: "connection refused",
    0x06: "TTL expired",
    0x07: "command not supported",
    0x08: "address type not supported",
}


class SocksError(RuntimeError):
    pass


def build_greeting() -> bytes:
    """Client greeting offering only the no-authentication method."""
    return bytes([SOCKS_VERSION, 0x01, NO_AUTH])


def parse_method_reply(data: bytes) -> None:
    if len(data) != 2:
        raise SocksError("short method-selection reply")
    ver, method = data[0], data[1]
    if ver != SOCKS_VERSION:
        raise SocksError(f"bad SOCKS version {ver:#x}")
    if method != NO_AUTH:
        raise SocksError(f"proxy demands auth method {method:#x}")


def build_connect(host: str, port: int) -> bytes:
    """CONNECT request for a domain-name destination (remote DNS)."""
    if not 1 <= port <= 65535:
        raise SocksError(f"port out of range: {port}")
    name = host.encode("idna") if any(ord(c) > 127 for c in host) else host.encode("ascii")
    if len(name) > 255:
        raise SocksError("hostname too long for SOCKS5")
    return (
        bytes([SOCKS_VERSION, CMD_CONNECT, 0x00, ATYP_DOMAIN, len(name)])
        + name
        + struct.pack("!H", port)
    )


def reply_bound_len(atyp: int) -> int:
    """Length of the bound-address field that follows a CONNECT reply head."""
    if atyp == ATYP_IPV4:
        return 4
    if atyp == ATYP_IPV6:
        return 16
    raise SocksError(f"unexpected reply ATYP {atyp:#x}")


def parse_connect_reply_head(head: bytes) -> int:
    """Validate the 4-byte reply header, return the ATYP for follow-up reads."""
    if len(head) != 4:
        raise SocksError("short CONNECT reply header")
    ver, rep, _rsv, atyp = head
    if ver != SOCKS_VERSION:
        raise SocksError(f"bad SOCKS version {ver:#x}")
    if rep != 0x00:
        raise SocksError(_REPLY.get(rep, f"SOCKS error {rep:#x}"))
    return atyp


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise SocksError("proxy closed connection")
        buf += chunk
    return bytes(buf)


def socks5_connect(
    proxy_host: str,
    proxy_port: int,
    dst_host: str,
    dst_port: int,
    timeout: float = 12.0,
) -> socket.socket:
    """Open a TCP tunnel to *dst* through the SOCKS5 proxy and return the socket."""
    sock = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    try:
        sock.sendall(build_greeting())
        parse_method_reply(_recv_exact(sock, 2))
        sock.sendall(build_connect(dst_host, dst_port))
        atyp = parse_connect_reply_head(_recv_exact(sock, 4))
        if atyp == ATYP_DOMAIN:
            dlen = _recv_exact(sock, 1)[0]
            _recv_exact(sock, dlen + 2)
        else:
            _recv_exact(sock, reply_bound_len(atyp) + 2)
        return sock
    except Exception:
        sock.close()
        raise
