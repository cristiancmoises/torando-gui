# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 Cristian Cezar Moisés — AGPL-3.0-only
"""Minimal, dependency-free reader for the MaxMind DB (.mmdb) binary format.

Only what Torando needs: walk the binary search tree for an IPv4/IPv6 address
and decode the record (maps, strings, doubles, ints, arrays, booleans,
pointers). This lets us resolve an exit IP to latitude/longitude + city from a
locally installed GeoLite2-City database, fully offline, with no third-party
network calls and no C extension.

Format reference: https://maxmind.github.io/MaxMind-DB/ . The reader is
intentionally read-only and tolerant: any structural problem raises MMDBError,
which callers turn into "no location" rather than a crash or a fabricated guess.
"""

from __future__ import annotations

import ipaddress
import struct
from pathlib import Path

_METADATA_MARKER = b"\xab\xcd\xefMaxMind.com"
_DATA_SEPARATOR = 16  # bytes of zero padding between tree and data section


class MMDBError(Exception):
    """Raised when the buffer is not a usable MaxMind DB."""


class MMDB:
    """Read-only view over an mmdb buffer."""

    def __init__(self, data: bytes) -> None:
        self._buf = data
        meta = self._read_metadata()
        try:
            self.node_count = int(meta["node_count"])
            self.record_size = int(meta["record_size"])
            self.ip_version = int(meta["ip_version"])
        except (KeyError, TypeError, ValueError) as exc:
            raise MMDBError(f"bad metadata: {exc}") from exc
        if self.record_size not in (24, 28, 32):
            raise MMDBError(f"unsupported record_size {self.record_size}")
        self.node_byte_size = self.record_size * 2 // 8
        self.search_tree_size = self.node_byte_size * self.node_count
        self.data_section_start = self.search_tree_size + _DATA_SEPARATOR
        self._ipv4_start = 0
        if self.ip_version == 6:
            self._ipv4_start = self._compute_ipv4_start()

    @classmethod
    def open(cls, path: Path) -> MMDB:
        return cls(Path(path).read_bytes())

    # --- public lookup ---------------------------------------------------
    def get(self, ip: str) -> dict | None:
        """Return the decoded record for ``ip`` or None if absent/unparseable."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        if addr.version == 6 and self.ip_version == 4:
            return None
        packed = addr.packed
        bit_count = len(packed) * 8
        node = self._ipv4_start if (addr.version == 4 and self.ip_version == 6) else 0
        for i in range(bit_count):
            if node >= self.node_count:
                break
            bit = (packed[i >> 3] >> (7 - (i & 7))) & 1
            node = self._read_node(node, bit)
        if node <= self.node_count:
            return None  # == node_count: empty; < node_count: ran out of bits
        value, _ = self._decode(self._data_offset(node), self.data_section_start)
        return value if isinstance(value, dict) else None

    # --- tree ------------------------------------------------------------
    def _read_node(self, node: int, index: int) -> int:
        base = node * self.node_byte_size
        buf = self._buf
        if self.record_size == 24:
            off = base + index * 3
            return int.from_bytes(buf[off : off + 3], "big")
        if self.record_size == 28:
            mid = buf[base + 3]
            if index == 0:
                return ((mid & 0xF0) << 20) | int.from_bytes(buf[base : base + 3], "big")
            return ((mid & 0x0F) << 24) | int.from_bytes(buf[base + 4 : base + 7], "big")
        off = base + index * 4
        return int.from_bytes(buf[off : off + 4], "big")

    def _compute_ipv4_start(self) -> int:
        node = 0
        for _ in range(96):
            if node >= self.node_count:
                break
            node = self._read_node(node, 0)
        return node

    def _data_offset(self, pointer: int) -> int:
        return (pointer - self.node_count) + self.search_tree_size

    # --- data section decoder -------------------------------------------
    def _decode(self, offset: int, pbase: int) -> tuple[object, int]:
        buf = self._buf
        ctrl = buf[offset]
        offset += 1
        type_ = ctrl >> 5
        if type_ == 1:
            return self._decode_pointer(ctrl, offset, pbase)
        if type_ == 0:  # extended type: real type is next byte + 7
            type_ = buf[offset] + 7
            offset += 1
        size = ctrl & 0x1F
        if size == 29:
            size = 29 + buf[offset]
            offset += 1
        elif size == 30:
            size = 285 + int.from_bytes(buf[offset : offset + 2], "big")
            offset += 2
        elif size == 31:
            size = 65821 + int.from_bytes(buf[offset : offset + 3], "big")
            offset += 3
        return self._decode_value(type_, size, offset, pbase)

    def _decode_value(self, type_: int, size: int, offset: int, pbase: int) -> tuple[object, int]:
        buf = self._buf
        if type_ == 2:  # utf-8 string
            return buf[offset : offset + size].decode("utf-8", "replace"), offset + size
        if type_ == 3:  # double
            return struct.unpack(">d", buf[offset : offset + 8])[0], offset + 8
        if type_ == 4:  # bytes
            return bytes(buf[offset : offset + size]), offset + size
        if type_ in (5, 6, 9, 10):  # unsigned ints
            return int.from_bytes(buf[offset : offset + size], "big"), offset + size
        if type_ == 7:  # map
            out: dict[object, object] = {}
            for _ in range(size):
                key, offset = self._decode(offset, pbase)
                val, offset = self._decode(offset, pbase)
                out[key] = val
            return out, offset
        if type_ == 8:  # signed 32-bit int
            return int.from_bytes(buf[offset : offset + size], "big", signed=True), offset + size
        if type_ == 11:  # array
            arr: list[object] = []
            for _ in range(size):
                val, offset = self._decode(offset, pbase)
                arr.append(val)
            return arr, offset
        if type_ == 14:  # boolean — size carries the value, no payload bytes
            return bool(size), offset
        if type_ == 15:  # float (32-bit)
            return struct.unpack(">f", buf[offset : offset + 4])[0], offset + 4
        if type_ in (12, 13):  # cache container / end marker — not expected here
            raise MMDBError(f"unexpected control type {type_}")
        raise MMDBError(f"unknown type {type_}")

    def _decode_pointer(self, ctrl: int, offset: int, pbase: int) -> tuple[object, int]:
        buf = self._buf
        size = (ctrl >> 3) & 0x3
        high = ctrl & 0x7
        if size == 0:
            pointer = (high << 8) | buf[offset]
            offset += 1
        elif size == 1:
            pointer = (high << 16) | int.from_bytes(buf[offset : offset + 2], "big")
            pointer += 2048
            offset += 2
        elif size == 2:
            pointer = (high << 24) | int.from_bytes(buf[offset : offset + 3], "big")
            pointer += 526336
            offset += 3
        else:
            pointer = int.from_bytes(buf[offset : offset + 4], "big")
            offset += 4
        value, _ = self._decode(pbase + pointer, pbase)
        return value, offset

    # --- metadata --------------------------------------------------------
    def _read_metadata(self) -> dict:
        idx = self._buf.rfind(_METADATA_MARKER)
        if idx == -1:
            raise MMDBError("metadata marker not found")
        start = idx + len(_METADATA_MARKER)
        meta, _ = self._decode(start, start)
        if not isinstance(meta, dict):
            raise MMDBError("metadata is not a map")
        return meta


# --- discovery -----------------------------------------------------------
DEFAULT_CITY_PATHS = (
    Path("/usr/share/GeoIP/GeoLite2-City.mmdb"),
    Path("/var/lib/GeoIP/GeoLite2-City.mmdb"),
    Path("/usr/local/share/GeoIP/GeoLite2-City.mmdb"),
    Path("/usr/share/tor/geoip-city.mmdb"),
    Path("/etc/torando-gui/GeoLite2-City.mmdb"),
)


def find_city_db() -> Path | None:
    for p in DEFAULT_CITY_PATHS:
        if p.exists():
            return p
    return None


def open_default() -> MMDB | None:
    path = find_city_db()
    if path is None:
        return None
    try:
        return MMDB.open(path)
    except (OSError, MMDBError, IndexError, struct.error, RecursionError, ValueError):
        # A truncated/corrupt DB can make the decoder index past EOF, unpack a
        # short slice, or recurse on a cyclic pointer during metadata parsing.
        # Honour the never-crash contract: treat any such DB as "unavailable".
        return None
