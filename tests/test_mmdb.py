# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 Cristian Cezar Moisés — AGPL-3.0-only
"""Round-trip tests for the dependency-free MaxMind DB reader.

A minimal in-test encoder builds a valid one-network IPv4 database (record_size
24, ip_version 4) so the reader is exercised end to end — tree walk, data
decoding, and metadata parsing — without shipping a binary fixture.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest
from torando_gui import geoip, mmdb


# --- minimal MMDB encoder (mirrors the format the reader consumes) -----------
def _ctrl(type_id: int, size: int) -> bytes:
    assert size < 29
    return bytes([(type_id << 5) | size])


def _enc(value: object) -> bytes:
    if isinstance(value, bool):
        return bytes([1 if value else 0, 14 - 7])  # type 14 (extended), size = value
    if isinstance(value, str):
        raw = value.encode("utf-8")
        return _ctrl(2, len(raw)) + raw
    if isinstance(value, float):
        return _ctrl(3, 8) + struct.pack(">d", value)
    if isinstance(value, int):
        raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
        return _ctrl(5 if len(raw) <= 2 else 6, len(raw)) + raw
    if isinstance(value, list):
        out = bytes([len(value), 11 - 7])  # type 11 (extended array)
        for item in value:
            out += _enc(item)
        return out
    if isinstance(value, dict):
        out = _ctrl(7, len(value))
        for key, val in value.items():
            out += _enc(key) + _enc(val)
        return out
    raise TypeError(type(value))


def _build_db() -> bytes:
    record = {
        "city": {"names": {"en": "Göteborg"}},
        "country": {"iso_code": "SE"},
        "location": {"latitude": 57.7065, "longitude": 11.967},
    }
    metadata = {
        "node_count": 1,
        "record_size": 24,
        "ip_version": 4,
        "database_type": "Test-City",
        "languages": ["en"],
        "binary_format_major_version": 2,
        "binary_format_minor_version": 0,
        "build_epoch": 0,
        "description": {"en": "torando test db"},
    }
    # node 0: left record (bit 0) -> data pointer 17 (= node_count 1 + 16);
    #         right record (bit 1) -> 1 (== node_count) meaning "no data".
    tree = (17).to_bytes(3, "big") + (1).to_bytes(3, "big")
    separator = b"\x00" * 16
    return tree + separator + _enc(record) + b"\xab\xcd\xef" + b"MaxMind.com" + _enc(metadata)


def test_roundtrip_lookup_hit():
    db = mmdb.MMDB(_build_db())
    rec = db.get("1.2.3.4")  # high bit 0 -> left -> data
    assert rec is not None
    assert rec["location"]["latitude"] == 57.7065
    assert rec["location"]["longitude"] == 11.967
    assert rec["country"]["iso_code"] == "SE"
    assert rec["city"]["names"]["en"] == "Göteborg"


def test_roundtrip_lookup_miss():
    db = mmdb.MMDB(_build_db())
    assert db.get("200.0.0.1") is None  # high bit 1 -> right -> no data


def test_citydb_normalizes_record():
    db = mmdb.MMDB(_build_db())
    out = geoip.CityDB(db).lookup("1.2.3.4")
    assert out == {"lat": 57.7065, "lon": 11.967, "city": "Göteborg", "country": "se"}


def test_citydb_miss_returns_none():
    db = mmdb.MMDB(_build_db())
    assert geoip.CityDB(db).lookup("200.0.0.1") is None


def test_garbage_buffer_raises():
    with pytest.raises(mmdb.MMDBError):
        mmdb.MMDB(b"this is not a maxmind database")


def test_discovery_absent(monkeypatch):
    monkeypatch.setattr(mmdb, "DEFAULT_CITY_PATHS", (Path("/nonexistent/GeoLite2-City.mmdb"),))
    assert mmdb.find_city_db() is None
    assert mmdb.open_default() is None
    assert geoip.load_city_default() is None


def test_citydb_lookup_survives_corrupt_pointer():
    # Corrupt node 0's left record so the tree walk yields a data pointer far
    # past the buffer; the decoder would index out of range. The never-crash
    # contract requires CityDB.lookup to translate that to None, not raise.
    raw = bytearray(_build_db())  # metadata stays intact -> MMDB() constructs fine
    raw[0:3] = (0xFFFFFF).to_bytes(3, "big")
    db = mmdb.MMDB(bytes(raw))
    assert geoip.CityDB(db).lookup("1.2.3.4") is None


def test_open_default_survives_truncated_file(tmp_path, monkeypatch):
    good = _build_db()
    truncated = good[: len(good) // 2]  # cut through data/metadata -> unusable
    p = tmp_path / "GeoLite2-City.mmdb"
    p.write_bytes(truncated)
    monkeypatch.setattr(mmdb, "DEFAULT_CITY_PATHS", (p,))
    assert mmdb.open_default() is None  # never raises despite the corrupt DB
    assert geoip.load_city_default() is None
