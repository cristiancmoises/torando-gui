# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 Cristian Cezar Moisés — AGPL-3.0-only
"""Resolve an exit IP to a country using Tor's own GeoIP database.

Tor ships ``/usr/share/tor/geoip`` as ascending ``low,high,CC`` integer ranges.
Reusing it keeps geolocation fully offline and authoritative for what Tor knows.
If the file is absent the resolver simply returns None and the UI shows the
exit IP without a country — it never invents a location.
"""

from __future__ import annotations

import bisect
import ipaddress
import struct
from pathlib import Path

from . import mmdb

# A truncated/corrupt .mmdb makes the decoder index past EOF or recurse on a
# cyclic pointer; translate those to "no location" so a bad DB never crashes
# the daemon (the never-crash contract documented in mmdb.py).
_DECODE_ERRORS = (mmdb.MMDBError, IndexError, struct.error, RecursionError, ValueError)

DEFAULT_PATHS = (
    Path("/usr/share/tor/geoip"),
    Path("/usr/local/share/tor/geoip"),
    Path("/etc/tor/geoip"),
)

# Codes Tor uses for "unknown"; treated as no answer.
_UNKNOWN = {"??", "a1", "a2"}


class GeoIP:
    """Binary-searchable view of Tor's IPv4 geoip ranges."""

    def __init__(self, lows: list[int], highs: list[int], ccs: list[str]) -> None:
        self._lows = lows
        self._highs = highs
        self._ccs = ccs

    def __len__(self) -> int:
        return len(self._lows)

    @classmethod
    def load(cls, path: Path) -> GeoIP:
        lows: list[int] = []
        highs: list[int] = []
        ccs: list[str] = []
        with open(path, encoding="ascii", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(",")
                if len(parts) < 3:
                    continue
                try:
                    lo = int(parts[0])
                    hi = int(parts[1])
                except ValueError:
                    continue
                lows.append(lo)
                highs.append(hi)
                ccs.append(parts[2].strip().lower())
        # Tor ships the file sorted by low; sort defensively in case it is not.
        if lows and any(lows[i] > lows[i + 1] for i in range(len(lows) - 1)):
            order = sorted(range(len(lows)), key=lambda i: lows[i])
            lows = [lows[i] for i in order]
            highs = [highs[i] for i in order]
            ccs = [ccs[i] for i in order]
        return cls(lows, highs, ccs)

    def lookup(self, ip: str) -> str | None:
        try:
            n = int(ipaddress.IPv4Address(ip))
        except (ipaddress.AddressValueError, ValueError):
            return None
        i = bisect.bisect_right(self._lows, n) - 1
        if 0 <= i < len(self._lows) and self._lows[i] <= n <= self._highs[i]:
            cc = self._ccs[i]
            return None if cc in _UNKNOWN else cc
        return None


def find_default() -> Path | None:
    for p in DEFAULT_PATHS:
        if p.exists():
            return p
    return None


def load_default() -> GeoIP | None:
    path = find_default()
    if path is None:
        return None
    try:
        return GeoIP.load(path)
    except OSError:
        return None


class CityDB:
    """City-level resolver over a GeoLite2-City .mmdb (lat/lon + city name)."""

    def __init__(self, db: mmdb.MMDB) -> None:
        self._db = db

    @classmethod
    def load(cls, path: Path) -> CityDB:
        return cls(mmdb.MMDB.open(path))

    def lookup(self, ip: str) -> dict[str, object] | None:
        """Return {lat, lon, city, country} for ``ip`` or None if not found.

        Any field may be None; callers should treat coordinates as optional and
        never fabricate them.
        """
        try:
            rec = self._db.get(ip)
        except _DECODE_ERRORS:
            return None
        if not isinstance(rec, dict):
            return None
        loc = rec.get("location") or {}
        lat = loc.get("latitude")
        lon = loc.get("longitude")
        city = ((rec.get("city") or {}).get("names") or {}).get("en")
        cc = (rec.get("country") or {}).get("iso_code")
        if lat is None and lon is None and city is None and cc is None:
            return None
        return {
            "lat": float(lat) if isinstance(lat, (int, float)) else None,
            "lon": float(lon) if isinstance(lon, (int, float)) else None,
            "city": city if isinstance(city, str) else None,
            "country": cc.lower() if isinstance(cc, str) else None,
        }


def find_city_default() -> Path | None:
    return mmdb.find_city_db()


def load_city_default() -> CityDB | None:
    db = mmdb.open_default()
    return CityDB(db) if db is not None else None
