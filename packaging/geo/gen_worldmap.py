# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 Cristian Cezar Moisés — AGPL-3.0-only
"""Regenerate backend/torando_gui/webroot/worldmap.js from Natural Earth 110m.

Self-contained: downloads the public-domain land + country GeoJSON if not
cached, projects equirectangular (plate carree) so the same lon/lat -> x/y maps
both the coastlines and the exit marker, simplifies the coastline to a single
SVG path, and computes area-weighted country centroids keyed by ISO-3166-1
alpha-2.

Usage:  python3 packaging/geo/gen_worldmap.py
Sources (public domain, Natural Earth via martynafford/natural-earth-geojson):
  110m/physical/ne_110m_land.json
  110m/cultural/ne_110m_admin_0_countries.json
"""

from __future__ import annotations

import json
import sys
import urllib.request
from pathlib import Path

W = 1000.0
H = 500.0
BASE = "https://raw.githubusercontent.com/martynafford/natural-earth-geojson/master/110m"
SOURCES = {
    "land.json": f"{BASE}/physical/ne_110m_land.json",
    "countries.json": f"{BASE}/cultural/ne_110m_admin_0_countries.json",
}
CACHE = Path(__file__).resolve().parent / "cache"
OUT = Path(__file__).resolve().parents[2] / "backend" / "torando_gui" / "webroot" / "worldmap.js"


def project(lon: float, lat: float) -> tuple[float, float]:
    return (lon + 180.0) / 360.0 * W, (90.0 - lat) / 180.0 * H


def _fetch(name: str, url: str) -> dict:
    CACHE.mkdir(parents=True, exist_ok=True)
    path = CACHE / name
    if not path.exists():
        sys.stdout.write(f"downloading {url}\n")
        with urllib.request.urlopen(url, timeout=60) as resp:  # noqa: S310 (fixed https URL)
            path.write_bytes(resp.read())
    return json.loads(path.read_text(encoding="utf-8"))


def _decimate(ring: list[tuple[float, float]], eps: float) -> list[tuple[float, float]]:
    out: list[tuple[float, float]] = []
    last: tuple[float, float] | None = None
    for x, y in ring:
        if last is None or abs(x - last[0]) + abs(y - last[1]) >= eps:
            out.append((x, y))
            last = (x, y)
    return out


def _ring_path(ring: list[list[float]], eps: float, min_pts: int) -> str:
    pts = _decimate([project(lon, lat) for lon, lat in ring], eps)
    if len(pts) < min_pts:
        return ""
    segs = [f"M{pts[0][0]:.1f} {pts[0][1]:.1f}"]
    segs += [f"L{x:.1f} {y:.1f}" for x, y in pts[1:]]
    return "".join(segs) + "Z"


def land_path(land: dict, eps: float = 1.1, min_pts: int = 5) -> str:
    parts: list[str] = []
    for feat in land["features"]:
        geom = feat["geometry"]
        polys = geom["coordinates"] if geom["type"] == "MultiPolygon" else [geom["coordinates"]]
        for poly in polys:
            for ring in poly:
                seg = _ring_path(ring, eps, min_pts)
                if seg:
                    parts.append(seg)
    return "".join(parts)


def _centroid(ring: list[list[float]]) -> tuple[float, float, float]:
    a = cx = cy = 0.0
    n = len(ring)
    for i in range(n - 1):
        x0, y0 = ring[i]
        x1, y1 = ring[i + 1]
        cross = x0 * y1 - x1 * y0
        a += cross
        cx += (x0 + x1) * cross
        cy += (y0 + y1) * cross
    if a == 0:
        return sum(p[0] for p in ring) / n, sum(p[1] for p in ring) / n, 0.0
    a *= 0.5
    return cx / (6.0 * a), cy / (6.0 * a), abs(a)


def centroids(countries: dict) -> tuple[dict, dict]:
    points: dict[str, list[int]] = {}
    names: dict[str, str] = {}
    for feat in countries["features"]:
        props = feat["properties"]
        cc = (props.get("ISO_A2") or "").strip().lower()
        if len(cc) != 2 or cc == "-9":
            continue
        geom = feat["geometry"]
        polys = geom["coordinates"] if geom["type"] == "MultiPolygon" else [geom["coordinates"]]
        best = None
        for poly in polys:
            cand = _centroid(poly[0])
            if best is None or cand[2] > best[2]:
                best = cand
        if best is None:
            continue
        x, y = project(best[0], best[1])
        points[cc] = [round(x), round(y)]
        names[cc] = props.get("NAME") or props.get("ADMIN") or cc.upper()
    return points, names


def main() -> int:
    land = _fetch("land.json", SOURCES["land.json"])
    countries = _fetch("countries.json", SOURCES["countries.json"])
    pts, names = centroids(countries)
    payload = {"w": int(W), "h": int(H), "land": land_path(land), "points": pts, "names": names}
    with open(OUT, "w", encoding="utf-8") as fh:
        fh.write("// SPDX-License-Identifier: AGPL-3.0-only\n")
        fh.write("// Copyright (c) 2026 Cristian Cezar Moisés — AGPL-3.0-only\n")
        fh.write("// Generated from Natural Earth 110m (public domain). Do not edit by hand.\n")
        fh.write("window.TORANDO_MAP = ")
        fh.write(json.dumps(payload, separators=(",", ":")))
        fh.write(";\n")
    kb = OUT.stat().st_size / 1024
    sys.stdout.write(f"wrote {OUT} ({len(pts)} countries, {kb:.1f} KiB)\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
