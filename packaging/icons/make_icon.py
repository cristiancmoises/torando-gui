# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 Cristian Cezar Moisés — AGPL-3.0-only
"""Render the Torando onion-ring icon to PNG at the requested size.

Usage: python3 make_icon.py OUT.png [SIZE]

Uses Pillow for the nice anti-aliased rings when it's installed; falls back to a
pure-stdlib PNG writer (a flat branded square) otherwise, so a packaging build
never hard-fails just because Pillow is missing. No network, no external assets.
"""

from __future__ import annotations

import struct
import sys
import zlib

INK = (14, 11, 22, 255)
VIOLET = (154, 109, 255, 255)
MINT = (54, 224, 166, 255)

try:
    from PIL import Image, ImageDraw

    _HAVE_PIL = True
except ImportError:  # pragma: no cover - exercised only where Pillow is absent
    _HAVE_PIL = False


def _write_solid_png(path: str, size: int, rgba: tuple[int, int, int, int]) -> None:
    """Write a valid size×size 8-bit RGBA PNG of a solid colour, stdlib only."""
    row = bytes(rgba) * size
    raw = b"".join(b"\x00" + row for _ in range(size))  # filter byte 0 per scanline

    def chunk(typ: bytes, data: bytes) -> bytes:
        body = typ + data
        return (
            struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)
        )

    png = (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(raw, 9))
        + chunk(b"IEND", b"")
    )
    with open(path, "wb") as fh:
        fh.write(png)


def _ring(draw, cx: int, cy: int, r: int, color, width: int) -> None:
    draw.ellipse((cx - r, cy - r, cx + r, cy + r), outline=color, width=width)


def render(path: str, size: int = 256) -> None:
    if not _HAVE_PIL:
        _write_solid_png(path, size, INK)
        return
    # supersample 4x then downscale for clean anti-aliased rings
    s = size * 4
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    radius = int(s * 0.22)
    d.rounded_rectangle((0, 0, s - 1, s - 1), radius=radius, fill=INK)
    cx = cy = s // 2
    w = max(2, s // 22)
    _ring(d, cx, cy, int(s * 0.34), VIOLET, w)
    _ring(d, cx, cy, int(s * 0.25), VIOLET, w)
    _ring(d, cx, cy, int(s * 0.155), MINT, w)
    core = int(s * 0.06)
    d.ellipse((cx - core, cy - core, cx + core, cy + core), fill=MINT)
    img = img.resize((size, size), Image.LANCZOS)
    img.save(path, "PNG")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write("usage: make_icon.py OUT.png [SIZE]\n")
        raise SystemExit(2)
    out = sys.argv[1]
    sz = int(sys.argv[2]) if len(sys.argv) > 2 else 256
    render(out, sz)
    sys.stdout.write(f"wrote {out} ({sz}x{sz})\n")
