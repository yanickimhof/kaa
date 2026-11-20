"""Menu bar icon: a grey ring around a green, orange or red dot, drawn without any image library."""

from __future__ import annotations

import math
import struct
import zlib
from pathlib import Path

SIZE = 44      # drawn at 2x, shown at 22 pt
SS = 4         # supersampling per axis


def _png(w: int, h: int, rgba: bytes) -> bytes:
    raw = b"".join(b"\x00" + rgba[y * w * 4:(y + 1) * w * 4] for y in range(h))

    def chunk(tag: bytes, data: bytes) -> bytes:
        return (struct.pack(">I", len(data)) + tag + data
                + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF))

    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 6, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b""))


RING = (166, 166, 172)   # neutral light grey: readable on a light and on a dark menu bar


def render(color: tuple[int, int, int] | None = None) -> bytes:
    """A grey ring around a coloured dot (green, orange or red); a faint grey dot when unknown."""
    c = SIZE / 2
    r_out, r_in, r_dot = c - 3.0, c - 6.5, 8.0
    px = bytearray()
    n = SS * SS
    for y in range(SIZE):
        for x in range(SIZE):
            ring = dot = 0
            for sy in range(SS):
                for sx in range(SS):
                    d = math.hypot(x + (sx + .5) / SS - c, y + (sy + .5) / SS - c)
                    if r_in <= d <= r_out:
                        ring += 1
                    elif d <= r_dot:
                        dot += 1
            fill = color or RING
            a_ring, a_dot = ring / n, dot / n * (1 if color else .45)
            a = a_ring + a_dot
            rgb = tuple(round((RING[i] * a_ring + fill[i] * a_dot) / a) for i in range(3)) if a else RING
            px += bytes((*rgb, round(255 * min(1, a))))
    return _png(SIZE, SIZE, bytes(px))


def ensure(directory: Path, name: str, color: tuple[int, int, int] | None = None) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{name}.png"
    path.write_bytes(render(color))
    return path
