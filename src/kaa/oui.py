"""Vendor lookup from the public IEEE OUI registry.

Kaa ships no vendor table. ``kaa update-data`` downloads the official
registry once and stores it locally; lookups are then fully offline.
"""

from __future__ import annotations

import csv
import urllib.request
from pathlib import Path

IEEE_URL = "https://standards-oui.ieee.org/oui/oui.csv"


def normalize_mac(mac: str) -> str:
    parts = mac.replace("-", ":").lower().split(":")
    return ":".join(p.zfill(2) for p in parts)


def is_randomized(mac: str) -> bool:
    """Locally administered bit set: phones and laptops rotating their MAC."""
    return bool(int(normalize_mac(mac).split(":")[0], 16) & 0x02)


def is_multicast(mac: str) -> bool:
    return bool(int(normalize_mac(mac).split(":")[0], 16) & 0x01)


class Oui:
    def __init__(self, path: Path):
        self.path = path
        self._table: dict[str, str] = {}
        if path.exists():
            with path.open(newline="", encoding="utf-8", errors="replace") as fh:
                for row in csv.DictReader(fh):
                    key = (row.get("Assignment") or "").strip().upper()
                    org = (row.get("Organization Name") or "").strip()
                    if len(key) == 6 and org:
                        self._table[key] = org

    @property
    def loaded(self) -> bool:
        return bool(self._table)

    def lookup(self, mac: str) -> str | None:
        if is_randomized(mac):
            return None
        key = normalize_mac(mac).replace(":", "")[:6].upper()
        return self._table.get(key)


def download(dest: Path, url: str = IEEE_URL, timeout: float = 30.0) -> int:
    dest.parent.mkdir(parents=True, exist_ok=True)
    req = urllib.request.Request(url, headers={"User-Agent": "kaa-oui-update"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
        body = resp.read()
    head = body[:200].decode("utf-8", errors="replace")
    if "Assignment" not in head:
        raise ValueError("unexpected OUI file format")
    tmp = dest.with_suffix(".tmp")
    tmp.write_bytes(body)
    tmp.replace(dest)
    return len(body)
