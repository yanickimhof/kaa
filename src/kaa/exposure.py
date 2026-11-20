"""Exposure check: what the Internet can reach on your public address.

Opt in (``[exposure] enabled = true``). Kaa asks a public service for its own address, then
asks Shodan's free InternetDB what it has seen open on that address. Only your public IP
address leaves the Mac, never anything about your local network. The answer reflects
Shodan's last crawl, not a live probe.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request

TRACE_URL = "https://1.1.1.1/cdn-cgi/trace"
DB_URL = "https://internetdb.shodan.io/{ip}"
RISKY = {21, 22, 23, 25, 135, 139, 445, 1883, 3389, 5900, 8080}
_IP = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _get(url: str, ctx, timeout: float = 12.0) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "kaa-exposure"})
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:  # noqa: S310
        return r.read(200_000)


def public_ip(ctx) -> str | None:
    for line in _get(TRACE_URL, ctx).decode("utf-8", "replace").splitlines():
        if line.startswith("ip="):
            ip = line[3:].strip()
            return ip if _IP.match(ip) else None
    return None


def lookup(ip: str, ctx) -> dict:
    """{"ports": [...], "vulns": [...]}; an unknown address (404) means nothing was seen."""
    try:
        data = json.loads(_get(DB_URL.format(ip=ip), ctx))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return {"ports": [], "vulns": []}
        raise
    ports = sorted({int(p) for p in data.get("ports", []) if isinstance(p, int)})
    vulns = sorted({str(v) for v in data.get("vulns", []) if re.match(r"^CVE-\d{4}-\d+$", str(v))})
    return {"ports": ports, "vulns": vulns}


def mask(ip: str) -> str:
    a = ip.split(".")
    return f"{a[0]}.{a[1]}.x.x" if len(a) == 4 else "x.x.x.x"
