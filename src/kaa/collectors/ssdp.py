"""SSDP / UPnP discovery: one standard multicast M-SEARCH, then listen."""

from __future__ import annotations

import socket
import time

MSEARCH = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    'MAN: "ssdp:discover"\r\n'
    "MX: 2\r\n"
    "ST: ssdp:all\r\n\r\n"
).encode()


def parse_response(data: bytes) -> dict[str, str]:
    headers: dict[str, str] = {}
    for line in data.decode("utf-8", errors="replace").split("\r\n")[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return headers


def collect(duration: float = 2.5) -> dict[str, dict]:
    """Returns {ip: {"server": str, "st": [...], "location": str}}."""
    found: dict[str, dict] = {}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.4)
    try:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.sendto(MSEARCH, ("239.255.255.250", 1900))
        end = time.monotonic() + duration
        while time.monotonic() < end:
            try:
                data, (ip, _port) = sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            h = parse_response(data)
            entry = found.setdefault(ip, {"server": "", "st": set(), "location": ""})
            entry["server"] = h.get("server", entry["server"])
            entry["location"] = h.get("location", entry["location"])
            if "st" in h:
                entry["st"].add(h["st"])
            elif "nt" in h:
                entry["st"].add(h["nt"])
    except OSError:
        pass
    finally:
        sock.close()
    return {ip: {**v, "st": sorted(v["st"])} for ip, v in found.items()}
