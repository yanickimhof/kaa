"""Multicast DNS / DNS-SD discovery (Bonjour, Avahi). Standard, polite, local."""

from __future__ import annotations

import time
from collections import defaultdict


def collect(duration: float = 4.0) -> dict[str, dict]:
    """Returns {ip: {"services": [...], "names": [...], "txt": {...}}}."""
    try:
        from zeroconf import ServiceBrowser, ServiceListener, Zeroconf, ZeroconfServiceTypes
    except ImportError:  # pragma: no cover
        return {}

    found: dict[str, dict] = defaultdict(lambda: {"services": set(), "names": set(), "txt": {}})

    class Listener(ServiceListener):
        def _handle(self, zc, type_, name):
            try:
                info = zc.get_service_info(type_, name, timeout=1500)
            except Exception:
                return
            if not info:
                return
            for addr in info.parsed_addresses():
                if "." not in addr:
                    continue
                entry = found[addr]
                entry["services"].add(type_.removesuffix(".local."))
                entry["names"].add(name.split("." + type_)[0])
                for k, v in (info.properties or {}).items():
                    try:
                        entry["txt"][k.decode()] = v.decode(errors="replace") if v else ""
                    except Exception:
                        continue

        def add_service(self, zc, type_, name):
            self._handle(zc, type_, name)

        def update_service(self, zc, type_, name):
            self._handle(zc, type_, name)

        def remove_service(self, zc, type_, name):
            pass

    zc = Zeroconf()
    try:
        types = ZeroconfServiceTypes.find(zc=zc, timeout=max(1.0, duration / 2))
        browsers = [ServiceBrowser(zc, t, Listener()) for t in types]
        time.sleep(max(1.0, duration / 2))
        for b in browsers:
            b.cancel()
    finally:
        zc.close()

    return {ip: {"services": sorted(v["services"]), "names": sorted(v["names"]),
                 "txt": v["txt"]} for ip, v in found.items()}
