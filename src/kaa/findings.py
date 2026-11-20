"""Deterministic findings. Severity is decided here, never by the AI layer.

Wording lives in ``texts.py`` (English and French); this module decides *what* is wrong.
"""

from __future__ import annotations

from typing import Any

from . import texts
from .exposure import RISKY as exposure_risky
from .models import FindingSpec

# open port -> (rule id, severity)
PORT_RULES: dict[int, tuple[str, str]] = {
    23: ("KAA-PORT-TELNET", "high"), 21: ("KAA-PORT-FTP", "medium"),
    3389: ("KAA-PORT-RDP", "high"), 5900: ("KAA-PORT-VNC", "medium"),
    554: ("KAA-PORT-RTSP", "low"), 1883: ("KAA-PORT-MQTT", "low"),
}
IOT_CLASSES = {"camera", "lock", "appliance", "iot", "plug", "light", "sensor", "thermostat", "hub", "car"}
PEOPLE_CLASSES = {"computer", "phone", "tablet", "wearable"}
WEAK_WIFI = {"open", "wep", "wpa"}
FLAP_DROPS = 4              # disconnections within one hour
CRITICAL_OFFLINE_MIN = 15   # minutes before a critical device is reported missing
FIRMWARE_DAYS = 180         # days before a critical device is due a firmware check


def _facts(d: dict) -> dict[str, Any]:
    return d.get("facts", {})


def _spec(did: int | None, rule: str, severity: str, name: str, evidence: dict) -> FindingSpec:
    title, detail, fix = texts.render("en", rule, name, evidence)  # type: ignore[misc]
    return FindingSpec(did, rule, severity, title, detail, fix, evidence)


def evaluate(devices: list[dict], ctx: dict[str, Any]) -> list[FindingSpec]:
    """``devices`` carry a ``facts`` dict. ``ctx`` keys: baseline_at, scanned_ids,
    gateway_alert, flaps, offline_min."""
    specs: list[FindingSpec] = []
    baseline = ctx.get("baseline_at")
    scanned: set[int] = set(ctx.get("scanned_ids", ()))

    for d in devices:
        f = _facts(d)
        name = d.get("label") or d.get("hostname") or d.get("vendor") or d["mac"]
        did = d["id"]

        if baseline and d["first_seen"] > baseline and d["trust"] == "unknown":
            specs.append(_spec(did, "KAA-NEW-DEVICE", "medium", name,
                               {"mac": d["mac"], "ip": d["ip"], "first_seen": d["first_seen"]}))

        drops = int(ctx.get("flaps", {}).get(did, 0))
        if drops >= FLAP_DROPS and d["trust"] != "guest":
            specs.append(_spec(did, "KAA-FLAPPING", "low", name, {"drops_last_hour": drops}))

        minutes = ctx.get("offline_min", {}).get(did)
        if d.get("critical") == 1 and minutes is not None and minutes >= CRITICAL_OFFLINE_MIN:
            specs.append(_spec(did, "KAA-CRITICAL-OFFLINE", "high", name, {"minutes": int(minutes)}))

        if d["randomized"] and d["trust"] == "unknown":
            specs.append(_spec(did, "KAA-RANDOM-MAC", "info", name, {"mac": d["mac"]}))

        if d["class"] == "unknown" and d["trust"] == "unknown" and not d["randomized"]:
            specs.append(_spec(did, "KAA-UNIDENTIFIED", "low", name,
                               {"mac": d["mac"], "vendor": d.get("vendor")}))

        if did in scanned:
            ports = set(f.get("open_ports", []))
            for port, (rid, sev) in PORT_RULES.items():
                if port in ports:
                    specs.append(_spec(did, rid, sev, name, {
                        "port": port, "open_ports": sorted(ports), "method": "tcp connect"}))
            base = f.get("ports_baseline")
            fresh = sorted(ports - set(base)) if base is not None else []
            if fresh:
                high = any(PORT_RULES.get(p, ("", ""))[1] == "high" for p in fresh)
                specs.append(_spec(did, "KAA-PORT-NEW", "high" if high else "medium", name, {
                    "ports": ", ".join(str(p) for p in fresh), "count": len(fresh), "open_ports": sorted(ports)}))
            if f.get("is_gateway") and 80 in ports and 443 not in ports:
                specs.append(_spec(did, "KAA-GW-HTTP", "low", name, {"open_ports": sorted(ports)}))
            if d["class"] == "lock" and ports:
                specs.append(_spec(did, "KAA-LOCK-EXPOSED", "high", name,
                                   {"open_ports": sorted(ports)}))
            if d["class"] == "camera" and 80 in ports and 443 not in ports:
                specs.append(_spec(did, "KAA-CAMERA-HTTP", "medium", name,
                                   {"open_ports": sorted(ports)}))
            if f.get("probe_tls_expired"):
                specs.append(_spec(did, "KAA-TLS-EXPIRED", "medium", name,
                                   {"expired": str(f["probe_tls_expired"])}))
            if f.get("probe_ftp_anon"):
                specs.append(_spec(did, "KAA-FTP-ANON", "high", name, {"port": 21}))

        age = ctx.get("firmware_age", {}).get(did)
        if age is not None and age >= FIRMWARE_DAYS:
            specs.append(_spec(did, "KAA-FIRMWARE-CHECK", "low", name, {"days": int(age)}))

        if f.get("is_gateway") and any("InternetGatewayDevice" in s for s in f.get("ssdp_st", [])):
            specs.append(_spec(did, "KAA-UPNP-IGD", "medium", name, {
                "ssdp_st": [s for s in f.get("ssdp_st", []) if "Gateway" in s],
                "server": f.get("ssdp_server")}))

    iot = [d for d in devices if d["class"] in IOT_CLASSES and d["trust"] != "guest"]
    people = [d for d in devices if d["class"] in PEOPLE_CLASSES and d["trust"] != "guest"]
    if len(iot) >= 3 and people:
        names = ", ".join(sorted({(d.get("label") or d.get("hostname") or d["mac"]) for d in iot})[:5])
        specs.append(_spec(None, "KAA-NO-SEGMENTATION", "low", "",
                           {"iot": len(iot), "people": len(people), "names": names}))

    wifi = ctx.get("wifi") or {}
    if wifi.get("mode") in WEAK_WIFI:
        specs.append(_spec(None, "KAA-WIFI-WEAK", "high", "", {"mode": wifi.get("label") or wifi["mode"]}))

    by_id = {d["id"]: d for d in devices}
    for did, k in (ctx.get("kev") or {}).items():
        d = by_id.get(did)
        if d:
            name = d.get("label") or d.get("hostname") or d.get("vendor") or d["mac"]
            specs.append(_spec(did, "KAA-KEV-MODEL", "high" if k.get("ransomware") else "medium", name, k))

    ex = ctx.get("exposure") or {}
    if ex.get("ports"):
        risky = [p for p in ex["ports"] if p in exposure_risky]
        specs.append(_spec(None, "KAA-EXPOSED-PORTS", "high" if risky else "medium", "",
                           {"ports": ", ".join(str(p) for p in ex["ports"]), "count": len(ex["ports"])}))
    if ex.get("vulns"):
        specs.append(_spec(None, "KAA-EXPOSED-VULNS", "high", "",
                           {"cves": ", ".join(ex["vulns"][:5]), "count": len(ex["vulns"])}))

    cloud = ctx.get("cloud") or []
    low = sorted({c["name"] or c["kind"] for c in cloud if c.get("battery") == "low"})
    if low:
        specs.append(_spec(None, "KAA-CLOUD-BATTERY", "low", "", {"names": ", ".join(low), "count": len(low)}))
    gone = sorted({c["name"] or c["kind"] for c in cloud if c.get("reachable") is False})
    if gone:
        specs.append(_spec(None, "KAA-CLOUD-OFFLINE", "low", "", {"names": ", ".join(gone), "count": len(gone)}))

    alert = ctx.get("gateway_alert")
    if alert:
        specs.append(_spec(alert.get("device_id"), "KAA-GATEWAY-MAC-CHANGED", "high", "", alert))
    return specs
