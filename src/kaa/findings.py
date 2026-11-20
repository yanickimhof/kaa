"""Deterministic findings. Severity is decided here, never by the AI layer."""

from __future__ import annotations

from typing import Any

from .models import FindingSpec

PORT_RULES: dict[int, tuple[str, str, str, str, str]] = {
    23: ("KAA-PORT-TELNET", "high", "Telnet is open",
         "Telnet sends logins in clear text and is a classic entry point for IoT malware.",
         "Turn Telnet off in the device settings. Use SSH if remote access is needed."),
    21: ("KAA-PORT-FTP", "medium", "FTP is open",
         "FTP transmits credentials and files without encryption.",
         "Disable FTP or replace it with SFTP. Restrict access to trusted devices."),
    3389: ("KAA-PORT-RDP", "high", "Remote Desktop (RDP) is open",
           "RDP is heavily targeted by brute force and exploits.",
           "Disable RDP if unused. Otherwise require network level authentication and a VPN."),
    5900: ("KAA-PORT-VNC", "medium", "VNC screen sharing is open",
           "VNC is often protected by a weak password and has no encryption by default.",
           "Turn off screen sharing if unused, or set a strong password and tunnel it."),
    554: ("KAA-PORT-RTSP", "low", "Video stream port (RTSP) is open",
          "Cameras exposing RTSP sometimes serve their stream without a password.",
          "Check that the stream asks for credentials and that the camera has no default password."),
    1883: ("KAA-PORT-MQTT", "low", "MQTT broker without TLS is reachable",
           "Plain MQTT carries data and commands in clear text, sometimes with no login.",
           "Require authentication and move to MQTT over TLS (port 8883)."),
}


def _facts(d: dict) -> dict[str, Any]:
    return d.get("facts", {})


def evaluate(devices: list[dict], ctx: dict[str, Any]) -> list[FindingSpec]:
    """``devices`` carry a ``facts`` dict. ``ctx`` keys: baseline_at, scanned_ids,
    gateway_alert."""
    specs: list[FindingSpec] = []
    baseline = ctx.get("baseline_at")
    scanned: set[int] = set(ctx.get("scanned_ids", ()))

    for d in devices:
        f = _facts(d)
        name = d.get("label") or d.get("hostname") or d.get("vendor") or d["mac"]
        did = d["id"]

        if baseline and d["first_seen"] > baseline and d["trust"] == "unknown":
            specs.append(FindingSpec(
                did, "KAA-NEW-DEVICE", "medium", f"New device joined: {name}",
                "A device that was not present at the first scan appeared on your network.",
                "If you recognise it, mark it Known. If not, change your Wi-Fi password "
                "and review your router's client list.",
                {"mac": d["mac"], "ip": d["ip"], "first_seen": d["first_seen"]}))

        if d["randomized"] and d["trust"] == "unknown":
            specs.append(FindingSpec(
                did, "KAA-RANDOM-MAC", "info", f"Private Wi-Fi address: {name}",
                "This device uses a randomised MAC address, a privacy feature of modern "
                "phones and laptops. It cannot be recognised by vendor.",
                "Mark it Known once you have identified the owner.",
                {"mac": d["mac"]}))

        if d["class"] == "unknown" and d["trust"] == "unknown" and not d["randomized"]:
            specs.append(FindingSpec(
                did, "KAA-UNIDENTIFIED", "low", f"Unidentified device: {name}",
                "Kaa could not tell what this device is from its vendor and services.",
                "Check the IP in your router, then label it so it is tracked from now on.",
                {"mac": d["mac"], "vendor": d.get("vendor")}))

        if did in scanned:
            ports = set(f.get("open_ports", []))
            for port, (rid, sev, title, detail, fix) in PORT_RULES.items():
                if port in ports:
                    specs.append(FindingSpec(
                        did, rid, sev, f"{title} on {name}", detail, fix,
                        {"port": port, "open_ports": sorted(ports),
                         "method": "tcp connect"}))
            if f.get("is_gateway") and 80 in ports and 443 not in ports:
                specs.append(FindingSpec(
                    did, "KAA-GW-HTTP", "low", "Router admin page has no HTTPS",
                    "The gateway serves its admin interface over plain HTTP only.",
                    "Enable HTTPS for the admin interface if your router supports it.",
                    {"open_ports": sorted(ports)}))

        if f.get("is_gateway") and any("InternetGatewayDevice" in s
                                       for s in f.get("ssdp_st", [])):
            specs.append(FindingSpec(
                did, "KAA-UPNP-IGD", "medium", "UPnP is enabled on your router",
                "UPnP lets any device on the network open ports to the Internet "
                "without asking you.",
                "Disable UPnP in the router settings, then forward ports manually "
                "only if something breaks.",
                {"ssdp_st": [s for s in f.get("ssdp_st", []) if "Gateway" in s],
                 "server": f.get("ssdp_server")}))

    alert = ctx.get("gateway_alert")
    if alert:
        gid = alert.get("device_id")
        specs.append(FindingSpec(
            gid, "KAA-GATEWAY-MAC-CHANGED", "high", "Your router's hardware address changed",
            "The device answering as your gateway now has a different MAC address. "
            "This happens when the router is replaced, and in ARP spoofing attacks.",
            "If you did not swap your router, treat this as an attack: disconnect "
            "unknown devices and check the router. If you did, acknowledge to accept.",
            alert))
    return specs
