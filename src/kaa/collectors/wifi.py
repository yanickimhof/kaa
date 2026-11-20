"""Wi-Fi encryption of the network this Mac is on (macOS, read only, nothing is sent)."""

from __future__ import annotations

import json
import subprocess
import sys

LABELS = {"open": "Open (no encryption)", "wep": "WEP", "wpa": "WPA", "wpa2": "WPA2", "wpa3": "WPA3"}


def classify(raw: str) -> dict | None:
    """Map a macOS security string to {"mode", "label"}; None when it is not understood."""
    s = (raw or "").lower()
    if "wpa3" in s:
        mode = "wpa3"
    elif "wpa2" in s:
        mode = "wpa2"
    elif "owe" in s:
        mode = "wpa3"  # enhanced open: encrypted
    elif "wep" in s:
        mode = "wep"
    elif "none" in s or s.endswith("_open"):
        mode = "open"
    elif "wpa" in s:
        mode = "wpa"
    else:
        return None
    label = LABELS[mode]
    if "transition" in s:
        label += " (transition)"
    elif "personal" in s and mode in ("wpa2", "wpa3"):
        label += " Personal"
    elif "enterprise" in s:
        label += " Enterprise"
    return {"mode": mode, "label": label}


def security(timeout: float = 25.0) -> dict | None:
    """The current Wi-Fi security, or None (not macOS, no Wi-Fi, or not connected)."""
    if sys.platform != "darwin":
        return None
    try:
        out = subprocess.run(["/usr/sbin/system_profiler", "SPAirPortDataType", "-json"],
                             capture_output=True, text=True, timeout=timeout, check=False).stdout
        data = json.loads(out)
    except (OSError, ValueError, subprocess.SubprocessError):
        return None
    for block in data.get("SPAirPortDataType", []):
        for iface in block.get("spairport_airport_interfaces", []):
            cur = iface.get("spairport_current_network_information")
            if isinstance(cur, dict) and cur.get("spairport_security_mode"):
                return classify(str(cur["spairport_security_mode"]))
    return None
