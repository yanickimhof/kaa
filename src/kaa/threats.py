"""Threat watch: which actively exploited vulnerabilities concern *your* devices.

Source: the CISA Known Exploited Vulnerabilities (KEV) catalogue, a public JSON
file. Opt in (``[threats] enabled = true``): Kaa then downloads that one file about
once a day. Nothing about your network is sent; the matching happens locally
against the vendors and names of the devices Kaa has found.
"""

from __future__ import annotations

import datetime as dt
import json
import re
import urllib.request
from pathlib import Path
from typing import Any

FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
MAX_BYTES = 20 * 1024 * 1024
NOISE = {"inc", "ltd", "llc", "gmbh", "corp", "corporation", "co", "company", "technologies",
         "technology", "systems", "electronics", "communications", "communication", "group",
         "international", "limited", "the", "and", "devices", "device", "laboratories",
         "silicon", "private", "address", "registration", "authority", "ieee", "unknown"}
# words that say what a device is, not which product it is: never enough to match
GENERIC = {"router", "camera", "lock", "switch", "bridge", "home", "smart", "hub", "light", "sensor",
           "printer", "series", "office", "room", "mac", "linux", "upnp", "http", "wifi", "wireless",
           "firmware", "gateway", "server", "client", "network", "module", "web", "multiple", "products",
           "product", "software", "android", "windows", "local", "internet", "access", "point", "mini",
           "pro", "plus", "air", "max", "the", "sdk", "dev"}
# vendor names as CISA writes them, for brands whose registry name differs
ALIASES = {"apple": {"apple"}, "amazon": {"amazon"}, "google": {"google"}, "eero": {"eero"},
           "espressif": {"espressif"}, "netatmo": {"netatmo", "legrand"},
           "logitech": {"logitech"}, "samsung": {"samsung"}, "tp-link": {"tp-link", "tplink"},
           "asus": {"asus", "asustek"}, "netgear": {"netgear"}, "d-link": {"d-link", "dlink"},
           "tado": {"tado"}, "nuki": {"nuki"}, "electrolux": {"electrolux"}, "epson": {"epson", "seiko"}}


def download(path: Path) -> int:
    from .oui import ssl_context

    req = urllib.request.Request(FEED_URL, headers={"User-Agent": "kaa-threat-watch"})
    with urllib.request.urlopen(req, timeout=30, context=ssl_context()) as resp:  # noqa: S310
        data = resp.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("feed larger than expected")
    json.loads(data)  # refuse anything that is not valid JSON
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_bytes(data)
    tmp.replace(path)
    return len(data)


def load(path: Path) -> list[dict[str, Any]]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    items = raw.get("vulnerabilities", []) if isinstance(raw, dict) else []
    return [v for v in items if isinstance(v, dict)]


def _tokens(text: str) -> set[str]:
    return {t for t in re.split(r"[^a-z0-9]+", (text or "").lower()) if len(t) >= 3}


def _expand(keys: set[str]) -> set[str]:
    out = set(keys)
    for t in keys:
        out |= ALIASES.get(t, set())
    return out


def device_keys(device: dict, extra: list[str] | None = None) -> set[str]:
    """Vendor words for one device, without corporate noise words."""
    return _expand({t for t in _tokens(device.get("vendor") or "") if t not in NOISE})


def profile(d: dict, obs: dict | None = None) -> dict:
    """What Kaa knows about the exact product: model words, and the firmware when known."""
    obs = obs or {}
    models = [str(m) for m in (obs.get("cloud.model"), obs.get("ssdp.server"), d.get("hostname"),
                               *(obs.get("mdns.names") or [])) if m]
    keys: set[str] = set()
    for m in models:
        keys |= _tokens(m)
    keys -= NOISE | GENERIC
    # the brand can also come from the model ("Nuki Smart Lock") or the hostname ("tado-IB23...")
    brand = {t for t in _tokens(str(obs.get("cloud.model") or "")) if t not in NOISE | GENERIC}
    host = re.split(r"[^a-z0-9]+", (d.get("hostname") or "").lower())[0]
    if len(host) >= 3 and host not in NOISE | GENERIC:
        brand.add(host)
    return {"model_keys": keys, "vendor_keys": _expand(brand), "model": str(obs.get("cloud.model") or ""),
            "firmware": str(obs.get("cloud.firmware") or "")}


def _model_hit(product: set[str], vendor: set[str], keys: set[str], vkeys: set[str]) -> bool:
    shared = (product - NOISE - GENERIC) & keys
    if not shared:
        return False
    # a model number such as "rt-ac66u" is distinctive by itself; a plain word needs the vendor too
    return bool(vkeys & vendor) or any(len(t) >= 4 and any(c.isdigit() for c in t) for t in shared)


def match(entries: list[dict], devices: list[dict], keywords: list[str] | None = None,
          days: int = 365, limit: int = 30, today: dt.date | None = None,
          profiles: dict[Any, dict] | None = None) -> list[dict]:
    """Entries that concern a device. A *model* match (product words found in the device's
    model, hostname or UPnP banner) is kept for three years: without the firmware version the
    safe reading is "check it". A *vendor* match is kept for ``days``."""
    today = today or dt.date.today()
    oldest = (today - dt.timedelta(days=days)).isoformat()
    oldest_model = (today - dt.timedelta(days=days * 3)).isoformat()
    profiles = profiles or {}
    per_device = []
    for d in devices:
        pr = profiles.get(d.get("id") if d.get("id") is not None else d.get("mac"), {})
        per_device.append((d, device_keys(d) | pr.get("vendor_keys", set()), pr.get("model_keys", set()), pr))
    extra = {k.lower() for k in (keywords or []) if k.strip()}
    name_of = lambda d: (d.get("label") or d.get("hostname") or d.get("vendor") or d["mac"])  # noqa: E731
    out = []
    for e in entries:
        added = str(e.get("dateAdded", ""))
        if added < oldest_model:
            continue
        vendor = _tokens(str(e.get("vendorProject", "")))
        product = _tokens(str(e.get("product", "")))
        by_model = [(d, pr) for d, vk, mk, pr in per_device if mk and _model_hit(product, vendor, mk, vk)]
        by_vendor = [d for d, vk, _, _ in per_device if vk and vk & (vendor | product)] if added >= oldest else []
        extra_hit = sorted(k for k in extra if k in vendor or k in product
                           or k in str(e.get("vendorProject", "")).lower()) if added >= oldest else []
        if not by_model and not by_vendor and not extra_hit:
            continue
        hit = [d for d, _ in by_model] + [d for d in by_vendor if d not in [x for x, _ in by_model]]
        out.append({
            "cve": e.get("cveID", ""), "vendor": e.get("vendorProject", ""),
            "product": e.get("product", ""), "name": e.get("vulnerabilityName", ""),
            "summary": e.get("shortDescription", ""), "action": e.get("requiredAction", ""),
            "added": added, "due": e.get("dueDate", ""),
            "ransomware": str(e.get("knownRansomwareCampaignUse", "")).lower() == "known",
            "match": "model" if by_model else "vendor",
            "devices": list(dict.fromkeys(name_of(d) for d in hit))[:6],
            "device_ids": [d["id"] for d, _ in by_model if d.get("id") is not None],
            "models": [{"device": name_of(d), "model": pr.get("model", ""), "firmware": pr.get("firmware", "")}
                       for d, pr in by_model][:6],
            "keywords": extra_hit,
        })
    out.sort(key=lambda x: (x["match"] != "model", -int(x["added"].replace("-", "") or 0)))
    return out[:limit]
