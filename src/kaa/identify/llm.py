"""Optional local AI resolver for devices the signatures cannot name.

Design rules, enforced here and not by prompt alone:

* The model only proposes a device class. It never sets severity or findings.
* The class must belong to the closed list in ``CLASSES``.
* Confidence is capped well below the deterministic rules.
* Only coarse metadata is sent (never MAC addresses or IPs).
* The endpoint must be loopback unless the user explicitly allows otherwise.
"""

from __future__ import annotations

import hashlib
import json
import re
import urllib.request
from typing import Any
from urllib.parse import urlparse

from ..models import CLASSES

AI_CONF_CAP = 0.7
SENT_FIELDS = ("vendor", "hostname", "mdns_services", "mdns_names", "ssdp_server",
               "ssdp_st", "open_ports")

PROMPT = (
    "You identify devices on a home network from metadata. "
    "Answer with one JSON object only: "
    '{"class": <one of the allowed classes>, "confidence": <0..1>, "reason": <short>}. '
    "If the metadata is not enough, use class \"unknown\". Allowed classes: "
    + ", ".join(CLASSES)
)


class AIConfigError(ValueError):
    pass


def check_endpoint(endpoint: str, allow_remote: bool) -> None:
    host = urlparse(endpoint).hostname or ""
    if host not in {"127.0.0.1", "localhost", "::1"} and not allow_remote:
        raise AIConfigError(
            "AI endpoint is not loopback. Kaa keeps data local; set "
            "ai.allow_remote = true to override."
        )


def payload_for(facts: dict[str, Any]) -> dict[str, Any]:
    return {k: facts[k] for k in SENT_FIELDS if facts.get(k) not in (None, "", [])}


def facts_hash(facts: dict[str, Any]) -> str:
    blob = json.dumps(payload_for(facts), sort_keys=True).encode()
    return hashlib.sha256(blob).hexdigest()[:16]


def parse_answer(text: str) -> tuple[str, float, str] | None:
    m = re.search(r"\{.*\}", text, re.S)
    if not m:
        return None
    try:
        obj = json.loads(m.group(0))
    except json.JSONDecodeError:
        return None
    cls = str(obj.get("class", "")).strip().lower()
    if cls not in CLASSES or cls == "unknown":
        return None
    try:
        conf = float(obj.get("confidence", 0))
    except (TypeError, ValueError):
        return None
    conf = max(0.0, min(AI_CONF_CAP, conf))
    return cls, round(conf, 3), str(obj.get("reason", ""))[:200]


def resolve(facts: dict[str, Any], endpoint: str, model: str,
            allow_remote: bool = False, timeout: float = 60.0
            ) -> tuple[str, float, list[dict]] | None:
    check_endpoint(endpoint, allow_remote)
    payload = payload_for(facts)
    if not payload:
        return None
    body = json.dumps({
        "model": model or "local",
        "temperature": 0,
        "messages": [{"role": "system", "content": PROMPT},
                     {"role": "user", "content": json.dumps(payload)}],
    }).encode()
    req = urllib.request.Request(
        endpoint.rstrip("/") + "/chat/completions", data=body,
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
        data = json.loads(resp.read())
    text = data["choices"][0]["message"]["content"]
    parsed = parse_answer(text)
    if not parsed:
        return None
    cls, conf, reason = parsed
    evidence = [{"rule": "ai-hypothesis", "label": "AI hypothesis (local model)",
                 "confidence": conf, "matched": payload, "reason": reason}]
    return cls, conf, evidence
