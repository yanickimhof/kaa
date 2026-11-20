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
import urllib.error
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
    if urlparse(endpoint).scheme not in ("http", "https"):
        raise AIConfigError("AI endpoint must start with http:// or https://")
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


def complete(system: str, user: str, endpoint: str, model: str, provider: str = "openai",
             key: str = "", allow_remote: bool = False, max_tokens: int = 700,
             timeout: float = 60.0) -> str:
    """One model call. Anthropic Messages API or any OpenAI compatible server."""
    check_endpoint(endpoint, allow_remote)
    base = endpoint.rstrip("/")
    if provider == "anthropic":
        url = base + "/messages"
        headers = {"Content-Type": "application/json", "x-api-key": key,
                   "anthropic-version": "2023-06-01"}
        body = {"model": model, "max_tokens": max_tokens,
                "system": system, "messages": [{"role": "user", "content": user}]}
    else:
        url = base + "/chat/completions"
        headers = {"Content-Type": "application/json"}
        if key:
            headers["Authorization"] = "Bearer " + key
        body = {"model": model or "local", "temperature": 0, "max_tokens": max_tokens,
                "messages": [{"role": "system", "content": system},
                             {"role": "user", "content": user}]}
    def send(payload: dict) -> dict:
        req = urllib.request.Request(url, data=json.dumps(payload).encode(), headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
                return json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            detail = exc.read(600).decode("utf-8", "replace")
            try:
                detail = json.loads(detail)["error"]["message"]
            except (ValueError, KeyError, TypeError):
                pass
            raise ValueError(f"HTTP {exc.code}: {detail}") from exc

    if provider == "anthropic":
        # Recent models "think" by default and thinking eats the token budget: a short answer
        # can then come back empty. These answers need no reasoning, so ask for none.
        try:
            data = send({**body, "thinking": {"type": "disabled"}})
        except ValueError as exc:
            if "thinking" not in str(exc).lower():
                raise
            data = send(body)  # an older model that does not know the option
        text = "".join(b.get("text", "") for b in data.get("content", []) if b.get("type") == "text")
        if not text.strip() and data.get("stop_reason") == "max_tokens":
            raise ValueError("the answer was cut off before any text; try again")
        return text
    data = send(body)
    return data["choices"][0]["message"]["content"]


def resolve(facts: dict[str, Any], endpoint: str, model: str,
            allow_remote: bool = False, timeout: float = 60.0,
            provider: str = "openai", key: str = ""
            ) -> tuple[str, float, list[dict]] | None:
    payload = payload_for(facts)
    if not payload:
        return None
    text = complete(PROMPT, json.dumps(payload), endpoint, model, provider, key,
                    allow_remote, 300, timeout)
    parsed = parse_answer(text)
    if not parsed:
        return None
    cls, conf, reason = parsed
    evidence = [{"rule": "ai-hypothesis", "label": "AI hypothesis",
                 "confidence": conf, "matched": payload, "reason": reason}]
    return cls, conf, evidence
