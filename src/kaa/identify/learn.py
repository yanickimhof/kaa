"""Learn from manual corrections: turn one fix into a rule that fits similar devices."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

import yaml

FILE = "learned.yaml"
HOST_CONF = 0.8     # same hostname family: strong
VENDOR_CONF = 0.55  # same vendor only: weak, easily outvoted by real evidence


def hostname_stem(hostname: str | None) -> str | None:
    """``eero-living-room`` -> ``eero``; ``Shelly1-A4CF12`` -> ``shelly``; too short -> None."""
    if not hostname:
        return None
    h = re.sub(r"\.(local|lan|home)$", "", hostname.strip().lower())
    h = re.sub(r"[-_ ]?[0-9a-f]{4,}$", "", h)       # trailing hardware id
    h = re.sub(r"[-_ ]?\d+$", "", h)                # trailing counter
    h = re.split(r"[-_ ]", h)[0] if "-" in h or "_" in h else h
    return h if len(h) >= 4 else None


def build_rule(cls: str, facts: dict[str, Any]) -> dict | None:
    stem = hostname_stem(facts.get("hostname"))
    vendor = facts.get("vendor")
    if stem:
        when, conf, why = {"hostname": {"regex": "^" + re.escape(stem)}}, HOST_CONF, f"name starts with {stem}"
    elif vendor and not facts.get("randomized_mac"):
        when, conf, why = {"vendor": {"equals": vendor}}, VENDOR_CONF, f"vendor {vendor}"
    else:
        return None
    key = hashlib.sha1(repr((cls, sorted(when.items()))).encode()).hexdigest()[:8]
    return {"id": f"learned-{key}", "class": cls, "label": f"Learned from you ({why})",
            "confidence": conf, "when": when}


def remember(directory: Path, rule: dict) -> bool:
    """Append the rule unless an identical one exists. Returns True when added."""
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / FILE
    rules = yaml.safe_load(path.read_text(encoding="utf-8")) if path.exists() else []
    rules = [r for r in (rules or []) if isinstance(r, dict)]
    rules = [r for r in rules if r["id"] != rule["id"]]
    # a newer correction for the same condition replaces the older one
    rules = [r for r in rules if r["when"] != rule["when"]]
    rules.append(rule)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(yaml.safe_dump(rules, sort_keys=False, allow_unicode=True), encoding="utf-8")
    tmp.replace(path)
    return True
