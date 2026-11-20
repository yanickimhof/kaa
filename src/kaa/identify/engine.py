"""Deterministic device identification from signature files.

Signatures are plain YAML data (see ``src/kaa/data/signatures``). Each match
returns its evidence so every classification can be audited. Independent
rules that agree on a class reinforce each other (noisy-or).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from ..models import CLASSES

MAX_CONF = 0.98


@dataclass(frozen=True)
class Rule:
    id: str
    cls: str
    label: str
    confidence: float
    when: dict[str, dict[str, Any]]


def load_rules(*dirs: Path) -> list[Rule]:
    rules: list[Rule] = []
    for d in dirs:
        if not d or not d.exists():
            continue
        for path in sorted(d.glob("*.yaml")):
            raw = yaml.safe_load(path.read_text(encoding="utf-8")) or []
            for item in raw:
                if item["class"] not in CLASSES:
                    raise ValueError(f"{path.name}: unknown class {item['class']!r}")
                conf = float(item["confidence"])
                if not 0 < conf <= 1:
                    raise ValueError(f"{path.name}: bad confidence in {item['id']}")
                rules.append(Rule(item["id"], item["class"], item.get("label", item["class"]),
                                  conf, item["when"]))
    return rules


def _as_list(v: Any) -> list:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def _check(fact: Any, op: str, expected: Any) -> bool:
    if op == "is_true":
        return bool(fact) is bool(expected)
    if fact in (None, "", []):
        return False
    if op == "equals":
        return str(fact).lower() == str(expected).lower()
    if op == "contains":
        return str(expected).lower() in str(fact).lower()
    if op == "regex":
        return re.search(str(expected), str(fact), re.I) is not None
    if op == "has":
        return str(expected).lower() in {str(x).lower() for x in _as_list(fact)}
    if op == "has_any":
        have = {str(x).lower() for x in _as_list(fact)}
        return any(str(e).lower() in have for e in _as_list(expected))
    if op == "has_contains":
        return any(str(expected).lower() in str(x).lower() for x in _as_list(fact))
    raise ValueError(f"unknown operator {op!r}")


def match_rule(rule: Rule, facts: dict[str, Any]) -> dict[str, Any] | None:
    matched: dict[str, Any] = {}
    for field_name, pred in rule.when.items():
        fact = facts.get(field_name)
        for op, expected in pred.items():
            if not _check(fact, op, expected):
                return None
        matched[field_name] = fact
    return matched


def classify(facts: dict[str, Any], rules: list[Rule]) -> tuple[str, float, list[dict]]:
    per_class: dict[str, list[tuple[Rule, dict]]] = {}
    for rule in rules:
        hit = match_rule(rule, facts)
        if hit is not None:
            per_class.setdefault(rule.cls, []).append((rule, hit))
    if not per_class:
        return "unknown", 0.0, []

    def combined(hits: list[tuple[Rule, dict]]) -> float:
        miss = 1.0
        for r, _ in hits:
            miss *= 1 - r.confidence
        return min(MAX_CONF, 1 - miss)

    best_cls = max(per_class, key=lambda c: combined(per_class[c]))
    hits = sorted(per_class[best_cls], key=lambda h: -h[0].confidence)
    evidence = [{"rule": r.id, "label": r.label, "confidence": r.confidence,
                 "matched": {k: v for k, v in m.items()}} for r, m in hits]
    return best_cls, round(combined(hits), 3), evidence
