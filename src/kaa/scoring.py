"""Transparent health score: 100 minus capped penalties per severity."""

from __future__ import annotations

PENALTY = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 0}
CAP = {"critical": 75, "high": 45, "medium": 32, "low": 12, "info": 0}


def grade(value: int) -> str:
    if value >= 90:
        return "Excellent"
    if value >= 75:
        return "Good"
    if value >= 50:
        return "Needs attention"
    return "At risk"


def compute(findings: list[dict]) -> dict:
    """Only open findings count. Acknowledged ones are accepted risk."""
    counts = {s: 0 for s in PENALTY}
    for f in findings:
        if f["status"] == "open":
            counts[f["severity"]] += 1
    points = {s: min(CAP[s], counts[s] * PENALTY[s]) for s in PENALTY}
    value = max(0, 100 - sum(points.values()))
    return {"value": value, "grade": grade(value), "counts": counts, "points": points}
