"""Transparent health score: 100 minus capped penalties per severity.

Acknowledging a finding records that you accept the risk; it does not make the risk
smaller, so it keeps costing points and is reported separately as ``accepted``.
"""

from __future__ import annotations

PENALTY = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 0}
CAP = {"critical": 75, "high": 45, "medium": 32, "low": 12, "info": 0}


def grade(value: int, any_issue: bool = True) -> tuple[str, str]:
    """(id, English label). The interface translates the id."""
    if value >= 90 and not any_issue:
        return "clear", "No known issue"
    if value >= 90:
        return "very_good", "Very good"
    if value >= 75:
        return "good", "Good"
    if value >= 50:
        return "attention", "Needs attention"
    return "risk", "At risk"


def compute(findings: list[dict]) -> dict:
    counts = {s: 0 for s in PENALTY}
    accepted = 0
    for f in findings:
        if f["status"] == "open":
            counts[f["severity"]] += 1
        if f["status"] == "ack" and f["severity"] != "info":
            accepted += 1
    penalised = dict(counts)
    for f in findings:
        if f["status"] == "ack":
            penalised[f["severity"]] += 1
    points = {s: min(CAP[s], penalised[s] * PENALTY[s]) for s in PENALTY}
    value = max(0, 100 - sum(points.values()))
    gid, label = grade(value, any(n for s, n in penalised.items() if s != "info"))
    return {"value": value, "grade": label, "grade_id": gid, "counts": counts,
            "accepted": accepted, "points": points}
