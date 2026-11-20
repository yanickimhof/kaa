from __future__ import annotations

from dataclasses import dataclass, field

SEVERITIES = ("critical", "high", "medium", "low", "info")
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}

CLASSES = (
    "router", "access_point", "computer", "phone", "tablet", "tv", "media",
    "speaker", "camera", "printer", "nas", "game_console", "sensor",
    "plug", "light", "thermostat", "car", "hub", "server", "wearable",
    "iot", "lock", "appliance", "unknown",
)

TRUST_LEVELS = ("unknown", "known", "guest")


@dataclass
class FindingSpec:
    device_id: int | None
    rule_id: str
    severity: str
    title: str
    detail: str
    fix: str
    evidence: dict = field(default_factory=dict)

    @property
    def key(self) -> tuple[int, str]:
        return (self.device_id or 0, self.rule_id)
