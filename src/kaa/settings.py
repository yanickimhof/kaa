"""Settings that can be changed from the web app, stored in ``config.toml``."""

from __future__ import annotations

import re
import tomllib
from typing import Any

from .config import Config

CLOCK = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")

# name -> (section, key, kind)
FIELDS: dict[str, tuple[str, str, str]] = {
    "notify": ("notify", "enabled", "bool"),
    "digest_hour": ("notify", "digest_hour", "hour"),
    "quiet_start": ("notify", "quiet_start", "clock"),
    "wake_weekday": ("notify", "wake_weekday", "clock"),
    "wake_weekend": ("notify", "wake_weekend", "clock"),
    "interval": ("scan", "interval", "interval"),
    "portscan": ("scan", "portscan", "bool"),
    "lang": ("ui", "lang", "lang"),
    "threats": ("threats", "enabled", "bool"),
    "exposure": ("exposure", "enabled", "bool"),
    "threat_keywords": ("threats", "keywords", "words"),
}
ATTR = {"notify": "notify", "digest_hour": "digest_hour", "quiet_start": "quiet_start",
        "wake_weekday": "wake_weekday", "wake_weekend": "wake_weekend",
        "interval": "interval", "portscan": "portscan", "lang": "lang", "threats": "threats", "exposure": "exposure",
        "threat_keywords": "threat_keywords"}


class SettingsError(ValueError):
    pass


def to_dict(cfg: Config) -> dict[str, Any]:
    out = {k: getattr(cfg, a) for k, a in ATTR.items()}
    out["ai"] = {"enabled": cfg.ai_enabled, "endpoint": cfg.ai_endpoint, "model": cfg.ai_model}
    out["network"] = {"scope": cfg.networks or ["auto"], "host": cfg.host, "port": cfg.port}
    return out


def _clean(kind: str, value: Any) -> Any:
    if kind == "bool":
        if not isinstance(value, bool):
            raise SettingsError("expected true or false")
        return value
    if kind == "hour":
        if not isinstance(value, int) or isinstance(value, bool) or not -1 <= value <= 23:
            raise SettingsError("hour must be -1 (off) or 0 to 23")
        return value
    if kind == "interval":
        if not isinstance(value, int) or isinstance(value, bool) or not 60 <= value <= 86400:
            raise SettingsError("interval must be 60 to 86400 seconds")
        return value
    if kind == "clock":
        if not isinstance(value, str) or not CLOCK.match(value):
            raise SettingsError("time must look like 07:30")
        return value
    if kind == "lang":
        if value not in ("fr", "en"):
            raise SettingsError("language must be fr or en")
        return value
    if kind == "words":
        if not isinstance(value, list) or len(value) > 30:
            raise SettingsError("expected a short list of words")
        words = [str(w).strip().lower()[:40] for w in value if str(w).strip()]
        return words
    raise SettingsError("unknown setting")  # pragma: no cover


def apply(cfg: Config, updates: dict[str, Any]) -> dict[str, Any]:
    """Validate and apply; returns what changed. Unknown names are refused."""
    unknown = set(updates) - set(FIELDS)
    if unknown:
        raise SettingsError(f"unknown setting: {sorted(unknown)[0]}")
    cleaned = {name: _clean(FIELDS[name][2], v) for name, v in updates.items()}
    for name, v in cleaned.items():
        setattr(cfg, ATTR[name], v)
    return cleaned


# ---- minimal TOML writer (the stdlib only reads TOML) -------------------
def _lit(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    if isinstance(v, list):
        return "[" + ", ".join(_lit(x) for x in v) + "]"
    s = str(v).replace("\\", "\\\\").replace('"', '\\"')
    s = "".join(c if c >= " " and c != "\x7f" else f"\\u{ord(c):04x}" for c in s)
    return f'"{s}"'


def dumps(data: dict[str, dict[str, Any]]) -> str:
    out = []
    for section, table in data.items():
        out.append(f"[{section}]")
        out.extend(f"{k} = {_lit(v)}" for k, v in table.items())
        out.append("")
    return "\n".join(out)


def save(cfg: Config, names: list[str]) -> None:
    """Write the given settings into config.toml, keeping every other key."""
    path = cfg.home / "config.toml"
    raw: dict[str, dict[str, Any]] = {}
    if path.exists():
        with path.open("rb") as fh:
            raw = {k: dict(v) for k, v in tomllib.load(fh).items() if isinstance(v, dict)}
    for name in names:
        section, key, _kind = FIELDS[name]
        raw.setdefault(section, {})[key] = getattr(cfg, ATTR[name])
    tmp = path.with_suffix(".tmp")
    tmp.write_text(dumps(raw), encoding="utf-8")
    tmp.replace(path)
