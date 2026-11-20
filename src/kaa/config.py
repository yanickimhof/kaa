"""Configuration. Nothing is hard coded to a specific network or machine.

Everything lives in one folder (``KAA_HOME`` if set, otherwise the platform
default) and an optional ``config.toml`` inside it.
"""

from __future__ import annotations

import os
import secrets
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}

# Ports probed by the opt-in port scan. Chosen for what matters at home:
# remote admin, file sharing, cameras, printers, brokers and web panels.
DEFAULT_PORTS = [
    21, 22, 23, 53, 80, 139, 443, 445, 554, 631, 1883, 3389,
    5000, 5001, 5900, 8000, 8080, 8443, 8883, 9100,
]


def home_dir() -> Path:
    env = os.environ.get("KAA_HOME")
    if env:
        return Path(env).expanduser()
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "Kaa"
    xdg = os.environ.get("XDG_DATA_HOME")
    base = Path(xdg) if xdg else Path.home() / ".local" / "share"
    return base / "kaa"


@dataclass
class Config:
    home: Path = field(default_factory=home_dir)
    host: str = "127.0.0.1"
    port: int = 8473
    interval: int = 300  # seconds between automatic cycles
    networks: list[str] = field(default_factory=list)  # empty = auto-detect
    max_hosts: int = 1024
    exclude: list[str] = field(default_factory=list)  # IPs or MACs never probed
    sweep: bool = True  # gentle UDP sweep so the ARP table is complete
    portscan: bool = False  # opt-in
    ports: list[int] = field(default_factory=lambda: list(DEFAULT_PORTS))
    mdns_seconds: float = 4.0
    ssdp_seconds: float = 2.5
    ai_enabled: bool = False
    ai_endpoint: str = ""  # OpenAI compatible, for example a local mlx_lm.server
    ai_model: str = ""
    ai_allow_remote: bool = False
    ai_provider: str = "anthropic"  # anthropic (best quality) or openai (any compatible server)
    ai_key: str = ""
    notify: bool = True  # desktop notification for new alerts
    digest_hour: int = 8  # local hour of the daily summary, -1 to disable
    lang: str = "fr"  # interface, alerts and AI answers: fr or en
    exposure: bool = False  # opt in: ask Shodan InternetDB what is open on your public IP
    threats: bool = False  # opt in: download the CISA KEV catalogue once a day
    threat_keywords: list[str] = field(default_factory=list)
    quiet_start: str = "22:00"  # no notification from this time...
    wake_weekday: str = "07:30"  # ...until this time Monday to Friday
    wake_weekend: str = "09:00"  # ...and this time on Saturday and Sunday

    @property
    def db_path(self) -> Path:
        return self.home / "kaa.db"

    @property
    def data_dir(self) -> Path:
        return self.home / "data"

    @property
    def user_signatures(self) -> Path:
        return self.home / "signatures"


def load(home: Path | None = None) -> Config:
    cfg = Config(home=home or home_dir())
    cfg.home.mkdir(parents=True, exist_ok=True)
    try:
        cfg.home.chmod(0o700)  # the inventory of your network is for you only
    except OSError:
        pass
    path = cfg.home / "config.toml"
    if path.exists():
        with path.open("rb") as fh:
            raw = tomllib.load(fh)
        srv = raw.get("server", {})
        scan = raw.get("scan", {})
        ai = raw.get("ai", {})
        nt = raw.get("notify", {})
        th = raw.get("threats", {})
        cfg.lang = raw.get("ui", {}).get("lang", cfg.lang) if raw.get("ui", {}).get("lang") in ("fr", "en") else cfg.lang
        cfg.host = srv.get("host", cfg.host)
        cfg.port = int(srv.get("port", cfg.port))
        cfg.interval = int(scan.get("interval", cfg.interval))
        cfg.networks = list(scan.get("networks", cfg.networks))
        cfg.max_hosts = int(scan.get("max_hosts", cfg.max_hosts))
        cfg.exclude = [str(x).lower() for x in scan.get("exclude", cfg.exclude)]
        cfg.sweep = bool(scan.get("sweep", cfg.sweep))
        cfg.portscan = bool(scan.get("portscan", cfg.portscan))
        cfg.ports = [int(p) for p in scan.get("ports", cfg.ports)]
        cfg.mdns_seconds = float(scan.get("mdns_seconds", cfg.mdns_seconds))
        cfg.ssdp_seconds = float(scan.get("ssdp_seconds", cfg.ssdp_seconds))
        cfg.ai_enabled = bool(ai.get("enabled", cfg.ai_enabled))
        cfg.ai_endpoint = str(ai.get("endpoint", cfg.ai_endpoint))
        cfg.ai_model = str(ai.get("model", cfg.ai_model))
        cfg.ai_allow_remote = bool(ai.get("allow_remote", cfg.ai_allow_remote))
        cfg.ai_provider = str(ai.get("provider", cfg.ai_provider))
        cfg.ai_key = (os.environ.get("KAA_AI_KEY") or os.environ.get("ANTHROPIC_API_KEY")
                      or str(ai.get("key", "")))
        for keyfile in (cfg.home / "ai.key", Path.home() / ".kaa" / "ai.key"):
            if not cfg.ai_key and keyfile.exists():
                cfg.ai_key = keyfile.read_text(encoding="utf-8").strip()
        if cfg.ai_key and "enabled" not in ai:  # a key present means: use the AI
            cfg.ai_enabled = True
        if cfg.ai_provider == "anthropic":
            cfg.ai_endpoint = cfg.ai_endpoint or "https://api.anthropic.com/v1"
            cfg.ai_model = cfg.ai_model or "claude-haiku-5-5"
            cfg.ai_allow_remote = True
        cfg.notify = bool(nt.get("enabled", cfg.notify))
        cfg.digest_hour = int(nt.get("digest_hour", cfg.digest_hour))
        cfg.threats = bool(th.get("enabled", cfg.threats))
        cfg.exposure = bool(raw.get("exposure", {}).get("enabled", cfg.exposure))
        cfg.threat_keywords = [str(x).lower() for x in th.get("keywords", cfg.threat_keywords)]
        cfg.quiet_start = str(nt.get("quiet_start", cfg.quiet_start))
        cfg.wake_weekday = str(nt.get("wake_weekday", cfg.wake_weekday))
        cfg.wake_weekend = str(nt.get("wake_weekend", cfg.wake_weekend))
    if cfg.host not in LOOPBACK_HOSTS:
        raise ValueError(
            f"server.host={cfg.host!r} refused: Kaa only listens on loopback."
        )
    return cfg


def load_token(cfg: Config) -> str:
    """Per-install secret required for every state-changing API call."""
    path = cfg.home / "token"
    if path.exists():
        return path.read_text().strip()
    token = secrets.token_urlsafe(32)
    path.write_text(token)
    path.chmod(0o600)
    return token
