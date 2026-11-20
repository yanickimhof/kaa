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
    port: int = 8731
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
    path = cfg.home / "config.toml"
    if path.exists():
        with path.open("rb") as fh:
            raw = tomllib.load(fh)
        srv = raw.get("server", {})
        scan = raw.get("scan", {})
        ai = raw.get("ai", {})
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
