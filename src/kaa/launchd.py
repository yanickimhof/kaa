"""Run Kaa in the background on macOS as a per-user LaunchAgent.

No admin rights, nothing system wide: the agent starts when you log in, restarts
if it crashes, and `kaa service uninstall` removes every trace.
"""

from __future__ import annotations

import os
import plistlib
import subprocess
import sys
from pathlib import Path

from .config import Config

LABEL = "app.kaa.agent"


def plist_path() -> Path:
    return Path.home() / "Library" / "LaunchAgents" / f"{LABEL}.plist"


def build_plist(cfg: Config, python: str | None = None) -> dict:
    log = str(cfg.home / "kaa.log")
    env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:/usr/local/bin",
           "KAA_HOME": str(cfg.home)}
    return {
        "Label": LABEL,
        "ProgramArguments": [python or sys.executable, "-m", "kaa.cli", "serve"],
        "RunAtLoad": True,
        # Restart after a crash, but not after a clean exit (for example when Kaa
        # is already running), and never faster than every 30 seconds.
        "KeepAlive": {"SuccessfulExit": False},
        "ThrottleInterval": 30,
        "ProcessType": "Background",
        "EnvironmentVariables": env,
        "StandardOutPath": log,
        "StandardErrorPath": log,
    }


def _domain() -> str:
    return f"gui/{os.getuid()}"


def _launchctl(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["launchctl", *args], capture_output=True, text=True)


def is_loaded() -> bool:
    return _launchctl("print", f"{_domain()}/{LABEL}").returncode == 0


def install(cfg: Config) -> tuple[bool, str]:
    if sys.platform != "darwin":
        return False, "Background service is macOS only for now (launchd)."
    from .cli import kaa_running, port_busy  # local import: cli imports this module

    url = f"http://{cfg.host}:{cfg.port}"
    if not is_loaded() and port_busy(cfg.host, cfg.port):
        who = "Kaa is already running in a terminal. Stop it with Ctrl+C, then retry." \
            if kaa_running(url) else f"Port {cfg.port} is used by another program."
        return False, who
    path = plist_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as fh:
        plistlib.dump(build_plist(cfg), fh)
    _launchctl("bootout", f"{_domain()}/{LABEL}")
    res = _launchctl("bootstrap", _domain(), str(path))
    if res.returncode != 0:
        return False, f"launchctl failed: {res.stderr.strip() or res.stdout.strip()}"
    _launchctl("kickstart", "-k", f"{_domain()}/{LABEL}")
    return True, f"Kaa now runs in the background at {url}. Log: {cfg.home / 'kaa.log'}"


def uninstall() -> tuple[bool, str]:
    if sys.platform != "darwin":
        return False, "Background service is macOS only for now (launchd)."
    _launchctl("bootout", f"{_domain()}/{LABEL}")
    path = plist_path()
    if path.exists():
        path.unlink()
    return True, "Background service removed."


def status() -> str:
    if sys.platform != "darwin":
        return "not supported on this platform"
    if is_loaded():
        return "running in the background (launchd)"
    return "installed but not loaded" if plist_path().exists() else "not installed"
