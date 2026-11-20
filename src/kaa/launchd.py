"""Run Kaa in the background on macOS as a per-user LaunchAgent.

No admin rights, nothing system wide: the agent starts when you log in, restarts
if it crashes, and `kaa service uninstall` removes every trace.
"""

from __future__ import annotations

import os
import plistlib
import subprocess
import sys
import time
from pathlib import Path

from .config import Config

LABEL = "app.kaa.agent"
MENU_LABEL = "app.kaa.menubar"


def plist_path(label: str = LABEL) -> Path:
    return Path.home() / "Library" / "LaunchAgents" / f"{label}.plist"


def build_menubar_plist(cfg: Config, python: str | None = None) -> dict:
    """The menu bar item: a small GUI process that talks to the local service."""
    log = str(cfg.home / "menubar.log")
    return {
        "Label": MENU_LABEL,
        "ProgramArguments": [python or sys.executable, "-m", "kaa.cli", "menubar",
                             "--port", str(cfg.port)],
        "RunAtLoad": True,
        "KeepAlive": {"SuccessfulExit": False},
        "ThrottleInterval": 30,
        "ProcessType": "Interactive",
        "EnvironmentVariables": {"KAA_HOME": str(cfg.home)},
        "StandardOutPath": log,
        "StandardErrorPath": log,
    }


def _load(label: str, data: dict) -> str | None:
    path = plist_path(label)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as fh:
        plistlib.dump(data, fh)
    _launchctl("bootout", f"{_domain()}/{label}")
    # bootout is asynchronous: bootstrapping while the old agent is still shutting
    # down fails with "Input/output error". Wait for it to be gone, retry once.
    for _ in range(20):
        if not is_loaded(label):
            break
        time.sleep(0.25)
    res = _launchctl("bootstrap", _domain(), str(path))
    if res.returncode != 0:
        time.sleep(2)
        res = _launchctl("bootstrap", _domain(), str(path))
    if res.returncode != 0:
        return res.stderr.strip() or res.stdout.strip()
    # RunAtLoad starts the agent as soon as it is bootstrapped; no kickstart needed
    # (kickstart can block on a GUI agent such as the menu bar item).
    return None


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
    try:
        return subprocess.run(["launchctl", *args], capture_output=True, text=True,
                              timeout=20)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(["launchctl", *args], 124, "", "launchctl timed out")


def is_loaded(label: str = LABEL) -> bool:
    return _launchctl("print", f"{_domain()}/{label}").returncode == 0


def install(cfg: Config) -> tuple[bool, str]:
    if sys.platform != "darwin":
        return False, "Background service is macOS only for now (launchd)."
    from .cli import kaa_running, port_busy  # local import: cli imports this module

    url = f"http://{cfg.host}:{cfg.port}"
    if not is_loaded() and port_busy(cfg.host, cfg.port):
        who = "Kaa is already running in a terminal. Stop it with Ctrl+C, then retry." \
            if kaa_running(url) else f"Port {cfg.port} is used by another program."
        return False, who
    from . import macos

    ok, note = macos.ensure_identity()
    if not ok:
        return False, note
    err = _load(LABEL, build_plist(cfg))
    if err:
        return False, f"launchctl failed: {err}"
    msg = f"Kaa now runs in the background at {url}. Log: {cfg.home / 'kaa.log'}"
    try:
        import rumps  # noqa: F401
    except ImportError:
        return True, msg + " (menu bar icon unavailable: rumps is not installed)"
    err = _load(MENU_LABEL, build_menubar_plist(cfg))
    return True, msg + (f" Menu bar icon failed: {err}" if err else
                        " Menu bar icon started (top right, next to the clock).")


def uninstall() -> tuple[bool, str]:
    if sys.platform != "darwin":
        return False, "Background service is macOS only for now (launchd)."
    for label in (MENU_LABEL, LABEL):
        _launchctl("bootout", f"{_domain()}/{label}")
        path = plist_path(label)
        if path.exists():
            path.unlink()
    return True, "Background service and menu bar icon removed."


def status() -> str:
    if sys.platform != "darwin":
        return "not supported on this platform"
    if is_loaded():
        return "running in the background (launchd)"
    return "installed but not loaded" if plist_path().exists() else "not installed"
