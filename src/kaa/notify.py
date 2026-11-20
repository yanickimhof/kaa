"""Desktop notifications. Local only: nothing leaves the machine."""

from __future__ import annotations

import datetime as dt
import shutil
import subprocess
import sys


def _applescript(text: str) -> str:
    return text.replace("\\", "\\\\").replace('"', '\\"')


def send(title: str, message: str) -> bool:
    """Show a notification. Returns False when the platform has no way to do it."""
    title, message = title[:80], message[:240]
    try:
        if sys.platform == "darwin":
            script = (f'display notification "{_applescript(message)}" '
                      f'with title "{_applescript(title)}"')
            return subprocess.run(["osascript", "-e", script], capture_output=True,
                                  timeout=10).returncode == 0
        if shutil.which("notify-send"):
            return subprocess.run(["notify-send", title, message], capture_output=True,
                                  timeout=10).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        pass
    return False


def parse_clock(text: str, default: dt.time) -> dt.time:
    try:
        h, m = str(text).strip().split(":")
        return dt.time(int(h), int(m))
    except (ValueError, TypeError):
        return default


def is_quiet(now: dt.datetime, start: dt.time, wake_weekday: dt.time,
             wake_weekend: dt.time) -> bool:
    """Quiet from ``start`` in the evening until the wake time of the next morning.

    Weekends have their own, later wake time (Saturday and Sunday mornings).
    """
    wake = wake_weekend if now.weekday() >= 5 else wake_weekday
    t = now.time()
    return t >= start or t < wake
