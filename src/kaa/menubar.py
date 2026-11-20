"""macOS menu bar item. Optional: ``pip install "kaa[menubar]"``."""

from __future__ import annotations

import json
import urllib.request
import webbrowser
from pathlib import Path

from . import icon


def _get(url: str) -> dict | None:
    try:
        with urllib.request.urlopen(url, timeout=3) as r:  # noqa: S310
            return json.loads(r.read())
    except (OSError, ValueError):
        return None


def tier(score: int | None) -> str:
    return "none" if score is None else "ok" if score >= 90 else "warn" if score >= 70 else "crit"


def run(base: str, cache: Path | None = None) -> None:
    cache = cache or Path.home() / ".kaa" / "icons"
    try:
        import rumps
    except ImportError as exc:
        raise SystemExit('Menu bar needs: pip install "kaa[menubar]"') from exc

    class KaaMenu(rumps.App):
        def __init__(self) -> None:
            super().__init__("Kaa", title=None, quit_button=None)
            self._shown: str | None = None
            self.status = rumps.MenuItem("Starting…")
            self.menu = [
                self.status, None,
                rumps.MenuItem("Open Kaa", callback=lambda _: webbrowser.open(base)),
                rumps.MenuItem("Scan now", callback=self.scan),
                None,
                rumps.MenuItem("Quit", callback=rumps.quit_application),
            ]
            self.refresh(None)

        def scan(self, _):
            req = urllib.request.Request(
                f"{base}/api/session")  # token fetched, then used for the scan call
            try:
                with urllib.request.urlopen(req, timeout=3) as r:  # noqa: S310
                    token = json.loads(r.read())["token"]
                post = urllib.request.Request(
                    f"{base}/api/scan", data=b'{"ports": false}', method="POST",
                    headers={"Content-Type": "application/json", "X-Kaa-Token": token})
                urllib.request.urlopen(post, timeout=3)  # noqa: S310
            except OSError:
                rumps.notification("Kaa", "", "Kaa is not running.")

        def show(self, score: int | None) -> None:
            """Grey ring, coloured dot: green when all is well, orange when something needs a look, red when urgent."""
            level = tier(score)
            if level == self._shown:
                return
            self._shown = level
            colors = {"ok": (52, 199, 89), "warn": (255, 159, 10), "crit": (255, 69, 58), "none": None}
            self.icon = str(icon.ensure(cache, f"dot-{level}", colors[level]))
            self.template = False

        @rumps.timer(30)
        def refresh(self, _):
            data = _get(f"{base}/api/overview")
            if not data:
                self.show(None)
                self.status.title = "Not running"
                return
            score = data["score"]["value"]
            self.show(score)
            self.status.title = (f"Score {score}  ·  {data['online']} online  ·  "
                                 f"{data['open_findings']} to review")

    KaaMenu().run()
