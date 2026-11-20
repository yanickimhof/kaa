"""macOS menu bar item. Optional: ``pip install "kaa[menubar]"``."""

from __future__ import annotations

import json
import urllib.request
import webbrowser


def _get(url: str) -> dict | None:
    try:
        with urllib.request.urlopen(url, timeout=3) as r:  # noqa: S310
            return json.loads(r.read())
    except (OSError, ValueError):
        return None


def glyph(score: int | None) -> str:
    if score is None:
        return "⚪"
    return "🟢" if score >= 90 else "🟡" if score >= 75 else "🟠" if score >= 50 else "🔴"


def run(base: str) -> None:
    try:
        import rumps
    except ImportError as exc:
        raise SystemExit('Menu bar needs: pip install "kaa[menubar]"') from exc

    class KaaMenu(rumps.App):
        def __init__(self) -> None:
            super().__init__("Kaa", title="Kaa", quit_button=None)
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

        @rumps.timer(30)
        def refresh(self, _):
            data = _get(f"{base}/api/overview")
            if not data:
                self.title = "Kaa ⚪"
                self.status.title = "Not running"
                return
            score = data["score"]["value"]
            self.title = f"Kaa {glyph(score)} {score}"
            self.status.title = (f"{data['online']} online, "
                                 f"{data['open_findings']} to review")

    KaaMenu().run()
