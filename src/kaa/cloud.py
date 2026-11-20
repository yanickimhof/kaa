"""Tado and Netatmo, read only, with Kaa's own authorisation.

Kaa never reuses tokens from another app: Netatmo invalidates a refresh token as soon as two
programs refresh it. Each source here has its own grant, stored in ``cloud.json`` (mode 0600)
inside Kaa's data folder. Nothing is ever written to either service.
"""

from __future__ import annotations

import json
import os
import secrets
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

TADO_CLIENT = "1bb50063-6b0c-4d11-bd99-387f4a91cc46"  # Tado's public device-flow client
TADO_OAUTH = "https://login.tado.com/oauth2"
TADO_API = "https://my.tado.com/api/v2"
TADO_HOPS = "https://hops.tado.com"
NETATMO = "https://api.netatmo.com"
NETATMO_SCOPE = "read_station read_thermostat read_camera read_presence read_homecoach read_smokedetector"
NETATMO_REDIRECT = "http://127.0.0.1:8473/oauth/netatmo"

# Netatmo module type -> Kaa class
TADO_NAMES = {"IB": "Internet Bridge", "BU": "Bridge", "VA": "Radiator valve", "RU": "Thermostat", "TR": "Thermostat", "SU": "Thermostat"}
NETATMO_CLASS = {"NACamera": "camera", "NOC": "camera", "NDB": "camera", "NAMain": "sensor", "NAModule1": "sensor",
                 "NAModule2": "sensor", "NAModule3": "sensor", "NAModule4": "sensor", "NHC": "sensor",
                 "NSD": "sensor", "NCO": "sensor", "NATherm1": "thermostat", "NRV": "thermostat",
                 "NAPlug": "hub", "NIS": "sensor"}


class CloudError(Exception):
    pass


def _http(method: str, url: str, form: dict | None = None, token: str | None = None,
          ctx: Any = None, timeout: float = 15.0) -> Any:
    data = urllib.parse.urlencode(form).encode() if form is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if form is not None:
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            raw = r.read()
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")[:300]
        try:
            err = json.loads(body)
            body = str(err.get("error_description") or err.get("error") or err)
        except ValueError:
            pass
        raise CloudError(f"HTTP {exc.code}: {body}") from exc
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        raise CloudError(f"network: {exc}") from exc
    try:
        return json.loads(raw) if raw else {}
    except ValueError as exc:
        raise CloudError("unreadable answer") from exc


class Cloud:
    """Holds the two grants and normalises what both services report."""

    def __init__(self, home: Path, ctx: Any = None) -> None:
        self.path = Path(home) / "cloud.json"
        self.ctx = ctx
        self._lock = threading.Lock()

    # ---- storage ----
    def _load(self) -> dict:
        try:
            return json.loads(self.path.read_text())
        except (OSError, ValueError):
            return {}

    def _save(self, data: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            json.dump(data, fh)
        os.replace(tmp, self.path)

    def _update(self, source: str, **changes: Any) -> dict:
        with self._lock:
            data = self._load()
            data.setdefault(source, {}).update(changes)
            self._save(data)
            return data[source]

    def status(self) -> dict:
        d = self._load()
        t, n = d.get("tado", {}), d.get("netatmo", {})
        return {"tado": {"connected": bool(t.get("refresh")), "pending": bool(t.get("device_code")) and t.get("expires", 0) > time.time()},
                "netatmo": {"configured": bool(n.get("client_id") and n.get("client_secret")), "connected": bool(n.get("refresh"))}}

    def connected(self) -> list[str]:
        return [k for k, v in self.status().items() if v["connected"]]

    def disconnect(self, source: str) -> None:
        with self._lock:
            data = self._load()
            if source == "netatmo":
                data["netatmo"] = {k: v for k, v in data.get("netatmo", {}).items() if k in ("client_id", "client_secret")}
            else:
                data.pop(source, None)
            self._save(data)

    # ---- Tado: device authorisation, no secret needed ----
    def tado_begin(self) -> dict:
        r = _http("POST", f"{TADO_OAUTH}/device_authorize", {"client_id": TADO_CLIENT, "scope": "offline_access"}, ctx=self.ctx)
        self._update("tado", device_code=r["device_code"], interval=int(r.get("interval", 5)),
                     expires=time.time() + int(r.get("expires_in", 300)))
        return {"user_code": r.get("user_code"), "url": r.get("verification_uri_complete") or r.get("verification_uri"),
                "interval": int(r.get("interval", 5)), "expires_in": int(r.get("expires_in", 300))}

    def tado_poll(self) -> dict:
        t = self._load().get("tado", {})
        if not t.get("device_code"):
            return {"status": "idle"}
        try:
            r = _http("POST", f"{TADO_OAUTH}/token", {"client_id": TADO_CLIENT, "device_code": t["device_code"],
                      "grant_type": "urn:ietf:params:oauth:grant-type:device_code"}, ctx=self.ctx)
        except CloudError as exc:
            msg = str(exc)
            if "authorization_pending" in msg or "pending" in msg or "slow_down" in msg:
                return {"status": "pending"}
            self._update("tado", device_code=None)
            return {"status": "failed", "error": msg}
        self._update("tado", device_code=None, access=r["access_token"], refresh=r["refresh_token"],
                     expires=time.time() + int(r.get("expires_in", 600)) - 30)
        return {"status": "connected"}

    def _tado_token(self) -> str:
        t = self._load().get("tado", {})
        if not t.get("refresh"):
            raise CloudError("tado not connected")
        if t.get("access") and t.get("expires", 0) > time.time():
            return t["access"]
        r = _http("POST", f"{TADO_OAUTH}/token", {"client_id": TADO_CLIENT, "grant_type": "refresh_token",
                  "refresh_token": t["refresh"]}, ctx=self.ctx)
        self._update("tado", access=r["access_token"], refresh=r.get("refresh_token", t["refresh"]),
                     expires=time.time() + int(r.get("expires_in", 600)) - 30)
        return r["access_token"]

    def tado_fetch(self) -> list[dict]:
        tok = self._tado_token()
        me = _http("GET", f"{TADO_API}/me", token=tok, ctx=self.ctx)
        homes = me.get("homes") or []
        if not homes:
            return []
        hid = homes[0]["id"]
        out: list[dict] = []

        def add(dev: dict, room: str | None) -> None:
            kind = dev.get("type") or dev.get("deviceType") or ""
            battery = str(dev.get("batteryState") or "").upper()
            conn = (dev.get("connection") or dev.get("connectionState") or {})
            state = conn.get("state") or conn.get("value")
            out.append({"source": "tado", "ext_id": str(dev.get("serialNumber") or dev.get("serialNo") or dev.get("shortSerialNo") or len(out)),
                        "name": room or TADO_NAMES.get(kind[:2], kind or "tado"), "kind": kind, "model": kind,
                        "firmware": dev.get("firmwareVersion") or dev.get("currentFwVersion"),
                        "battery": "low" if battery in ("LOW", "CRITICAL") else ("ok" if battery == "NORMAL" else "unknown"),
                        "battery_pct": None, "reachable": None if state is None else state == "CONNECTED",
                        "parent": None, "cls": "thermostat"})

        try:  # LINE_X devices only exist here
            data = _http("GET", f"{TADO_HOPS}/homes/{hid}/roomsAndDevices", token=tok, ctx=self.ctx)
            for room in data.get("rooms", []):
                rname = room.get("roomName") or (room.get("room") or {}).get("name")
                devs = room.get("devices", [])
                for dev in devs:  # several devices in one room: tell them apart by type
                    add(dev, rname if len(devs) == 1 else f"{rname} · {dev.get('type', '')}")
            for dev in data.get("otherDevices", []):
                add(dev, None)
        except CloudError:
            for dev in _http("GET", f"{TADO_API}/homes/{hid}/devices", token=tok, ctx=self.ctx) or []:
                add(dev, None)
        return out

    # ---- Netatmo: your own app, authorisation code flow ----
    def netatmo_config(self, client_id: str, client_secret: str) -> None:
        self._update("netatmo", client_id=client_id.strip(), client_secret=client_secret.strip())

    def netatmo_url(self) -> str:
        n = self._load().get("netatmo", {})
        if not (n.get("client_id") and n.get("client_secret")):
            raise CloudError("netatmo app not configured")
        state = secrets.token_urlsafe(16)
        self._update("netatmo", state=state)
        q = urllib.parse.urlencode({"client_id": n["client_id"], "redirect_uri": NETATMO_REDIRECT,
                                    "scope": NETATMO_SCOPE, "state": state})
        return f"{NETATMO}/oauth2/authorize?{q}"

    def netatmo_callback(self, code: str, state: str) -> None:
        n = self._load().get("netatmo", {})
        if not n.get("state") or not secrets.compare_digest(n["state"], state or ""):
            raise CloudError("state mismatch")
        r = _http("POST", f"{NETATMO}/oauth2/token", {"grant_type": "authorization_code", "client_id": n["client_id"],
                  "client_secret": n["client_secret"], "code": code, "redirect_uri": NETATMO_REDIRECT,
                  "scope": NETATMO_SCOPE}, ctx=self.ctx)
        self._update("netatmo", state=None, access=r["access_token"], refresh=r["refresh_token"],
                     expires=time.time() + int(r.get("expires_in", 10800)) - 60)

    def _netatmo_token(self) -> str:
        n = self._load().get("netatmo", {})
        if not n.get("refresh"):
            raise CloudError("netatmo not connected")
        if n.get("access") and n.get("expires", 0) > time.time():
            return n["access"]
        r = _http("POST", f"{NETATMO}/oauth2/token", {"grant_type": "refresh_token", "refresh_token": n["refresh"],
                  "client_id": n["client_id"], "client_secret": n["client_secret"]}, ctx=self.ctx)
        self._update("netatmo", access=r["access_token"], refresh=r.get("refresh_token", n["refresh"]),
                     expires=time.time() + int(r.get("expires_in", 10800)) - 60)
        return r["access_token"]

    def netatmo_fetch(self) -> list[dict]:
        tok = self._netatmo_token()
        out: list[dict] = []
        seen: set[str] = set()

        def add(mid: str, typ: str, name: str, fw: Any, bat_state: Any, bat_pct: Any, reach: Any, parent: Any) -> None:
            if mid in seen:
                return
            seen.add(mid)
            pct = bat_pct if isinstance(bat_pct, (int, float)) and 0 <= bat_pct <= 100 else None  # mV values are not a percentage
            low = str(bat_state or "").lower() in ("low", "very_low") or (pct is not None and pct < 20)
            out.append({"source": "netatmo", "ext_id": mid, "name": name or typ, "kind": typ, "model": typ,
                        "firmware": str(fw) if fw is not None else None,
                        "battery": "low" if low else ("ok" if (bat_state or bat_pct is not None) else "unknown"),
                        "battery_pct": int(pct) if pct is not None else None,
                        "reachable": reach if isinstance(reach, bool) else None, "parent": parent,
                        "cls": NETATMO_CLASS.get(typ, "sensor")})

        try:  # energy and security homes: thermostats, valves, cameras, doorbells
            homes = _http("GET", f"{NETATMO}/api/homesdata", token=tok, ctx=self.ctx).get("body", {}).get("homes", [])
        except CloudError:
            homes = []
        for h in homes:
            status: dict[str, dict] = {}
            try:
                st = _http("GET", f"{NETATMO}/api/homestatus?{urllib.parse.urlencode({'home_id': h['id']})}", token=tok, ctx=self.ctx)
                status = {m["id"]: m for m in st.get("body", {}).get("home", {}).get("modules", [])}
            except CloudError:
                pass
            for m in h.get("modules", []):
                s = status.get(m["id"], {})
                add(m["id"], m.get("type", ""), m.get("name", ""), s.get("firmware_revision"),
                    s.get("battery_state"), s.get("battery_level"), s.get("reachable"), m.get("bridge"))
        try:  # weather stations and their modules
            devs = _http("GET", f"{NETATMO}/api/getstationsdata", token=tok, ctx=self.ctx).get("body", {}).get("devices", [])
        except CloudError:
            devs = []
        for d in devs:
            add(d.get("_id", ""), d.get("type", "NAMain"), d.get("module_name") or d.get("station_name", ""),
                d.get("firmware"), None, None, d.get("reachable"), None)
            for m in d.get("modules", []):
                add(m.get("_id", ""), m.get("type", ""), m.get("module_name", ""), m.get("firmware"),
                    None, m.get("battery_percent"), m.get("reachable"), d.get("_id"))
        try:  # Healthy Home Coach
            coaches = _http("GET", f"{NETATMO}/api/gethomecoachsdata", token=tok, ctx=self.ctx).get("body", {}).get("devices", [])
        except CloudError:
            coaches = []
        for d in coaches:
            add(d.get("_id", ""), d.get("type", "NHC"), d.get("station_name") or d.get("module_name", ""), d.get("firmware"),
                None, None, d.get("reachable"), None)
        return out

    def fetch_all(self) -> tuple[list[dict], dict[str, str]]:
        """(devices, errors per source). One source failing never hides the other."""
        devices: list[dict] = []
        errors: dict[str, str] = {}
        for source, fn in (("tado", self.tado_fetch), ("netatmo", self.netatmo_fetch)):
            if source not in self.connected():
                continue
            try:
                devices.extend(fn())
            except CloudError as exc:
                errors[source] = str(exc)
        return devices, errors
