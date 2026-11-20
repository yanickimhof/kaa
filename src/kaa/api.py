"""Local HTTP API and web app.

Security model for a tool that lives on localhost:
* Loopback only (enforced in config and by the server bind).
* Host header allow-list: blocks DNS rebinding.
* State changing calls need a per-install token in a custom header, which
  browsers will not send cross-origin without a CORS preflight we never grant.
"""

from __future__ import annotations

import hmac
import threading
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import __version__
from . import settings as settings_mod
from . import texts
from .cloud import CloudError
from .models import CLASSES, SEVERITY_RANK, TRUST_LEVELS
from .service import Service

WEB = Path(__file__).parent / "web"
ALLOWED_HOSTS = {"127.0.0.1", "localhost", "[::1]"}


def hostname(header: str) -> str:
    """Host without port, keeping IPv6 brackets."""
    if header.startswith("["):
        return header.split("]")[0] + "]"
    return header.rsplit(":", 1)[0] if ":" in header else header


class DevicePatch(BaseModel):
    trust: str | None = None
    label: str | None = None
    device_class: str | None = None
    critical: bool | None = None


class NetatmoConfig(BaseModel):
    client_id: str
    client_secret: str


class AskRequest(BaseModel):
    question: str


class ExplainRequest(BaseModel):
    finding_id: int


class ScanRequest(BaseModel):
    ports: bool = False


def create_app(service: Service, token: str) -> FastAPI:
    app = FastAPI(title="Kaa", version=__version__, docs_url=None, redoc_url=None)

    @app.middleware("http")
    async def host_guard(request: Request, call_next):
        if hostname(request.headers.get("host") or "") not in ALLOWED_HOSTS:
            return JSONResponse({"detail": "forbidden host"}, status_code=403)
        resp = await call_next(request)
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
            "frame-ancestors 'none'")
        return resp

    def require_token(x_kaa_token: str | None = Header(default=None)) -> None:
        if not x_kaa_token or not hmac.compare_digest(x_kaa_token, token):
            raise HTTPException(401, "missing or invalid token")

    @app.get("/api/session")
    def session():
        return {"token": token, "version": __version__,
                "classes": CLASSES, "trust_levels": TRUST_LEVELS}

    @app.get("/api/overview")
    def overview():
        return service.summary()

    @app.get("/api/devices")
    def devices():
        out = []
        for d in service.db.list_devices():
            facts = service.facts_for(d)
            d["role"] = "gateway" if facts["is_gateway"] else "self" if facts["is_self"] else None
            out.append(d)
        return out

    def localise(items: list[dict], lang: str | None = None) -> list[dict]:
        lang = lang if lang in ("fr", "en") else service.cfg.lang
        names = {d["id"]: (d.get("label") or d.get("hostname") or d.get("vendor") or d["mac"])
                 for d in service.db.list_devices()}
        out = []
        for f in items:
            r = texts.render(lang, f["rule_id"], names.get(f["device_id"], ""), f.get("evidence") or {})
            out.append({**f, "title": r[0], "detail": r[1], "fix": r[2]} if r else f)
        return out

    @app.get("/api/exposure")
    def get_exposure():
        return service.exposure()

    @app.get("/api/devices/{device_id}/presence")
    def device_presence(device_id: int, hours: int = 168):
        if not service.db.get_device(device_id):
            raise HTTPException(404, "unknown device")
        return service.presence(device_id, min(max(hours, 1), 336))

    @app.get("/api/devices/{device_id}")
    def device(device_id: int, lang: str | None = None):
        d = service.db.get_device(device_id)
        if not d:
            raise HTTPException(404, "unknown device")
        d["facts"] = service.facts_for(d)
        d["findings"] = localise(sorted(
            (f for f in service.db.list_findings() if f["device_id"] == device_id
             and f["status"] != "resolved"),
            key=lambda f: SEVERITY_RANK[f["severity"]]), lang)
        d["history"] = service.db.list_events(30, device_id=device_id)
        return d

    @app.patch("/api/devices/{device_id}", dependencies=[Depends(require_token)])
    def patch_device(device_id: int, body: DevicePatch):
        if not service.db.get_device(device_id):
            raise HTTPException(404, "unknown device")
        if body.trust is not None and body.trust not in TRUST_LEVELS:
            raise HTTPException(422, "invalid trust level")
        fields = {}
        if body.trust is not None:
            fields["trust"] = body.trust
        if body.label is not None:
            fields["label"] = body.label.strip()[:80] or None
        if body.critical is not None:
            fields["critical"] = 1 if body.critical else 0
        learned: list[str] = []
        if body.device_class is not None:
            if body.device_class != "auto" and body.device_class not in CLASSES:
                raise HTTPException(422, "invalid device type")
            if fields:
                service.db.set_fields(device_id, **fields)
            learned = service.set_class(device_id, body.device_class)
        else:
            service.db.set_fields(device_id, **fields)
            service.identify_all()
        service.evaluate()
        return {**service.db.get_device(device_id), "applied_to": learned}

    @app.get("/api/findings")
    def findings(status: str | None = None, lang: str | None = None):
        items = service.db.list_findings(status)
        if status is None:
            items = [f for f in items if f["status"] != "resolved"]
        return localise(sorted(items, key=lambda f: (SEVERITY_RANK[f["severity"]], f["id"])), lang)

    @app.post("/api/findings/{finding_id}/ack", dependencies=[Depends(require_token)])
    def ack(finding_id: int, undo: bool = False):
        rows = [f for f in service.db.list_findings() if f["id"] == finding_id]
        if not rows or not service.db.ack_finding(finding_id, ack=not undo):
            raise HTTPException(404, "unknown or resolved finding")
        if rows[0]["rule_id"] == "KAA-GATEWAY-MAC-CHANGED" and not undo:
            service.accept_gateway_change()
        service.evaluate()
        return {"ok": True}

    @app.post("/api/scan", dependencies=[Depends(require_token)])
    def scan(body: ScanRequest):
        if service.state["running"]:
            return {"started": False, "reason": "already running"}
        threading.Thread(target=service.run_cycle, kwargs={"ports": body.ports},
                         daemon=True).start()
        return {"started": True}

    @app.get("/api/internet")
    def internet():
        return service.internet()

    @app.post("/api/speedtest", dependencies=[Depends(require_token)])
    def speedtest():
        if service.state.get("speedtest_running"):
            return {"started": False}
        threading.Thread(target=service.run_speedtest, daemon=True).start()
        return {"started": True}

    @app.get("/api/report")
    def report(days: int = 7):
        return service.report(max(1, min(days, 90)))

    @app.get("/api/settings")
    def get_settings():
        return settings_mod.to_dict(service.cfg)

    @app.put("/api/settings", dependencies=[Depends(require_token)])
    def put_settings(body: dict[str, Any]):
        try:
            changed = settings_mod.apply(service.cfg, body)
        except settings_mod.SettingsError as exc:
            raise HTTPException(422, str(exc)) from exc
        settings_mod.save(service.cfg, list(changed))
        if changed.get("exposure"):
            threading.Thread(target=service.refresh_exposure, kwargs={"force": True}, daemon=True).start()
        if changed.get("threats"):
            threading.Thread(target=service.refresh_threats, kwargs={"force": True},
                             daemon=True).start()
        return settings_mod.to_dict(service.cfg)

    @app.post("/api/ai/brief", dependencies=[Depends(require_token)])
    def ai_brief():
        return service.ai_brief()

    @app.post("/api/ai/ask", dependencies=[Depends(require_token)])
    def ai_ask(body: AskRequest):
        return service.ai_ask(body.question)

    @app.post("/api/ai/explain", dependencies=[Depends(require_token)])
    def ai_explain(body: ExplainRequest):
        return service.ai_explain(body.finding_id)

    @app.post("/api/ai/triage", dependencies=[Depends(require_token)])
    def ai_triage():
        return service.ai_triage()

    @app.get("/api/cloud")
    def cloud():
        return service.cloud_view()

    @app.post("/api/cloud/tado/begin", dependencies=[Depends(require_token)])
    def tado_begin():
        try:
            return service.cloud.tado_begin()
        except CloudError as exc:
            raise HTTPException(502, str(exc)) from exc

    @app.post("/api/cloud/tado/poll", dependencies=[Depends(require_token)])
    def tado_poll():
        r = service.cloud.tado_poll()
        if r["status"] == "connected":
            threading.Thread(target=service.cloud_sync, kwargs={"force": True}, daemon=True).start()
        return r

    @app.put("/api/cloud/netatmo/config", dependencies=[Depends(require_token)])
    def netatmo_config(body: NetatmoConfig):
        if not body.client_id.strip() or not body.client_secret.strip():
            raise HTTPException(422, "client id and secret are required")
        service.cloud.netatmo_config(body.client_id, body.client_secret)
        return service.cloud.status()

    @app.post("/api/cloud/netatmo/start", dependencies=[Depends(require_token)])
    def netatmo_start():
        try:
            return {"url": service.cloud.netatmo_url()}
        except CloudError as exc:
            raise HTTPException(409, str(exc)) from exc

    @app.get("/oauth/netatmo", response_class=HTMLResponse)
    def netatmo_callback(code: str = "", state: str = "", error: str = ""):
        try:
            if error or not code:
                raise CloudError(error or "no code")
            service.cloud.netatmo_callback(code, state)
            threading.Thread(target=service.cloud_sync, kwargs={"force": True}, daemon=True).start()
            msg = "Netatmo connected. You can close this tab."
        except CloudError as exc:
            msg = f"Netatmo connection failed: {str(exc)[:120]}"
        from html import escape
        return HTMLResponse(f"<!doctype html><meta charset=utf-8><title>Kaa</title>"
                            f"<body style='font:16px system-ui;padding:3rem'><p>{escape(msg)}</p>"
                            f"<p><a href='/'>Kaa</a></p>")

    @app.post("/api/cloud/{source}/disconnect", dependencies=[Depends(require_token)])
    def cloud_disconnect(source: str):
        if source not in ("tado", "netatmo"):
            raise HTTPException(404, "unknown source")
        service.cloud.disconnect(source)
        service.db.replace_cloud(source, [])
        return service.cloud.status()

    @app.post("/api/cloud/sync", dependencies=[Depends(require_token)])
    def cloud_sync():
        return service.cloud_sync(force=True)

    @app.get("/api/threats")
    def get_threats():
        return service.threats()

    @app.post("/api/threats/refresh", dependencies=[Depends(require_token)])
    def refresh_threats():
        threading.Thread(target=service.refresh_threats, kwargs={"force": True},
                         daemon=True).start()
        return {"started": True}

    @app.get("/api/hygiene")
    def hygiene():
        return {"checks": service.hygiene()}

    @app.get("/api/digest")
    def digest(hours: int = 24):
        return service.digest(min(max(hours, 1), 168))

    @app.get("/api/events")
    def events(limit: int = 100):
        return service.db.list_events(min(max(limit, 1), 500))

    @app.get("/")
    def index():
        return FileResponse(WEB / "index.html")

    app.mount("/", StaticFiles(directory=WEB), name="web")
    return app
