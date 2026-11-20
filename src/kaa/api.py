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

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import __version__
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

    @app.get("/api/devices/{device_id}")
    def device(device_id: int):
        d = service.db.get_device(device_id)
        if not d:
            raise HTTPException(404, "unknown device")
        d["facts"] = service.facts_for(d)
        d["findings"] = sorted(
            (f for f in service.db.list_findings() if f["device_id"] == device_id
             and f["status"] != "resolved"),
            key=lambda f: SEVERITY_RANK[f["severity"]])
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
        service.db.set_fields(device_id, **fields)
        service.identify_all()
        service.evaluate()
        return service.db.get_device(device_id)

    @app.get("/api/findings")
    def findings(status: str | None = None):
        items = service.db.list_findings(status)
        if status is None:
            items = [f for f in items if f["status"] != "resolved"]
        return sorted(items, key=lambda f: (SEVERITY_RANK[f["severity"]], f["id"]))

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

    @app.get("/api/events")
    def events(limit: int = 100):
        return service.db.list_events(min(max(limit, 1), 500))

    @app.get("/")
    def index():
        return FileResponse(WEB / "index.html")

    app.mount("/", StaticFiles(directory=WEB), name="web")
    return app
