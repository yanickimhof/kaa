"""The scan cycle: discover, enrich, identify, evaluate, score."""

from __future__ import annotations

import json
import socket
import threading
import time
from importlib import resources
from pathlib import Path
from typing import Any

import psutil

from . import findings as findings_mod
from . import scoring
from .collectors import arp, mdns, portscan, ssdp
from .config import Config
from .db import Database, now
from .identify import engine, llm
from .oui import Oui, is_randomized
from .scope import ScopeError, build_scope, local_interfaces


def builtin_signatures() -> Path:
    return Path(str(resources.files("kaa") / "data" / "signatures"))


class Service:
    def __init__(self, cfg: Config, db: Database):
        self.cfg = cfg
        self.db = db
        self.oui = Oui(cfg.data_dir / "oui.csv")
        self.rules = engine.load_rules(builtin_signatures(), cfg.user_signatures)
        self._lock = threading.Lock()
        self.state: dict[str, Any] = {
            "running": False, "last_run": None, "last_error": None,
            "last_duration": None, "scope": [], "oui_loaded": self.oui.loaded,
            "ai": cfg.ai_enabled,
        }

    # ---- facts ---------------------------------------------------------
    def facts_for(self, device: dict) -> dict[str, Any]:
        obs = self.db.observations(device["id"])
        return {
            "vendor": device.get("vendor"),
            "hostname": device.get("hostname"),
            "randomized_mac": device["randomized"],
            "is_gateway": obs.get("net.role") == "gateway",
            "is_self": obs.get("net.role") == "self",
            "mdns_services": obs.get("mdns.services", []),
            "mdns_names": obs.get("mdns.names", []),
            "ssdp_server": obs.get("ssdp.server", ""),
            "ssdp_st": obs.get("ssdp.st", []),
            "open_ports": obs.get("scan.open_ports", []),
        }

    # ---- one cycle -----------------------------------------------------
    def run_cycle(self, ports: bool | None = None) -> bool:
        if not self._lock.acquire(blocking=False):
            return False
        started = time.monotonic()
        self.state.update(running=True, last_error=None)
        try:
            self._cycle(self.cfg.portscan if ports is None else ports)
        except ScopeError as exc:
            self.state["last_error"] = f"scope: {exc}"
        except Exception as exc:  # keep the service alive whatever a collector does
            self.state["last_error"] = f"{type(exc).__name__}: {exc}"
        finally:
            self.state.update(running=False, last_run=now(),
                              last_duration=round(time.monotonic() - started, 1))
            self._lock.release()
        return True

    def _cycle(self, do_ports: bool) -> None:
        cfg, db = self.cfg, self.db
        scope = build_scope(cfg.networks, cfg.max_hosts, cfg.exclude)
        self.state["scope"] = scope.describe()
        if cfg.sweep:
            arp.sweep(scope)

        table = [n for n in arp.read_table()
                 if scope.allowed(n.ip) and n.mac not in cfg.exclude]
        online: set[int] = set()
        by_ip: dict[str, int] = {}
        new_ids: list[int] = []

        own = [i for i in local_interfaces() if scope.contains(i.ip)]
        entries = [(n.ip, n.mac, False) for n in table]
        for i in own:
            if i.mac:
                entries.append((i.ip, i.mac, True))

        for ip, mac, is_self in entries:
            did, is_new = db.upsert_device(mac, ip, is_randomized(mac))
            online.add(did)
            by_ip[ip] = did
            if is_new:
                new_ids.append(did)
                db.add_event("device_new", f"New device {mac} at {ip}", did)
            if is_self:
                db.observe(did, "net", "role", "self")
                db.set_fields(did, hostname=socket.gethostname())
            vendor = self.oui.lookup(mac)
            if vendor:
                db.set_fields(did, vendor=vendor)

        for did in db.mark_offline_except(online):
            db.add_event("device_offline", "Device went offline", did)

        # hostnames for devices that have none yet
        need = [d["ip"] for d in db.list_devices()
                if d["online"] and not d["hostname"] and d["ip"]]
        for ip, name in arp.reverse_dns(need).items():
            if ip in by_ip:
                db.set_fields(by_ip[ip], hostname=name)

        # gateway role and gateway MAC watch
        gw_ip = arp.default_gateway()
        gateway_alert = self._watch_gateway(gw_ip, by_ip)

        # discovery protocols
        for ip, data in mdns.collect(cfg.mdns_seconds).items():
            did = by_ip.get(ip)
            if did:
                db.observe(did, "mdns", "services", data["services"])
                db.observe(did, "mdns", "names", data["names"])
                if data["names"] and not db.get_device(did)["hostname"]:
                    db.set_fields(did, hostname=data["names"][0])
        for ip, data in ssdp.collect(cfg.ssdp_seconds).items():
            did = by_ip.get(ip)
            if did:
                db.observe(did, "ssdp", "server", data["server"])
                db.observe(did, "ssdp", "st", data["st"])

        scanned_ids: set[int] = set(json.loads(db.meta_get("scanned_ids") or "[]"))
        if do_ports:
            ips = [ip for ip in by_ip if scope.allowed(ip)]
            results = portscan.scan(scope, ips, cfg.ports)
            for ip, open_ports in results.items():
                db.observe(by_ip[ip], "scan", "open_ports", open_ports)
                scanned_ids.add(by_ip[ip])
            db.meta_set("scanned_ids", json.dumps(sorted(scanned_ids)))

        self.identify_all()
        self.evaluate(gateway_alert, scanned_ids)

        if db.meta_get("baseline_at") is None:
            db.meta_set("baseline_at", now())
            db.add_event("baseline", f"Baseline set with {len(online)} devices")

    def _watch_gateway(self, gw_ip: str | None, by_ip: dict[str, int]) -> dict | None:
        db = self.db
        if not gw_ip or gw_ip not in by_ip:
            raw = db.meta_get("gateway_alert")
            return json.loads(raw) if raw else None
        did = by_ip[gw_ip]
        db.observe(did, "net", "role", "gateway")
        mac = db.get_device(did)["mac"]
        trusted = db.meta_get("gateway_mac")
        if trusted is None:
            db.meta_set("gateway_mac", mac)
        elif trusted != mac and db.meta_get("gateway_alert") is None:
            alert = {"device_id": did, "ip": gw_ip, "old_mac": trusted, "new_mac": mac}
            db.meta_set("gateway_alert", json.dumps(alert))
            db.add_event("gateway_mac_changed",
                         f"Gateway {gw_ip} changed from {trusted} to {mac}", did)
        raw = db.meta_get("gateway_alert")
        return json.loads(raw) if raw else None

    def accept_gateway_change(self) -> None:
        raw = self.db.meta_get("gateway_alert")
        if raw:
            self.db.meta_set("gateway_mac", json.loads(raw)["new_mac"])
            self.db._x("delete from meta where key='gateway_alert'")

    # ---- identify and evaluate ----------------------------------------
    def identify_all(self) -> None:
        for d in self.db.list_devices():
            facts = self.facts_for(d)
            cls, conf, evidence = engine.classify(facts, self.rules)
            source = "rules"
            if cls == "unknown" and self.cfg.ai_enabled and self.cfg.ai_endpoint:
                cls, conf, evidence, source = self._ask_ai(d, facts)
            self.db.set_classification(d["id"], cls, conf, source if cls != "unknown" else "", evidence)

    def _ask_ai(self, d: dict, facts: dict) -> tuple[str, float, list[dict], str]:
        h = llm.facts_hash(facts)
        if self.db.observations(d["id"]).get("ai.facts_hash") == h:
            return "unknown", 0.0, [], ""  # same metadata as last attempt, do not ask again
        try:
            res = llm.resolve(facts, self.cfg.ai_endpoint, self.cfg.ai_model,
                              self.cfg.ai_allow_remote)
        except (llm.AIConfigError, OSError, ValueError, KeyError):
            return "unknown", 0.0, [], ""
        self.db.observe(d["id"], "ai", "facts_hash", h)
        if not res:
            return "unknown", 0.0, [], ""
        return res[0], res[1], res[2], "ai"

    def evaluate(self, gateway_alert: dict | None = None,
                 scanned_ids: set[int] | None = None) -> None:
        devices = self.db.list_devices()
        for d in devices:
            d["facts"] = self.facts_for(d)
        if gateway_alert is None:
            raw = self.db.meta_get("gateway_alert")
            gateway_alert = json.loads(raw) if raw else None
        if scanned_ids is None:
            scanned_ids = set(json.loads(self.db.meta_get("scanned_ids") or "[]"))
        ctx = {"baseline_at": self.db.meta_get("baseline_at"),
               "scanned_ids": scanned_ids, "gateway_alert": gateway_alert}
        self.db.sync_findings(findings_mod.evaluate(devices, ctx))
        result = scoring.compute(self.db.list_findings())
        self.db.add_score(result["value"], result)

    # ---- background loop ----------------------------------------------
    def loop(self, stop: threading.Event) -> None:
        while not stop.is_set():
            self.run_cycle()
            stop.wait(self.cfg.interval)

    def summary(self) -> dict:
        findings = self.db.list_findings()
        devices = self.db.list_devices()
        return {
            "score": scoring.compute(findings),
            "devices": len(devices),
            "online": sum(1 for d in devices if d["online"]),
            "unidentified": sum(1 for d in devices if d["class"] == "unknown"),
            "open_findings": sum(1 for f in findings if f["status"] == "open"),
            "state": self.state,
            "history": self.db.list_scores(60),
            "cpu": psutil.cpu_percent(interval=None),
        }
