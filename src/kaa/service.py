"""The scan cycle: discover, enrich, identify, evaluate, score."""

from __future__ import annotations

import datetime as dt
import json
import re
import socket
import threading
import time
from importlib import resources
from pathlib import Path
from typing import Any

import psutil

from . import findings as findings_mod
from . import notify as notify_mod
from . import exposure as exposure_mod
from . import scoring, threats
from .collectors import arp, mdns, portscan, probes, speed, ssdp, wifi
from .cloud import Cloud
from .config import Config
from .db import Database, now
from .identify import engine, learn, llm
from .oui import REDACTED_MACS, Oui, is_randomized, ssl_context, valid_mac
from .scope import ScopeError, build_scope, local_interfaces


def builtin_signatures() -> Path:
    return Path(str(resources.files("kaa") / "data" / "signatures"))


_ADDR = re.compile(r"(?i)\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b|\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[0-9a-f]{16,}(?:-[0-9a-f]+)*\b")


def _scrub(text: str) -> str:
    return _ADDR.sub("[address]", text)


class Service:
    def __init__(self, cfg: Config, db: Database):
        self.cfg = cfg
        self.db = db
        self.oui = Oui(cfg.data_dir / "oui.csv")
        self.rules = engine.load_rules(builtin_signatures(), cfg.user_signatures)
        self._lock = threading.Lock()
        self.cloud = Cloud(cfg.home, ssl_context())
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
            "probe_tls_expired": obs.get("probe.tls_expired", ""),
            "probe_ftp_anon": obs.get("probe.ftp_anon", False),
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
        else:
            try:
                self._alerts()
            except Exception as exc:  # a notification problem must never stop scanning
                print(f"[kaa] alerts: {type(exc).__name__}: {exc}", flush=True)
        finally:
            self.state.update(running=False, last_run=now(),
                              last_duration=round(time.monotonic() - started, 1))
            self._lock.release()
            print(f"[kaa] cycle {self.state['last_run']} "
                  f"{'ERROR ' + self.state['last_error'] if self.state['last_error'] else 'ok'} "
                  f"neighbours={self.state.get('neighbours')} sweep={self.state.get('sweep')} "
                  f"took={self.state['last_duration']}s", flush=True)
        return True

    def _cycle(self, do_ports: bool) -> None:
        cfg, db = self.cfg, self.db
        scope = build_scope(cfg.networks, cfg.max_hosts, cfg.exclude)
        self.state["scope"] = scope.describe()
        if cfg.sweep:
            stats = arp.sweep(scope)
            self.state["sweep"] = stats if isinstance(stats, dict) else None

        table = [n for n in arp.read_table()
                 if scope.allowed(n.ip) and n.mac not in cfg.exclude]
        self.state["neighbours"] = len(table)
        online: set[int] = set()
        by_ip: dict[str, int] = {}
        new_ids: list[int] = []

        own = [i for i in local_interfaces() if scope.contains(i.ip)]
        own_ips = {i.ip for i in own}
        entries = [(n.ip, n.mac, False) for n in table if n.ip not in own_ips]
        for i in own:
            # macOS can report a placeholder hardware address to background
            # processes; fall back to a stable interface based identity.
            entries.append((i.ip, i.mac if valid_mac(i.mac) else f"self:{i.name}", True))

        # 0.1.0 stored this Mac under a placeholder address: drop that stale row.
        db.drop_placeholder_devices(REDACTED_MACS)
        # Once macOS reports the real hardware address, retire the stand-in identity.
        db.drop_placeholder_devices(f"self:{i.name}" for i in own if valid_mac(i.mac))

        for ip, mac, is_self in entries:
            real = valid_mac(mac)
            before = db.device_ip(mac)
            was_online = db.device_online(mac)
            did, is_new = db.upsert_device(mac, ip, real and not is_self and is_randomized(mac))
            online.add(did)
            if before and ip and before != ip:
                db.add_event("ip_change", f"Address changed {before} to {ip}", did)
            by_ip[ip] = did
            if was_online is False and not is_self:
                db.add_event("device_online", "Device is back online", did)
            if is_new and not is_self:
                new_ids.append(did)
                db.add_event("device_new", f"New device {mac} at {ip}", did)
            if is_self:
                db.observe(did, "net", "role", "self")
                db.set_fields(did, hostname=socket.gethostname())
                me = db.get_device(did)
                if me and me["trust"] == "unknown":  # your own machine is never a stranger
                    db.set_fields(did, trust="known")
            vendor = self.oui.lookup(mac) if real else None
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
                if 443 in open_ports:
                    db.observe(by_ip[ip], "probe", "tls_expired", probes.tls_expired(ip) or "")
                if 21 in open_ports:
                    db.observe(by_ip[ip], "probe", "ftp_anon", probes.ftp_anonymous(ip))
            db.meta_set("scanned_ids", json.dumps(sorted(scanned_ids)))

        if db.meta_get("baseline_at") is None:
            db.meta_set("baseline_at", now())
            db.meta_set("baseline_count", str(len(online)))
            db.add_event("baseline", f"Baseline set with {len(online)} devices")
        elif int(db.meta_get("baseline_count") or 0) <= 1 < len(online):
            # The first scan only saw this machine (discovery was blind): start over,
            # otherwise every real device would be reported as a stranger.
            db.meta_set("baseline_at", now())
            db.meta_set("baseline_count", str(len(online)))
            db.add_event("baseline", f"Baseline reset with {len(online)} devices")

        try:
            self.wifi_refresh()
        except Exception:  # noqa: BLE001  a missing Wi-Fi reading must never break a scan
            pass
        try:
            self.cloud_sync()
        except Exception as exc:  # noqa: BLE001  the cloud must never break a scan
            self.state["cloud_errors"] = {"sync": f"{type(exc).__name__}: {exc}"}
        self.identify_all()
        self._auto_critical()
        self.evaluate(gateway_alert, scanned_ids)

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
            if d.get("class_source") in ("user", "cloud"):
                continue  # set by hand or told by the vendor cloud: never overridden
            facts = self.facts_for(d)
            cls, conf, evidence = engine.classify(facts, self.rules)
            source = "rules"
            if cls == "unknown" and self.cfg.ai_enabled and self.cfg.ai_endpoint:
                cls, conf, evidence, source = self._ask_ai(d, facts)
            self.db.set_classification(d["id"], cls, conf, source if cls != "unknown" else "", evidence)

    # ---- Tado and Netatmo -------------------------------------------------
    def cloud_sync(self, force: bool = False) -> dict:
        """Every 10 minutes: inventory of radio devices, and the real model of Wi-Fi ones."""
        if not self.cloud.connected():
            return {}
        if not force and time.time() - float(self.state.get("cloud_ts") or 0) < 600:
            return {}
        self.state["cloud_ts"] = time.time()
        devs, errors = self.cloud.fetch_all()
        self.state["cloud_errors"] = errors
        for source in self.cloud.connected():
            if source not in errors:
                self.db.replace_cloud(source, [d for d in devs if d["source"] == source])
        by_mac = {d["mac"].lower(): d for d in self.db.list_devices()}
        for r in devs:
            d = by_mac.get(str(r["ext_id"]).lower())
            if not d:
                continue
            self.db.observe(d["id"], "cloud", "model", r["model"])
            if r.get("firmware"):
                self.db.observe(d["id"], "cloud", "firmware", r["firmware"])
            if d.get("class_source") != "user":
                self.db.set_classification(d["id"], r["cls"], 0.95, "cloud", [{
                    "rule": f"cloud-{r['source']}", "label": f"{r['source'].title()} {r['model']}",
                    "confidence": 0.95, "matched": {"model": r["model"]},
                    "reason": "Reported by the vendor account you connected."}])
            if not d.get("label") and r.get("name"):
                self.db.set_fields(d["id"], label=r["name"])
        return {"devices": len(devs), "errors": errors}

    def wifi_refresh(self, force: bool = False) -> None:
        """Every 10 minutes: the encryption of the Wi-Fi this Mac uses (read only)."""
        if not force and time.time() - float(self.state.get("wifi_ts") or 0) < 600:
            return
        self.state["wifi_ts"] = time.time()
        self.state["wifi"] = wifi.security()

    def cloud_view(self) -> dict:
        return {**self.cloud.status(), "devices": self.db.list_cloud(),
                "errors": self.state.get("cloud_errors") or {}}

    def _auto_critical(self) -> None:
        """First time a device is classified, mark serious ones critical. Your choice wins after."""
        for d in self.db.list_devices():
            if d.get("critical") is None and d["class"] != "unknown":
                gw = self.db.observations(d["id"]).get("net.role") == "gateway"
                self.db.set_fields(d["id"], critical=1 if gw or d["class"] in ("lock", "camera") else 0)

    # ---- internet health --------------------------------------------------
    def run_speedtest(self) -> dict:
        if self.state.get("speedtest_running"):
            return {"started": False}
        self.state["speedtest_running"] = True
        try:
            r = speed.run(ssl_context(), lambda p: self.state.__setitem__("speedtest_phase", p))
            self.db.add_speedtest(r)
            return {"started": True, **r}
        finally:
            self.state["speedtest_running"] = False
            self.state["speedtest_phase"] = None

    def internet_watch(self, stop: threading.Event) -> None:
        """Every 15 s: is the Internet reachable, and how fast? Records outages with their duration."""
        down_since: float | None = None
        fails = 0
        series = self.state.setdefault("net_ping", [])
        while not stop.wait(15):
            ms = speed.ping()
            series.append({"ts": now(), "ms": ms})
            del series[:-60]
            ok = ms is not None
            fails = 0 if ok else fails + 1
            if down_since is None and fails >= 2:
                down_since = time.time() - 30
                self.db.add_event("internet_down", "Internet connection lost")
            elif down_since is not None and ok:
                mins = max(1, round((time.time() - down_since) / 60))
                self.db.add_event("internet_up", f"Internet back after about {mins} min")
                down_since = None

    def presence(self, device_id: int, hours: int = 168) -> dict:
        """Hour by hour over the last ``hours``: share of the hour spent online, None when unknown."""
        end = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        start = end - dt.timedelta(hours=hours)
        kinds = {"device_new": 1, "device_online": 1, "device_offline": 0}
        evs = sorted((e for e in self.db.list_events(2000, device_id=device_id) if e["kind"] in kinds),
                     key=lambda e: e["ts"])
        stamps = [(dt.datetime.fromisoformat(e["ts"]), kinds[e["kind"]]) for e in evs]
        dev = self.db.get_device(device_id)
        cells: list[float | None] = []
        online_s = known_s = 0.0
        for h in range(hours):
            a, b = start + dt.timedelta(hours=h), start + dt.timedelta(hours=h + 1)
            state = None
            for ts, st in stamps:
                if ts <= a:
                    state = st
            marks = [(max(ts, a), st) for ts, st in stamps if a < ts < b]
            cur, t0, on, known = state, a, 0.0, 0.0
            for ts, st in marks + [(b, None)]:
                span = (ts - t0).total_seconds()
                if cur is not None:
                    known += span
                    on += span if cur else 0
                cur, t0 = (st if st is not None else cur), ts
            if dev and dev["online"] and stamps and stamps[-1][1] == 1 and b > end:
                pass
            cells.append(round(on / 3600, 2) if known >= 1800 else None)
            online_s += on
            known_s += known
        return {"hours": hours, "cells": cells,
                "online_pct": round(100 * online_s / known_s) if known_s else None}

    def internet(self) -> dict:
        since = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=7)).replace(microsecond=0).isoformat()
        ev = self.db.list_events(300, since=since)
        tests = self.db.list_speedtests(30)
        pings = list(self.state.get("net_ping") or [])
        live = [p["ms"] for p in pings if p["ms"] is not None]
        return {"last": tests[-1] if tests else None, "history": tests,
                "outages_7d": sum(1 for e in ev if e["kind"] == "internet_down"),
                "running": bool(self.state.get("speedtest_running")),
                "phase": self.state.get("speedtest_phase"),
                "live": {"up": bool(pings) and pings[-1]["ms"] is not None,
                         "ms": pings[-1]["ms"] if pings else None,
                         "avg": round(sum(live) / len(live), 1) if live else None,
                         "series": pings[-30:]}}

    def set_class(self, device_id: int, cls: str) -> list[str]:
        """Manual type for one device. Teaches Kaa and returns names of devices it also changed."""
        d = self.db.get_device(device_id)
        if cls == "auto":
            self.db.set_classification(device_id, "unknown", 0.0, "", [])
            self.identify_all()
            return []
        before = {x["id"]: x["class"] for x in self.db.list_devices()}
        evidence = [{"rule": "manual", "label": "Set by you", "confidence": 1.0, "matched": {}}]
        self.db.set_classification(device_id, cls, 1.0, "user", evidence)
        rule = learn.build_rule(cls, self.facts_for(d))
        if rule:
            learn.remember(self.cfg.user_signatures, rule)
            self.rules = engine.load_rules(builtin_signatures(), self.cfg.user_signatures)
        self.identify_all()
        changed = []
        for x in self.db.list_devices():
            if x["id"] != device_id and x["class"] == cls and before.get(x["id"]) != cls:
                changed.append(x.get("label") or x.get("hostname") or x.get("vendor") or x["mac"])
        return changed

    def _ask_ai(self, d: dict, facts: dict) -> tuple[str, float, list[dict], str]:
        h = llm.facts_hash(facts)
        if self.db.observations(d["id"]).get("ai.facts_hash") == h:
            return "unknown", 0.0, [], ""  # same metadata as last attempt, do not ask again
        try:
            res = llm.resolve(facts, self.cfg.ai_endpoint, self.cfg.ai_model,
                              self.cfg.ai_allow_remote, provider=self.cfg.ai_provider,
                              key=self.cfg.ai_key)
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
        hour_ago = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=1)
                    ).replace(microsecond=0).isoformat()
        flaps: dict[int, int] = {}
        for e in self.db.list_events(500, since=hour_ago):
            if e["kind"] == "device_offline" and e["device_id"] is not None:
                flaps[e["device_id"]] = flaps.get(e["device_id"], 0) + 1
        offline_min: dict[int, float] = {}
        for d in devices:
            if d.get("critical") == 1 and not d["online"]:
                last = dt.datetime.fromisoformat(d["last_seen"])
                offline_min[d["id"]] = (dt.datetime.now(dt.timezone.utc) - last).total_seconds() / 60
        ctx = {"baseline_at": self.db.meta_get("baseline_at"), "flaps": flaps, "offline_min": offline_min,
               "scanned_ids": scanned_ids, "gateway_alert": gateway_alert,
               "cloud": self.db.list_cloud(), "wifi": self.state.get("wifi"),
               "kev": self._kev_model_hits(devices),
               "exposure": (self.exposure()["data"] or {}) if self.cfg.exposure else {}}
        self.db.sync_findings(findings_mod.evaluate(devices, ctx))
        result = scoring.compute(self.db.list_findings())
        self.db.add_score(result["value"], result)

    # ---- notifications and daily summary ----------------------------------
    NOTIFY_SEVERITIES = ("medium", "high", "critical")

    def quiet_now(self, when: dt.datetime | None = None) -> bool:
        c = self.cfg
        return notify_mod.is_quiet(
            when or dt.datetime.now(),
            notify_mod.parse_clock(c.quiet_start, dt.time(22, 0)),
            notify_mod.parse_clock(c.wake_weekday, dt.time(7, 30)),
            notify_mod.parse_clock(c.wake_weekend, dt.time(9, 0)))

    def _alerts(self) -> None:
        """Notify once for each new alert, then once a day with a summary.

        During quiet hours nothing is sent and nothing is forgotten: the alerts
        stay pending and go out together at wake up time.
        """
        db = self.db
        top = max((f["id"] for f in db.list_findings()), default=0)
        last = db.meta_get("notified_finding_id")
        if last is None:  # first run: do not flood with history
            db.meta_set("notified_finding_id", str(top))
            return
        if not self.cfg.notify:
            db.meta_set("notified_finding_id", str(top))
            return
        if self.quiet_now():
            return
        db.meta_set("notified_finding_id", str(top))
        fresh = [f for f in db.list_findings("open") if f["id"] > int(last)
                 and f["severity"] in self.NOTIFY_SEVERITIES]
        if fresh:
            fresh.sort(key=lambda f: scoring.PENALTY.get(f["severity"], 0), reverse=True)
            head = fresh[0]["title"]
            more = f" (+{len(fresh) - 1} more)" if len(fresh) > 1 else ""
            notify_mod.send("Kaa: new alert", head + more)
        hour = self.cfg.digest_hour
        today = dt.date.today().isoformat()
        if 0 <= hour <= 23 and dt.datetime.now().hour >= hour \
                and db.meta_get("digest_date") != today:
            db.meta_set("digest_date", today)
            notify_mod.send("Kaa: last 24 hours", self.digest()["headline"])

    def digest(self, hours: int = 24) -> dict:
        db = self.db
        since = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=hours)
                 ).replace(microsecond=0).isoformat()
        events = db.list_events(500, since=since)
        # one device flapping ten times is one device, not ten
        count = lambda kind: len({e["device_id"] if e["device_id"] is not None else e["id"]  # noqa: E731
                                  for e in events if e["kind"] == kind})
        findings = db.list_findings()
        opened = [f for f in findings if f["first_seen"] >= since]
        resolved = [f for f in findings if f["status"] == "resolved" and f["last_seen"] >= since]
        summary = self.summary()
        before = db.score_at_or_before(since)
        now_score = summary["score"]["value"]
        parts = [f"score {now_score}" + (f" ({now_score - before:+d})" if before is not None
                                         and before != now_score else ""),
                 f"{summary['online']}/{summary['devices']} devices online"]
        if count("device_new"):
            parts.append(f"{count('device_new')} new")
        if opened:
            parts.append(f"{len(opened)} alert(s) opened")
        if resolved:
            parts.append(f"{len(resolved)} resolved")
        return {"since": since, "score": now_score, "score_before": before,
                "new_devices": count("device_new"), "went_offline": count("device_offline"),
                "alerts_opened": [f["title"] for f in opened][:10],
                "alerts_resolved": [f["title"] for f in resolved][:10],
                "headline": ", ".join(parts)}

    def report(self, days: int = 7) -> dict:
        """Facts for the weekly report: changes, open issues, Internet health, threats."""
        d = self.digest(days * 24)
        scores = [x["value"] for x in self.db.list_scores(2000)
                  if x["ts"] >= d["since"]] or [d["score"]]
        tests = [t for t in self.db.list_speedtests(500) if t["ts"] >= d["since"]]
        avg = lambda k: round(sum(t[k] for t in tests if t[k] is not None) / max(1, sum(1 for t in tests if t[k] is not None)), 1) if tests else None  # noqa: E731
        ev = self.db.list_events(1000, since=d["since"])
        open_f = [f for f in self.db.list_findings("open") if f["severity"] != "info"]
        return {
            "days": days, "since": d["since"], "score": d["score"],
            "score_min": min(scores), "score_max": max(scores), "score_start": d["score_before"],
            "new_devices": d["new_devices"], "went_offline": d["went_offline"],
            "alerts_opened": d["alerts_opened"], "alerts_resolved": d["alerts_resolved"],
            "open": [{"severity": f["severity"], "title": f["title"], "device_id": f["device_id"]}
                     for f in sorted(open_f, key=lambda f: scoring.PENALTY.get(f["severity"], 0), reverse=True)][:15],
            "internet": {"tests": len(tests), "avg_down": avg("down"), "avg_up": avg("up"),
                         "avg_latency": avg("latency"),
                         "outages": sum(1 for e in ev if e["kind"] == "internet_down")},
            "threat_matches": len(self.threats()["items"]) if self.cfg.threats else None,
            "devices": self.summary()["devices"], "online": self.summary()["online"],
        }

    # ---- AI analyst -----------------------------------------------------
    def _ai_on(self) -> bool:
        return bool(self.cfg.ai_enabled and self.cfg.ai_endpoint)

    def _ai_facts(self) -> dict:
        """What the model may know: names, types, states, findings. Never MAC or IP addresses."""
        devs = self.db.list_devices()
        names = {d["id"]: (d.get("label") or d.get("hostname") or d.get("vendor") or "unknown") for d in devs}
        return {
            "devices": [{"name": names[d["id"]], "class": d.get("class"), "vendor": d.get("vendor"),
                         "online": bool(d.get("online")), "trust": d.get("trust"),
                         "critical": d.get("critical") == 1} for d in devs][:60],
            "findings": [{"id": f["id"], "rule": f["rule_id"], "severity": f["severity"], "title": f["title"],
                          "device": names.get(f["device_id"]), "detail": f.get("detail", "")}
                         for f in self.db.list_findings("open")][:25],
            "threats": [{"cve": t["cve"], "product": t["product"], "devices": t["devices"],
                         "ransomware": t["ransomware"]} for t in self.threats()["items"][:8]],
        }

    def _ai(self, task: str, user: str, max_tokens: int = 700) -> dict:
        if not self._ai_on():
            return {"enabled": False, "text": ""}
        user = _scrub(user)  # last line of defence: no hardware or IP address leaves the Mac
        lang = "French" if self.cfg.lang == "fr" else "English"
        system = ("You are the security analyst of a home network, inside an app called Kaa. "
                  f"Answer in {lang}. Use only the facts given; never invent a device, CVE, "
                  "setting or number. If the facts do not answer, say so. Be concise and concrete. "
                  "Plain text only: no Markdown, no asterisks, no headings. "
                  + task)
        try:
            text = llm.complete(system, user, self.cfg.ai_endpoint, self.cfg.ai_model,
                                self.cfg.ai_provider, self.cfg.ai_key, self.cfg.ai_allow_remote, max_tokens)
            return {"enabled": True, "text": text.strip(), "error": None}
        except Exception as exc:  # noqa: BLE001
            return {"enabled": True, "text": "", "error": f"{type(exc).__name__}: {exc}"}

    def ai_brief(self) -> dict:
        return self._ai("Write a briefing: one sentence verdict, then at most 4 prioritised actions, "
                        "each naming the exact device.", json.dumps(self._ai_facts()), 600)

    def ai_ask(self, question: str) -> dict:
        q = question.strip()[:500]
        return self._ai("Answer the user's question about their network. At most 120 words.",
                        json.dumps({"facts": self._ai_facts(), "question": q}), 500)

    def ai_explain(self, finding_id: int) -> dict:
        f = next((x for x in self.db.list_findings() if x["id"] == finding_id), None)
        if not f:
            return {"enabled": self._ai_on(), "text": "", "error": "unknown finding"}
        dev = self.db.get_device(f["device_id"]) if f["device_id"] else None
        info = {"finding": {"rule": f["rule_id"], "severity": f["severity"], "title": f["title"],
                            "detail": f["detail"], "evidence": f["evidence"]},
                "device": {"name": (dev or {}).get("label") or (dev or {}).get("hostname") or (dev or {}).get("vendor"),
                           "class": (dev or {}).get("class"), "vendor": (dev or {}).get("vendor")}}
        return self._ai("Explain this alert for this exact device: what it means in practice, how real the "
                        "risk is at home, then numbered steps to fix it. At most 150 words.",
                        json.dumps(info), 600)

    def ai_triage(self) -> dict:
        """Which listed exploited vulnerabilities truly concern the devices you own."""
        items = self.threats()["items"][:8]
        if not items:
            return {"enabled": self._ai_on(), "text": "", "error": None, "items": []}
        facts = {"devices": self._ai_facts()["devices"], "vulnerabilities": [
            {"cve": t["cve"], "vendor": t["vendor"], "product": t["product"], "name": t["name"],
             "summary": t["summary"], "matched_devices": t["devices"]} for t in items]}
        r = self._ai('Return only a JSON array, one object per vulnerability: {"cve": str, '
                     '"relevant": "yes"|"maybe"|"no", "why": one short sentence}. Say "no" when the '
                     "product is clearly not something these devices run (for example enterprise "
                     "software, or a different product line of the same vendor).",
                     json.dumps(facts), 900)
        parsed: list = []
        m = re.search(r"\[.*\]", r.get("text", ""), re.S)
        if m:
            try:
                parsed = [x for x in json.loads(m.group(0)) if isinstance(x, dict) and "cve" in x]
            except ValueError:
                parsed = []
        r["items"] = parsed
        return r

    # ---- threat watch ---------------------------------------------------
    @property
    def kev_path(self) -> Path:
        return self.cfg.data_dir / "kev.json"

    def refresh_threats(self, force: bool = False) -> None:
        """Download the catalogue when it is missing or older than a day."""
        if not self.cfg.threats:
            return
        path = self.kev_path
        fresh = path.exists() and time.time() - path.stat().st_mtime < 86400
        if fresh and not force:
            return
        try:
            threats.download(path)
            self.state["threats_error"] = None
        except Exception as exc:  # offline, blocked, malformed: never stop the service
            self.state["threats_error"] = f"{type(exc).__name__}: {exc}"

    def _kev_entries(self) -> list[dict]:
        if not self.cfg.threats:
            return []
        path = self.kev_path
        try:
            mtime = path.stat().st_mtime
        except OSError:
            return []
        cached = getattr(self, "_kev_cache", None)
        if not cached or cached[0] != mtime:
            self._kev_cache = cached = (mtime, threats.load(path))
        return cached[1]

    def _kev_inputs(self) -> tuple[list[dict], dict]:
        """LAN devices and radio devices (Tado, Netatmo) with what is known of their exact product."""
        devs = self.db.list_devices()
        profiles = {d["id"]: threats.profile(d, self.db.observations(d["id"])) for d in devs}
        macs = {str(d["mac"]).lower() for d in devs}
        names = " ".join(f"{d.get('hostname') or ''} {d.get('label') or ''}" for d in devs).lower()
        for r in self.db.list_cloud():
            rid = str(r["ext_id"]).lower()
            if rid in macs or (len(rid) >= 6 and rid in names):  # already listed as a network device
                continue
            pseudo = {"id": None, "mac": f"{r['source']}:{r['ext_id']}", "vendor": r["source"],
                      "label": r.get("name") or r.get("kind"), "hostname": None}
            devs.append(pseudo)
            profiles[pseudo["mac"]] = threats.profile(
                pseudo, {"cloud.model": f"{r.get('model') or ''} {r.get('kind') or ''}".strip(),
                         "cloud.firmware": r.get("firmware")})
        return devs, profiles

    def _kev_model_hits(self, devices: list[dict]) -> dict[int, dict]:
        """Per LAN device: the exploited flaws whose product matches its model (finding input)."""
        entries = self._kev_entries()
        if not entries:
            return {}
        devs, profiles = self._kev_inputs()
        hits: dict[int, dict] = {}
        for it in threats.match(entries, devs, self.cfg.threat_keywords, profiles=profiles, limit=200):
            if it["match"] != "model":
                continue
            for did in it["device_ids"]:
                h = hits.setdefault(did, {"cve": it["cve"], "product": it["product"], "count": 0,
                                          "firmware": profiles[did].get("firmware") or "unknown", "ransomware": 0})
                h["count"] += 1
                h["ransomware"] = int(bool(h["ransomware"] or it["ransomware"]))
        return hits

    def threats(self) -> dict:
        path = self.kev_path
        entries = self._kev_entries()
        updated = (dt.datetime.fromtimestamp(path.stat().st_mtime, dt.timezone.utc)
                   .replace(microsecond=0).isoformat() if path.exists() else None)
        devs, profiles = self._kev_inputs()
        known = [p for p in profiles.values()]
        return {"enabled": self.cfg.threats, "updated": updated, "catalog": len(entries),
                "error": self.state.get("threats_error"),
                "coverage": {"devices": len(devs), "with_model": sum(1 for p in known if p["model_keys"]),
                             "with_firmware": sum(1 for p in known if p["firmware"])},
                "items": threats.match(entries, devs, self.cfg.threat_keywords, profiles=profiles)
                if entries else []}

    # ---- network hygiene ------------------------------------------------
    def hygiene(self) -> list[dict]:
        """Plain checks for the home page: status ok / warn / na, with the numbers behind it."""
        live = [f for f in self.db.list_findings() if f["status"] in ("open", "ack")]
        by_rule: dict[str, list[dict]] = {}
        for f in live:
            by_rule.setdefault(f["rule_id"], []).append(f)
        has = lambda *ids: sum(len(by_rule.get(i, [])) for i in ids)  # noqa: E731

        def flag(*ids: str) -> str:
            """warn while something is open; ack when everything left was acknowledged."""
            found = [f for i in ids for f in by_rule.get(i, [])]
            return "warn" if any(f["status"] == "open" for f in found) else "ack" if found else "ok"
        scanned = bool(json.loads(self.db.meta_get("scanned_ids") or "[]"))
        wifi_now = self.state.get("wifi")
        checks: list[dict] = []

        def add(cid: str, status: str, **ev: Any) -> None:
            checks.append({"id": cid, "status": status, "ev": ev})

        if wifi_now:
            add("wifi", flag("KAA-WIFI-WEAK"), mode=wifi_now["label"])
        else:
            add("wifi", "na")
        add("upnp", flag("KAA-UPNP-IGD"))
        exposed = has("KAA-PORT-TELNET", "KAA-PORT-FTP", "KAA-PORT-RDP", "KAA-PORT-VNC", "KAA-PORT-RTSP",
                      "KAA-PORT-MQTT", "KAA-LOCK-EXPOSED", "KAA-FTP-ANON", "KAA-CAMERA-HTTP", "KAA-GW-HTTP")
        add("exposed", flag("KAA-PORT-TELNET", "KAA-PORT-FTP", "KAA-PORT-RDP", "KAA-PORT-VNC", "KAA-PORT-RTSP",
                            "KAA-PORT-MQTT", "KAA-LOCK-EXPOSED", "KAA-FTP-ANON", "KAA-CAMERA-HTTP", "KAA-GW-HTTP")
            if exposed else ("ok" if scanned else "na"), n=exposed)
        ex = self.exposure()
        if ex["data"] is not None:
            add("exposure", flag("KAA-EXPOSED-PORTS", "KAA-EXPOSED-VULNS"), n=len(ex["data"]["ports"]))
        else:
            add("exposure", "na")
        seg = by_rule.get("KAA-NO-SEGMENTATION")
        add("seg", flag("KAA-NO-SEGMENTATION"), **({k: v for k, v in seg[0]["evidence"].items() if k in ("iot", "people")} if seg else {}))
        review = has("KAA-NEW-DEVICE", "KAA-UNIDENTIFIED")
        add("review", flag("KAA-NEW-DEVICE", "KAA-UNIDENTIFIED"), n=review)
        add("gw", flag("KAA-GATEWAY-MAC-CHANGED"))
        if self.cfg.threats and self.kev_path.exists():
            th = self.threats()
            hits = sum(1 for i in th["items"] if i["match"] == "model")
            add("kev", "warn" if hits else "ok", n=hits, devices=th["coverage"]["devices"])
        else:
            add("kev", "na")
        if self.cloud.connected():
            n = has("KAA-CLOUD-BATTERY", "KAA-CLOUD-OFFLINE")
            add("radio", flag("KAA-CLOUD-BATTERY", "KAA-CLOUD-OFFLINE"), n=n)
        return checks

    # ---- exposure (opt in) ------------------------------------------------
    def refresh_exposure(self, force: bool = False) -> None:
        """At most every 12 hours: what Shodan's InternetDB has seen open on the public address."""
        if not self.cfg.exposure:
            return
        last = float(self.db.meta_get("exposure_ts") or 0)
        if not force and time.time() - last < 43200:
            return
        try:
            ctx = ssl_context()
            ip = exposure_mod.public_ip(ctx)
            if not ip:
                raise ValueError("public address not found")
            seen = exposure_mod.lookup(ip, ctx)
            self.db.meta_set("exposure", json.dumps({**seen, "ip": exposure_mod.mask(ip)}))
            self.db.meta_set("exposure_ts", str(time.time()))
            self.state["exposure_error"] = None
        except Exception as exc:  # noqa: BLE001  offline or blocked: never stop the service
            self.state["exposure_error"] = f"{type(exc).__name__}: {exc}"

    def exposure(self) -> dict:
        raw = self.db.meta_get("exposure")
        data = json.loads(raw) if (raw and self.cfg.exposure) else None
        ts = self.db.meta_get("exposure_ts")
        return {"enabled": self.cfg.exposure, "data": data, "error": self.state.get("exposure_error"),
                "checked": (dt.datetime.fromtimestamp(float(ts), dt.timezone.utc).replace(microsecond=0).isoformat()
                            if ts and data else None)}

    # ---- background loop ----------------------------------------------
    def loop(self, stop: threading.Event) -> None:
        threading.Thread(target=self.internet_watch, args=(stop,), daemon=True).start()
        while not stop.is_set():
            threading.Thread(target=self.refresh_threats, daemon=True).start()
            threading.Thread(target=self.refresh_exposure, daemon=True).start()
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
