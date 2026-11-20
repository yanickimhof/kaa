from test_service import world  # noqa: F401  (shared fixture)

from kaa import notify
from kaa import service as svc
from kaa.collectors import arp


def test_first_run_is_silent_then_new_alert_notifies_once(world, monkeypatch):
    service, state = world
    sent = []
    monkeypatch.setattr(svc.notify_mod, "send", lambda t, m: sent.append((t, m)) or True)
    service.cfg.digest_hour = -1
    monkeypatch.setattr(service, "quiet_now", lambda when=None: False)  # tests must not depend on the clock
    service.run_cycle()
    assert sent == []  # history never floods the first run
    service.db.meta_set("baseline_at", "2000-01-01T00:00:00+00:00")  # timestamps have 1 s resolution
    full = list(state["v"])
    state["v"] = full + [arp.Neighbour("192.168.50.77", "a4:83:e7:00:11:22")]
    service.run_cycle()
    assert len(sent) == 1 and "New device" in sent[0][1]
    service.run_cycle()
    assert len(sent) == 1  # the same alert is not repeated


def test_notifications_can_be_switched_off(world, monkeypatch):
    service, state = world
    sent = []
    monkeypatch.setattr(svc.notify_mod, "send", lambda t, m: sent.append(m) or True)
    service.cfg.notify = False
    service.cfg.digest_hour = -1
    service.run_cycle()
    state["v"] = state["v"] + [arp.Neighbour("192.168.50.77", "a4:83:e7:00:11:22")]
    service.run_cycle()
    assert sent == []


def test_digest_counts_changes(world):
    service, _ = world
    service.run_cycle()
    d = service.digest()
    assert d["score"] == service.summary()["score"]["value"]
    assert isinstance(d["headline"], str) and "devices online" in d["headline"]


def test_daily_digest_is_sent_once_per_day(world, monkeypatch):
    service, _ = world
    sent = []
    monkeypatch.setattr(svc.notify_mod, "send", lambda t, m: sent.append(t) or True)
    service.cfg.digest_hour = 0
    monkeypatch.setattr(service, "quiet_now", lambda when=None: False)
    service.run_cycle()   # first run only records state
    service.run_cycle()
    service.run_cycle()
    assert sent.count("Kaa: last 24 hours") == 1


def test_applescript_quoting():
    assert notify._applescript('a "b" \\c') == 'a \\"b\\" \\\\c'




def test_digest_and_history_endpoints(world):
    from fastapi.testclient import TestClient

    from kaa.api import create_app
    service, _ = world
    service.run_cycle()
    c = TestClient(create_app(service, "secret"), base_url="http://127.0.0.1:8473")
    d = c.get("/api/digest").json()
    assert {"score", "new_devices", "alerts_opened", "headline"} <= set(d)
    dev = c.get("/api/devices").json()[0]
    h = c.get(f"/api/devices/{dev['id']}").json()["history"]
    assert isinstance(h, list)


def test_quiet_hours_weekday_and_weekend():
    import datetime as dt
    s, wd, we = dt.time(22, 0), dt.time(7, 30), dt.time(9, 0)
    mon = lambda h, m: dt.datetime(2026, 11, 16, h, m)   # Monday  # noqa: E731
    sat = lambda h, m: dt.datetime(2026, 11, 21, h, m)   # Saturday  # noqa: E731
    assert notify.is_quiet(mon(7, 29), s, wd, we) and not notify.is_quiet(mon(7, 30), s, wd, we)
    assert notify.is_quiet(sat(8, 59), s, wd, we) and not notify.is_quiet(sat(9, 0), s, wd, we)
    assert notify.is_quiet(mon(23, 0), s, wd, we) and not notify.is_quiet(mon(21, 59), s, wd, we)


def test_alerts_raised_while_quiet_are_sent_at_wake_up(world, monkeypatch):
    service, state = world
    sent = []
    monkeypatch.setattr(svc.notify_mod, "send", lambda t, m: sent.append(m) or True)
    service.cfg.digest_hour = -1
    service.run_cycle()
    service.db.meta_set("baseline_at", "2000-01-01T00:00:00+00:00")
    state["v"] = state["v"] + [arp.Neighbour("192.168.50.77", "a4:83:e7:00:11:22")]
    monkeypatch.setattr(service, "quiet_now", lambda when=None: True)
    service.run_cycle()
    assert sent == []                      # held back during the night
    monkeypatch.setattr(service, "quiet_now", lambda when=None: False)
    service.run_cycle()
    assert len(sent) == 1                  # delivered once at wake up


def test_flapping_device_raises_a_low_alert_and_ip_change_is_recorded(world):
    service, state = world
    service.run_cycle()
    dev = next(d for d in service.db.list_devices() if d["ip"] == "192.168.50.20")
    for _ in range(4):
        service.db.add_event("device_offline", "Device went offline", dev["id"])
    state["v"] = [n if n.ip != "192.168.50.20" else arp.Neighbour("192.168.50.99", n.mac)
                  for n in state["v"]]
    service.run_cycle()
    rules = {f["rule_id"] for f in service.db.list_findings("open")}
    assert "KAA-FLAPPING" in rules
    assert any(e["kind"] == "ip_change" for e in service.db.list_events(50))


def test_settings_threats_and_ai_endpoints(world, monkeypatch):
    from fastapi.testclient import TestClient

    from kaa.api import create_app
    service, _ = world
    service.run_cycle()
    monkeypatch.setattr(service, "refresh_threats", lambda force=False: None)
    c = TestClient(create_app(service, "secret"), base_url="http://127.0.0.1:8473")
    hdr = {"X-Kaa-Token": "secret"}
    assert c.get("/api/settings").json()["notify"] is True
    assert c.put("/api/settings", json={"notify": False}).status_code in (401, 403)
    r = c.put("/api/settings", json={"notify": False, "wake_weekday": "06:30"}, headers=hdr)
    assert r.status_code == 200 and r.json()["wake_weekday"] == "06:30"
    assert c.put("/api/settings", json={"interval": 1}, headers=hdr).status_code == 422
    assert c.put("/api/settings", json={"host": "0.0.0.0"}, headers=hdr).status_code == 422
    t = c.get("/api/threats").json()
    assert t["enabled"] is False and t["items"] == []
    b = c.post("/api/ai/brief", headers=hdr).json()
    assert b["enabled"] is False
    page = c.get("/").text
    assert 'id="brief"' in page and 'id="hygiene"' in page


def test_manual_type_sticks_and_teaches_similar_devices(world):
    from fastapi.testclient import TestClient

    from kaa.api import create_app
    from kaa.identify import learn
    assert learn.hostname_stem("eero-living-room") == "eero"
    assert learn.hostname_stem("Shelly1-A4CF12.local") == "shelly"
    assert learn.hostname_stem("tv") is None
    service, _ = world
    service.run_cycle()
    a = service.db.list_devices()[0]
    service.db.set_fields(a["id"], hostname="gizmo-kitchen")
    c = TestClient(create_app(service, "secret"), base_url="http://127.0.0.1:8473")
    r = c.patch(f"/api/devices/{a['id']}", json={"device_class": "plug"}, headers={"X-Kaa-Token": "secret"})
    assert r.status_code == 200 and r.json()["class"] == "plug" and r.json()["class_source"] == "user"
    from kaa.identify import engine
    similar = {"vendor": None, "hostname": "gizmo-garage", "randomized_mac": False, "is_gateway": False,
               "mdns_services": [], "mdns_names": [], "ssdp_server": "", "ssdp_st": [], "open_ports": []}
    assert engine.classify(similar, service.rules)[0] == "plug"            # cascaded by the learned rule
    service.run_cycle()                                                     # and it survives a rescan
    assert service.db.get_device(a["id"])["class"] == "plug"
    assert c.patch(f"/api/devices/{a['id']}", json={"device_class": "toaster"},
                   headers={"X-Kaa-Token": "secret"}).status_code == 422


def test_findings_are_served_in_the_chosen_language_and_critical_devices_are_watched(world):
    from fastapi.testclient import TestClient

    from kaa.api import create_app
    service, _ = world
    service.run_cycle()
    c = TestClient(create_app(service, "secret"), base_url="http://127.0.0.1:8473")
    fr = c.get("/api/findings?lang=fr").json()
    en = c.get("/api/findings?lang=en").json()
    assert any("UPnP" in f["title"] and "activé" in f["title"] for f in fr)
    assert any("UPnP is enabled" in f["title"] for f in en)
    hdr = {"X-Kaa-Token": "secret"}
    assert c.put("/api/settings", json={"lang": "de"}, headers=hdr).status_code == 422
    assert c.put("/api/settings", json={"lang": "en"}, headers=hdr).json()["lang"] == "en"
    # a critical device that vanished raises a finding after 15 minutes
    dev = next(d for d in service.db.list_devices() if d["ip"] == "192.168.50.20")
    c.patch(f"/api/devices/{dev['id']}", json={"critical": True}, headers=hdr)
    service.db._x("update devices set online=0, last_seen='2000-01-01T00:00:00+00:00' where id=?", (dev["id"],))
    service.evaluate()
    assert "KAA-CRITICAL-OFFLINE" in {f["rule_id"] for f in service.db.list_findings("open")}


def test_report_and_internet_endpoints(world, monkeypatch):
    from fastapi.testclient import TestClient

    from kaa.api import create_app
    from kaa.collectors import speed
    service, _ = world
    service.run_cycle()
    monkeypatch.setattr(speed, "run", lambda ctx, progress=None: {"latency": 12.5, "jitter": 1.0, "loss": 0.0, "down": 480.0, "up": 95.0})
    assert service.run_speedtest()["down"] == 480.0
    c = TestClient(create_app(service, "secret"), base_url="http://127.0.0.1:8473")
    net = c.get("/api/internet").json()
    assert net["last"]["down"] == 480.0 and net["outages_7d"] == 0
    assert c.get("/api/report").status_code == 404           # the weekly report was retired


def test_ai_features_use_the_model_with_facts_and_never_addresses(world, monkeypatch):
    from fastapi.testclient import TestClient

    from kaa.api import create_app
    from kaa.identify import llm
    service, _ = world
    service.run_cycle()
    service.cfg.ai_enabled, service.cfg.ai_endpoint = True, "https://api.anthropic.com/v1"
    service.cfg.ai_provider, service.cfg.ai_key, service.cfg.ai_allow_remote = "anthropic", "k", True
    seen = []

    def fake(system, user, *a, **k):
        seen.append((system, user))
        return '[{"cve": "CVE-1", "relevant": "no", "why": "other product"}]' if "JSON array" in system else "ok"

    monkeypatch.setattr(llm, "complete", fake)
    c = TestClient(create_app(service, "secret"), base_url="http://127.0.0.1:8473")
    h = {"X-Kaa-Token": "secret"}
    assert c.post("/api/ai/ask", json={"question": "Qui est le plus risqué ?"}, headers=h).json()["text"] == "ok"
    fid = service.db.list_findings("open")[0]["id"]
    assert c.post("/api/ai/explain", json={"finding_id": fid}, headers=h).json()["text"] == "ok"
    assert "French" in seen[0][0]                      # default language is French
    blob = " ".join(u for _, u in seen)
    assert "192.168" not in blob and "aa:bb" not in blob.lower()   # no addresses leave the Mac
    monkeypatch.setattr(service, "threats", lambda: {"items": [{"cve": "CVE-1", "vendor": "v", "product": "p", "name": "n", "summary": "s", "devices": ["x"], "ransomware": False}]})
    t = c.post("/api/ai/triage", headers=h).json()
    assert t["items"][0]["relevant"] == "no"


def test_scrub_removes_every_address():
    from kaa.service import _scrub
    out = _scrub('New device a4:83:e7:00:11:22 at 192.168.4.77 id CF0C59B1548C1ADA-07BE9DC40A17BA51')
    assert "a4:83" not in out and "192.168" not in out and "CF0C59B1" not in out
