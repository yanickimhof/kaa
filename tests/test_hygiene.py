import datetime as dt

from fastapi.testclient import TestClient

from kaa import findings, threats
from kaa.api import create_app
from kaa.collectors import wifi

TODAY = dt.date(2026, 11, 20)
KEV = [
    {"cveID": "CVE-2026-1111", "vendorProject": "Nuki", "product": "SL-3000 Smart Lock", "dateAdded": "2025-06-01",
     "knownRansomwareCampaignUse": "Unknown"},
    {"cveID": "CVE-2026-2222", "vendorProject": "Acme", "product": "Router", "dateAdded": "2026-10-01"},
    {"cveID": "CVE-2026-3333", "vendorProject": "Acme", "product": "RT-AC66U", "dateAdded": "2024-03-01",
     "knownRansomwareCampaignUse": "Known"},
]


def test_model_match_needs_the_product_not_just_a_generic_word():
    lock = {"id": 7, "mac": "aa", "vendor": "Silicon Laboratories", "label": "Nuki Lock", "hostname": None}
    other = {"id": 8, "mac": "bb", "vendor": "Acme Inc.", "label": None, "hostname": "router"}
    profiles = {7: threats.profile(lock, {"cloud.model": "Nuki SL-3000", "cloud.firmware": "3.4.1"}),
                8: threats.profile(other, {})}
    got = threats.match(KEV, [lock, other], profiles=profiles, today=TODAY)
    by = {g["cve"]: g for g in got}
    assert by["CVE-2026-1111"]["match"] == "model" and by["CVE-2026-1111"]["device_ids"] == [7]
    assert by["CVE-2026-1111"]["models"][0]["firmware"] == "3.4.1"
    # "router" alone is a generic word: only the plain vendor match remains, and it is not a model match
    assert by["CVE-2026-2222"]["match"] == "vendor" and by["CVE-2026-2222"]["device_ids"] == []
    assert got[0]["match"] == "model"                       # model matches come first


def test_a_model_number_matches_even_without_the_vendor():
    d = {"id": 3, "mac": "cc", "vendor": None, "label": None, "hostname": "RT-AC66U-1A2B"}
    got = threats.match(KEV, [d], profiles={3: threats.profile(d, {})}, today=TODAY)
    assert [g["cve"] for g in got] == ["CVE-2026-3333"] and got[0]["match"] == "model"


def _dev(i, cls, trust="known", label=None):
    return {"id": i, "mac": f"02:00:00:00:00:{i:02d}", "ip": f"192.168.1.{i}", "class": cls, "trust": trust,
            "label": label or f"dev{i}", "hostname": None, "vendor": None, "randomized": False,
            "first_seen": "2026-01-01T00:00:00+00:00", "online": True, "critical": 0, "facts": {}}


def test_segmentation_and_weak_wifi_findings():
    devs = [_dev(1, "computer"), _dev(2, "camera"), _dev(3, "lock"), _dev(4, "appliance")]
    rules = {s.rule_id: s for s in findings.evaluate(devs, {"wifi": {"mode": "wep", "label": "WEP"}})}
    assert rules["KAA-NO-SEGMENTATION"].evidence["iot"] == 3
    assert rules["KAA-WIFI-WEAK"].severity == "high"
    guest = [_dev(1, "computer")] + [_dev(i, "camera", trust="guest") for i in (2, 3, 4)]
    assert "KAA-NO-SEGMENTATION" not in {s.rule_id for s in findings.evaluate(guest, {"wifi": {"mode": "wpa3"}})}


def test_model_finding_is_medium_and_high_with_ransomware():
    devs = [_dev(5, "lock", label="Nuki Lock")]
    kev = {5: {"cve": "CVE-1", "product": "Smart Lock", "count": 1, "firmware": "unknown", "ransomware": 0}}
    spec = next(s for s in findings.evaluate(devs, {"kev": kev}) if s.rule_id == "KAA-KEV-MODEL")
    assert spec.severity == "medium" and "CVE-1" in spec.detail
    kev[5]["ransomware"] = 1
    assert next(s for s in findings.evaluate(devs, {"kev": kev}) if s.rule_id == "KAA-KEV-MODEL").severity == "high"


def test_wifi_security_mapping():
    assert wifi.classify("spairport_security_mode_wpa3_transition") == {"mode": "wpa3", "label": "WPA3 (transition)"}
    assert wifi.classify("spairport_security_mode_wpa2_personal")["mode"] == "wpa2"
    assert wifi.classify("spairport_security_mode_none")["mode"] == "open"
    assert wifi.classify("spairport_security_mode_wep")["mode"] == "wep"
    assert wifi.classify("spairport_security_mode_wpa_personal")["mode"] == "wpa"
    assert wifi.classify("something odd") is None


def test_hygiene_endpoint_reports_each_check(env):
    cfg, db, service = env
    service.state["wifi"] = {"mode": "wep", "label": "WEP"}
    service.evaluate()
    c = TestClient(create_app(service, "secret"), base_url="http://127.0.0.1:8473")
    checks = {x["id"]: x for x in c.get("/api/hygiene").json()["checks"]}
    assert checks["wifi"]["status"] == "warn" and checks["wifi"]["ev"]["mode"] == "WEP"
    assert checks["upnp"]["status"] == "ok" and checks["kev"]["status"] == "na"
    assert checks["exposed"]["status"] == "na"             # no port scan has run yet
    assert "radio" not in checks                           # no cloud account connected


def test_presence_and_exposure(env, monkeypatch):
    import datetime as dt
    import json

    from kaa import exposure
    cfg, db, service = env
    did, _ = db.upsert_device("02:00:00:00:00:99", "192.168.1.9", False)
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    for kind, back in (("device_new", 10), ("device_offline", 6), ("device_online", 3)):
        db._x("insert into events(ts,kind,device_id,message) values(?,?,?,?)",
              ((now - dt.timedelta(hours=back)).isoformat(), kind, did, kind))
    p = service.presence(did, 12)
    assert p["hours"] == 12 and len(p["cells"]) == 12
    assert p["cells"][0] is None and p["cells"][-1] == 1.0     # unknown before the first sighting, then online
    assert 0 in p["cells"] and p["online_pct"] is not None      # the three offline hours

    monkeypatch.setattr(exposure, "public_ip", lambda ctx: "203.0.113.7")
    monkeypatch.setattr(exposure, "lookup", lambda ip, ctx: {"ports": [80, 3389], "vulns": ["CVE-2024-0001"]})
    assert service.exposure()["enabled"] is False
    cfg.exposure = True
    service.refresh_exposure(force=True)
    data = service.exposure()["data"]
    assert data["ports"] == [80, 3389] and data["ip"] == "203.0.x.x"   # the address is stored masked
    service.evaluate()
    rules = {f["rule_id"]: f for f in db.list_findings("open")}
    assert rules["KAA-EXPOSED-PORTS"]["severity"] == "high" and "CVE-2024-0001" in rules["KAA-EXPOSED-VULNS"]["detail"]
    checks = {c["id"]: c for c in service.hygiene()}
    assert checks["exposure"]["status"] == "warn"


def test_scoring_grades_and_accepted():
    from kaa import scoring
    assert scoring.compute([])["grade_id"] == "clear"
    acked = [{"status": "ack", "severity": "low"}]
    r = scoring.compute(acked)
    assert r["value"] == 97 and r["accepted"] == 1 and r["grade_id"] == "very_good"
    assert scoring.compute([{"status": "open", "severity": "critical"}] * 4)["grade_id"] == "risk"


def test_new_port_and_firmware_rules():
    cam = {**_dev(2, "camera", label="Garden camera"), "critical": 1,
           "facts": {"open_ports": [80, 554, 8080], "ports_baseline": [80, 554]}}
    rules = {s.rule_id: s for s in findings.evaluate([cam], {"scanned_ids": {2}, "firmware_age": {2: 200}})}
    assert rules["KAA-PORT-NEW"].evidence["ports"] == "8080" and rules["KAA-PORT-NEW"].severity == "medium"
    assert rules["KAA-FIRMWARE-CHECK"].evidence["days"] == 200
    telnet = {**cam, "facts": {"open_ports": [80, 23], "ports_baseline": [80]}}
    assert {s.rule_id: s for s in findings.evaluate([telnet], {"scanned_ids": {2}})}["KAA-PORT-NEW"].severity == "high"
    calm = {**cam, "facts": {"open_ports": [80], "ports_baseline": [80, 554]}}
    assert not [s for s in findings.evaluate([calm], {"scanned_ids": {2}, "firmware_age": {2: 10}})
                if s.rule_id in ("KAA-PORT-NEW", "KAA-FIRMWARE-CHECK")]


def test_firmware_checked_endpoint_resets_the_clock(env):
    cfg, db, service = env
    did, _ = db.upsert_device("02:00:00:00:00:77", "192.168.1.7", False, ts="2025-01-01T00:00:00+00:00")
    db.set_fields(did, critical=1)
    service.evaluate()
    assert any(f["rule_id"] == "KAA-FIRMWARE-CHECK" for f in db.list_findings())
    c = TestClient(create_app(service, "secret"), base_url="http://127.0.0.1:8473")
    assert c.post(f"/api/devices/{did}/firmware-checked", headers={"x-kaa-token": "secret"}).status_code == 200
    assert not [f for f in db.list_findings() if f["rule_id"] == "KAA-FIRMWARE-CHECK" and f["status"] == "open"]
    assert c.get(f"/api/devices/{did}").json()["firmware_checked"]
