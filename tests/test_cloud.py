import os
import stat
import time

from fastapi.testclient import TestClient

import kaa.cloud as cloud_mod
from kaa.api import create_app
from test_service import world  # noqa: F401  (shared fixture)


def fake_http(calls):
    def _http(method, url, form=None, token=None, ctx=None, timeout=15.0):
        calls.append((method, url, form))
        if url.endswith("/device_authorize"):
            return {"device_code": "dc", "user_code": "ABCD", "verification_uri_complete": "https://login.tado.com/x", "interval": 5, "expires_in": 300}
        if url.endswith("/oauth2/token") and "tado" in url:
            return {"access_token": "ta", "refresh_token": "tr", "expires_in": 600}
        if url.endswith("/oauth2/token"):
            return {"access_token": "na", "refresh_token": "nr", "expires_in": 10800}
        if url.endswith("/me"):
            return {"homes": [{"id": 7}]}
        if "roomsAndDevices" in url:
            return {"rooms": [{"roomName": "Salon", "devices": [{"serialNumber": "VA1", "type": "VA02", "batteryState": "LOW",
                    "connection": {"state": "CONNECTED"}, "firmwareVersion": "54.1"}]},
                    {"roomName": "Bureau", "devices": [{"serialNumber": "RU1", "type": "RU04", "connection": {"state": "CONNECTED"}},
                    {"serialNumber": "VA2", "type": "VA04", "connection": {"state": "CONNECTED"}}]}],
                    "otherDevices": [{"serialNumber": "IB1", "type": "IB02", "connection": {"state": "CONNECTED"}}]}
        if url.endswith("/homesdata"):
            return {"body": {"homes": [{"id": "h1", "modules": [
                {"id": "a4:83:e7:aa:bb:cc", "type": "NACamera", "name": "Camera salon"},
                {"id": "70:ee:50:00:00:01", "type": "NRV", "name": "Vanne chambre", "bridge": "x"}]}]}}
        if "homestatus" in url:
            return {"body": {"home": {"modules": [{"id": "70:ee:50:00:00:01", "battery_state": "low", "reachable": False, "firmware_revision": 12},
                                                   {"id": "a4:83:e7:aa:bb:cc", "firmware_revision": 301}]}}}
        if url.endswith("/gethomecoachsdata"):
            return {"body": {"devices": [{"_id": "70:ee:50:91:04:e0", "type": "NHC", "station_name": "Coach", "firmware": 200, "reachable": True}]}}
        return {"body": {"devices": []}}
    return _http


def test_tado_flow_and_secret_file_is_private(world, monkeypatch):
    service, _ = world
    calls = []
    monkeypatch.setattr(cloud_mod, "_http", fake_http(calls))
    begin = service.cloud.tado_begin()
    assert begin["user_code"] == "ABCD" and begin["url"].startswith("https://login.tado.com")
    assert service.cloud.tado_poll()["status"] == "connected"
    assert service.cloud.connected() == ["tado"]
    mode = stat.S_IMODE(os.stat(service.cloud.path).st_mode)
    assert mode == 0o600
    devs = service.cloud.tado_fetch()
    by = {d["ext_id"]: d for d in devs}
    assert by["VA1"]["name"] == "Salon" and by["VA1"]["battery"] == "low" and by["VA1"]["reachable"] is True
    assert by["RU1"]["name"] == "Bureau · RU04" and by["VA2"]["name"] == "Bureau · VA04"  # two devices in one room
    assert by["IB1"]["name"] == "Internet Bridge"


def test_netatmo_needs_matching_state_and_has_its_own_grant(world, monkeypatch):
    service, _ = world
    monkeypatch.setattr(cloud_mod, "_http", fake_http([]))
    service.cloud.netatmo_config("cid", "secret")
    url = service.cloud.netatmo_url()
    assert "redirect_uri=http%3A%2F%2F127.0.0.1%3A8473%2Foauth%2Fnetatmo" in url and "read_camera" in url
    import pytest
    with pytest.raises(cloud_mod.CloudError):
        service.cloud.netatmo_callback("code", "wrong-state")
    state = service.cloud._load()["netatmo"]["state"]
    service.cloud.netatmo_callback("code", state)
    assert service.cloud.status()["netatmo"]["connected"]
    service.cloud.disconnect("netatmo")
    st = service.cloud.status()["netatmo"]
    assert st["configured"] and not st["connected"]  # app credentials stay, the grant goes


def test_sync_classifies_camera_by_mac_raises_findings_and_respects_user_choice(world, monkeypatch):
    service, _ = world
    service.run_cycle()
    monkeypatch.setattr(cloud_mod, "_http", fake_http([]))
    service.cloud.netatmo_config("cid", "secret")
    service.cloud.netatmo_url()
    service.cloud.netatmo_callback("c", service.cloud._load()["netatmo"]["state"])
    service.state["cloud_ts"] = 0
    out = service.cloud_sync(force=True)
    assert out["devices"] >= 3
    assert any(c["kind"] == "NHC" for c in service.db.list_cloud())
    cam = next(d for d in service.db.list_devices() if d["mac"] == "a4:83:e7:aa:bb:cc")
    assert cam["class"] == "camera" and cam["class_source"] == "cloud"
    service.identify_all()                       # signatures must not overwrite the vendor's answer
    assert next(d for d in service.db.list_devices() if d["id"] == cam["id"])["class"] == "camera"
    service.evaluate()
    rules = {f["rule_id"] for f in service.db.list_findings()}
    assert {"KAA-CLOUD-BATTERY", "KAA-CLOUD-OFFLINE"} <= rules
    # a manual choice always wins
    service.db.set_classification(cam["id"], "speaker", 1.0, "user", [])
    service.cloud_sync(force=True)
    assert next(d for d in service.db.list_devices() if d["id"] == cam["id"])["class"] == "speaker"


def test_cloud_api_and_callback_page(world, monkeypatch):
    service, _ = world
    monkeypatch.setattr(cloud_mod, "_http", fake_http([]))
    c = TestClient(create_app(service, "secret"), base_url="http://127.0.0.1:8473")
    h = {"X-Kaa-Token": "secret"}
    assert c.post("/api/cloud/tado/begin").status_code in (401, 403)
    assert c.post("/api/cloud/tado/begin", headers=h).json()["user_code"] == "ABCD"
    assert c.post("/api/cloud/tado/poll", headers=h).json()["status"] == "connected"
    assert c.put("/api/cloud/netatmo/config", json={"client_id": "a", "client_secret": "b"}, headers=h).status_code == 200
    assert "authorize" in c.post("/api/cloud/netatmo/start", headers=h).json()["url"]
    bad = c.get("/oauth/netatmo?code=x&state=nope")
    assert bad.status_code == 200 and "failed" in bad.text
    view = c.get("/api/cloud").json()
    assert view["tado"]["connected"] and "client_secret" not in str(view)
    assert c.post("/api/cloud/unknown/disconnect", headers=h).status_code == 404
