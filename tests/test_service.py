import ipaddress

import pytest
from fastapi.testclient import TestClient

from kaa import scoring
from kaa.api import create_app
from kaa.collectors import arp
from kaa.collectors.arp import Neighbour
from kaa.scope import Scope
import kaa.service as svc

GW = "192.168.50.1"


@pytest.fixture()
def world(env, monkeypatch):
    cfg, db, service = env
    scope = Scope([ipaddress.ip_network("192.168.50.0/24")], set(), set(), 1024)
    table = {"v": [Neighbour(GW, "00:11:22:33:44:55"),
                   Neighbour("192.168.50.20", "a4:83:e7:aa:bb:cc")]}
    monkeypatch.setattr(svc, "build_scope", lambda *a, **k: scope)
    monkeypatch.setattr(svc, "local_interfaces", lambda: [])
    monkeypatch.setattr(arp, "sweep", lambda s: 0)
    monkeypatch.setattr(arp, "read_table", lambda: table["v"])
    monkeypatch.setattr(arp, "default_gateway", lambda: GW)
    monkeypatch.setattr(arp, "reverse_dns", lambda ips: {GW: "router.lan"})
    monkeypatch.setattr(svc.mdns, "collect", lambda d: {
        "192.168.50.20": {"services": ["_sonos._tcp"], "names": ["Living"], "txt": {}}})
    monkeypatch.setattr(svc.ssdp, "collect", lambda d: {
        GW: {"server": "MiniUPnPd", "st": ["urn:schemas-upnp-org:device:InternetGatewayDevice:1"],
             "location": ""}})
    monkeypatch.setattr(svc.portscan, "scan", lambda s, ips, ports: {
        GW: [80, 23], "192.168.50.20": []})
    return service, table


def test_first_cycle_sets_baseline_without_new_device_noise(world):
    service, _ = world
    service.run_cycle()
    assert service.state["last_error"] is None
    devs = service.db.list_devices()
    assert len(devs) == 2
    assert not [f for f in service.db.list_findings() if f["rule_id"] == "KAA-NEW-DEVICE"]
    by_ip = {d["ip"]: d for d in devs}
    assert by_ip[GW]["class"] == "router"
    assert by_ip["192.168.50.20"]["class"] == "speaker"


def test_upnp_finding_and_score(world):
    service, _ = world
    service.run_cycle()
    rules = {f["rule_id"] for f in service.db.list_findings()}
    assert "KAA-UPNP-IGD" in rules
    assert scoring.compute(service.db.list_findings())["value"] < 100


def test_port_scan_findings_only_when_scanned(world):
    service, _ = world
    service.run_cycle(ports=False)
    assert "KAA-PORT-TELNET" not in {f["rule_id"] for f in service.db.list_findings()}
    service.run_cycle(ports=True)
    found = {f["rule_id"]: f for f in service.db.list_findings()}
    assert found["KAA-PORT-TELNET"]["severity"] == "high"
    assert "KAA-GW-HTTP" in found


def test_new_device_after_baseline_is_flagged_then_resolved_when_known(world):
    service, table = world
    service.run_cycle()
    table["v"].append(Neighbour("192.168.50.77", "00:de:ad:be:ef:01"))
    import time; time.sleep(1.1)  # first_seen must sort after baseline_at (1s resolution)
    service.run_cycle()
    new = [f for f in service.db.list_findings() if f["rule_id"] == "KAA-NEW-DEVICE"]
    assert len(new) == 1 and new[0]["status"] == "open"
    service.db.set_fields(new[0]["device_id"], trust="known")
    service.evaluate()
    new = [f for f in service.db.list_findings() if f["rule_id"] == "KAA-NEW-DEVICE"]
    assert new[0]["status"] == "resolved"


def test_gateway_mac_change_is_high_and_ackable(world):
    service, table = world
    service.run_cycle()
    table["v"][0] = Neighbour(GW, "66:77:88:99:aa:bb")
    service.run_cycle()
    f = [x for x in service.db.list_findings() if x["rule_id"] == "KAA-GATEWAY-MAC-CHANGED"]
    assert f and f[0]["severity"] == "high"
    service.accept_gateway_change()
    service.run_cycle()
    f = [x for x in service.db.list_findings() if x["rule_id"] == "KAA-GATEWAY-MAC-CHANGED"]
    assert f[0]["status"] == "resolved"


def test_offline_device_marked(world):
    service, table = world
    service.run_cycle()
    table["v"].pop()
    service.run_cycle()
    assert [d["online"] for d in service.db.list_devices() if d["ip"] == "192.168.50.20"] == [False]


def test_acknowledging_does_not_raise_the_score(world):
    service, _ = world
    service.run_cycle()
    before = scoring.compute(service.db.list_findings())
    f = [x for x in service.db.list_findings() if x["rule_id"] == "KAA-UPNP-IGD"][0]
    service.db.ack_finding(f["id"])
    after = scoring.compute(service.db.list_findings())
    assert after["value"] == before["value"]             # accepting a risk does not remove it
    assert after["accepted"] == before["accepted"] + 1 and after["counts"]["medium"] == before["counts"]["medium"] - 1


# ---- API ------------------------------------------------------------------

def client(service):
    return TestClient(create_app(service, "secret"), base_url="http://127.0.0.1:8731")


def test_api_reads_and_requires_token_for_writes(world):
    service, _ = world
    service.run_cycle()
    c = client(service)
    assert c.get("/api/overview").json()["devices"] == 2
    dev = c.get("/api/devices").json()[0]
    assert c.patch(f"/api/devices/{dev['id']}", json={"trust": "known"}).status_code == 401
    ok = c.patch(f"/api/devices/{dev['id']}", json={"trust": "known"},
                 headers={"X-Kaa-Token": "secret"})
    assert ok.status_code == 200 and ok.json()["trust"] == "known"
    bad = c.patch(f"/api/devices/{dev['id']}", json={"trust": "root"},
                  headers={"X-Kaa-Token": "secret"})
    assert bad.status_code == 422


def test_api_rejects_foreign_host_header(world):
    service, _ = world
    c = TestClient(create_app(service, "secret"), base_url="http://evil.example:8731")
    assert c.get("/api/overview").status_code == 403


def test_ui_is_served(world):
    service, _ = world
    c = client(service)
    r = c.get("/")
    assert r.status_code == 200 and "Kaa" in r.text
    assert "default-src 'self'" in r.headers["content-security-policy"]


def test_self_with_redacted_mac_gets_stable_identity(world, monkeypatch):
    from kaa.scope import LocalInterface
    service, _ = world
    iface = LocalInterface("en0", "192.168.50.99", ipaddress.ip_network("192.168.50.0/24"),
                           "02:00:00:00:00:00")
    monkeypatch.setattr(svc, "local_interfaces", lambda: [iface])
    service.run_cycle()
    me = [d for d in service.db.list_devices() if d["ip"] == "192.168.50.99"]
    assert len(me) == 1 and me[0]["mac"] == "self:en0" and not me[0]["randomized"]
    assert service.state["last_error"] is None


def test_legacy_placeholder_row_is_removed_and_self_is_trusted(world, monkeypatch):
    from kaa.scope import LocalInterface
    service, _ = world
    service.db.upsert_device("02:00:00:00:00:00", "192.168.50.99", False)
    iface = LocalInterface("en0", "192.168.50.99", ipaddress.ip_network("192.168.50.0/24"),
                           "02:00:00:00:00:00")
    monkeypatch.setattr(svc, "local_interfaces", lambda: [iface])
    service.run_cycle()
    me = [d for d in service.db.list_devices() if d["ip"] == "192.168.50.99"]
    assert [d["mac"] for d in me] == ["self:en0"]
    assert me[0]["trust"] == "known"
    assert not any(f["rule_id"] == "KAA-NEW-DEVICE" and f["device_id"] == me[0]["id"]
                   for f in service.db.list_findings())


def test_existing_self_row_is_upgraded_to_known(world, monkeypatch):
    from kaa.scope import LocalInterface
    service, _ = world
    did, _ = service.db.upsert_device("self:en0", "192.168.50.99", False)
    assert service.db.get_device(did)["trust"] == "unknown"
    iface = LocalInterface("en0", "192.168.50.99", ipaddress.ip_network("192.168.50.0/24"),
                           "02:00:00:00:00:00")
    monkeypatch.setattr(svc, "local_interfaces", lambda: [iface])
    service.run_cycle()
    assert service.db.get_device(did)["trust"] == "known"


def test_baseline_is_redone_after_a_blind_first_scan(world):
    service, state = world
    full = list(state["v"])
    state["v"] = []                       # first scan sees nobody but this machine
    service.run_cycle()
    state["v"] = full                     # discovery starts working
    service.run_cycle()
    assert not any(f["rule_id"] == "KAA-NEW-DEVICE" for f in service.db.list_findings("open"))
