import datetime as dt

import pytest
from fastapi.testclient import TestClient

from kaa import settings
from kaa.api import create_app
from kaa.identify import llm


def test_ai_endpoint_must_be_http():
    for bad in ("file:///etc/passwd", "ftp://127.0.0.1/x", "127.0.0.1:8080"):
        with pytest.raises(llm.AIConfigError):
            llm.check_endpoint(bad, allow_remote=True)
    llm.check_endpoint("http://127.0.0.1:8080/v1", allow_remote=False)


def test_security_headers_and_no_store(env):
    cfg, db, service = env
    c = TestClient(create_app(service, "secret"), base_url="http://127.0.0.1:8473")
    r = c.get("/api/overview")
    assert r.headers["cache-control"] == "no-store"
    csp = r.headers["content-security-policy"]
    assert "object-src 'none'" in csp and "base-uri 'none'" in csp and "frame-ancestors 'none'" in csp
    assert c.get("/api/overview", headers={"host": "evil.example"}).status_code == 403


def test_mutations_need_the_token(env):
    cfg, db, service = env
    c = TestClient(create_app(service, "secret"), base_url="http://127.0.0.1:8473")
    for method, url in (("post", "/api/scan"), ("put", "/api/settings"), ("post", "/api/speedtest"),
                        ("post", "/api/ai/ask"), ("post", "/api/cloud/sync"), ("post", "/api/devices/1/firmware-checked")):
        assert getattr(c, method)(url).status_code == 401, url


def test_toml_values_with_control_characters_round_trip(tmp_path):
    import tomllib
    text = settings.dumps({"threats": {"keywords": ["a\nb", 'q"uote', "tab\t"]}})
    assert tomllib.loads(text)["threats"]["keywords"] == ["a\nb", 'q"uote', "tab\t"]


def test_prune_keeps_recent_rows_and_the_inventory(env):
    cfg, db, service = env
    did, _ = db.upsert_device("02:00:00:00:00:55", "192.168.1.5", False)
    old = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=200)).isoformat()
    db._x("insert into events(ts,kind,device_id,message) values(?,?,?,?)", (old, "x", did, "old"))
    db._x("insert into scores(ts,value,breakdown) values(?,?,?)", (old, 90, "{}"))
    db._x("insert into speedtests(ts,down,up,latency,jitter,loss) values(?,?,?,?,?,?)", (old, 1, 1, 1, 1, 0))
    db.add_event("recent", "recent", did)
    out = db.prune()
    assert out["events"] == 1 and out["scores"] == 1 and out["speedtests"] == 0
    assert db.get_device(did) and [e["message"] for e in db.list_events(10, device_id=did)] == ["recent"]
