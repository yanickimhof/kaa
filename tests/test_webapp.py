"""The web app is installable: manifest, icons and the links in index.html."""
import json

from fastapi.testclient import TestClient

from kaa.api import create_app


def test_manifest_and_icons_are_served(env):
    _, _, service = env
    c = TestClient(create_app(service, "secret"), base_url="http://127.0.0.1:8731")
    html = c.get("/").text
    assert 'rel="manifest"' in html
    m = c.get("/manifest.json")
    assert m.status_code == 200
    data = json.loads(m.text)
    assert data["display"] == "standalone" and data["start_url"] == "/"
    sizes = {i["sizes"] for i in data["icons"]}
    assert {"192x192", "512x512"} <= sizes
    for icon in data["icons"]:
        r = c.get("/" + icon["src"])
        assert r.status_code == 200 and r.headers["content-type"] == "image/png"
