"""Serve Kaa with entirely synthetic data. Nothing is scanned and nothing touches your network.

    python scripts/demo.py [--port 8480]

Used to produce the screenshots in docs/img and handy for trying the interface.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import random
import tempfile
import threading
from pathlib import Path

NOW = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)

# (mac suffix, ip, hostname, vendor, label, class, trust, ports, online)
LAN = [
    ("01", "192.168.1.1", "gateway", "Example Networks", "Gateway", "router", "trusted", [53, 80], True),
    ("02", "192.168.1.21", "ap-living", "Example Networks", "Access point (living room)", "access_point", "trusted", [], True),
    ("03", "192.168.1.22", "ap-office", "Example Networks", "Access point (office)", "access_point", "trusted", [], True),
    ("10", "192.168.1.30", None, "Apple, Inc.", "Laptop (Alex)", "computer", "trusted", [], True),
    ("11", "192.168.1.31", None, "Apple, Inc.", "Phone (Alex)", "phone", "trusted", [], True),
    ("12", "192.168.1.32", None, "Apple, Inc.", "Tablet (Alex)", "tablet", "trusted", [], True),
    ("13", "192.168.1.33", None, "Apple, Inc.", "Laptop (Sam)", "computer", "trusted", [], True),
    ("14", "192.168.1.34", None, "Apple, Inc.", "Phone (Sam)", "phone", "trusted", [], True),
    ("15", "192.168.1.35", None, "Samsung Electronics", "Phone (guest)", "phone", "guest", [], False),
    ("20", "192.168.1.40", "living-tv", "Example Media", "Living room TV", "tv", "trusted", [8008], True),
    ("21", "192.168.1.41", None, "Example Audio", "Kitchen speaker", "speaker", "trusted", [], True),
    ("30", "192.168.1.50", None, "Example Home", "Smart lock", "lock", "trusted", [], True),
    ("31", "192.168.1.51", None, "Example Home", "Front door camera", "camera", "trusted", [554], True),
    ("32", "192.168.1.52", None, "Example Home", "Garden camera", "camera", "trusted", [554], True),
    ("33", "192.168.1.53", None, "Example Home", "Air quality monitor", "sensor", "trusted", [], True),
    ("34", "192.168.1.54", None, "Example Home", "Heating bridge", "iot", "trusted", [], True),
    ("35", "192.168.1.55", None, "Example Home", "Weather station", "sensor", "trusted", [], True),
    ("40", "192.168.1.60", None, "Example Print", "Printer", "printer", "trusted", [631, 9100], False),
    ("41", "192.168.1.61", None, "Example Appliances", "Washing machine", "appliance", "trusted", [], False),
    ("50", "192.168.1.70", None, None, None, "unknown", "unknown", [], True),
]
# (ext id, name, kind, model, firmware, battery, pct, reachable, cls)
RADIO = [(f"r{i}", f"Door sensor {i}", "door sensor", "Contact S1", "12", "ok", 90 - i * 4, True, "sensor") for i in range(1, 7)] + \
        [(f"t{i}", f"Thermostat {i}", "thermostat", "Valve T2", "63", "ok" if i != 4 else "low", 85 - i * 5 if i != 4 else 14, True, "iot") for i in range(1, 6)] + \
        [("a1", "Anemometer", "anemometer", "Wind W1", "27", "ok", 70, True, "sensor"),
         ("a2", "Rain gauge", "rain gauge", "Rain R1", "13", "ok", 80, True, "sensor")]


def seed(home: Path):
    os.environ["KAA_HOME"] = str(home)
    from kaa import config as config_mod
    from kaa.db import Database
    from kaa.service import Service

    cfg = config_mod.load()
    cfg.threats = False
    cfg.exposure = False
    cfg.ai_enabled = False
    cfg.lang = "en"
    db = Database(cfg.home / "kaa.db")
    svc = Service(cfg, db)
    rnd = random.Random(7)
    first = (NOW - dt.timedelta(days=21)).isoformat()
    for suf, ip, host, vendor, label, cls, trust, ports, online in LAN:
        mac = f"02:aa:bb:cc:00:{suf}" if cls in ("phone", "tablet", "computer") else f"a0:b1:c2:00:00:{suf}"
        did, _ = db.upsert_device(mac, ip, mac.startswith("02"), ts=first)
        db.set_fields(did, hostname=host, vendor=vendor, label=label, trust=trust,
                      critical=1 if cls in ("router", "lock", "camera") else 0)
        db.set_classification(did, cls, 0.95 if cls != "unknown" else 0.0, "demo", [{"rule": "vendor-" + cls, "label": f"Vendor and name point to a {cls}", "confidence": 0.9, "matched": {"vendor": {"contains": (vendor or "").split(",")[0].lower()}}}] if cls != "unknown" else [])
        db._x("update devices set online=?, last_seen=? where id=?", (int(online), NOW.isoformat() if online else (NOW - dt.timedelta(hours=9)).isoformat(), did))
        db.observe(did, "scan", "open_ports", ports)
        if cls == "router":
            db.observe(did, "net", "role", "gateway")
        # presence: online most of the time, short gaps; phones leave during the day
        up = True
        db._x("insert into events(ts,kind,device_id,message) values(?,?,?,?)", ((NOW - dt.timedelta(hours=169)).isoformat(), "device_online", did, label or "device"))
        for h in range(168, 0, -1):
            ts = NOW - dt.timedelta(hours=h)
            if cls in ("phone", "tablet") and trust != "guest":
                want = not (9 <= ts.hour < 17 and ts.weekday() < 5) or rnd.random() < 0.15
            elif trust == "guest":
                want = ts.weekday() >= 5 and rnd.random() < 0.7
            elif cls in ("printer", "appliance"):
                want = rnd.random() < 0.35
            else:
                want = rnd.random() > 0.01
            if want != up:
                db._x("insert into events(ts,kind,device_id,message) values(?,?,?,?)",
                      (ts.isoformat(), "device_online" if want else "device_offline", did, label or "device"))
                up = want
    db.replace_cloud("Example Home", [{"ext_id": e[0], "name": e[1], "kind": e[2], "model": e[3], "firmware": e[4], "battery": e[5],
                               "battery_pct": e[6], "reachable": e[7], "cls": e[8]} for e in RADIO])
    # history
    for h in range(60, 0, -1):
        db._x("insert into scores(ts,value,breakdown) values(?,?,?)",
              ((NOW - dt.timedelta(hours=h)).isoformat(), min(100, 88 + rnd.randint(0, 8) + (h < 25) * 4), "{}"))
    for d in range(14, 0, -1):
        db._x("insert into speedtests(ts,down,up,latency,jitter,loss) values(?,?,?,?,?,?)",
              ((NOW - dt.timedelta(days=d)).isoformat(), 470 + rnd.randint(-40, 40), 92 + rnd.randint(-8, 8),
               11 + rnd.random() * 4, 2 + rnd.random() * 3, 0))
    for i, (kind, msg) in enumerate([("device_new", "New device: Garden camera"), ("device_offline", "Printer went offline"),
                                    ("device_online", "Phone (Sam) came online")] * 8):
        db._x("insert into events(ts,kind,device_id,message) values(?,?,?,?)",
              ((NOW - dt.timedelta(minutes=17 * (i + 1))).isoformat(), kind, None, msg))
    db.meta_set("baseline_at", first)
    svc.state.update(last_run=NOW.isoformat(), last_duration=6.4, scope=["192.168.1.0/24"],
                     wifi={"mode": "wpa3", "label": "WPA3 Personal"},
                     net_ping=[{"ts": (NOW - dt.timedelta(seconds=15 * i)).isoformat(), "ms": 11 + (i * 7 % 5), "up": True} for i in range(59, -1, -1)])
    svc.evaluate()
    return cfg, svc


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8480)
    args = ap.parse_args()
    import uvicorn
    from kaa.api import create_app

    with tempfile.TemporaryDirectory() as tmp:
        cfg, svc = seed(Path(tmp))
        cfg.port = args.port
        print(f"Kaa demo (synthetic data) on http://127.0.0.1:{args.port}")
        uvicorn.run(create_app(svc, "demo-token"), host="127.0.0.1", port=args.port, log_level="warning")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
