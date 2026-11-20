"""SQLite storage. One file, local, human readable with any SQLite client."""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .models import FindingSpec

SCHEMA = """
create table if not exists meta(key text primary key, value text);
create table if not exists devices(
  id integer primary key autoincrement,
  mac text not null unique,
  ip text, hostname text, vendor text, label text,
  trust text not null default 'unknown',
  class text not null default 'unknown',
  class_conf real not null default 0,
  class_source text not null default '',
  class_evidence text not null default '[]',
  randomized integer not null default 0,
  online integer not null default 0,
  first_seen text not null, last_seen text not null
);
create table if not exists observations(
  device_id integer not null references devices(id) on delete cascade,
  source text not null, key text not null, value text not null, updated text not null,
  primary key(device_id, source, key)
);
create table if not exists findings(
  id integer primary key autoincrement,
  device_id integer references devices(id) on delete cascade,
  rule_id text not null, severity text not null, title text not null,
  detail text not null, fix text not null,
  evidence text not null default '{}',
  status text not null default 'open',
  first_seen text not null, last_seen text not null
);
create table if not exists events(
  id integer primary key autoincrement,
  ts text not null, kind text not null, device_id integer, message text not null
);
create table if not exists scores(
  ts text not null, value integer not null, breakdown text not null
);
"""


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Database:
    def __init__(self, path: Path | str):
        self.path = str(path)
        self._lock = threading.RLock()
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("pragma foreign_keys = on")
        self.conn.execute("pragma journal_mode = wal")
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    # ---- helpers -------------------------------------------------------
    def _q(self, sql: str, args: Iterable[Any] = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self.conn.execute(sql, tuple(args)).fetchall()

    def _x(self, sql: str, args: Iterable[Any] = ()) -> sqlite3.Cursor:
        with self._lock:
            cur = self.conn.execute(sql, tuple(args))
            self.conn.commit()
            return cur

    # ---- meta ----------------------------------------------------------
    def meta_get(self, key: str) -> str | None:
        rows = self._q("select value from meta where key=?", (key,))
        return rows[0]["value"] if rows else None

    def meta_set(self, key: str, value: str) -> None:
        self._x("insert into meta(key,value) values(?,?) "
                "on conflict(key) do update set value=excluded.value", (key, value))

    # ---- devices -------------------------------------------------------
    def upsert_device(self, mac: str, ip: str | None, randomized: bool,
                      ts: str | None = None) -> tuple[int, bool]:
        ts = ts or now()
        rows = self._q("select id from devices where mac=?", (mac,))
        if rows:
            did = rows[0]["id"]
            self._x("update devices set ip=coalesce(?,ip), last_seen=?, online=1 "
                    "where id=?", (ip, ts, did))
            return did, False
        cur = self._x(
            "insert into devices(mac,ip,randomized,online,first_seen,last_seen) "
            "values(?,?,?,?,?,?)", (mac, ip, int(randomized), 1, ts, ts))
        return int(cur.lastrowid), True

    def mark_offline_except(self, online_ids: set[int]) -> list[int]:
        """Returns ids that just went offline."""
        rows = self._q("select id from devices where online=1")
        gone = [r["id"] for r in rows if r["id"] not in online_ids]
        for did in gone:
            self._x("update devices set online=0 where id=?", (did,))
        return gone

    def set_fields(self, device_id: int, **fields: Any) -> None:
        allowed = {"hostname", "vendor", "label", "trust", "ip"}
        sets = {k: v for k, v in fields.items() if k in allowed}
        if not sets:
            return
        cols = ", ".join(f"{k}=?" for k in sets)
        self._x(f"update devices set {cols} where id=?", (*sets.values(), device_id))

    def set_classification(self, device_id: int, cls: str, conf: float,
                           source: str, evidence: list[dict]) -> None:
        self._x("update devices set class=?, class_conf=?, class_source=?, "
                "class_evidence=? where id=?",
                (cls, conf, source, json.dumps(evidence), device_id))

    def list_devices(self) -> list[dict]:
        return [self._device(r) for r in
                self._q("select * from devices order by online desc, "
                        "cast(substr(ip, instr(ip,'.')+1) as text), ip")]

    def get_device(self, device_id: int) -> dict | None:
        rows = self._q("select * from devices where id=?", (device_id,))
        return self._device(rows[0]) if rows else None

    @staticmethod
    def _device(r: sqlite3.Row) -> dict:
        d = dict(r)
        d["class_evidence"] = json.loads(d["class_evidence"] or "[]")
        d["online"] = bool(d["online"])
        d["randomized"] = bool(d["randomized"])
        return d

    # ---- observations --------------------------------------------------
    def observe(self, device_id: int, source: str, key: str, value: Any) -> None:
        self._x("insert into observations(device_id,source,key,value,updated) "
                "values(?,?,?,?,?) on conflict(device_id,source,key) do update "
                "set value=excluded.value, updated=excluded.updated",
                (device_id, source, key, json.dumps(value), now()))

    def observations(self, device_id: int) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for r in self._q("select source,key,value from observations "
                         "where device_id=?", (device_id,)):
            out[f"{r['source']}.{r['key']}"] = json.loads(r["value"])
        return out

    # ---- findings ------------------------------------------------------
    def sync_findings(self, specs: list[FindingSpec]) -> None:
        ts = now()
        wanted = {s.key for s in specs}
        for s in specs:
            rows = self._q("select id,status from findings where "
                           "coalesce(device_id,0)=? and rule_id=?", s.key)
            if rows:
                status = rows[0]["status"]
                if status == "resolved":
                    status = "open"
                self._x("update findings set severity=?, title=?, detail=?, fix=?, "
                        "evidence=?, status=?, last_seen=? where id=?",
                        (s.severity, s.title, s.detail, s.fix,
                         json.dumps(s.evidence), status, ts, rows[0]["id"]))
            else:
                self._x("insert into findings(device_id,rule_id,severity,title,"
                        "detail,fix,evidence,status,first_seen,last_seen) "
                        "values(?,?,?,?,?,?,?,'open',?,?)",
                        (s.device_id, s.rule_id, s.severity, s.title, s.detail,
                         s.fix, json.dumps(s.evidence), ts, ts))
        for r in self._q("select id,device_id,rule_id from findings "
                         "where status in ('open','ack')"):
            if (r["device_id"] or 0, r["rule_id"]) not in wanted:
                self._x("update findings set status='resolved', last_seen=? "
                        "where id=?", (ts, r["id"]))

    def list_findings(self, status: str | None = None) -> list[dict]:
        sql = "select * from findings"
        args: tuple = ()
        if status:
            sql += " where status=?"
            args = (status,)
        out = []
        for r in self._q(sql, args):
            d = dict(r)
            d["evidence"] = json.loads(d["evidence"] or "{}")
            out.append(d)
        return out

    def ack_finding(self, finding_id: int, ack: bool = True) -> bool:
        cur = self._x("update findings set status=? where id=? and status in "
                      "('open','ack')", ("ack" if ack else "open", finding_id))
        return cur.rowcount > 0

    # ---- events and scores --------------------------------------------
    def add_event(self, kind: str, message: str, device_id: int | None = None) -> None:
        self._x("insert into events(ts,kind,device_id,message) values(?,?,?,?)",
                (now(), kind, device_id, message))

    def list_events(self, limit: int = 100) -> list[dict]:
        return [dict(r) for r in self._q(
            "select * from events order by id desc limit ?", (limit,))]

    def add_score(self, value: int, breakdown: dict) -> None:
        self._x("insert into scores(ts,value,breakdown) values(?,?,?)",
                (now(), value, json.dumps(breakdown)))

    def list_scores(self, limit: int = 200) -> list[dict]:
        rows = self._q("select * from scores order by ts desc limit ?", (limit,))
        return [{"ts": r["ts"], "value": r["value"]} for r in reversed(rows)]
