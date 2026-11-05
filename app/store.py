"""SQLite persistence: runs, hash-chained events, and the org install policy."""
import json
import sqlite3
import threading
import time

from .config import settings

_lock = threading.RLock()
_conn = sqlite3.connect(settings.data_dir / "quarantine.db", check_same_thread=False)
_conn.row_factory = sqlite3.Row
_conn.executescript("""
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS runs (
  id TEXT PRIMARY KEY, spec TEXT, ecosystem TEXT, name TEXT, version TEXT, sha256 TEXT,
  status TEXT, verdict TEXT, score INTEGER, created REAL, finished REAL, client TEXT,
  report TEXT
);
CREATE TABLE IF NOT EXISTS events (
  run_id TEXT, seq INTEGER, ts REAL, source TEXT, type TEXT, data TEXT, hash TEXT,
  PRIMARY KEY (run_id, seq)
);
CREATE TABLE IF NOT EXISTS policy (
  ecosystem TEXT, name TEXT, version TEXT, sha256 TEXT, decision TEXT, note TEXT,
  run_id TEXT, verdict TEXT, decided_at REAL,
  PRIMARY KEY (ecosystem, name, version)
);
""")


def q(sql, args=(), one=False):
    with _lock:
        cur = _conn.execute(sql, args)
        rows = cur.fetchall()
        _conn.commit()
    rows = [dict(r) for r in rows]
    return (rows[0] if rows else None) if one else rows


def create_run(run_id, spec, client):
    q("INSERT INTO runs (id, spec, status, created, client) VALUES (?,?,?,?,?)",
      (run_id, spec, "queued", time.time(), client))


def update_run(run_id, **fields):
    if "report" in fields:
        fields["report"] = json.dumps(fields["report"], default=str)
    cols = ", ".join(f"{k}=?" for k in fields)
    q(f"UPDATE runs SET {cols} WHERE id=?", (*fields.values(), run_id))


def get_run(run_id):
    r = q("SELECT * FROM runs WHERE id=?", (run_id,), one=True)
    if r and r.get("report"):
        r["report"] = json.loads(r["report"])
    return r


def list_runs(limit=50):
    return q("SELECT id, spec, ecosystem, name, version, status, verdict, score, created, finished "
             "FROM runs ORDER BY created DESC LIMIT ?", (limit,))


def add_event(run_id, seq, ts, source, etype, data, h):
    q("INSERT INTO events (run_id, seq, ts, source, type, data, hash) VALUES (?,?,?,?,?,?,?)",
      (run_id, seq, ts, source, etype, json.dumps(data, default=str), h))


def events(run_id, after=-1, limit=100000):
    rows = q("SELECT seq, ts, source, type, data, hash FROM events WHERE run_id=? AND seq>? ORDER BY seq LIMIT ?",
             (run_id, after, limit))
    for r in rows:
        r["data"] = json.loads(r["data"])
    return rows


def recent_client_runs(client, since):
    r = q("SELECT COUNT(*) AS n FROM runs WHERE client=? AND created>?", (client, since), one=True)
    return r["n"] if r else 0


def set_policy(ecosystem, name, version, sha256, decision, note, run_id, verdict):
    q("INSERT OR REPLACE INTO policy VALUES (?,?,?,?,?,?,?,?,?)",
      (ecosystem, name, version, sha256, decision, note, run_id, verdict, time.time()))


def get_policy(ecosystem, name, version):
    return q("SELECT * FROM policy WHERE ecosystem=? AND name=? AND version=?", (ecosystem, name, version),
             one=True)


def list_policy():
    return q("SELECT * FROM policy ORDER BY decided_at DESC")


def totals():
    r = q("SELECT COUNT(*) AS runs, "
          "SUM(CASE WHEN verdict='MALICIOUS' THEN 1 ELSE 0 END) AS malicious, "
          "SUM(CASE WHEN verdict='SUSPICIOUS' THEN 1 ELSE 0 END) AS suspicious, "
          "SUM(CASE WHEN verdict='CLEAN' THEN 1 ELSE 0 END) AS clean FROM runs WHERE status='done'", one=True)
    return {k: (v or 0) for k, v in (r or {}).items()}
