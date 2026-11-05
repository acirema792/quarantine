"""HTTP-level behaviour: security headers, decision auth, gate semantics, SSE resume, rate limit."""
import json
import time

import pytest
from fastapi.testclient import TestClient

from app import agent, evidence, main, store
from app.config import settings


@pytest.fixture()
def client():
    return TestClient(main.app)


def fake_done_run(source="registry", name="leftpad-x", version="1.0.0", verdict="CLEAN"):
    rid = f"{int(time.time() * 1e6):032x}"[-32:]
    store.create_run(rid, f"npm:{name}@{version}", "pytest")
    prev = "0" * 64
    for seq, ev in enumerate([{"type": "step", "step": "intake", "status": "done"},
                              {"type": "target", "name": name},
                              {"type": "run_done", "verdict": verdict}]):
        payload = {**ev, "seq": seq, "source": "pipeline"}
        prev = evidence.chain_hash(prev, payload)
        store.add_event(rid, seq, time.time(), "pipeline", ev["type"], ev, prev)
    store.update_run(rid, status="done", ecosystem="npm", name=name, version=version, sha256="ab" * 32,
                     verdict=verdict, score=0, finished=time.time(),
                     report={"target": {"source": source}, "assessment": {"metrics": {}}})
    return rid


def test_security_headers(client):
    r = client.get("/")
    csp = r.headers["content-security-policy"]
    assert "script-src 'self'" in csp and "object-src 'none'" in csp
    assert r.headers["x-content-type-options"] == "nosniff"


def test_gate_requires_exact_version(client):
    rid = fake_done_run(name="gate-pkg", version="1.0.0")
    assert client.post(f"/api/runs/{rid}/decision", json={"decision": "approve"}).status_code == 200
    assert client.get("/api/gate", params={"ecosystem": "npm", "name": "gate-pkg", "version": "1.0.0"}).json()["decision"] == "allow"
    # approving 1.0.0 must not approve "whatever latest is"
    no_ver = client.get("/api/gate", params={"ecosystem": "npm", "name": "gate-pkg"}).json()
    assert no_ver["decision"] == "unknown"
    other = client.get("/api/gate", params={"ecosystem": "npm", "name": "gate-pkg", "version": "2.0.0"}).json()
    assert other["decision"] == "unknown"


def test_decisions_on_real_packages_need_the_admin_token(client, monkeypatch):
    monkeypatch.setattr(settings, "admin_token", "s3cret")
    real = fake_done_run(source="registry", name="real-pkg")
    fixture = fake_done_run(source="fixture", name="fixture-pkg")
    assert client.post(f"/api/runs/{real}/decision", json={"decision": "approve"}).status_code == 403
    assert client.post(f"/api/runs/{real}/decision", json={"decision": "approve"},
                       headers={"X-Admin-Token": "wrong"}).status_code == 403
    assert client.post(f"/api/runs/{real}/decision", json={"decision": "block"},
                       headers={"X-Admin-Token": "s3cret"}).status_code == 200
    # sample shipments stay open so the public demo's approval flow works
    assert client.post(f"/api/runs/{fixture}/decision", json={"decision": "approve"}).status_code == 200


def test_sse_resumes_from_last_event_id(client):
    rid = fake_done_run(name="sse-pkg")
    with client.stream("GET", f"/api/runs/{rid}/events", headers={"Last-Event-ID": "0"}) as r:
        body = "".join(r.iter_text())
    seqs = [json.loads(line[6:])["seq"] for line in body.splitlines() if line.startswith("data: {\"")]
    assert seqs == [1, 2]
    assert "event: end" in body


def test_trusted_fields_cannot_be_overridden_by_event_data():
    run = agent.Run(f"{int(time.time() * 1e6) + 7:032x}"[-32:], "x")
    store.create_run(run.id, "x", "pytest")
    run.emit("sandbox", {"type": "output", "source": "pipeline", "seq": 999, "hash": "f" * 64, "line": "hi"})
    ev = store.events(run.id)[0]
    assert ev["source"] == "sandbox" and ev["seq"] == 0 and "source" not in ev["data"]


def test_telemetry_flood_is_capped():
    run = agent.Run(f"{int(time.time() * 1e6) + 9:032x}"[-32:], "x")
    store.create_run(run.id, "x", "pytest")
    for i in range(agent.MAX_TELEMETRY_EVENTS + 500):
        run.emit("sandbox", {"type": "output", "line": str(i)})
    rows = store.events(run.id)
    assert len(rows) == agent.MAX_TELEMETRY_EVENTS + 1
    assert rows[-1]["type"] == "telemetry_truncated"


def test_rate_limit_and_xff_is_not_trusted_from_the_internet(client, monkeypatch):
    monkeypatch.setattr(settings, "rate_limit_per_hour", 1)
    monkeypatch.setattr(agent, "start", lambda spec, ip: store.create_run(f"{abs(hash((spec, ip, time.time()))):032x}"[-32:], spec, ip) or "ok")
    h = {"X-Forwarded-For": "1.2.3.4"}
    assert client.post("/api/runs", json={"spec": "fixture:left-padder"}, headers=h).status_code == 200
    # a spoofed header from a non-local peer must not reset the limit
    h2 = {"X-Forwarded-For": "5.6.7.8"}
    assert client.post("/api/runs", json={"spec": "fixture:left-padder"}, headers=h2).status_code == 429


def test_bad_specs_rejected(client):
    assert client.post("/api/runs", json={"spec": "npm:../../etc"}).status_code == 400


def test_hidden_test_fixtures_are_not_listed(client):
    names = {f["name"] for f in client.get("/api/fixtures").json()}
    assert "color-utils-pro" in names and "telemetry-forger" not in names


def test_fixture_decisions_never_touch_real_policy(client):
    rid = fake_done_run(source="fixture", name="color-utils-pro", version="4.2.1", verdict="MALICIOUS")
    assert client.post(f"/api/runs/{rid}/decision", json={"decision": "approve"}).status_code == 200
    g = client.get("/api/gate", params={"ecosystem": "npm", "name": "color-utils-pro", "version": "4.2.1"}).json()
    assert g["decision"] == "unknown"


def test_public_deployment_without_admin_token_refuses_real_decisions(client, monkeypatch):
    monkeypatch.setattr(settings, "admin_token", "")
    monkeypatch.setattr(settings, "public_url", "https://demo.example")
    rid = fake_done_run(source="registry", name="pub-pkg")
    assert client.post(f"/api/runs/{rid}/decision", json={"decision": "approve"}).status_code == 403
