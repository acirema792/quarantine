"""Quarantine control plane (FastAPI). Runs on the Vultr VM; the only component
that holds the Vultr Inference key and talks to the Docker engine."""
from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import agent, fetcher, sandbox, store
from .config import settings
from .llm import llm

STATIC = Path(__file__).parent / "static"
app = FastAPI(title="Quarantine", version="1.0.0",
              description="Customs for the agent supply chain — sandboxed package & MCP detonation on Vultr.")
app.mount("/static", StaticFiles(directory=STATIC), name="static")


@app.on_event("startup")
def _startup():
    try:
        n = sandbox.reap_orphans()
        if n:
            print(f"[quarantine] reaped {n} orphaned sandbox resources")
    except Exception as exc:  # docker unavailable: health endpoint reports it
        print(f"[quarantine] docker not reachable: {exc}")
    if settings.manage_firewall:
        print(f"[quarantine] host firewall: {sandbox.host_firewall(ensure=True)}")
    # mark runs interrupted by a restart
    for r in store.q("SELECT id FROM runs WHERE status IN ('queued','running')"):
        store.update_run(r["id"], status="error", report={"error": "interrupted by restart"})


def _client_ip(req: Request):
    fwd = req.headers.get("x-forwarded-for")
    return (fwd.split(",")[0].strip() if fwd else (req.client.host if req.client else "?"))


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


@app.get("/api/health")
def health():
    model = None
    if llm.enabled:
        try:
            model = llm.model()
        except Exception:
            model = None
    return {"ok": True, "engine": sandbox.engine_info(),
            "inference": {"provider": "Vultr Serverless Inference", "base_url": settings.inference_base,
                          "configured": llm.enabled, "model": model, "last_error": llm.last_error},
            "limits": {"memory": settings.mem_limit, "cpus": settings.nano_cpus / 1e9,
                       "pids": settings.pids_limit, "wall_clock_s": settings.run_timeout},
            "registry_targets": settings.allow_registry_targets}


@app.get("/api/fixtures")
def fixtures():
    return fetcher.list_fixtures()


class RunIn(BaseModel):
    spec: str = Field(..., max_length=240, examples=["fixture:color-utils-pro", "npm:left-pad@1.3.0",
                                                      "pypi:requests==2.32.3"])


@app.post("/api/runs")
def create_run(body: RunIn, req: Request):
    try:
        fetcher.parse_spec(body.spec)
    except fetcher.TargetError as exc:
        raise HTTPException(400, str(exc))
    ip = _client_ip(req)
    if store.recent_client_runs(ip, time.time() - 3600) >= settings.rate_limit_per_hour:
        raise HTTPException(429, "rate limit: too many scans from your address this hour")
    return {"id": agent.start(body.spec, ip)}


@app.get("/api/runs")
def runs():
    return store.list_runs()


@app.get("/api/runs/{run_id}")
def run_detail(run_id: str):
    r = store.get_run(run_id)
    if not r:
        raise HTTPException(404, "not found")
    r.pop("client", None)
    r["policy"] = store.get_policy(r.get("ecosystem"), r.get("name"), r.get("version")) if r.get("name") else None
    return r


@app.get("/api/runs/{run_id}/events")
async def run_events(run_id: str, request: Request, after: int = -1):
    if not store.get_run(run_id):
        raise HTTPException(404, "not found")

    async def gen():
        last = after
        idle = 0
        while True:
            rows = store.events(run_id, last)
            for row in rows:
                last = row["seq"]
                data = {"seq": row["seq"], "ts": row["ts"], "source": row["source"], "hash": row["hash"],
                        **row["data"]}
                yield f"id: {row['seq']}\ndata: {json.dumps(data, default=str)}\n\n"
            run = agent.ACTIVE.get(run_id)
            finished = (run is None or run.done) and not rows
            if finished:
                r = store.get_run(run_id)
                if r and r["status"] in ("done", "error"):
                    yield "event: end\ndata: {}\n\n"
                    return
            if await request.is_disconnected():
                return
            if rows:
                idle = 0
            else:
                idle += 1
                if idle % 30 == 0:
                    yield ": keepalive\n\n"
            if run is not None and not run.done:
                await asyncio.to_thread(_wait, run, 0.5)
            else:
                await asyncio.sleep(0.5)

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


def _wait(run, timeout):
    with run.cond:
        run.cond.wait(timeout=timeout)


@app.get("/api/runs/{run_id}/receipt")
def receipt(run_id: str):
    r = store.get_run(run_id)
    if not r or not r.get("report") or "receipt" not in r["report"]:
        raise HTTPException(404, "no receipt yet")
    return JSONResponse(r["report"]["receipt"], headers={
        "Content-Disposition": f'attachment; filename="quarantine-receipt-{run_id[:12]}.json"'})


@app.get("/api/runs/{run_id}/verify")
def verify(run_id: str):
    return agent.verify(run_id)


class DecisionIn(BaseModel):
    decision: str = Field(..., pattern="^(approve|block)$")
    note: str = Field("", max_length=500)


@app.post("/api/runs/{run_id}/decision")
def decide(run_id: str, body: DecisionIn, req: Request):
    if settings.admin_token and req.headers.get("x-admin-token") != settings.admin_token:
        raise HTTPException(403, "admin token required")
    r = store.get_run(run_id)
    if not r or r["status"] != "done":
        raise HTTPException(400, "run not finished")
    store.set_policy(r["ecosystem"], r["name"], r["version"], r["sha256"],
                     "allow" if body.decision == "approve" else "block", body.note, run_id, r["verdict"])
    return {"ok": True, "policy": store.get_policy(r["ecosystem"], r["name"], r["version"])}


@app.get("/api/policy")
def policy():
    return store.list_policy()


@app.get("/api/gate")
def gate(ecosystem: str, name: str, version: str = ""):
    """Install gate for CI / coding agents: allow | block | unknown."""
    p = store.get_policy(ecosystem, name, version) if version else None
    if not p:
        rows = store.q("SELECT * FROM policy WHERE ecosystem=? AND name=? ORDER BY decided_at DESC",
                       (ecosystem, name))
        p = next((x for x in rows if not version or x["version"] == version), None)
    if p:
        return {"decision": p["decision"], "version": p["version"], "sha256": p["sha256"],
                "run_id": p["run_id"], "verdict": p["verdict"]}
    last = store.q("SELECT id, verdict, version FROM runs WHERE ecosystem=? AND name=? AND status='done' "
                   "ORDER BY finished DESC LIMIT 1", (ecosystem, name), one=True)
    return {"decision": "unknown", "last_scan": last}


@app.get("/api/stats")
def stats():
    t = store.totals()
    rows = store.q("SELECT report FROM runs WHERE status='done' ORDER BY finished DESC LIMIT 500")
    decoys = denied = exfil = 0
    for r in rows:
        try:
            m = json.loads(r["report"])["assessment"]["metrics"]
        except Exception:
            continue
        decoys += m.get("decoys_read", 0)
        denied += m.get("egress_denied", 0)
        exfil += m.get("bytes_exfiltrated", 0)
    return {**t, "decoys_tripped": decoys, "egress_blocked": denied, "bytes_exfiltrated": exfil}
