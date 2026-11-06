"""Quarantine control plane (FastAPI). Runs on the Vultr VM; the only component
that holds the Vultr Inference key and talks to the Docker engine."""
from __future__ import annotations

import asyncio
import hmac
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

CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; "
       "connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    if not request.url.path.startswith("/docs") and request.url.path != "/openapi.json":
        resp.headers["Content-Security-Policy"] = CSP
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["X-Frame-Options"] = "DENY"
    p = request.url.path
    if p == "/" or (p.startswith("/static/") and p.endswith((".js", ".css"))):
        # revalidate (cheap 304 via ETag) so a deploy reaches visitors on their next load
        resp.headers["Cache-Control"] = "no-cache"
    return resp


@app.on_event("startup")
def _startup():
    try:
        n = sandbox.reap_orphans()
        if n:
            print(f"[quarantine] reaped {n} orphaned sandbox resources")
    except Exception as exc:  # docker unavailable: health endpoint reports it
        print(f"[quarantine] docker not reachable: {exc}")
    if settings.manage_firewall:
        print(f"[quarantine] host firewall rule: {sandbox.host_firewall(ensure=True)}")
    import threading
    threading.Thread(target=lambda: print(f"[quarantine] firewall probe: {sandbox.probe_host_firewall()}"),
                     daemon=True).start()
    # mark runs interrupted by a restart
    for r in store.q("SELECT id FROM runs WHERE status IN ('queued','running')"):
        store.update_run(r["id"], status="error", report={"error": "interrupted by restart"})


def _client_ip(req: Request):
    peer = req.client.host if req.client else "?"
    fwd = req.headers.get("x-forwarded-for")
    # Only trust X-Forwarded-For from the local reverse proxy (Caddy), never from the internet.
    if fwd and peer in ("127.0.0.1", "::1"):
        return fwd.split(",")[-1].strip()
    return peer


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
    return [{k: v for k, v in f.items() if not k.startswith("_")} for f in fetcher.list_fixtures()
            if not f.get("hidden")]


class RunIn(BaseModel):
    spec: str = Field(..., max_length=240, examples=["fixture:color-utils-pro", "npm:left-pad@1.3.0",
                                                      "pypi:requests==2.32.3"])


@app.post("/api/runs")
def create_run(body: RunIn, req: Request):
    spec = body.spec.strip()
    # A bare sample-shipment name (as shown in the sidebar) means that sample, not a registry
    # package that does not exist. An explicit "npm:"/"pypi:" prefix still goes to the registry.
    if spec in {f["name"] for f in fetcher.list_fixtures() if not f.get("hidden")}:
        spec = f"fixture:{spec}"
    try:
        fetcher.parse_spec(spec)
    except fetcher.TargetError as exc:
        raise HTTPException(400, str(exc))
    ip = _client_ip(req)
    if store.recent_client_runs(ip, time.time() - 3600) >= settings.rate_limit_per_hour:
        raise HTTPException(429, "rate limit: too many scans from your address this hour")
    try:
        return {"id": agent.start(spec, ip)}
    except agent.QueueFull as exc:
        raise HTTPException(503, str(exc))


@app.get("/api/runs")
def runs():
    return store.list_runs()


@app.get("/api/runs/{run_id}")
def run_detail(run_id: str):
    r = store.get_run(run_id)
    if not r:
        raise HTTPException(404, "not found")
    r.pop("client", None)
    is_fixture = ((r.get("report") or {}).get("target") or {}).get("source") == "fixture"
    eco = f"fixture-{r.get('ecosystem')}" if is_fixture else r.get("ecosystem")
    r["policy"] = store.get_policy(eco, r.get("name"), r.get("version")) if r.get("name") else None
    return r


@app.get("/api/runs/{run_id}/events")
async def run_events(run_id: str, request: Request, after: int = -1):
    if not await asyncio.to_thread(store.get_run, run_id):
        raise HTTPException(404, "not found")
    try:  # EventSource reconnects send Last-Event-ID: resume instead of replaying
        after = max(after, int(request.headers.get("last-event-id", "-1")))
    except ValueError:
        pass

    async def gen():
        last = after
        idle = 0
        while True:
            rows = await asyncio.to_thread(store.events, run_id, last, 400)
            for row in rows:
                last = row["seq"]
                data = {**row["data"], "seq": row["seq"], "ts": row["ts"], "source": row["source"],
                        "hash": row["hash"]}
                yield f"id: {row['seq']}\ndata: {json.dumps(data, default=str)}\n\n"
            run = agent.ACTIVE.get(run_id)
            finished = (run is None or run.done) and not rows
            if finished:
                r = await asyncio.to_thread(store.get_run, run_id)
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
    r = store.get_run(run_id)
    if not r or r["status"] != "done":
        raise HTTPException(400, "run not finished")
    is_fixture = ((r.get("report") or {}).get("target") or {}).get("source") == "fixture"
    # Policy for real packages is an admin decision. Sample shipments stay open so anyone
    # can try the approval flow on the public demo without touching real policy.
    if not is_fixture:
        if not settings.admin_token and not settings.allow_open_decisions:
            raise HTTPException(403, "admin token required: set ADMIN_TOKEN (or ALLOW_OPEN_DECISIONS=1 for local dev)")
        if settings.admin_token and not hmac.compare_digest(
                req.headers.get("x-admin-token", ""), settings.admin_token):
            raise HTTPException(403, "admin token required to set policy for real packages")
    # Sample shipments live in their own namespace, so approving the demo "color-utils-pro"
    # can never make the gate allow a real npm package of the same name.
    eco = f"fixture-{r['ecosystem']}" if is_fixture else r["ecosystem"]
    store.set_policy(eco, r["name"], r["version"], r["sha256"],
                     "allow" if body.decision == "approve" else "block", body.note, run_id, r["verdict"])
    return {"ok": True, "policy": store.get_policy(eco, r["name"], r["version"])}


@app.get("/api/policy")
def policy():
    return store.list_policy()


@app.get("/api/gate")
def gate(ecosystem: str, name: str, version: str = ""):
    """Install gate for CI / coding agents: allow | block | unknown.

    Decisions are per exact version: approving x@1.0.0 says nothing about x@latest.
    Without a version the gate can only report "unknown" (qnpm resolves it first)."""
    if not version:
        last = store.q("SELECT id, verdict, version FROM runs WHERE ecosystem=? AND name=? AND status='done' "
                       "ORDER BY finished DESC LIMIT 1", (ecosystem, name), one=True)
        return {"decision": "unknown", "error": "exact version required", "last_scan": last}
    p = store.get_policy(ecosystem, name, version)
    if p:
        run = store.get_run(p["run_id"]) or {}
        integrity = (((run.get("report") or {}).get("target")) or {}).get("integrity", "")
        return {"decision": p["decision"], "version": p["version"], "sha256": p["sha256"],
                "integrity": integrity,
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
