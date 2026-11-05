"""Evidence -> verdict, and tamper-evident receipts.

The verdict is computed *deterministically* from what was observed. The LLM
writes the explanation but cannot change the verdict, so a package that tells
"AI reviewers" it is safe gains nothing (and is flagged for trying).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
from pathlib import Path

from .config import settings
from .static_scan import scan_tool_description

SEV_POINTS = {"critical": 45, "high": 25, "medium": 10, "low": 3, "info": 0}
SHELL_PROFILES = (".bashrc", ".zshrc", ".profile", ".bash_profile", ".config/autostart", "crontab")


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def chain_hash(prev, payload):
    return hashlib.sha256((prev + canonical(payload)).encode()).hexdigest()


def _receipt_key():
    p = settings.data_dir / "receipt.key"
    env = os.environ.get("RECEIPT_KEY")
    if env:
        return env.encode()
    if not p.exists():
        p.write_text(secrets.token_hex(32))
        p.chmod(0o600)
    return p.read_text().strip().encode()


def sign(payload: dict) -> str:
    return hmac.new(_receipt_key(), canonical(payload).encode(), hashlib.sha256).hexdigest()


def assess(events, static_findings, det, allow_hosts, pids_limit):
    """Turn raw telemetry into scored signals + a verdict."""
    sig = []
    seen = set()

    def add(sev, kind, title, detail="", owasp="", source="runtime"):
        if (kind, title) in seen:
            return
        seen.add((kind, title))
        sig.append({"severity": sev, "kind": kind, "title": title, "detail": detail, "owasp": owasp,
                    "source": source})

    decoys, denied, canary_hosts, allowed, locked_hits = set(), {}, set(), {}, set()
    big_tunnels, held_open = [], set()
    stats = {}
    done_attempts, started_attempts, anomalies = set(), set(), []
    for ev in events:
        t, src = ev.get("type"), ev.get("_source")
        if t == "runner_start":
            started_attempts.add(ev.get("attempt"))
        elif t == "decoy_read" and ev.get("phase") in ("install", "exercise", "mcp"):
            decoys.add(ev["path"])
        elif t == "egress" and ev.get("verdict") == "DENY":
            host = ev.get("host")
            if ev.get("reason") == "registry_locked_after_install":
                locked_hits.add(host)
                continue
            denied.setdefault(host, []).append(ev)
            if ev.get("canary_hit"):
                canary_hosts.add(host)
        elif t == "egress" and ev.get("verdict") == "ALLOW":
            out = ev.get("bytes_out") or 0
            allowed[ev.get("host")] = allowed.get(ev.get("host"), 0) + out
            big_tunnels.append(ev) if out > 64 * 1024 else None
            if ev.get("cut_by_policy"):
                held_open.add(ev.get("host"))
        elif t in ("telemetry_anomaly", "telemetry_truncated", "runner_error"):
            anomalies.append(ev)
        elif t == "net_attempt":
            if not ev.get("dst", "").endswith(":3128"):
                add("high", "direct_connect", f"Direct connection attempt to {ev['dst']} (no route out)",
                    "Bypassed the HTTP proxy; the internal network has no route to the internet.", "ASI02")
        elif t == "fs_change":
            p = ev.get("path", "")
            if any(s in p for s in SHELL_PROFILES):
                add("high", "persistence", f"Modified shell profile {p.split('/')[-1]}",
                    f"{ev.get('change')} during {ev.get('phase')} — classic persistence hook.", "ASI05")
        elif t == "mcp_tool":
            for f in scan_tool_description(ev.get("name"), ev.get("description")):
                add("critical", "tool_poisoning", f"Poisoned MCP tool description: '{ev.get('name')}'",
                    f.get("snippet", ""), "ASI01")
        elif t == "runner_done":
            stats = ev.get("stats") or {}
            done_attempts.add(ev.get("attempt"))
        elif t == "stats":
            stats["peak_mem_mb"] = max(stats.get("peak_mem_mb", 0), ev.get("peak_mem_mb") or 0)
            stats["peak_pids_cgroup"] = max(stats.get("peak_pids_cgroup", 0), ev.get("peak_pids") or 0)
        elif t == "phase_end" and ev.get("timed_out"):
            add("medium", "timeout", f"{ev.get('phase')} phase hit its time cap ({ev.get('seconds')}s)",
                "Killed by the runner timeout.", "ASI08")

    # Decoys: one credential read can be honest (an AWS SDK reads ~/.aws/credentials when
    # called, and may then fail to reach AWS). Conviction needs more: a decoy value seen in
    # outbound traffic, a sweep of several stores, or a large upload.
    sweep = len(decoys) >= 3
    uploaded = bool(big_tunnels)
    for d in sorted(decoys):
        sev = "critical" if (sweep or canary_hosts or uploaded) else "high"
        why = ("One of several credential stores read in the same run." if sweep else
               "Read, and a decoy value was then seen leaving." if canary_hosts else
               "Read, then a large upload went out." if uploaded else
               "Planted honeytoken file. Some SDKs read this legitimately; review the call site.")
        add(sev, "decoy_read", f"Read decoy credential {d.replace('/home/dev', '~')}", why, "ASI03")
    for host in sorted(canary_hosts):
        add("critical", "exfil_attempt", f"Tried to send decoy credentials to {host}",
            "Decoy secret found in the outbound request. Blocked at the egress proxy — 0 bytes delivered.",
            "ASI02")
    for host in sorted(set(denied) - canary_hosts):
        add("high", "egress_denied", f"Outbound connection to {host} blocked",
            f"{len(denied[host])} attempt(s); host not in allowlist.", "ASI02")

    for host in sorted(locked_hits):
        add("high", "registry_after_install", f"Contacted {host} after install finished",
            "Registries are only reachable while dependencies install; runtime traffic there was refused.",
            "ASI02")
    for host, out in sorted(allowed.items()):
        if out > 256 * 1024 or any(t.get("host") == host for t in big_tunnels):
            add("high", "registry_upload", f"Uploaded {out // 1024} KB to {host}",
                "Package downloads send a few KB of requests; this looks like publishing or a dead-drop.",
                "ASI02")
    for host in sorted(held_open):
        add("medium", "registry_held_open", f"Kept a connection to {host} open past install",
            "The proxy cut it when the registry was locked.", "ASI02")

    # Telemetry integrity: the runner is out of the package's reach (different uid), so a
    # missing summary or a forged/flooded stream is itself evidence.
    missing = sorted(a for a in started_attempts - done_attempts if a is not None) if started_attempts else []
    if anomalies or missing or det.get("telemetry_drained") is False:
        detail = "; ".join(sorted({a.get("detail") or a.get("type") for a in anomalies})[:3]) or \
            "the in-sandbox runner did not report a summary"
        add("high", "telemetry_tampering", "Sandbox telemetry was disrupted", detail, "ASI10")
    if not started_attempts and det.get("seconds") is not None:
        add("high", "telemetry_tampering", "Sandbox runner never reported in",
            "No runner_start event: the sandbox failed or its output was suppressed.", "ASI10")

    peak_pids = max(stats.get("pids_peak", 0), stats.get("peak_pids_cgroup", 0))
    if peak_pids >= int(pids_limit * 0.85) or stats.get("procs_total", 0) > 500:
        add("critical", "resource_exhaustion",
            f"Process explosion: {stats.get('procs_total', peak_pids)} processes spawned (cap {pids_limit})",
            "Fork-bomb behaviour contained by the pids cgroup limit.", "ASI08")
    if det.get("oom_killed"):
        add("high", "resource_exhaustion", "Memory cap hit (OOM-killed)", "Contained by the memory cgroup.", "ASI08")
    if det.get("killed_wall_clock"):
        add("medium", "timeout", "Hit the hard wall-clock limit", "Sandbox was killed by the control plane.", "ASI08")

    # Static findings contribute, but are capped: they're hints, not proof.
    static_pts = 0
    poisoned_files = {f["file"] for f in static_findings if f["rule"] == "tool-poison"}
    for f in static_findings:
        if f["rule"] == "ai-injection" and f["file"] in poisoned_files:
            continue  # same text already reported as tool poisoning
        if f["rule"] == "ai-injection":
            add("high", "ai_injection", "Prompt injection aimed at AI reviewers",
                f"{f['file']}:{f['line']} — {f['snippet']}", "ASI01", source="static")
            continue
        if f["rule"] == "tool-poison":
            add("critical", "tool_poisoning", "Hidden instructions in MCP tool description (source)",
                f"{f['file']}:{f['line']} — {f['snippet']}", "ASI01", source="static")
            continue
        static_pts += SEV_POINTS[f["severity"]] // 3

    runtime_pts = sum(SEV_POINTS[s["severity"]] for s in sig)
    score = min(100, runtime_pts + min(static_pts, 20))
    critical = any(s["severity"] == "critical" for s in sig)
    if critical or score >= 60:
        verdict = "MALICIOUS"
    elif score >= 20:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sig.sort(key=lambda s: order[s["severity"]])
    metrics = {
        "decoys_read": len(decoys),
        "egress_denied": sum(len(v) for v in denied.values()),
        "egress_denied_hosts": sorted(denied),
        # measured by the proxy: bytes forwarded upstream to non-allowlisted hosts
        "bytes_exfiltrated": sum((e.get("bytes_out") or 0) for v in denied.values() for e in v),
        "allowed_bytes_out": allowed,
        "registry_bytes_out": sum(allowed.values()),
        "registry_after_install": sorted(locked_hits),
        "peak_pids": peak_pids,
        "procs_total": stats.get("procs_total", 0),
        "peak_mem_mb": stats.get("peak_mem_mb", 0),
    }
    return {"verdict": verdict, "score": score, "signals": sig, "metrics": metrics}
