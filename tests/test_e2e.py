"""End-to-end: real Docker sandboxes, real proxy, mock Vultr Inference.

Each fixture is pushed through the full pipeline exactly as the web app does.
"""
import time

import pytest

from tests.conftest import needs_docker

pytestmark = needs_docker


def run_spec(spec, timeout=240):
    from app import agent, store
    rid = agent.start(spec, "pytest")
    t0 = time.time()
    while time.time() - t0 < timeout:
        r = store.get_run(rid)
        if r["status"] in ("done", "error"):
            return r, [e["data"] | {"source": e["source"]} for e in store.events(rid)]
        time.sleep(0.5)
    raise AssertionError(f"{spec} did not finish")


def no_leftovers():
    import docker
    c = docker.from_env()
    return (not c.containers.list(all=True, filters={"label": "dev.quarantine.run"})
            and not c.networks.list(filters={"label": "dev.quarantine.run"}))


@pytest.mark.parametrize("spec,verdict,must_have", [
    ("fixture:color-utils-pro", "MALICIOUS", {"decoy_read", "exfil_attempt", "persistence"}),
    ("fixture:mcp-weather-plus", "MALICIOUS", {"tool_poisoning", "exfil_attempt", "decoy_read"}),
    ("fixture:requestz", "MALICIOUS", {"decoy_read", "exfil_attempt", "ai_injection"}),
    ("fixture:turbo-build-cache", "MALICIOUS", {"resource_exhaustion"}),
    ("fixture:left-padder", "CLEAN", set()),
])
def test_fixture_verdicts(spec, verdict, must_have):
    r, events = run_spec(spec)
    assert r["status"] == "done", r.get("report")
    rep = r["report"]
    kinds = {s["kind"] for s in rep["assessment"]["signals"]}
    assert rep["assessment"]["verdict"] == verdict, rep["assessment"]["signals"]
    assert must_have <= kinds, kinds
    # containment invariants, read back from docker inspect
    for d in rep["detonation"]:
        p = d["proof"]
        assert p["network_internal"] and p["readonly_rootfs"] and p["cap_drop"] == ["ALL"]
        assert p["real_secrets_in_env"] == [] and not p["docker_socket_mounted"] and not p["privileged"]
        assert p["memory_mb"] == p["memory_swap_mb"] and p["pids_limit"] > 0
        assert d["teardown"]["verified"]
    # the control plane holds VULTR_INFERENCE_API_KEY; the sandbox must never see it
    starts = [e for e in events if e.get("type") == "runner_start"]
    assert starts and all(e["secret_env"] == [] for e in starts)
    assert rep["assessment"]["metrics"]["bytes_exfiltrated"] == 0
    # model was used for planning + explanation
    assert rep["plan"]["source"].startswith("vultr-inference")
    assert rep["explanation"]["source"] == "vultr-inference"
    from app import agent
    assert agent.verify(r["id"])["ok"]
    assert no_leftovers()


def test_self_healing_harness():
    """The mock analyst writes a buggy harness for left-padder; the error goes back to
    the model, a fixed harness runs in a fresh sandbox."""
    r, events = run_spec("fixture:left-padder")
    assert len(r["report"]["detonation"]) == 2
    assert r["report"]["plan"]["source"] == "vultr-inference (healed)"
    steps = [e for e in events if e.get("type") == "step" and e.get("status") == "healing"]
    assert steps


def test_escape_artist_is_fully_contained():
    r, events = run_spec("fixture:escape-artist")
    lines = [e.get("line", "") for e in events if e.get("type") == "output"]
    probes = [ln for ln in lines if ln.startswith("ESCAPE ") and "SUMMARY" not in ln]
    assert len(probes) >= 12, probes
    assert not [ln for ln in probes if "SUCCEEDED" in ln], probes
    assert no_leftovers()


def test_tampered_event_breaks_verification():
    from app import agent, store
    r, _ = run_spec("fixture:mcp-weather-plus")
    store.q("UPDATE events SET data=replace(data, 'DENY', 'ALLOW') WHERE run_id=? AND type='egress'", (r["id"],))
    assert not agent.verify(r["id"])["ok"]
