"""Disposable detonation sandbox on the Vultr VM's Docker engine.

One run = one fresh internal network + one egress-proxy container + one sandbox
container, all destroyed (and verified destroyed) when the run ends.

Containment controls (each one is read back from `docker inspect` and shown to
the user as proof, not just claimed):
  * process isolation  - gVisor `runsc` user-space kernel when available
  * no network route   - per-run `internal` bridge; the proxy is the only exit
  * secret hygiene     - explicit env allowlist, decoy credentials only
  * resource limits    - memory (no swap), CPU, pids, wall clock, tmpfs sizes
  * least privilege    - non-root uid, cap-drop ALL, no-new-privileges, ro rootfs
  * lifecycle          - everything removed after the run; removal is verified
"""
from __future__ import annotations

import json
import random
import shutil
import subprocess
import threading
import time
import uuid
from pathlib import Path

import docker
from docker.errors import APIError, NotFound
from docker.types import IPAMConfig, IPAMPool, Ulimit

from .config import settings

LABEL = "dev.quarantine.run"
SANDBOX_UID = 10001

_client = None


def client():
    global _client
    if _client is None:
        _client = docker.from_env(timeout=60)
    return _client


def resolve_runtime():
    runtimes = (client().info().get("Runtimes") or {}).keys()
    if settings.runtime == "auto":
        return "runsc" if "runsc" in runtimes else "runc"
    return settings.runtime


def _fw_rule():
    return ["INPUT", "-s", f"{settings.subnet_pool}.0.0/16", "-j", "DROP"]


def host_firewall(ensure=False):
    """Sandbox subnets may talk to their proxy (bridged) but never to the host's own IPs."""
    ipt = shutil.which("iptables")
    if not ipt:
        return {"active": False, "reason": "iptables not found"}
    try:
        check = subprocess.run([ipt, "-C", *_fw_rule()], capture_output=True, timeout=10)
        if check.returncode != 0 and ensure:
            subprocess.run([ipt, "-I", *_fw_rule()], check=True, capture_output=True, timeout=10)
            check = subprocess.run([ipt, "-C", *_fw_rule()], capture_output=True, timeout=10)
        return {"active": check.returncode == 0, "rule": "iptables -I " + " ".join(_fw_rule())}
    except Exception as exc:
        return {"active": False, "reason": str(exc)[:200]}


def _create_network(c, short, labels):
    used = set()
    for n in c.networks.list():
        for cfg in (n.attrs.get("IPAM") or {}).get("Config") or []:
            used.add(cfg.get("Subnet"))
    last = None
    for _ in range(8):
        subnet = f"{settings.subnet_pool}.{random.randint(1, 254)}.0/24"
        if subnet in used:
            continue
        try:
            ipam = IPAMConfig(pool_configs=[IPAMPool(subnet=subnet)])
            return c.networks.create(f"q-net-{short}", driver="bridge", internal=True, labels=labels,
                                     ipam=ipam, check_duplicate=True)
        except APIError as exc:
            last = exc
    raise RuntimeError(f"could not allocate a sandbox subnet: {last}")


def engine_info():
    try:
        info = client().info()
        rt = resolve_runtime()
        return {"ok": True, "runtime": rt, "gvisor": rt == "runsc",
                "available_runtimes": sorted((info.get("Runtimes") or {}).keys()),
                "kernel": info.get("KernelVersion"), "cpus": info.get("NCPU"),
                "mem_gb": round((info.get("MemTotal") or 0) / 1e9, 1),
                "sandbox_image": settings.sandbox_image, "host_firewall": host_firewall()}
    except Exception as exc:  # pragma: no cover - depends on host
        return {"ok": False, "error": str(exc)}


def _follow(container, source, on_event, stop):
    buf = b""
    try:
        for chunk in container.logs(stream=True, follow=True, stdout=True, stderr=True):
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                _dispatch(line, source, on_event)
            if stop.is_set() and not buf:
                pass
    except Exception:
        pass
    if buf:
        _dispatch(buf, source, on_event)


def _dispatch(line, source, on_event):
    text = line.decode(errors="replace").strip()
    if not text:
        return
    try:
        ev = json.loads(text)
        if isinstance(ev, dict) and ev.get("q") == 1:
            ev.pop("q", None)
            on_event(source, ev)
            return
    except ValueError:
        pass
    on_event(source, {"type": "raw", "line": text[:400]})


def _stats(container, on_event, stop):
    peak_mem, peak_pids, last = 0, 0, 0.0
    try:
        for s in container.stats(stream=True, decode=True):
            if stop.is_set():
                break
            mem = (s.get("memory_stats") or {}).get("usage") or 0
            pids = (s.get("pids_stats") or {}).get("current") or 0
            peak_mem, peak_pids = max(peak_mem, mem), max(peak_pids, pids)
            now = time.time()
            if now - last > 0.9:
                last = now
                on_event("engine", {"type": "stats", "mem_mb": round(mem / 1048576, 1),
                                    "pids": pids, "peak_mem_mb": round(peak_mem / 1048576, 1),
                                    "peak_pids": peak_pids})
    except Exception:
        pass


def containment_proof(attrs, runtime, net_attrs):
    hc = attrs.get("HostConfig", {})
    cfg = attrs.get("Config", {})
    env_keys = [e.split("=", 1)[0] for e in cfg.get("Env") or []]
    secretish = [k for k in env_keys if "VULTR" in k or k.endswith("_API_KEY") and k != "OPENAI_API_KEY"]
    return {
        "runtime": hc.get("Runtime") or runtime,
        "gvisor": (hc.get("Runtime") or runtime) == "runsc",
        "network": hc.get("NetworkMode"),
        "network_internal": bool(net_attrs.get("Internal")),
        "readonly_rootfs": bool(hc.get("ReadonlyRootfs")),
        "user": cfg.get("User"),
        "cap_drop": hc.get("CapDrop"),
        "cap_add": hc.get("CapAdd"),
        "privileged": bool(hc.get("Privileged")),
        "security_opt": hc.get("SecurityOpt"),
        "memory_mb": round((hc.get("Memory") or 0) / 1048576),
        "memory_swap_mb": round((hc.get("MemorySwap") or 0) / 1048576),
        "cpus": (hc.get("NanoCpus") or 0) / 1e9,
        "pids_limit": hc.get("PidsLimit"),
        "tmpfs": hc.get("Tmpfs"),
        "mounts": [{"dst": m.get("Destination"), "rw": m.get("RW")} for m in attrs.get("Mounts") or []],
        "docker_socket_mounted": any("docker.sock" in (m.get("Source") or "") for m in attrs.get("Mounts") or []),
        "env_keys": env_keys,
        "real_secrets_in_env": secretish,
        "image": cfg.get("Image"),
        "image_id": attrs.get("Image"),
    }


def detonate(run_id: str, jobdir: Path, job: dict, on_event, allow_hosts, canaries):
    """Run one detonation. Blocks until finished. Returns a result dict."""
    c = client()
    runtime = resolve_runtime()
    short = run_id[:12]
    labels = {LABEL: run_id}
    net = proxy = box = None
    stop = threading.Event()
    threads = []
    result = {"runtime": runtime, "killed_wall_clock": False}
    t0 = time.time()

    try:
        net = _create_network(c, short, labels)
        on_event("engine", {"type": "lifecycle", "action": "network_created", "name": net.name,
                            "internal": True,
                            "subnet": ((net.attrs.get("IPAM") or {}).get("Config") or [{}])[0].get("Subnet")})

        proxy = c.containers.run(
            settings.proxy_image, detach=True, name=f"q-egress-{short}", labels=labels,
            environment={"ALLOW_HOSTS": ",".join(allow_hosts), "CANARIES": ",".join(canaries),
                         "UPSTREAM_PROXY": settings.upstream_proxy},
            network="bridge", read_only=True, cap_drop=["ALL"], security_opt=["no-new-privileges"],
            mem_limit="128m", pids_limit=64, nano_cpus=500_000_000,
        )
        net.connect(proxy, aliases=["egress"])
        proxy.reload()
        proxy_ip = proxy.attrs["NetworkSettings"]["Networks"][net.name]["IPAddress"]
        # Address the proxy by IP: the sandbox needs no DNS at all (and gVisor's netstack
        # does not depend on Docker's embedded resolver).
        job = dict(job, proxy_url=f"http://{proxy_ip}:3128")
        (jobdir / "job.json").write_text(json.dumps(job))
        for p in jobdir.iterdir():
            p.chmod(0o644)  # readable by the unprivileged sandbox user; mounted read-only
        jobdir.chmod(0o755)
        th = threading.Thread(target=_follow, args=(proxy, "proxy", on_event, stop), daemon=True)
        th.start()
        threads.append(th)
        on_event("engine", {"type": "lifecycle", "action": "proxy_started", "allow": allow_hosts})

        box = c.containers.create(
            settings.sandbox_image, name=f"q-sbx-{short}", labels=labels, hostname="dev-laptop",
            runtime=runtime, network=net.name, user=f"{SANDBOX_UID}:{SANDBOX_UID}", dns=["127.0.0.1"],
            environment={"Q_JOB": "/job/job.json", "HOME": "/home/dev"},
            volumes={str(jobdir): {"bind": "/job", "mode": "ro"}},
            read_only=True,
            tmpfs={
                "/tmp": "rw,nosuid,nodev,size=64m,mode=1777",
                "/home/dev": f"rw,nosuid,nodev,size=128m,uid={SANDBOX_UID},gid={SANDBOX_UID},mode=0700",
                "/work": f"rw,nosuid,nodev,exec,size=384m,uid={SANDBOX_UID},gid={SANDBOX_UID},mode=0755",
            },
            mem_limit=settings.mem_limit, memswap_limit=settings.mem_limit,
            nano_cpus=settings.nano_cpus, pids_limit=settings.pids_limit,
            cap_drop=["ALL"], security_opt=["no-new-privileges"], init=True,
            ulimits=[Ulimit(name="nofile", soft=1024, hard=1024)],
        )
        box.reload()
        net.reload()
        result["proof"] = containment_proof(box.attrs, runtime, net.attrs)
        result["proof"]["host_firewall"] = host_firewall()["active"]
        on_event("engine", {"type": "containment", "proof": result["proof"]})

        box.start()
        on_event("engine", {"type": "lifecycle", "action": "sandbox_started", "name": box.name,
                            "runtime": runtime})
        for target, args in ((_follow, (box, "sandbox", on_event, stop)), (_stats, (box, on_event, stop))):
            th = threading.Thread(target=target, args=args, daemon=True)
            th.start()
            threads.append(th)

        try:
            status = box.wait(timeout=settings.run_timeout)
            result["exit_code"] = status.get("StatusCode")
        except Exception:
            result["killed_wall_clock"] = True
            on_event("engine", {"type": "lifecycle", "action": "wall_clock_kill",
                                "after_s": settings.run_timeout})
            try:
                box.kill()
            except APIError:
                pass
            result["exit_code"] = None
        box.reload()
        state = box.attrs.get("State", {})
        result["oom_killed"] = bool(state.get("OOMKilled"))
        result["seconds"] = round(time.time() - t0, 2)
        time.sleep(1.0)  # let the proxy flush records for tunnels closing now
    finally:
        stop.set()
        result["teardown"] = teardown(run_id, net, proxy, box)
        on_event("engine", {"type": "lifecycle", "action": "teardown", **result["teardown"]})
        for th in threads:
            th.join(timeout=2)
    return result


def teardown(run_id, net=None, proxy=None, box=None):
    c = client()
    removed = {"sandbox": False, "proxy": False, "network": False}
    for key, obj in (("sandbox", box), ("proxy", proxy)):
        if obj is None:
            removed[key] = True
            continue
        try:
            obj.remove(force=True, v=True)
        except NotFound:
            pass
        except APIError:
            time.sleep(0.5)
            try:
                obj.remove(force=True, v=True)
            except Exception:
                pass
    if net is not None:
        for _ in range(5):
            try:
                net.remove()
                break
            except NotFound:
                break
            except APIError:
                time.sleep(0.5)
    # verify: nothing labelled with this run may survive
    left = c.containers.list(all=True, filters={"label": f"{LABEL}={run_id}"})
    nets = c.networks.list(filters={"label": f"{LABEL}={run_id}"})
    removed["sandbox"] = not any(x.name.startswith("q-sbx-") for x in left)
    removed["proxy"] = not any(x.name.startswith("q-egress-") for x in left)
    removed["network"] = not nets
    removed["verified"] = all(removed.values())
    return removed


def reap_orphans():
    """Called at startup: destroy anything a crashed run may have left behind."""
    c = client()
    n = 0
    for x in c.containers.list(all=True, filters={"label": LABEL}):
        try:
            x.remove(force=True)
            n += 1
        except Exception:
            pass
    for net in c.networks.list(filters={"label": LABEL}):
        try:
            net.remove()
            n += 1
        except Exception:
            pass
    return n


def new_run_id():
    return uuid.uuid4().hex
