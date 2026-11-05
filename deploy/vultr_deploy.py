#!/usr/bin/env python3
"""Create the Quarantine VM on Vultr with one command (Vultr API v2, stdlib only).

    VULTR_API_KEY=...  VULTR_INFERENCE_API_KEY=...  REPO_URL=https://github.com/<you>/quarantine.git \
        python3 deploy/vultr_deploy.py [--region sea] [--plan vc2-2c-4gb]

The VM boots Ubuntu 24.04 and runs deploy/install.sh from cloud-init, so no SSH is
needed. A Vultr firewall group opens only 80/443 (and 22 from your current IP).
Prints the public HTTPS URL when the app answers.
"""
import argparse
import base64
import json
import os
import sys
import time
import urllib.error
import urllib.request

API = "https://api.vultr.com/v2"
UBUNTU_2404 = 2284


def call(method, path, body=None):
    req = urllib.request.Request(API + path, method=method,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Authorization": f"Bearer {os.environ['VULTR_API_KEY']}",
                                          "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            raw = r.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        sys.exit(f"Vultr API {method} {path} failed: {e.code} {e.read().decode()[:400]}")


def my_ip():
    try:
        with urllib.request.urlopen("https://api.ipify.org", timeout=10) as r:
            return r.read().decode().strip()
    except Exception:
        return None


def ensure_firewall(label):
    groups = call("GET", "/firewalls?per_page=100").get("firewall_groups", [])
    g = next((x for x in groups if x.get("description") == label), None)
    if g:
        return g["id"]
    gid = call("POST", "/firewalls", {"description": label})["firewall_group"]["id"]
    for port in ("80", "443"):
        call("POST", f"/firewalls/{gid}/rules", {"ip_type": "v4", "protocol": "tcp", "port": port,
                                                 "subnet": "0.0.0.0", "subnet_size": 0, "notes": "web"})
    ip = my_ip()
    if ip:
        call("POST", f"/firewalls/{gid}/rules", {"ip_type": "v4", "protocol": "tcp", "port": "22",
                                                 "subnet": ip, "subnet_size": 32, "notes": "ssh (deployer)"})
    return gid


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--region", default=os.environ.get("VULTR_REGION", "sea"))
    ap.add_argument("--plan", default=os.environ.get("VULTR_PLAN", "vc2-2c-4gb"))
    ap.add_argument("--label", default="quarantine")
    ap.add_argument("--branch", default="main")
    args = ap.parse_args()
    for k in ("VULTR_API_KEY", "REPO_URL"):
        if not os.environ.get(k):
            sys.exit(f"set {k}")

    script = f"""#!/bin/bash
export REPO_URL={json.dumps(os.environ['REPO_URL'])} BRANCH={json.dumps(args.branch)}
export VULTR_INFERENCE_API_KEY={json.dumps(os.environ.get('VULTR_INFERENCE_API_KEY', ''))}
export DOMAIN={json.dumps(os.environ.get('DOMAIN', ''))}
apt-get update -qq && apt-get install -y -qq git curl >/dev/null
git clone -q --branch "$BRANCH" "$REPO_URL" /opt/quarantine
bash /opt/quarantine/deploy/install.sh > /var/log/quarantine-install.log 2>&1
"""
    fw = ensure_firewall("quarantine-web")
    inst = call("POST", "/instances", {
        "region": args.region, "plan": args.plan, "os_id": UBUNTU_2404, "label": args.label,
        "hostname": args.label, "firewall_group_id": fw, "backups": "disabled", "enable_ipv6": False,
        "tags": ["quarantine", "agent-rush"], "user_data": base64.b64encode(script.encode()).decode(),
    })["instance"]
    iid = inst["id"]
    print(f"instance {iid} created in {args.region} ({args.plan}); waiting for an IP…")
    ip = None
    for _ in range(120):
        d = call("GET", f"/instances/{iid}")["instance"]
        if d.get("main_ip") and d["main_ip"] != "0.0.0.0" and d.get("power_status") == "running":
            ip = d["main_ip"]
            break
        time.sleep(5)
    if not ip:
        sys.exit("instance did not get an IP in time; check the Vultr console")
    url = f"https://{os.environ.get('DOMAIN') or ip.replace('.', '-') + '.sslip.io'}"
    print(f"IP {ip}. cloud-init is installing Docker, gVisor and the app (5–10 min). Polling {url} …")
    for _ in range(180):
        try:
            with urllib.request.urlopen(url + "/api/health", timeout=10) as r:
                h = json.loads(r.read())
                print(json.dumps(h, indent=2))
                print(f"\nQuarantine is live: {url}")
                return
        except Exception:
            time.sleep(10)
    print(f"Not answering yet. Install log: ssh root@{ip} tail -f /var/log/quarantine-install.log")


if __name__ == "__main__":
    main()
