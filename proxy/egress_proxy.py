#!/usr/bin/env python3
"""Quarantine egress proxy.

The ONLY network exit a detonation sandbox has. It sits on two Docker networks:
the per-run *internal* network (no route out) and the default bridge. It runs
outside the sandbox, so the untrusted package cannot tamper with what it logs.

* default deny: only hosts in ALLOW_HOSTS (e.g. the npm / PyPI registries) are
  tunnelled; everything else gets 403 and a DENY record
* SSRF guard: even allowlisted names are refused if they resolve to private,
  loopback or link-local space (blocks 169.254.169.254 cloud metadata)
* decoy tripwire: URLs, headers, plain-HTTP bodies and hostnames are scanned for
  the per-run decoy credentials (raw, base64, hex) -> canary_hit
* accounting: bytes in/out per connection, so the report can say "0 bytes left
  the box" for denied destinations

Logs are JSON lines on stdout, consumed live by the control plane.
"""
import asyncio
import base64
import ipaddress
import json
import os
import socket
import sys
import time
from urllib.parse import urlsplit

ALLOW = {h.strip().lower() for h in os.environ.get("ALLOW_HOSTS", "").split(",") if h.strip()}
CANARIES = [c for c in os.environ.get("CANARIES", "").split(",") if c]
UPSTREAM = os.environ.get("UPSTREAM_PROXY", "")  # optional http://host:port (dev only)
PORT = int(os.environ.get("PORT", "3128"))
MAX_BODY_SCAN = 64 * 1024
T0 = time.time()


def _variants(tok):
    out = {tok, base64.b64encode(tok.encode()).decode().rstrip("="), tok.encode().hex()}
    # a 12-char slice catches tokens split into DNS labels / truncated
    if len(tok) > 16:
        out.add(tok[-12:])
    return out


CANARY_VARIANTS = {v: c for c in CANARIES for v in _variants(c)}


def log(**rec):
    rec.update({"q": 1, "type": "egress", "t": round(time.time() - T0, 3)})
    sys.stdout.write(json.dumps(rec) + "\n")
    sys.stdout.flush()


def canary_hits(*blobs):
    hits = set()
    for blob in blobs:
        if not blob:
            continue
        if isinstance(blob, bytes):
            blob = blob.decode("latin-1", errors="replace")
        for variant, canary in CANARY_VARIANTS.items():
            if variant in blob:
                hits.add(canary[:6] + "…")
    return sorted(hits)


def host_allowed(host):
    host = host.lower().rstrip(".")
    return any(host == a or host.endswith("." + a) for a in ALLOW)


def resolves_public(host, port):
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return None, "dns_failed"
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            if not UPSTREAM:  # in dev the upstream proxy resolves; skip
                return None, f"private_address:{ip}"
    return infos[0][4][0], None


async def pipe(reader, writer, counter, key):
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            counter[key] += len(data)
            writer.write(data)
            await writer.drain()
    except (ConnectionError, asyncio.CancelledError, OSError):
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def open_upstream(host, port):
    if UPSTREAM:
        u = urlsplit(UPSTREAM)
        r, w = await asyncio.open_connection(u.hostname, u.port)
        w.write(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode())
        await w.drain()
        status = await r.readline()
        while (await r.readline()) not in (b"\r\n", b""):
            pass
        if b" 200" not in status:
            raise ConnectionError(f"upstream refused: {status!r}")
        return r, w
    return await asyncio.open_connection(host, port)


async def deny(writer, rec, reason):
    rec.update({"verdict": "DENY", "reason": reason, "bytes_out": 0, "bytes_in": 0})
    log(**rec)
    body = b"Blocked by Quarantine egress policy\n"
    writer.write(b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nConnection: close\r\n"
                 b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
    try:
        await writer.drain()
    finally:
        writer.close()


async def handle(reader, writer):
    peer = writer.get_extra_info("peername")
    try:
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=15)
    except Exception:
        writer.close()
        return
    lines = head.decode("latin-1").split("\r\n")
    try:
        method, target, _ = lines[0].split(" ", 2)
    except ValueError:
        writer.close()
        return
    headers = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            headers[k.strip().lower()] = v.strip()

    if method.upper() == "CONNECT":
        host, _, port = target.rpartition(":")
        port = int(port or 443)
        rec = {"method": "CONNECT", "host": host, "port": port, "client": peer[0] if peer else None,
               "canary_hit": canary_hits(host, head)}
        if not host_allowed(host):
            return await deny(writer, rec, "not_in_allowlist")
        _, err = resolves_public(host, port)
        if err:
            return await deny(writer, rec, err)
        try:
            ur, uw = await asyncio.wait_for(open_upstream(host, port), timeout=15)
        except Exception as exc:
            rec.update({"verdict": "ERROR", "reason": str(exc)[:200]})
            log(**rec)
            writer.close()
            return
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()
        counter = {"out": 0, "in": 0}
        await asyncio.gather(pipe(reader, uw, counter, "out"), pipe(ur, writer, counter, "in"))
        rec.update({"verdict": "ALLOW", "bytes_out": counter["out"], "bytes_in": counter["in"]})
        log(**rec)
        return

    # Plain HTTP (absolute-form request target)
    url = urlsplit(target)
    host = url.hostname or headers.get("host", "").split(":")[0]
    port = url.port or 80
    body = b""
    clen = int(headers.get("content-length", "0") or 0)
    if clen:
        try:
            body = await asyncio.wait_for(reader.readexactly(min(clen, MAX_BODY_SCAN)), timeout=10)
        except Exception:
            body = b""
    rec = {"method": method, "host": host, "port": port, "path": (url.path or "/")[:300],
           "client": peer[0] if peer else None, "body_bytes": clen,
           "canary_hit": canary_hits(target, head, body)}
    if not host_allowed(host):
        return await deny(writer, rec, "not_in_allowlist")
    ip, err = resolves_public(host, port)
    if err:
        return await deny(writer, rec, err)
    # Forward a minimal HTTP/1.0 request (registries use HTTPS, so this path is rare)
    try:
        ur, uw = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=15)
        path = url.path or "/"
        if url.query:
            path += "?" + url.query
        fwd = [f"{method} {path} HTTP/1.0", f"Host: {host}"]
        fwd += [f"{k}: {v}" for k, v in headers.items()
                if k not in ("host", "proxy-connection", "connection", "keep-alive")]
        uw.write(("\r\n".join(fwd) + "\r\nConnection: close\r\n\r\n").encode() + body)
        await uw.drain()
        counter = {"out": len(body), "in": 0}
        await pipe(ur, writer, counter, "in")
        rec.update({"verdict": "ALLOW", "bytes_out": counter["out"], "bytes_in": counter["in"]})
    except Exception as exc:
        rec.update({"verdict": "ERROR", "reason": str(exc)[:200]})
    log(**rec)


async def main():
    server = await asyncio.start_server(handle, "0.0.0.0", PORT)
    log(method="-", host="-", port=PORT, verdict="READY", allow=sorted(ALLOW), canaries=len(CANARIES))
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
