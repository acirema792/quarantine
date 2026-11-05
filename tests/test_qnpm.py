"""qnpm (the install-gate shim) against a fake gate and a stub npm."""
import json
import os
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

QNPM = Path(__file__).resolve().parent.parent / "deploy" / "qnpm"
GOOD_INTEGRITY = "sha512-" + "A" * 86 + "=="
APPROVED = {("left-padder", "2.0.3"): {"decision": "allow", "integrity": GOOD_INTEGRITY},
            ("evil", "1.0.0"): {"decision": "block"}}


class Gate(BaseHTTPRequestHandler):
    def do_GET(self):
        q = {k: v[0] for k, v in parse_qs(urlsplit(self.path).query).items()}
        body = json.dumps(APPROVED.get((q.get("name"), q.get("version")), {"decision": "unknown"})).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


@pytest.fixture()
def env(tmp_path):
    srv = HTTPServer(("127.0.0.1", 0), Gate)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    bindir = tmp_path / "bin"
    bindir.mkdir()
    npm = bindir / "npm"
    # stub npm: `npm view x@v version --json` -> "v"; `npm view x@v dist.integrity` -> GOOD;
    # anything else records its argv
    npm.write_text("""#!/usr/bin/env bash
if [ "$1" = view ]; then
  spec="$2"; ver="${spec##*@}"
  case "$ver" in [0-9]*) ;; *) ver=2.0.3;; esac   # ranges/tags resolve to 2.0.3
  if [ "$3" = version ]; then echo "\\"$ver\\""; else echo "%s"; fi
  exit 0
fi
echo "$@" > "$(dirname "$0")/npm-called"
""" % GOOD_INTEGRITY)
    npm.chmod(0o755)
    e = dict(os.environ, PATH=f"{bindir}:{os.environ['PATH']}",
             QUARANTINE_URL=f"http://127.0.0.1:{srv.server_address[1]}", NO_PROXY="127.0.0.1",
             no_proxy="127.0.0.1")
    e.pop("HTTP_PROXY", None)
    e.pop("http_proxy", None)
    yield e, tmp_path, bindir
    srv.shutdown()


def run(args, env, cwd):
    return subprocess.run(["bash", str(QNPM), *args], env=env, cwd=cwd, capture_output=True, text=True,
                          timeout=60)


def lock(tmp, packages, version=3):
    (tmp / "package-lock.json").write_text(json.dumps({"lockfileVersion": version, "packages": packages}))


def test_install_pins_the_exact_checked_version(env):
    e, tmp, bindir = env
    r = run(["install", "left-padder@^2"], e, tmp)
    assert r.returncode == 0, r.stderr
    assert (bindir / "npm-called").read_text().strip() == "install left-padder@2.0.3"


def test_blocked_package_is_refused(env):
    e, tmp, bindir = env
    r = run(["install", "evil@1.0.0"], e, tmp)
    assert r.returncode == 1 and "BLOCKED" in r.stderr and not (bindir / "npm-called").exists()


def test_ci_refuses_v1_lockfiles(env):
    e, tmp, bindir = env
    lock(tmp, {}, version=1)
    r = run(["ci"], e, tmp)
    assert r.returncode == 1 and "v1" in r.stderr and not (bindir / "npm-called").exists()


def test_ci_refuses_entries_outside_the_registry_or_without_integrity(env):
    e, tmp, bindir = env
    lock(tmp, {"": {}, "node_modules/left-padder": {
        "version": "2.0.3", "resolved": "https://evil.example/left-padder.tgz", "integrity": GOOD_INTEGRITY}})
    assert run(["ci"], e, tmp).returncode == 1
    lock(tmp, {"": {}, "node_modules/left-padder": {
        "version": "2.0.3", "resolved": "https://registry.npmjs.org/left-padder/-/left-padder-2.0.3.tgz"}})
    assert run(["ci"], e, tmp).returncode == 1
    assert not (bindir / "npm-called").exists()


def test_ci_passes_only_when_every_entry_matches_its_approval(env):
    e, tmp, bindir = env
    good = {"version": "2.0.3", "integrity": GOOD_INTEGRITY,
            "resolved": "https://registry.npmjs.org/left-padder/-/left-padder-2.0.3.tgz"}
    lock(tmp, {"": {}, "node_modules/left-padder": good})
    r = run(["ci"], e, tmp)
    assert r.returncode == 0, r.stderr
    lock(tmp, {"": {}, "node_modules/left-padder": dict(good, integrity="sha512-" + "B" * 86 + "==")})
    assert run(["ci"], e, tmp).returncode == 1
