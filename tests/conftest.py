import os
import socket
import sys
import tempfile
import threading
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

MOCK_PORT = 8099
os.environ.setdefault("DATA_DIR", tempfile.mkdtemp(prefix="quarantine-test-"))
os.environ["VULTR_INFERENCE_API_KEY"] = "test-vultr-key"
os.environ["VULTR_INFERENCE_BASE_URL"] = f"http://127.0.0.1:{MOCK_PORT}/v1"
os.environ["VULTR_MODEL"] = "kimi-k2-instruct"
os.environ.setdefault("RATE_LIMIT_PER_HOUR", "1000")
os.environ["EXTRA_FIXTURES_DIR"] = str(ROOT / "tests" / "fixtures")
# The mock server is local; make sure no corporate proxy intercepts it.
os.environ["NO_PROXY"] = os.environ["no_proxy"] = "127.0.0.1,localhost"


def _port_open(port):
    with socket.socket() as s:
        return s.connect_ex(("127.0.0.1", port)) == 0


@pytest.fixture(scope="session", autouse=True)
def mock_inference():
    import uvicorn
    from tests.mock_inference import app

    if not _port_open(MOCK_PORT):
        server = uvicorn.Server(uvicorn.Config(app, port=MOCK_PORT, log_level="warning"))
        threading.Thread(target=server.run, daemon=True).start()
        for _ in range(50):
            if _port_open(MOCK_PORT):
                break
            time.sleep(0.1)
    yield


def docker_ready():
    try:
        import docker
        c = docker.from_env()
        c.ping()
        names = {t for i in c.images.list() for t in i.tags}
        return "quarantine-sandbox:latest" in names and "quarantine-proxy:latest" in names
    except Exception:
        return False


needs_docker = pytest.mark.skipif(not docker_ready(), reason="Docker engine + quarantine images required")
