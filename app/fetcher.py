"""Resolve a target spec to a package archive on the control plane.

Nothing here executes package code: archives are downloaded as bytes, verified
against registry integrity hashes, and extracted *as data* (no symlinks, no
path traversal, size caps) so the analyst agent can read them.
"""
from __future__ import annotations

import base64
import gzip
import hashlib
import io
import json
import re
import tarfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from .config import settings

NAME_RE = re.compile(r"^(@[a-z0-9][\w.-]*/)?[a-z0-9][\w.-]{0,213}$", re.I)
VER_RE = re.compile(r"^[\w.+-]{1,64}$")


class TargetError(ValueError):
    pass


@dataclass
class Target:
    spec: str
    ecosystem: str  # npm | pypi
    name: str
    version: str
    archive: Path
    archive_name: str
    sha256: str
    source: str  # fixture | registry
    source_url: str = ""
    integrity: str = ""
    integrity_ok: bool | None = None
    files_dir: Path | None = None
    files: list = field(default_factory=list)
    manifest: dict = field(default_factory=dict)
    mcp_command: list | None = None

    def public(self):
        return {
            "spec": self.spec, "ecosystem": self.ecosystem, "name": self.name, "version": self.version,
            "sha256": self.sha256, "source": self.source, "source_url": self.source_url,
            "integrity": self.integrity, "integrity_ok": self.integrity_ok,
            "file_count": len(self.files), "is_mcp_server": bool(self.mcp_command),
            "archive_name": self.archive_name,
        }


def list_fixtures():
    out = []
    for eco in ("npm", "pypi"):
        base = settings.fixtures_dir / eco
        if not base.exists():
            continue
        for d in sorted(base.iterdir()):
            if not d.is_dir():
                continue
            desc = ""
            if (d / "package.json").exists():
                desc = json.loads((d / "package.json").read_text()).get("description", "")
            elif (d / "setup.py").exists():
                m = re.search(r'description="([^"]+)"', (d / "setup.py").read_text())
                desc = m.group(1) if m else ""
            out.append({"spec": f"fixture:{d.name}", "ecosystem": eco, "name": d.name, "description": desc})
    return out


def parse_spec(spec: str):
    spec = spec.strip()
    if spec.startswith("fixture:"):
        return "fixture", spec[8:], ""
    eco = "npm"
    if ":" in spec:
        eco, spec = spec.split(":", 1)
        eco = eco.lower()
    if eco not in ("npm", "pypi"):
        raise TargetError("ecosystem must be npm or pypi")
    version = ""
    if eco == "pypi" and "==" in spec:
        spec, version = spec.split("==", 1)
    elif eco == "npm" and spec.rfind("@") > 0:
        i = spec.rfind("@")
        spec, version = spec[:i], spec[i + 1:]
    if not NAME_RE.match(spec) or (version and not VER_RE.match(version)):
        raise TargetError("invalid package name or version")
    return eco, spec, version


# ---------------------------------------------------------------------------
def _deterministic_tgz(src: Path, prefix: str) -> bytes:
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz:
        with tarfile.open(fileobj=gz, mode="w", format=tarfile.PAX_FORMAT) as tar:
            for p in sorted(src.rglob("*")):
                if p.is_file():
                    data = p.read_bytes()
                    info = tarfile.TarInfo(f"{prefix}/{p.relative_to(src).as_posix()}")
                    info.size, info.mtime, info.mode = len(data), 0, 0o644
                    tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _download(client: httpx.Client, url: str) -> bytes:
    cap = settings.max_package_mb * 1024 * 1024
    with client.stream("GET", url) as r:
        r.raise_for_status()
        chunks, total = [], 0
        for chunk in r.iter_bytes():
            total += len(chunk)
            if total > cap:
                raise TargetError(f"archive larger than {settings.max_package_mb} MB")
            chunks.append(chunk)
    return b"".join(chunks)


def _resolve_npm(client, name, version):
    meta_url = f"https://registry.npmjs.org/{name.replace('/', '%2F')}"
    r = client.get(meta_url)
    if r.status_code == 404:
        raise TargetError(f"npm package '{name}' not found")
    r.raise_for_status()
    meta = r.json()
    version = version or meta.get("dist-tags", {}).get("latest", "")
    info = meta.get("versions", {}).get(version)
    if not info:
        raise TargetError(f"version '{version}' not found for {name}")
    tarball = info["dist"]["tarball"]
    data = _download(client, tarball)
    integrity = info["dist"].get("integrity", "")
    ok = None
    if integrity.startswith("sha512-"):
        ok = base64.b64encode(hashlib.sha512(data).digest()).decode() == integrity[7:]
    return version, data, tarball, integrity, ok, f"{name.replace('/', '-')}-{version}.tgz"


def _resolve_pypi(client, name, version):
    url = f"https://pypi.org/pypi/{name}/{version}/json" if version else f"https://pypi.org/pypi/{name}/json"
    r = client.get(url)
    if r.status_code == 404:
        raise TargetError(f"PyPI package '{name}' not found")
    r.raise_for_status()
    meta = r.json()
    version = meta["info"]["version"]
    files = meta.get("urls") or []
    # Prefer the sdist: it is where install-time code (setup.py) lives.
    pick = next((f for f in files if f["packagetype"] == "sdist"), None) or \
        next((f for f in files if f["filename"].endswith(".whl")), None)
    if not pick:
        raise TargetError("no downloadable distribution")
    data = _download(client, pick["url"])
    want = pick.get("digests", {}).get("sha256", "")
    ok = (hashlib.sha256(data).hexdigest() == want) if want else None
    return version, data, pick["url"], f"sha256-{want}" if want else "", ok, pick["filename"]


def resolve(spec: str, workdir: Path) -> Target:
    workdir.mkdir(parents=True, exist_ok=True)
    kind, name, version = parse_spec(spec)
    if kind == "fixture":
        match = next((f for f in list_fixtures() if f["name"] == name), None)
        if not match:
            raise TargetError(f"unknown fixture '{name}'")
        eco = match["ecosystem"]
        src = settings.fixtures_dir / eco / name
        if eco == "npm":
            version = json.loads((src / "package.json").read_text())["version"]
            data = _deterministic_tgz(src, "package")
            archive_name = f"{name}-{version}.tgz"
        else:
            m = re.search(r'version="([^"]+)"', (src / "setup.py").read_text())
            version = m.group(1) if m else "0.0.0"
            data = _deterministic_tgz(src, f"{name}-{version}")
            archive_name = f"{name}-{version}.tar.gz"
        src_url, integrity, ok, source = f"bundled fixture ({eco})", "", None, "fixture"
    else:
        if not settings.allow_registry_targets:
            raise TargetError("registry targets are disabled on this deployment")
        eco = kind
        with httpx.Client(timeout=30, follow_redirects=True, headers={"User-Agent": "quarantine-scanner/1.0"}) as client:
            if eco == "npm":
                version, data, src_url, integrity, ok, archive_name = _resolve_npm(client, name, version)
            else:
                version, data, src_url, integrity, ok, archive_name = _resolve_pypi(client, name, version)
        source = "registry"
        if ok is False:
            raise TargetError("registry integrity hash mismatch — refusing to detonate")
    archive = workdir / archive_name
    archive.write_bytes(data)
    t = Target(spec=spec, ecosystem=eco, name=name, version=version, archive=archive,
               archive_name=archive_name, sha256=hashlib.sha256(data).hexdigest(), source=source,
               source_url=src_url, integrity=integrity, integrity_ok=ok)
    t.files_dir = workdir / "src"
    t.files = safe_extract(archive, t.files_dir)
    _detect_manifest(t)
    return t


# ---------------------------------------------------------------------------
def safe_extract(archive: Path, dest: Path, max_files=4000, max_bytes=60 * 1024 * 1024):
    """Extract regular files only; strip the archive's top-level dir; refuse traversal."""
    dest.mkdir(parents=True, exist_ok=True)
    out, total = [], 0

    def place(rel: str, data: bytes):
        nonlocal total
        parts = [p for p in rel.replace("\\", "/").split("/") if p not in ("", ".")]
        if len(parts) > 1:
            parts = parts[1:]  # drop "package/" or "name-1.0/"
        if not parts or any(p == ".." for p in parts):
            return
        total += len(data)
        if total > max_bytes or len(out) >= max_files:
            return
        target = dest.joinpath(*parts)
        if not str(target.resolve()).startswith(str(dest.resolve())):
            return
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        out.append({"path": "/".join(parts), "size": len(data)})

    name = archive.name
    if name.endswith(".whl") or name.endswith(".zip"):
        with zipfile.ZipFile(archive) as z:
            for info in z.infolist():
                if not info.is_dir() and info.file_size < 5 * 1024 * 1024:
                    place("pkg/" + info.filename, z.read(info))
    else:
        with tarfile.open(archive, "r:*") as tar:
            for m in tar.getmembers():
                if m.isfile() and m.size < 5 * 1024 * 1024:
                    f = tar.extractfile(m)
                    if f:
                        place(m.name, f.read())
    return sorted(out, key=lambda f: f["path"])


def _detect_manifest(t: Target):
    pj = t.files_dir / "package.json"
    if t.ecosystem == "npm" and pj.exists():
        try:
            t.manifest = json.loads(pj.read_text())
        except ValueError:
            t.manifest = {}
        m = t.manifest
        deps = {**(m.get("dependencies") or {}), **(m.get("peerDependencies") or {})}
        kw = [k.lower() for k in (m.get("keywords") or []) if isinstance(k, str)]
        bins = m.get("bin") if isinstance(m.get("bin"), dict) else {}
        is_mcp = (any(d.startswith("@modelcontextprotocol/") or d in ("fastmcp", "mcp-framework") for d in deps)
                  or "mcp" in kw or "model-context-protocol" in kw
                  or (t.name or "").startswith("@modelcontextprotocol/")
                  or re.search(r"(^|[-/@_])mcp([-/_]|$)", t.name or "") is not None
                  or any(re.search(r"(^|[-_])mcp([-_]|$)", b) for b in bins))
        if is_mcp:
            bin_field = m.get("bin")
            entry = None
            if isinstance(bin_field, str):
                entry = bin_field
            elif isinstance(bin_field, dict) and bin_field:
                entry = next(iter(bin_field.values()))
            entry = entry or m.get("main") or "index.js"
            entry = entry.lstrip("./")
            t.mcp_command = ["node", f"/work/node_modules/{t.manifest.get('name', t.name)}/{entry}"]
    elif t.ecosystem == "pypi":
        t.manifest = {"name": t.name, "version": t.version}
