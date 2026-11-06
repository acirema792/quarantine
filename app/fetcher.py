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
    roots = [settings.fixtures_dir] + ([settings.extra_fixtures_dir] if settings.extra_fixtures_dir else [])
    for root, eco in [(r, e) for r in roots for e in ("npm", "pypi")]:
        base = root / eco
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
            out.append({"spec": f"fixture:{d.name}", "ecosystem": eco, "name": d.name, "description": desc,
                        "_dir": str(d), "hidden": root != settings.fixtures_dir})
    return out


# What people actually paste: install commands, runner commands and registry links.
_CMD_PREFIXES = [
    (re.compile(r"^(?:npm\s+(?:install|i|add)|pnpm\s+(?:add|install|i)|yarn\s+add|bun\s+add|npx|pnpx|bunx|"
                r"pnpm\s+dlx|yarn\s+dlx)\s+", re.I), "npm"),
    (re.compile(r"^(?:(?:python3?\s+-m\s+)?pip3?\s+install|uv\s+pip\s+install|uv\s+add|uvx|pipx\s+(?:run|install)|"
                r"poetry\s+add)\s+", re.I), "pypi"),
]
_URLS = [
    (re.compile(r"^https?://(?:www\.)?npmjs\.com/package/((?:@[^/\s]+/)?[^/\s?#]+)(?:/v/([^/\s?#]+))?", re.I), "npm"),
    (re.compile(r"^https?://(?:www\.)?pypi\.org/project/([^/\s?#]+)(?:/([^/\s?#]+))?", re.I), "pypi"),
]
_RANGE = re.compile(r"^[\^~<>=*]|[<>]|\|\||\s-\s|\.x$|^x$", re.I)
EXAMPLES = "e.g. left-pad@1.3.0, npm:@modelcontextprotocol/server-everything, pypi:requests==2.32.3"


def _normalize(spec: str):
    """Turn a pasted command or registry link into (ecosystem or None, rest)."""
    for rx, eco in _URLS:
        m = rx.match(spec)
        if m:
            name, ver = m.group(1), m.group(2)
            return eco, name + ((("@" if eco == "npm" else "==") + ver) if ver else "")
    for rx, eco in _CMD_PREFIXES:
        m = rx.match(spec)
        if m:
            words = [w for w in spec[m.end():].split() if not w.startswith("-")]  # drop -y, -g, --save-dev …
            if len(words) != 1:
                raise TargetError(f"inspect one package at a time ({EXAMPLES})")
            return eco, words[0]
    parts = spec.split()
    if len(parts) == 2 and VER_RE.match(parts[1]) and parts[1][0].isdigit():  # "left-pad 1.3.0"
        return None, parts[0] + "\0" + parts[1]
    return None, spec


def parse_spec(spec: str):
    spec = spec.strip()
    if spec.startswith("fixture:"):
        return "fixture", spec[8:], ""
    if not spec:
        raise TargetError(f"type a package name ({EXAMPLES})")
    eco, spec = _normalize(spec)
    if eco is None:
        eco = "npm"
        m = re.match(r"^(npm|pypi|pip|pip3|python|py)\s*:", spec, re.I)
        if m:
            eco = "pypi" if m.group(1).lower() != "npm" else "npm"
            spec = spec[m.end():].strip()
        elif re.match(r"^[a-z][\w+.-]*:", spec, re.I):
            raise TargetError(f"only npm and PyPI packages are supported ({EXAMPLES})")
    version = ""
    if "\0" in spec:
        spec, version = spec.split("\0", 1)
    elif eco == "pypi":
        m = re.match(r"^([^=<>!~\[\s]+)(?:\[[^\]]*\])?\s*(==|===|>=|<=|~=|!=|>|<)?\s*(.*)$", spec)
        if m:
            spec, op, rest = m.group(1), m.group(2), m.group(3).strip()
            if op and op not in ("==", "==="):
                raise TargetError(f"use an exact version: {spec}=={rest.lstrip('=') or '1.0.0'} "
                                  "(Quarantine detonates one exact release)")
            version = rest
    elif spec.rfind("@") > 0:
        i = spec.rfind("@")
        spec, version = spec[:i], spec[i + 1:]
        if version and _RANGE.search(version):
            exact = re.sub(r"^[\^~>=<v\s]+", "", version)
            raise TargetError(f"use an exact version or a tag: {spec}@{exact or 'latest'} "
                              "(Quarantine detonates one exact release, not a range)")
    if not NAME_RE.match(spec):
        raise TargetError(f"that doesn't look like a package name ({EXAMPLES})")
    if version and not VER_RE.match(version):
        raise TargetError(f"invalid version '{version[:40]}' ({EXAMPLES})")
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


DOWNLOAD_HOSTS = {"registry.npmjs.org", "files.pythonhosted.org"}


def _download(client: httpx.Client, url: str) -> bytes:
    """Fetch an archive from the registries' own file hosts only; no redirects followed."""
    u = httpx.URL(url)
    if u.scheme != "https" or u.host not in DOWNLOAD_HOSTS:
        raise TargetError(f"refusing to download from {u.host}: not a registry file host")
    cap = settings.max_package_mb * 1024 * 1024
    with client.stream("GET", url, follow_redirects=False) as r:
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
        raise TargetError(f"npm package '{name}' not found on registry.npmjs.org; check the spelling")
    r.raise_for_status()
    meta = r.json()
    tags = meta.get("dist-tags", {})
    version = tags.get(version or "latest", version)  # accepts dist-tags such as "latest" / "next"
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
        raise TargetError(f"PyPI package '{name}' not found on pypi.org; check the spelling")
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
        src = Path(match["_dir"])
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
        # A bare name ("requests", "left-pad 1.3.0") names no ecosystem: try npm, then PyPI.
        bare = ":" not in spec and not any(rx.match(spec.strip()) for rx, _ in _CMD_PREFIXES)
        with httpx.Client(timeout=30, follow_redirects=True, headers={"User-Agent": "quarantine-scanner/1.0"}) as client:
            if eco == "npm":
                try:
                    version, data, src_url, integrity, ok, archive_name = _resolve_npm(client, name, version)
                except TargetError as exc:
                    if not (bare and "not found on registry.npmjs.org" in str(exc)):
                        raise
                    eco = "pypi"
                    try:
                        version, data, src_url, integrity, ok, archive_name = _resolve_pypi(client, name, version)
                    except TargetError as exc2:
                        if "not found on pypi.org" in str(exc2):
                            raise TargetError(f"'{name}' was found on neither npm nor PyPI; check the spelling") from None
                        raise
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
        # Streaming read with hard stops, so a decompression bomb costs bounded work.
        seen = 0
        with tarfile.open(archive, "r|*") as tar:
            for m in tar:
                seen += 1
                if seen > max_files * 2 or total > max_bytes or len(out) >= max_files:
                    break
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
