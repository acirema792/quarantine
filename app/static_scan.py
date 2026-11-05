"""Deterministic static rules over the extracted package (no code execution).

Static findings are *hints*: they steer the analyst agent and the harness, and
they add context to the report. The verdict leans on what actually happened in
the sandbox (see evidence.py), because obfuscated code defeats static rules.
"""
import re
from pathlib import Path

TEXT_EXT = {".js", ".cjs", ".mjs", ".ts", ".json", ".py", ".sh", ".md", ".txt", ".cfg", ".toml",
            ".yml", ".yaml", ".ini", ".html", ""}

# (id, severity, category, owasp_agentic, title, regex)
RULES = [
    ("cred-path", "high", "credential_access", "ASI03",
     "References credential files", re.compile(
         r"\.npmrc|\.aws/credentials|\.ssh/id_[a-z0-9]+|id_rsa|\.config/gh|\.git-credentials|\.docker/config\.json|"
         r"\.kube/config|wallet\.dat|\.pypirc", re.I)),
    ("env-harvest", "medium", "credential_access", "ASI03",
     "Harvests secrets from environment variables", re.compile(
         r"(Object\.(keys|entries)\(process\.env\)|os\.environ\.items\(\)|for \w+ in os\.environ)", re.I)),
    ("child-proc", "low", "execution", "ASI05",
     "Spawns child processes", re.compile(r"child_process|\bexecSync\(|\bspawn\(|subprocess\.(Popen|run|call)|os\.system\(")),
    ("dyn-code", "medium", "obfuscation", "ASI05",
     "Dynamic code evaluation", re.compile(r"\beval\(|new Function\(|\bexec\(compile\(|vm\.runInNewContext")),
    ("b64-blob", "medium", "obfuscation", "ASI05",
     "Large encoded blob", re.compile(r"[A-Za-z0-9+/]{300,}={0,2}")),
    ("net-out", "low", "network", "ASI02",
     "Makes outbound network requests", re.compile(
         r"https?\.request\(|\bfetch\(|urllib\.request|requests\.(get|post)|socket\.socket\(|net\.connect\(|dns\.resolve")),
    ("persistence", "medium", "persistence", "ASI05",
     "Touches shell profiles / autostart locations", re.compile(
         r"\.bashrc|\.zshrc|\.profile\b|crontab|LaunchAgents|systemd/user|/usr/local/bin/", re.I)),
    ("ai-injection", "high", "prompt_injection", "ASI01",
     "Text aimed at AI reviewers / agents (prompt injection)", re.compile(
         r"ignore (all |any )?(previous|prior) instructions|\b(ai|llm) (security |code )?(reviewers?|scanners?|auditors?)\b|"
         r"classify (this|the) package as|risk score 0|do not (mention|tell)", re.I)),
    ("tool-poison", "critical", "tool_poisoning", "ASI01",
     "Hidden instructions inside an MCP tool description", re.compile(
         r"<IMPORTANT>|before (calling|using) this tool,? read|pass (their|the) (full )?contents", re.I)),
]

INSTALL_HOOKS = ("preinstall", "install", "postinstall", "prepare", "prepublish")


def _line_of(text, idx):
    return text.count("\n", 0, idx) + 1


def scan_text(text, path="(text)", rules=RULES):
    findings = []
    for rid, sev, cat, asi, title, rx in rules:
        for m in rx.finditer(text):
            line = _line_of(text, m.start())
            snippet = text.splitlines()[line - 1].strip()[:220] if text else ""
            findings.append({"rule": rid, "severity": sev, "category": cat, "owasp": asi, "title": title,
                             "file": path, "line": line, "snippet": snippet})
            break  # one hit per rule per file keeps reports readable
    return findings


def scan_tool_description(name, description):
    """Used for runtime MCP tools/list results as well."""
    poison_rules = [r for r in RULES if r[0] in ("tool-poison", "ai-injection", "cred-path")]
    out = scan_text(description or "", f"mcp tool '{name}'", poison_rules)
    for f in out:
        if f["rule"] in ("cred-path", "ai-injection"):
            f.update(severity="critical", category="tool_poisoning", owasp="ASI01",
                     title="MCP tool description asks the agent to touch secrets / hide actions")
    return out


def scan_package(files_dir: Path, files, manifest, ecosystem):
    findings = []
    scripts = (manifest or {}).get("scripts") or {}
    for hook in INSTALL_HOOKS:
        if hook in scripts:
            findings.append({"rule": "install-hook", "severity": "medium", "category": "execution",
                             "owasp": "ASI04", "title": f"Runs code at install time ({hook})",
                             "file": "package.json", "line": 0, "snippet": f'"{hook}": "{scripts[hook]}"'})
    if ecosystem == "pypi" and any(f["path"] == "setup.py" for f in files):
        findings.append({"rule": "setup-py", "severity": "low", "category": "execution", "owasp": "ASI04",
                         "title": "setup.py executes at install time", "file": "setup.py", "line": 0,
                         "snippet": "sdist with setup.py"})
    for f in files:
        p = files_dir / f["path"]
        if Path(f["path"]).suffix.lower() not in TEXT_EXT or f["size"] > 512 * 1024:
            if Path(f["path"]).suffix.lower() in (".node", ".so", ".dll", ".exe", ".dylib"):
                findings.append({"rule": "native-binary", "severity": "info", "category": "execution",
                                 "owasp": "ASI04", "title": "Ships a native binary", "file": f["path"],
                                 "line": 0, "snippet": ""})
            continue
        try:
            text = p.read_text(errors="replace")
        except OSError:
            continue
        findings.extend(scan_text(text, f["path"]))
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return sorted(findings, key=lambda x: (order[x["severity"]], x["file"]))
