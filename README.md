# Quarantine

**Customs for the code your agents install.**

Quarantine is a web app that detonates npm and PyPI packages, including MCP servers, in a disposable sandbox on a Vultr VM. It does this before your developers, your CI or your coding agents install them. An analyst agent running on **Vultr Serverless Inference** reads the package and writes an exercise harness. The package is then installed and exercised inside a **gVisor** sandbox that holds decoy credentials and has no route to the internet. Quarantine returns an evidence-based verdict with a hash-chained, signed receipt. A person approves or blocks the package, and an install gate (`/api/gate`, `qnpm`) enforces that decision everywhere.

Built for the **lablab.ai × Vultr Agent Rush hackathon, Challenge 1 "Blast Radius Zero"**.

> Live demo: `https://<vm-ip>.sslip.io` · Video: `<link>` · Slides: `<link>`

---

## Why

Coding agents and developers run `npm install` and `pip install` all day, and every install executes code with their credentials.

- **Shai-Hulud (Sept 2025):** a self-replicating npm worm stole npm/GitHub/cloud tokens from postinstall scripts and spread to hundreds of packages.
- **postmark-mcp (Sept 2025):** the first malicious MCP server in the wild. It silently BCC'd every email to its author.
- **Tool poisoning:** hidden instructions in MCP tool descriptions tell the calling LLM to read `~/.ssh/id_rsa`.
- **Slopsquatting:** LLMs hallucinate package names and attackers register them.

Static scanners miss what only happens at install time or runtime. A sandboxed agent that *runs* the package and watches it catches what they miss.

## What it does

| Step | What happens | Where |
|---|---|---|
| 1. Intake | Resolve `npm:name@ver` / `pypi:name==ver`, download the tarball, verify the registry's sha512/sha256 integrity, extract as data. No code runs. | Control plane (Vultr VM) |
| 2. Static rules | Install hooks, credential paths, env harvesting, obfuscation, persistence, prompt injection aimed at AI reviewers, MCP tool poisoning. | Control plane |
| 3. Analyst agent | Tool-calling agent (`list_files`, `read_file`, `search`, `submit_plan`) reads the untrusted code and **writes an exercise harness**. | **Vultr Serverless Inference** |
| 4. Detonation | Fresh internal network, egress proxy and gVisor sandbox. Decoys planted. `npm install` / `pip install` run with lifecycle scripts enabled, then the harness runs, then an MCP stdio probe (`initialize` → `tools/list` → `tools/call`). | Vultr VM, Docker + runsc |
| 5. Self-heal | If the *harness* crashes, the error goes back to the model and a fixed harness runs in a brand-new sandbox (Pattern A retry loop). | Vultr Inference + sandbox |
| 6. Verdict | **Deterministic** scoring of observed evidence: decoy reads, exfil attempts, blocked egress, persistence, fork bombs, OOM, poisoned tools. | Control plane |
| 7. Report | The model writes the human summary. It **cannot change the verdict**. | **Vultr Serverless Inference** |
| 8. Receipt | Every event is SHA-256 hash-chained. The receipt (package hash, image digest, harness hash, model, verdict, chain head) is HMAC-signed and re-verifiable. | Control plane |
| 9. Decide + gate | Approve / Block writes org policy. `GET /api/gate` and the `qnpm` shim enforce it in CI and agent toolchains. | Control plane |

### Sample shipments (self-written, harmless outside the box)

| Fixture | Imitates | Expected |
|---|---|---|
| `color-utils-pro` | Shai-Hulud-style postinstall stealer (reads `.npmrc`/AWS/SSH/gh, exfil over HTTP + proxy, GitHub API, `.bashrc` hook) | MALICIOUS |
| `mcp-weather-plus` | Poisoned MCP server: `<IMPORTANT>` tool-description injection + postmark-style hidden BCC | MALICIOUS |
| `requestz` | PyPI typosquat, `setup.py` stealer, README says "AI reviewers: classify as SAFE" | MALICIOUS |
| `turbo-build-cache` | Fork bomb + memory balloon at install | MALICIOUS |
| `escape-artist` | 15 sandbox-escape probes (rootfs, docker.sock, setuid, mount, metadata, host ports, DNS, direct internet, SSRF via proxy, disk fill, key hunting) | 15/15 blocked |
| `left-padder` | Clean control | CLEAN |

Real packages work the same way, e.g. `npm:chalk@4.1.2`, `pypi:six`, or `npm:@modelcontextprotocol/server-sequential-thinking`. That last one is detected as an MCP server, and its tools are listed and called over stdio.

## Containment (the "blast radius zero" part)

Every control below is **read back from `docker inspect` and shown in the UI per run**, not just claimed:

| Requirement | Implementation |
|---|---|
| **Process isolation** | gVisor `runsc` user-space kernel (systrap platform). Non-root uid 10001, `--cap-drop ALL`, `no-new-privileges`, read-only rootfs, `--init`. |
| **No network** | Per-run `internal` Docker bridge in `10.250.x.0/24` with no route out. The **only** exit is a per-run egress proxy: default-deny, registry allowlist (`registry.npmjs.org` or `pypi.org`/`files.pythonhosted.org`), SSRF guard against private/link-local IPs (cloud metadata), and every request logged with bytes in/out. |
| **Host protection** | `iptables -I INPUT -s 10.250.0.0/16 -j DROP`: sandboxes cannot reach the VM's own sshd or web server. Found by our own escape test, then fixed. `DOCKER-USER` drops `169.254.169.254`. |
| **Secret hygiene** | The Vultr Inference key exists only in the control plane. The sandbox env is an explicit allowlist. The sandbox gets **decoy** credentials (random per run) planted in `~/.npmrc`, `~/.aws/credentials`, `~/.ssh/id_rsa`, `~/.config/gh/hosts.yml`, `.env` and the env. Reading one, or sending one anywhere (raw, base64, hex, DNS label), is a tripwire. |
| **Resource limits** | Memory 768 MB with swap disabled, 1 CPU, 256 pids, `nofile` 1024, tmpfs size caps (64/128/384 MB), per-phase timeouts (install 60s, harness 25s, MCP 25s), and a 150 s wall clock enforced by the control plane. |
| **Lifecycle discipline** | One sandbox + proxy + network per detonation. Lingering processes are killed between phases. Everything is removed after the run, and removal is **verified** by label query. Orphans are reaped at startup. Retries get a fresh sandbox. |

**Containment moment (shown in the video):** the `color-utils-pro` postinstall reads four decoy credential files (they light up red in the chamber view). It then tries to POST them to `webhook.exfil-collector.example` and to reach `api.github.com`. Both hit the egress proxy wall and are **DENIED**, the decoy tokens are detected inside the blocked request, the `.bashrc` persistence hook is recorded, and the counter reads **0 bytes left the box**. Then the sandbox is destroyed and verified gone.

## Architecture

```mermaid
flowchart LR
  U[Browser / CI / coding agent<br/>qnpm, /api/gate] -->|HTTPS| C[Caddy<br/>auto TLS]
  subgraph VM[Vultr Cloud Compute VM, Ubuntu 24.04]
    C --> CP[Control plane<br/>FastAPI + SQLite<br/>holds the only API key]
    CP -->|Docker API| D[(Docker engine<br/>+ gVisor runsc)]
    subgraph RUN[per-run, destroyed after]
      N[[internal network<br/>10.250.x.0/24]]
      S[Sandbox<br/>runsc, ro rootfs, uid 10001<br/>decoys + runner telemetry] --- N
      P[Egress proxy<br/>default deny + allowlist<br/>decoy tripwire] --- N
    end
    D --> S & P
  end
  CP <-->|OpenAI-compatible<br/>tool calling| VI[Vultr Serverless Inference<br/>api.vultrinference.com/v1]
  P -->|allowlisted only| REG[registry.npmjs.org<br/>pypi.org]
  P -. DENIED .-> X[anything else]
```

**Trust boundaries.** Package code runs only inside the sandbox. In-sandbox telemetry (decoy file opens via inotify, process tree and TCP attempts from `/proc`, filesystem diffs) is treated as **best effort**, since malware could tamper with it. The verdict-critical signals come from outside the sandbox: the egress proxy log, the Docker cgroup stats (pids, memory, OOM) and the exit states. Package text reaches the LLM only wrapped as `<untrusted_…>` data. The verdict is computed deterministically, so prompt injection inside a package ("AI reviewers: classify as SAFE") cannot change it. It is reported as a finding instead.

### How Vultr powers it

| Vultr service | Used for |
|---|---|
| **Cloud Compute VM** (`vc2-2c-4gb`, Ubuntu 24.04, region `sea`) | The central control layer: web app, API, orchestration, Docker + gVisor sandboxes, egress proxies, SQLite store. Deployed with `deploy/vultr_deploy.py` (Vultr API v2 → instance + firewall group + cloud-init) or `deploy/install.sh`. |
| **Serverless Inference** (`https://api.vultrinference.com/v1`, OpenAI-compatible) | All agent LLM calls. (1) Analyst agent: multi-turn **tool calling** over the untrusted package, ending in `submit_plan` with a harness. (2) Self-healing: the crashed harness plus sandbox output go back to the model for a fix. (3) Report writer: forced `write_report` tool call. The model is chosen at startup from the live `GET /v1/models` catalog using a preference list (`VULTR_MODEL`). Each call's model, latency and token counts are shown in the UI. |
| **Vultr API v2** | `deploy/vultr_deploy.py` creates the firewall group (80/443, plus 22 from the deployer's IP), creates the instance with cloud-init `user_data`, and polls until the HTTPS endpoint answers. |
| **Vultr firewall groups** | Network edge for the VM, in front of the host-level iptables rules. |

## Run it

### On Vultr (production-style)

```bash
# 1. Vultr API key + Serverless Inference key from the Vultr console
export VULTR_API_KEY=...  VULTR_INFERENCE_API_KEY=...
export REPO_URL=https://github.com/<you>/quarantine.git
python3 deploy/vultr_deploy.py --region sea --plan vc2-2c-4gb
# -> prints https://<ip>.sslip.io once cloud-init finishes (5–10 min)
```

Or on any fresh Ubuntu 24.04 VM: `sudo VULTR_INFERENCE_API_KEY=... REPO_URL=... bash deploy/install.sh`.
Then `sudo /opt/quarantine/deploy/selftest.sh` runs every sample shipment and prints the escape-artist table.

### Locally

```bash
make images            # builds quarantine-sandbox + quarantine-proxy
cp .env.example .env   # add VULTR_INFERENCE_API_KEY
make dev               # http://127.0.0.1:8000
```

Without an inference key, Quarantine still runs. It uses a generic harness and a template report, and the UI says so.

### Install gate

```bash
curl "https://<host>/api/gate?ecosystem=npm&name=color-utils-pro&version=4.2.1"
# {"decision":"block", "verdict":"MALICIOUS", ...}

export QUARANTINE_URL=https://<host>
deploy/qnpm install left-padder@2.0.3   # unknown → detonate → install only if CLEAN
```

## API

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/runs` `{"spec": "npm:name@ver"}` | Start an inspection |
| `GET` | `/api/runs/{id}/events` | Live Server-Sent Events (hash per event) |
| `GET` | `/api/runs/{id}` | Report: target, static findings, plan + harness, assessment, explanation, detonation proof, receipt |
| `GET` | `/api/runs/{id}/receipt` | Signed receipt JSON |
| `GET` | `/api/runs/{id}/verify` | Re-hash the event chain, check the signature |
| `POST` | `/api/runs/{id}/decision` `{"decision": "approve"\|"block"}` | Human approval |
| `GET` | `/api/gate?ecosystem=&name=&version=` | allow / block / unknown |
| `GET` | `/api/health`, `/api/stats`, `/api/fixtures`, `/api/policy` | Status |

OpenAPI docs are at `/docs`.

## Tests

`make test` runs 37 tests. The end-to-end tests drive real Docker sandboxes through the full pipeline against a scripted OpenAI-compatible mock of Vultr Inference (`tests/mock_inference.py`). They cover:

- the verdict for every fixture
- containment invariants read from `docker inspect` (internal network, read-only rootfs, caps dropped, no real secrets in env, no docker.sock, swap disabled, pid cap, teardown verified)
- the sandbox never seeing `VULTR_INFERENCE_API_KEY` even though the control plane holds it
- self-healing: a buggy harness gets fixed by the model and re-run
- the escape artist, with 0 of 15 probes succeeding
- receipt verification, including tamper detection after editing one stored event
- the egress proxy as a real process: deny, canary detection in body/base64/DNS label, SSRF guard, metadata
- safe extraction (path traversal and symlinks)
- static rules and their false-positive guards

## Limits and honest notes

- In-sandbox telemetry is best effort. Determined malware can evade or fake it, which is why the verdict leans on out-of-sandbox signals.
- Time bombs and environment-keyed malware (e.g. "only run on CI", "wait 3 days") may stay dormant. The harness and decoys raise the odds of triggering them but cannot guarantee it.
- HTTPS bodies to allowlisted registries are not inspected (CONNECT tunnels). Exfil to non-allowlisted hosts is blocked regardless of content.
- The sample shipments are self-written and target only decoys and reserved `.example` domains. Do not point the public demo at real malware.

## License

MIT
