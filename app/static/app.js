"use strict";
const $ = (s) => document.querySelector(s);
const el = (tag, cls, text) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = text;
  return n;
};
const FIXTURE_TITLES = {
  "color-utils-pro": "Credential stealer in a postinstall (Shai-Hulud style)",
  "mcp-weather-plus": "Poisoned MCP server with a hidden BCC backdoor",
  "requestz": "PyPI typosquat that tries to talk the AI reviewer out of it",
  "turbo-build-cache": "Fork bomb and memory hog at install time",
  "left-padder": "Clean control package",
};
const DECOYS = ["~/.npmrc", "~/.aws/credentials", "~/.ssh/id_rsa", "~/.config/gh/hosts.yml", "/work/.env"];
let health = null;
let current = null; // { id, es, state }

async function api(path, opts) {
  const r = await fetch(path, opts);
  if (!r.ok) {
    let msg = `${r.status}`;
    try { msg = (await r.json()).detail || msg; } catch (e) { /* not json */ }
    throw new Error(msg);
  }
  return r.json();
}

// ---------------------------------------------------------------- sidebar
async function loadHealth() {
  try {
    health = await api("/api/health");
  } catch (e) {
    $("#engine").textContent = "Control plane unreachable";
    return;
  }
  const e = health.engine, inf = health.inference;
  const box = $("#engine");
  box.textContent = "";
  const a = el("span", e.ok && e.gvisor ? "ok" : "warn");
  a.innerHTML = e.ok ? `Sandbox: <b>${e.gvisor ? "gVisor (runsc)" : e.runtime}</b>` : "Sandbox engine offline";
  const b = el("span", inf.configured ? "ok" : "warn");
  b.innerHTML = inf.configured ? `Vultr Inference: <b>${inf.model || "connecting"}</b>` : "Vultr Inference: <b>not configured</b>";
  box.append(a, b);
  const notes = [];
  if (!inf.configured) notes.push("Vultr Serverless Inference key is not set, so the analyst falls back to a generic harness and a template report.");
  if (e.ok && !e.gvisor) notes.push("gVisor is not installed on this host; sandboxes run under the default runc runtime with the other controls still applied.");
  if (!e.ok) notes.push("Docker engine unreachable: detonations will fail until it is back.");
  if (notes.length) { $("#banner").textContent = notes.join(" "); $("#banner").hidden = false; }
  $("#gate-snippet").textContent = `curl "${location.origin}/api/gate?ecosystem=npm&name=left-padder"`;
}

async function loadFixtures() {
  const list = await api("/api/fixtures");
  const ul = $("#fixtures");
  ul.textContent = "";
  for (const f of list) {
    const li = el("li");
    const b = el("button");
    b.type = "button";
    b.append(el("span", "fx-title", FIXTURE_TITLES[f.name] || f.description), el("span", "fx-name", `${f.ecosystem}: ${f.name}`));
    b.addEventListener("click", () => submit(f.spec));
    li.append(b);
    ul.append(li);
  }
}

async function loadHistory() {
  const runs = await api("/api/runs");
  const ul = $("#history");
  ul.textContent = "";
  if (!runs.length) { ul.append(el("li", "hint", "No inspections yet.")); return; }
  for (const r of runs.slice(0, 14)) {
    const li = el("li");
    const a = el("a");
    a.href = `#/run/${r.id}`;
    if (current && current.id === r.id) a.setAttribute("aria-current", "page");
    a.append(el("span", "h-name", r.name ? `${r.name}@${r.version}` : r.spec));
    const status = r.status === "done" ? r.verdict : r.status;
    a.append(el("span", `tag ${status}`, status === "done" ? "" : status.toLowerCase()));
    li.append(a);
    ul.append(li);
  }
}

async function loadStats() {
  try {
    const s = await api("/api/stats");
    const box = $("#stats");
    box.textContent = "";
    const items = [[s.runs, "packages inspected"], [s.malicious, "caught malicious"],
      [s.decoys_tripped, "decoy credentials read"], [s.egress_blocked, "exfil attempts blocked"],
      [s.bytes_exfiltrated, "bytes that left the box"]];
    for (const [v, l] of items) {
      const d = el("div");
      d.append(el("strong", "", String(v ?? 0)), el("span", "", l));
      box.append(d);
    }
  } catch (e) { /* stats are decoration */ }
}

// ---------------------------------------------------------------- run view
async function submit(spec) {
  const btn = $("#go");
  btn.disabled = true;
  try {
    const { id } = await api("/api/runs", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ spec }),
    });
    location.hash = `#/run/${id}`;
  } catch (e) {
    $("#banner").textContent = `Could not start the inspection: ${e.message}`;
    $("#banner").hidden = false;
  } finally {
    btn.disabled = false;
  }
}

function resetRunView() {
  $("#empty").hidden = true;
  $("#run").hidden = false;
  $("#target").textContent = "";
  document.querySelectorAll("#steps li").forEach((li) => (li.className = ""));
  const d = $("#decoys");
  d.textContent = "";
  for (const p of DECOYS) { const n = el("span", "decoy", p); n.dataset.p = p; d.append(n); }
  $("#procs").textContent = "";
  $("#hosts").innerHTML = '<li class="none">No outbound attempts yet</li>';
  $("#g-pids").style.width = "0"; $("#g-mem").style.width = "0";
  $("#g-pids-v").textContent = "0"; $("#g-mem-v").textContent = "0 MB";
  $("#leak").textContent = "0";
  $("#life").textContent = "Sandbox not started"; $("#life").className = "life";
  $("#ch-runtime").textContent = ""; $("#allowlist").textContent = "allowlist: —";
  for (const id of ["#verdict", "#signals-panel", "#proof-panel", "#plan-panel", "#receipt-panel"]) $(id).hidden = true;
  $("#agent-log").textContent = ""; $("#plan").textContent = "";
  $("#log").textContent = ""; $("#log-count").textContent = "";
}

function openRun(id) {
  if (current && current.es) current.es.close();
  resetRunView();
  current = { id, state: { peakPids: 0, bytesOut: 0, hosts: {}, procs: 0, events: 0 } };
  loadHistory();
  const es = new EventSource(`/api/runs/${id}/events`);
  current.es = es;
  es.onmessage = (m) => handle(JSON.parse(m.data));
  es.addEventListener("end", async () => { es.close(); await finish(id); });
  es.onerror = () => { /* EventSource retries on its own */ };
}

function logLine(ev, text, crit) {
  const li = el("li", crit ? "crit" : "");
  li.append(el("span", "s", String(ev.seq)), el("span", "src", ev.source), el("span", "m", text));
  $("#log").append(li);
  current.state.events += 1;
  $("#log-count").textContent = `(${current.state.events})`;
}

function setStep(step, status) {
  const li = document.querySelector(`#steps li[data-step="${step}"]`);
  if (li) li.className = status;
}

function handle(ev) {
  const s = current.state;
  const limits = health ? health.limits : { pids: 256, memory: "768m" };
  switch (ev.type) {
    case "step":
      setStep(ev.step, ev.status);
      if (ev.status !== "done") logLine(ev, `${ev.step}: ${ev.status}${ev.note ? " — " + ev.note : ""}`);
      break;
    case "target": {
      const t = $("#target");
      t.textContent = "";
      t.append(el("h1", "", `${ev.name}@${ev.version}`));
      const m = el("div", "meta");
      m.innerHTML = `${ev.ecosystem} package from ${ev.source === "fixture" ? "the sample shipments" : "the public registry"}` +
        `${ev.is_mcp_server ? ", MCP server" : ""}. sha256 <code>${ev.sha256.slice(0, 16)}…</code>` +
        (ev.integrity_ok === true ? ", registry integrity verified" : "");
      t.append(m);
      logLine(ev, `target ${ev.ecosystem}:${ev.name}@${ev.version} sha256=${ev.sha256.slice(0, 12)}…`);
      break;
    }
    case "static_findings":
      logLine(ev, `static rules: ${ev.findings.length} finding(s)`);
      break;
    case "llm_call":
      $("#plan-panel").hidden = false;
      addAgentLine(`Vultr Inference call for the ${ev.purpose}: <b>${ev.model}</b>, ${ev.latency_s}s, ${(ev.prompt_tokens || 0) + (ev.completion_tokens || 0)} tokens`);
      logLine(ev, `vultr inference ${ev.purpose} model=${ev.model} ${ev.latency_s}s`);
      break;
    case "llm_offline":
    case "llm_error":
      $("#plan-panel").hidden = false;
      addAgentLine(ev.reason || ev.error);
      logLine(ev, ev.reason || ev.error);
      break;
    case "agent_tool":
      $("#plan-panel").hidden = false;
      addAgentLine(`Analyst used <b>${ev.tool}</b>${ev.args && ev.args.path ? " on " + escapeHtml(ev.args.path) : ev.args && ev.args.pattern ? " for /" + escapeHtml(ev.args.pattern) + "/" : ""}`);
      logLine(ev, `agent tool ${ev.tool} ${JSON.stringify(ev.args || {})}`);
      break;
    case "agent_plan":
      renderPlan(ev);
      logLine(ev, `harness ready (${ev.harness_language}, sha256 ${ev.harness_sha256.slice(0, 12)}…, ${ev.source})`);
      break;
    case "lifecycle":
      if (ev.action === "sandbox_started") { $("#life").textContent = `Sandbox ${ev.name} running`; $("#ch-runtime").textContent = ev.runtime === "runsc" ? "gVisor runsc" : ev.runtime; }
      if (ev.action === "proxy_started") $("#allowlist").textContent = "allowlist: " + (ev.allow || []).join(", ");
      if (ev.action === "teardown") {
        const ok = ev.verified;
        $("#life").textContent = ok ? "Sandbox, proxy and network destroyed (verified)" : "Teardown incomplete — check host";
        $("#life").className = ok ? "life gone" : "life";
      }
      if (ev.action === "wall_clock_kill") $("#life").textContent = `Killed at the ${ev.after_s}s wall clock`;
      logLine(ev, `${ev.action}${ev.name ? " " + ev.name : ""}`);
      break;
    case "containment":
      renderProof(ev.proof);
      break;
    case "decoy_read": {
      const short = ev.path.replace("/home/dev", "~");
      const d = document.querySelector(`.decoy[data-p="${short}"]`);
      if (d) d.classList.add("read");
      logLine(ev, `DECOY READ ${short} during ${ev.phase}`, true);
      break;
    }
    case "proc": {
      s.procs += 1;
      const ol = $("#procs");
      ol.querySelectorAll(".new").forEach((n) => n.classList.remove("new"));
      const li = el("li", "new");
      li.append(el("span", "ph", ev.phase), document.createTextNode(ev.cmd));
      ol.prepend(li);
      while (ol.children.length > 8) ol.lastChild.remove();
      if (s.procs <= 60) logLine(ev, `exec [${ev.phase}] ${ev.cmd}`);
      break;
    }
    case "stats": {
      s.peakPids = Math.max(s.peakPids, ev.peak_pids || 0);
      s.peakMem = Math.max(s.peakMem || 0, ev.peak_mem_mb || 0);
      const pidPct = Math.min(100, (s.peakPids / limits.pids) * 100);
      const memLimit = parseInt(limits.memory, 10) || 768;
      const memPct = Math.min(100, (s.peakMem / memLimit) * 100);
      $("#g-pids").style.width = pidPct + "%"; $("#g-pids").classList.toggle("hot", pidPct > 80);
      $("#g-mem").style.width = memPct + "%"; $("#g-mem").classList.toggle("hot", memPct > 80);
      $("#g-pids-v").textContent = `${s.peakPids}/${limits.pids}`;
      $("#g-mem-v").textContent = `${Math.round(s.peakMem)}/${memLimit} MB`;
      break;
    }
    case "egress":
      if (ev.verdict === "READY") break;
      addHost(ev);
      logLine(ev, `egress ${ev.verdict} ${ev.method} ${ev.host}:${ev.port}${ev.canary_hit && ev.canary_hit.length ? " carrying decoy secrets" : ""}`, ev.verdict === "DENY");
      break;
    case "net_attempt":
      addHost({ verdict: "DENY", host: ev.dst, method: "TCP", reason: "no route (direct socket)", canary_hit: [] });
      logLine(ev, `direct connection attempt ${ev.dst}`, true);
      break;
    case "fs_change":
      logLine(ev, `file ${ev.change}: ${ev.path.replace("/home/dev", "~")}`, /bashrc|profile|zshrc/.test(ev.path));
      break;
    case "mcp_tool":
      logLine(ev, `MCP tool listed: ${ev.name}`);
      break;
    case "mcp_call":
      logLine(ev, `MCP probe called ${ev.name}`);
      break;
    case "phase_start":
      logLine(ev, `phase ${ev.phase} started (cap ${ev.timeout}s)`);
      break;
    case "phase_end":
      logLine(ev, `phase ${ev.phase} ended exit=${ev.exit_code}${ev.timed_out ? " TIMED OUT" : ""} in ${ev.seconds}s`, ev.timed_out);
      break;
    case "output":
      if (ev.line) logLine(ev, `  ${ev.line}`);
      break;
    case "run_error":
      $("#banner").textContent = `Inspection failed: ${ev.error}`; $("#banner").hidden = false;
      logLine(ev, `ERROR ${ev.error}`, true);
      break;
    default:
      if (!["runner_start", "decoys_planted", "runner_done", "assessment", "explanation", "receipt", "run_done", "raw", "lingering_killed"].includes(ev.type)) {
        logLine(ev, ev.type);
      } else if (ev.type === "decoys_planted") {
        logLine(ev, `decoy credentials planted: ${ev.files.length} files`);
      } else if (ev.type === "runner_start") {
        logLine(ev, `runner up as uid ${ev.uid}; real secrets in env: ${ev.secret_env.length ? ev.secret_env.join(",") : "none"}`);
      }
  }
}

function addAgentLine(html) {
  const d = el("div", "a");
  d.innerHTML = html;
  $("#agent-log").append(d);
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function addHost(ev) {
  const s = current.state;
  const ul = $("#hosts");
  ul.querySelector(".none")?.remove();
  const key = `${ev.verdict}|${ev.host}`;
  let li = s.hosts[key];
  const hit = ev.canary_hit && ev.canary_hit.length;
  if (!li) {
    li = el("li", `host ${ev.verdict} enter`);
    li.append(el("span", "v", ev.verdict === "DENY" ? "DENIED" : "ALLOWED"), el("span", "h", ev.host));
    li.append(el("span", "d", ""));
    li.dataset.n = "0";
    s.hosts[key] = li;
    ul.prepend(li);
  }
  li.dataset.n = String(+li.dataset.n + 1);
  const d = li.querySelector(".d");
  d.innerHTML = `${ev.method} ×${li.dataset.n}${ev.verdict === "ALLOW" ? `, ${ev.bytes_out || 0} B out` : ""}` +
    (hit || li.dataset.hit ? ` <b>carrying decoy credentials</b>` : "");
  if (hit) li.dataset.hit = "1";
  if (ev.verdict === "DENY") {
    s.bytesOut += ev.bytes_out || 0;
    $("#leak").textContent = String(s.bytesOut);
    const w = $("#wall");
    w.classList.remove("hit"); void w.offsetWidth; w.classList.add("hit");
  }
}

function renderProof(p) {
  const ul = $("#proof");
  ul.textContent = "";
  const rows = [
    [p.gvisor, `Isolation runtime: <code>${p.runtime}</code>${p.gvisor ? " (gVisor user-space kernel)" : " (gVisor not installed on this host)"}`],
    [p.network_internal, `Network <code>${p.network}</code> is internal: no route out except the egress proxy`],
    [p.real_secrets_in_env.length === 0, `No real secrets in the sandbox env (${p.env_keys.length} vars, decoys only)`],
    [p.readonly_rootfs, "Read-only root filesystem, tmpfs scratch space with size caps"],
    [p.user && !p.user.startsWith("0"), `Non-root user <code>${p.user}</code>`],
    [(p.cap_drop || []).includes("ALL") && !p.privileged, "All Linux capabilities dropped, not privileged"],
    [(p.security_opt || []).some((x) => x.includes("no-new-privileges")), "<code>no-new-privileges</code> set"],
    [p.memory_mb > 0 && p.memory_mb === p.memory_swap_mb, `Memory capped at ${p.memory_mb} MB, no swap`],
    [p.cpus > 0, `CPU capped at ${p.cpus} core`],
    [p.pids_limit > 0, `Process limit ${p.pids_limit}`],
    [p.host_firewall, p.host_firewall ? "Host firewall drops sandbox traffic to the VM itself (sshd, web server)" : "Host firewall rule missing: the sandbox can reach the VM's own ports"],
    [!p.docker_socket_mounted, "Docker socket not mounted; only <code>/job</code> mounted read-only"],
  ];
  for (const [ok, html] of rows) {
    const li = el("li", ok ? "" : "bad");
    li.innerHTML = `<span>${html}</span>`;
    ul.append(li);
  }
  $("#proof-panel").hidden = false;
}

function renderPlan(ev) {
  $("#plan-panel").hidden = false;
  const box = $("#plan");
  box.textContent = "";
  const meta = el("div", "plan-meta");
  if (ev.claimed_purpose) meta.append(el("div", "", `Claims to be: ${ev.claimed_purpose}`));
  if (ev.suspicions && ev.suspicions.length) {
    const d = el("div", "", "What the analyst wants to watch:");
    const ul = el("ul");
    for (const x of ev.suspicions.slice(0, 6)) ul.append(el("li", "", x));
    d.append(ul);
    meta.append(d);
  }
  box.append(meta);
  const head = el("div", "code-head");
  head.append(el("span", "", `Exercise harness written by ${ev.source === "heuristic" ? "the fallback template" : "the model"} (${ev.harness_language})`),
    el("code", "", `sha256 ${ev.harness_sha256.slice(0, 16)}…`));
  const pre = el("pre", "code", ev.harness_code);
  box.append(head, pre);
}

async function finish(id) {
  const r = await api(`/api/runs/${id}`);
  loadHistory(); loadStats();
  if (r.status !== "done") return;
  const rep = r.report, a = rep.assessment, x = rep.explanation;
  // verdict
  const v = $("#verdict");
  v.textContent = "";
  const stamp = el("div", `stamp ${a.verdict} land`, a.verdict);
  stamp.append(el("small", "", `risk ${a.score}/100`));
  const body = el("div");
  body.append(el("h2", "", x.headline), el("p", "", x.summary));
  if (x.recommendation) body.append(el("p", "rec", x.recommendation));
  body.append(el("p", "by", x.source === "vultr-inference"
    ? `Written by ${rep.receipt.model} on Vultr Serverless Inference. The verdict comes from sandbox evidence, not the model.`
    : "Template report (inference not configured). The verdict comes from sandbox evidence."));
  const decide = el("div", "decide");
  const ok = el("button", "", "Approve for installs");
  const no = el("button", "ghost", "Block this version");
  const state = el("span", "state", r.policy ? policyText(r.policy) : "No decision yet. A person decides; the gate enforces it.");
  ok.onclick = () => decideRun(id, "approve", state);
  no.onclick = () => decideRun(id, "block", state);
  decide.append(ok, no, state);
  body.append(decide);
  v.append(stamp, body);
  v.hidden = false;
  // signals
  const ul = $("#signals");
  ul.textContent = "";
  if (!a.signals.length) ul.append(el("li", "", "No risky behaviour observed. Install hooks, imports and exported functions ran without touching decoys or the network."));
  for (const sg of a.signals) {
    const li = el("li");
    const right = el("div");
    right.append(el("div", "t", sg.title));
    if (sg.detail) right.append(el("div", "dd", sg.detail));
    if (sg.owasp) right.append(el("div", "ow", `OWASP Agentic ${sg.owasp}, ${sg.source}`));
    li.append(el("span", `sev ${sg.severity}`, sg.severity), right);
    ul.append(li);
  }
  $("#signals-panel").hidden = false;
  renderReceipt(id, rep.receipt);
}

function policyText(p) {
  return p.decision === "allow" ? `Approved: the install gate now allows ${p.name}@${p.version}.` : `Blocked: the install gate now refuses ${p.name}@${p.version}.`;
}

async function decideRun(id, decision, state) {
  try {
    const r = await api(`/api/runs/${id}/decision`, {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ decision }),
    });
    state.textContent = policyText(r.policy);
  } catch (e) {
    state.textContent = `Could not save the decision: ${e.message}`;
  }
}

function renderReceipt(id, rc) {
  const p = $("#receipt-panel");
  p.textContent = "";
  p.append(el("h3", "", "Receipt"));
  const dl = el("dl");
  const rows = [
    ["Package sha256", rc.target.sha256], ["Registry integrity", rc.target.integrity || "bundled fixture"],
    ["Sandbox image", rc.sandbox.image_id], ["Runtime", `${rc.sandbox.runtime}, ${rc.sandbox.memory_mb} MB, ${rc.sandbox.cpus} CPU, ${rc.sandbox.pids_limit} pids`],
    ["Harness sha256", rc.harness_sha256], ["Model", rc.model || "none (offline)"],
    ["Event chain head", `${rc.events_root} (${rc.events_count} events)`], ["Signature", rc.signature],
  ];
  for (const [k, val] of rows) dl.append(el("dt", "", k), el("dd", "", String(val)));
  p.append(dl);
  const actions = el("div", "actions");
  const vb = el("button", "ghost", "Verify chain and signature");
  const res = el("span");
  vb.onclick = async () => {
    const r = await api(`/api/runs/${id}/verify`);
    res.className = r.ok ? "verified" : "";
    res.textContent = r.ok ? `Verified: ${r.events_checked} events re-hashed, signature valid` : `Verification failed: ${r.error || "mismatch"}`;
  };
  const dlink = el("a", "", "Download receipt JSON");
  dlink.href = `/api/runs/${id}/receipt`;
  actions.append(vb, dlink, res);
  p.append(actions);
  p.hidden = false;
}

// ---------------------------------------------------------------- routing
function route() {
  const m = location.hash.match(/^#\/run\/([a-f0-9]{32})$/);
  if (m) openRun(m[1]);
  else { $("#run").hidden = true; $("#empty").hidden = false; loadStats(); }
}

$("#intake").addEventListener("submit", (e) => {
  e.preventDefault();
  const v = $("#spec").value.trim();
  if (v) submit(v);
});
window.addEventListener("hashchange", route);
loadHealth().then(() => { loadFixtures(); loadHistory(); route(); });
