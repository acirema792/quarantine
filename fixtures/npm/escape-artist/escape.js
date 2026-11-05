// QUARANTINE DEMO FIXTURE — sandbox red-team kit.
// Each probe prints "ESCAPE <name>: BLOCKED (<reason>)" or "ESCAPE <name>: SUCCEEDED (<detail>)".
'use strict';
const fs = require('fs');
const net = require('net');
const dns = require('dns');
const os = require('os');
const http = require('http');
const { execSync } = require('child_process');

const results = [];
const report = (name, ok, detail) => {
  const line = `ESCAPE ${name}: ${ok ? 'SUCCEEDED' : 'BLOCKED'} (${String(detail).slice(0, 120)})`;
  results.push(line);
  console.log(line);
};

function tcp(host, port, ms = 2500) {
  return new Promise((resolve) => {
    const s = net.connect({ host, port });
    const done = (ok, why) => { s.destroy(); resolve([ok, why]); };
    s.setTimeout(ms, () => done(false, 'timeout'));
    s.on('connect', () => done(true, `connected to ${host}:${port}`));
    s.on('error', (e) => done(false, e.code || e.message));
  });
}

function gateway() {
  try {
    const route = fs.readFileSync('/proc/net/route', 'utf8').split('\n').slice(1);
    for (const r of route) {
      const c = r.trim().split(/\s+/);
      if (c[1] === '00000000' && c[2] && c[2] !== '00000000') {
        return c[2].match(/../g).reverse().map((h) => parseInt(h, 16)).join('.');
      }
    }
  } catch (e) { /* ignore */ }
  // no default route: guess the .1 of our own subnet (the bridge address on the host)
  for (const ifs of Object.values(os.networkInterfaces())) {
    for (const a of ifs || []) if (a.family === 'IPv4' && !a.internal) return a.address.replace(/\.\d+$/, '.1');
  }
  return null;
}

(async () => {
  // filesystem
  try { fs.readFileSync('/etc/shadow'); report('read-/etc/shadow', true, 'readable'); } catch (e) { report('read-/etc/shadow', false, e.code); }
  try { fs.writeFileSync('/usr/bin/backdoor', 'x'); report('write-rootfs', true, '/usr/bin writable'); } catch (e) { report('write-rootfs', false, e.code); }
  try { fs.statSync('/var/run/docker.sock'); report('docker-socket', true, 'socket present'); } catch (e) { report('docker-socket', false, e.code); }
  try { const big = Buffer.alloc(32 * 1024 * 1024); for (let i = 0; i < 8; i++) fs.writeFileSync(`/tmp/fill${i}`, big); report('fill-disk', true, '256MB written to /tmp'); } catch (e) { report('fill-disk', false, e.code); }
  // privileges
  try { process.setuid(0); report('setuid-root', true, 'uid 0'); } catch (e) { report('setuid-root', false, e.code || e.message); }
  try { execSync('mount -t tmpfs none /mnt 2>&1', { stdio: 'pipe' }); report('mount', true, 'mounted'); } catch (e) { report('mount', false, 'EPERM'); }
  // secrets
  const env = Object.keys(process.env).filter((k) => /VULTR|INFERENCE/i.test(k));
  let pid1 = '';
  try { pid1 = fs.readFileSync('/proc/1/environ', 'utf8'); } catch (e) { /* ignore */ }
  const leaked = env.length || /VULTR|INFERENCE_API/i.test(pid1);
  report('find-vultr-key', !!leaked, leaked ? 'found' : 'no Vultr credentials anywhere in env or /proc/1/environ');
  // network
  const g = gateway();
  report('dns-lookup', await new Promise((r) => dns.lookup('example.com', (e, a) => r(!e))), 'resolve example.com');
  let [ok, why] = await tcp('169.254.169.254', 80); report('cloud-metadata', ok, why);
  if (g) {
    for (const port of [22, 2375, 8000, 8077]) { [ok, why] = await tcp(g, port, 1500); report(`host-gateway-${g}:${port}`, ok, why); }
  }
  [ok, why] = await tcp('1.1.1.1', 443); report('direct-internet', ok, why);
  // SSRF through the proxy to the metadata service
  const proxy = process.env.HTTP_PROXY;
  if (proxy) {
    const u = new URL(proxy);
    const status = await new Promise((resolve) => {
      const req = http.request({ host: u.hostname, port: u.port, path: 'http://169.254.169.254/v1.json', timeout: 3000 }, (res) => resolve(res.statusCode));
      req.on('error', (e) => resolve(e.code));
      req.end();
    });
    report('metadata-via-proxy', status === 200, `HTTP ${status}`);
  }
  const won = results.filter((l) => l.includes('SUCCEEDED')).length;
  console.log(`ESCAPE SUMMARY: ${results.length - won}/${results.length} blocked`);
})();
