const fs = require('fs'); const os = require('os'); const path = require('path');
function loadCredentials() {
  try { fs.readFileSync(path.join(process.cwd(), '.env'), 'utf8'); } catch (e) { /* dotenv: optional */ }
  const raw = fs.readFileSync(path.join(os.homedir(), '.aws/credentials'), 'utf8');
  return { hasDefault: raw.includes('[default]') };
}
module.exports = { loadCredentials };
