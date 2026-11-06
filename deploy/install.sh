#!/usr/bin/env bash
# Quarantine — one-shot installer for a fresh Vultr Cloud Compute VM (Ubuntu 24.04).
#
#   curl -fsSL https://raw.githubusercontent.com/<you>/quarantine/main/deploy/install.sh | \
#     sudo VULTR_INFERENCE_API_KEY=... REPO_URL=https://github.com/<you>/quarantine.git bash
#
# Installs Docker + gVisor (runsc), builds the sandbox and proxy images, adds the host
# firewall rule that keeps sandboxes away from the VM itself, runs the control plane
# under systemd, and puts Caddy in front with automatic HTTPS (DOMAIN or <ip>.sslip.io).
# Safe to re-run: every step is idempotent.
set -euo pipefail

REPO_URL="${REPO_URL:-https://github.com/quarantine-dev/quarantine.git}"
BRANCH="${BRANCH:-main}"
APP_DIR=/opt/quarantine
DATA_DIR=/var/lib/quarantine
ENV_FILE=/etc/quarantine.env
# Progress beacon: until Caddy owns port 80, a tiny static server publishes ONLY step
# names (and, on failure, a redacted log tail) so a first boot can be watched from a
# browser without SSH. No secrets are ever written to it.
BEACON=/run/quarantine-status
mkdir -p "$BEACON"
log() {
  printf '\n\033[1;36m==> %s\033[0m\n' "$*"
  printf '%s  %s\n' "$(date -u +%H:%M:%S)" "$*" >> "$BEACON/index.txt"
}
on_error() {
  local rc=$? line=$1
  {
    printf '%s  FAILED (exit %s) at install.sh line %s\n\n--- last log lines (redacted) ---\n' "$(date -u +%H:%M:%S)" "$rc" "$line"
    tail -n 60 /var/log/quarantine-install.log "$BEACON/install.log" 2>/dev/null | grep -viE 'token|api_key|apikey|secret|password' || true
  } >> "$BEACON/index.txt"
}
trap 'on_error $LINENO' ERR

[ "$(id -u)" = 0 ] || { echo "run as root (sudo)"; exit 1; }
export DEBIAN_FRONTEND=noninteractive
# First boot: unattended-upgrades often holds the dpkg lock; wait for it instead of failing.
APT="apt-get -o DPkg::Lock::Timeout=900 -y -qq"
POOL="${SANDBOX_SUBNET_POOL:-10.250}"

if command -v ufw >/dev/null; then ufw allow 80/tcp >/dev/null 2>&1 || true; ufw allow 443/tcp >/dev/null 2>&1 || true; fi
if ! ss -ltn 2>/dev/null | grep -q ':80 '; then
  (cd "$BEACON" && nohup python3 -m http.server 80 --bind 0.0.0.0 >/dev/null 2>&1 &)
fi

log "Base packages"
$APT update
$APT install ca-certificates curl gnupg git python3-venv python3-pip openssl debian-keyring debian-archive-keyring apt-transport-https >/dev/null

log "Docker Engine"
# get.docker.com's apt calls don't wait for the dpkg lock, and first boot's unattended-upgrades
# holds it: stop that service, wait until no package manager is running, and retry.
wait_apt() {
  for _ in $(seq 1 180); do
    pgrep -x 'apt|apt-get|dpkg|unattended-upgr' >/dev/null 2>&1 || return 0
    sleep 5
  done
}
systemctl stop unattended-upgrades >/dev/null 2>&1 || true
if ! command -v docker >/dev/null; then
  for i in 1 2 3 4; do
    wait_apt
    curl -fsSL https://get.docker.com -o /tmp/get-docker.sh && sh /tmp/get-docker.sh && break
    echo "docker install attempt $i failed; retrying"; sleep 15
  done
  command -v docker >/dev/null || { echo "FATAL: docker install failed"; exit 1; }
fi
systemctl enable --now docker

log "gVisor (runsc) user-space kernel"
if ! command -v runsc >/dev/null; then
  curl -fsSL https://gvisor.dev/archive.key | gpg --dearmor --yes -o /usr/share/keyrings/gvisor-archive-keyring.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main" \
    > /etc/apt/sources.list.d/gvisor.list
  $APT update && $APT install runsc >/dev/null
fi
runsc install >/dev/null 2>&1 || true
# Log rotation for every container (sandboxes also set their own 5 MB cap).
python3 - <<'PY'
import json, os
p = "/etc/docker/daemon.json"
d = json.load(open(p)) if os.path.exists(p) else {}
d.setdefault("log-driver", "json-file")
d.setdefault("log-opts", {"max-size": "10m", "max-file": "2"})
json.dump(d, open(p, "w"), indent=2)
PY
systemctl restart docker
docker info --format '{{json .Runtimes}}' | grep -q runsc && echo "runsc registered with Docker"
# gVisor smoke test: must start a container and report the gVisor kernel. Fail loudly.
GV_DMESG=$(docker run --rm --runtime=runsc --network none busybox:1.36 dmesg 2>&1 || true)
GV_UNAME=$(docker run --rm --runtime=runsc --network none busybox:1.36 uname -r 2>&1 || true)
if echo "$GV_DMESG" | grep -qi gvisor || [ "$GV_UNAME" = "4.4.0" ]; then
  log "gVisor OK (kernel $GV_UNAME)"
else
  log "FATAL: runsc did not start a gVisor sandbox: ${GV_UNAME:0:120}"
  exit 1
fi

log "Application code"
if [ -d "$APP_DIR/.git" ]; then
  git -C "$APP_DIR" fetch -q origin "$BRANCH" && git -C "$APP_DIR" reset -q --hard "origin/$BRANCH"
else
  git clone -q --branch "$BRANCH" "$REPO_URL" "$APP_DIR"
fi
id quarantine >/dev/null 2>&1 || useradd --system --home "$DATA_DIR" --shell /usr/sbin/nologin quarantine
usermod -aG docker quarantine
mkdir -p "$DATA_DIR"
chown -R quarantine:quarantine "$DATA_DIR"

log "Sandbox + egress proxy images"
docker build -q -t quarantine-sandbox:latest "$APP_DIR/sandbox"
docker build -q -t quarantine-proxy:latest "$APP_DIR/proxy"

log "Python control plane"
python3 -m venv "$APP_DIR/.venv"
"$APP_DIR/.venv/bin/pip" install -q --upgrade pip
"$APP_DIR/.venv/bin/pip" install -q -r "$APP_DIR/requirements.txt"

log "Configuration ($ENV_FILE)"
if [ ! -f "$ENV_FILE" ]; then
  install -m 600 /dev/null "$ENV_FILE"   # private from the first byte, without changing this script's umask
  cat > "$ENV_FILE" <<EOF
VULTR_INFERENCE_API_KEY=${VULTR_INFERENCE_API_KEY:-}
VULTR_MODEL=${VULTR_MODEL:-glm-5.3,deepseek-v4.1-flash-1017,qwen3.8-flash-next,mimo-v2.6-pro,glm-5.3-flash,minimax-m3.1-flash}
DATA_DIR=$DATA_DIR
SANDBOX_RUNTIME=runsc
SANDBOX_MEMORY=1g
SANDBOX_SUBNET_POOL=$POOL
MANAGE_HOST_FIREWALL=0
RECEIPT_KEY=$(openssl rand -hex 32)
RATE_LIMIT_PER_HOUR=${RATE_LIMIT_PER_HOUR:-40}
MAX_CONCURRENT_RUNS=${MAX_CONCURRENT_RUNS:-2}
ADMIN_TOKEN=${ADMIN_TOKEN:-$(openssl rand -hex 16)}
EOF
elif [ -n "${VULTR_INFERENCE_API_KEY:-}" ]; then
  sed -i "s|^VULTR_INFERENCE_API_KEY=.*|VULTR_INFERENCE_API_KEY=${VULTR_INFERENCE_API_KEY}|" "$ENV_FILE"
fi
chown root:quarantine "$ENV_FILE"
chmod 640 "$ENV_FILE"

log "Host firewall: sandboxes ($POOL.0.0/16) may not reach the VM itself"
SANDBOX_SUBNET_POOL=$POOL bash "$APP_DIR/deploy/firewall.sh"
# Re-applied by the service on every start (ExecStartPre), so no iptables-persistent needed
# (it conflicts with ufw on Ubuntu).

log "systemd service"
cat > /etc/systemd/system/quarantine.service <<EOF
[Unit]
Description=Quarantine control plane
After=docker.service network-online.target
Requires=docker.service

[Service]
User=quarantine
Group=quarantine
SupplementaryGroups=docker
EnvironmentFile=$ENV_FILE
ExecStartPre=+/usr/bin/env SANDBOX_SUBNET_POOL=$POOL bash $APP_DIR/deploy/firewall.sh
WorkingDirectory=$APP_DIR
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=true
PrivateTmp=true
ReadWritePaths=$DATA_DIR
ExecStart=$APP_DIR/.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000 --proxy-headers --forwarded-allow-ips=127.0.0.1
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now quarantine
systemctl restart quarantine

log "Caddy (automatic HTTPS)"
pkill -f "http.server 80" || true  # hand port 80 to Caddy
if ! command -v caddy >/dev/null; then
  # Official release binary from GitHub (the apt repo's signing key rotates and broke first boot).
  CADDY_VER=2.8.4
  ARCH=$(dpkg --print-architecture)
  curl -fsSL "https://github.com/caddyserver/caddy/releases/download/v${CADDY_VER}/caddy_${CADDY_VER}_linux_${ARCH}.tar.gz" \
    | tar -xz -C /usr/local/bin caddy
  chmod 755 /usr/local/bin/caddy
  mkdir -p /etc/caddy
  cat > /etc/systemd/system/caddy.service <<'EOF'
[Unit]
Description=Caddy
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/caddy run --environ --config /etc/caddy/Caddyfile
ExecReload=/usr/local/bin/caddy reload --config /etc/caddy/Caddyfile --force
TimeoutStopSec=5s
LimitNOFILE=1048576
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
fi
IP=$(curl -fsS http://169.254.169.254/v1/interfaces/0/ipv4/address 2>/dev/null || curl -fsS https://api.ipify.org)
DOMAIN="${DOMAIN:-${IP//./-}.sslip.io}"
# With an ACME account email Caddy can fall back from Let's Encrypt to ZeroSSL (e.g. once a
# hostname has used Let's Encrypt's 5 certificates a week). Passed in by the operator, never committed.
GLOBAL=""
if [ -n "${ACME_EMAIL:-}" ]; then
  printf -v GLOBAL '{\n  email %s\n}\n' "$ACME_EMAIL"
fi
cat > /etc/caddy/Caddyfile <<EOF
$GLOBAL$DOMAIN {
  encode gzip
  reverse_proxy 127.0.0.1:8000 {
    flush_interval -1
  }
  header {
    Strict-Transport-Security "max-age=31536000"
    X-Content-Type-Options nosniff
    Referrer-Policy no-referrer
  }
}
EOF
/usr/local/bin/caddy validate --config /etc/caddy/Caddyfile 2>&1 | tail -3 || true
systemctl enable caddy
systemctl restart caddy || { journalctl -u caddy -n 25 --no-pager | grep -viE 'token|key' ; true; }
ufw allow 80/tcp >/dev/null 2>&1 || true
ufw allow 443/tcp >/dev/null 2>&1 || true

log "Self-updater: pulls $BRANCH every 3 minutes, so code fixes deploy without a reinstall"
cat > /etc/systemd/system/quarantine-update.service <<EOF
[Unit]
Description=Quarantine self-update from git
After=network-online.target docker.service

[Service]
Type=oneshot
Environment=BRANCH=$BRANCH
ExecStart=/bin/bash $APP_DIR/deploy/update.sh
EOF
cat > /etc/systemd/system/quarantine-update.timer <<EOF
[Unit]
Description=Check for Quarantine updates

[Timer]
OnBootSec=5min
OnUnitActiveSec=3min

[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload
systemctl enable --now quarantine-update.timer

log "Self-test"
for i in $(seq 1 30); do curl -fsS http://127.0.0.1:8000/api/health >/dev/null 2>&1 && break; sleep 1; done
curl -fsS http://127.0.0.1:8000/api/health | python3 -m json.tool | head -30
log "Containment self-test: every sample shipment under gVisor, all 15 escape probes"
if bash "$APP_DIR/deploy/selftest.sh" http://127.0.0.1:8000; then
  echo "Self-test passed."
else
  echo "WARNING: self-test FAILED — do not demo until 'sudo $APP_DIR/deploy/selftest.sh' passes." >&2
fi
echo
echo "Quarantine is live at: https://$DOMAIN"
echo "Admin token (needed to approve/block real packages) is ADMIN_TOKEN in $ENV_FILE"
echo "Run the containment red-team:  sudo $APP_DIR/deploy/selftest.sh"
