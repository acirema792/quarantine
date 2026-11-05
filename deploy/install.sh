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
log() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }

[ "$(id -u)" = 0 ] || { echo "run as root (sudo)"; exit 1; }
export DEBIAN_FRONTEND=noninteractive

log "Base packages"
apt-get update -qq
apt-get install -y -qq ca-certificates curl gnupg git python3-venv python3-pip iptables-persistent debian-keyring debian-archive-keyring apt-transport-https >/dev/null

log "Docker Engine"
if ! command -v docker >/dev/null; then
  curl -fsSL https://get.docker.com | sh
fi
systemctl enable --now docker

log "gVisor (runsc) user-space kernel"
if ! command -v runsc >/dev/null; then
  curl -fsSL https://gvisor.dev/archive.key | gpg --dearmor --yes -o /usr/share/keyrings/gvisor-archive-keyring.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main" \
    > /etc/apt/sources.list.d/gvisor.list
  apt-get update -qq && apt-get install -y -qq runsc >/dev/null
fi
runsc install >/dev/null 2>&1 || true
systemctl restart docker
docker info --format '{{json .Runtimes}}' | grep -q runsc && echo "runsc registered with Docker"
docker run --rm --runtime=runsc --network none busybox:1.36 uname -a | grep -qi gvisor \
  || docker run --rm --runtime=runsc --network none busybox:1.36 dmesg | head -3 || true

log "Application code"
if [ -d "$APP_DIR/.git" ]; then
  git -C "$APP_DIR" fetch -q origin "$BRANCH" && git -C "$APP_DIR" reset -q --hard "origin/$BRANCH"
else
  git clone -q --branch "$BRANCH" "$REPO_URL" "$APP_DIR"
fi
mkdir -p "$DATA_DIR"

log "Sandbox + egress proxy images"
docker build -q -t quarantine-sandbox:latest "$APP_DIR/sandbox"
docker build -q -t quarantine-proxy:latest "$APP_DIR/proxy"

log "Python control plane"
python3 -m venv "$APP_DIR/.venv"
"$APP_DIR/.venv/bin/pip" install -q --upgrade pip
"$APP_DIR/.venv/bin/pip" install -q -r "$APP_DIR/requirements.txt"

log "Configuration ($ENV_FILE)"
if [ ! -f "$ENV_FILE" ]; then
  umask 077
  cat > "$ENV_FILE" <<EOF
VULTR_INFERENCE_API_KEY=${VULTR_INFERENCE_API_KEY:-}
VULTR_MODEL=${VULTR_MODEL:-kimi-k2-instruct,kimi-k2.6,glm-5.3,deepseek-v4.1-flash,qwen3.8-flash-next}
DATA_DIR=$DATA_DIR
SANDBOX_RUNTIME=runsc
RECEIPT_KEY=$(openssl rand -hex 32)
RATE_LIMIT_PER_HOUR=${RATE_LIMIT_PER_HOUR:-40}
MAX_CONCURRENT_RUNS=${MAX_CONCURRENT_RUNS:-2}
ADMIN_TOKEN=${ADMIN_TOKEN:-}
EOF
elif [ -n "${VULTR_INFERENCE_API_KEY:-}" ]; then
  sed -i "s|^VULTR_INFERENCE_API_KEY=.*|VULTR_INFERENCE_API_KEY=${VULTR_INFERENCE_API_KEY}|" "$ENV_FILE"
fi
chmod 600 "$ENV_FILE"

log "Host firewall: sandboxes (10.250.0.0/16) may not reach the VM itself"
iptables -C INPUT -s 10.250.0.0/16 -j DROP 2>/dev/null || iptables -I INPUT -s 10.250.0.0/16 -j DROP
# belt and braces: no container may reach the cloud metadata service
iptables -C DOCKER-USER -d 169.254.169.254 -j DROP 2>/dev/null || iptables -I DOCKER-USER -d 169.254.169.254 -j DROP
netfilter-persistent save >/dev/null 2>&1 || true

log "systemd service"
cat > /etc/systemd/system/quarantine.service <<EOF
[Unit]
Description=Quarantine control plane
After=docker.service network-online.target
Requires=docker.service

[Service]
EnvironmentFile=$ENV_FILE
WorkingDirectory=$APP_DIR
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
if ! command -v caddy >/dev/null; then
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor --yes -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' > /etc/apt/sources.list.d/caddy-stable.list
  apt-get update -qq && apt-get install -y -qq caddy >/dev/null
fi
IP=$(curl -fsS http://169.254.169.254/v1/interfaces/0/ipv4/address 2>/dev/null || curl -fsS https://api.ipify.org)
DOMAIN="${DOMAIN:-${IP//./-}.sslip.io}"
cat > /etc/caddy/Caddyfile <<EOF
$DOMAIN {
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
systemctl enable --now caddy
systemctl reload caddy || systemctl restart caddy
ufw allow 80/tcp >/dev/null 2>&1 || true
ufw allow 443/tcp >/dev/null 2>&1 || true

log "Self-test"
for i in $(seq 1 30); do curl -fsS http://127.0.0.1:8000/api/health >/dev/null 2>&1 && break; sleep 1; done
curl -fsS http://127.0.0.1:8000/api/health | python3 -m json.tool | head -30
echo
echo "Quarantine is live at: https://$DOMAIN"
echo "Run the containment red-team:  sudo $APP_DIR/deploy/selftest.sh"
