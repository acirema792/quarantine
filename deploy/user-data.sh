#!/bin/bash
# Vultr Cloud-Init user-data for Quarantine (paste into "Cloud-Init User Data").
# Fill in the two values below. Progress is visible at http://<server-ip>/install.log
# until Caddy takes over port 80 (nothing secret is ever printed there).
S=/run/quarantine-status; mkdir -p "$S"
exec >>"$S/install.log" 2>&1
echo "first-boot user-data started $(date -u)"
(ufw allow 80/tcp; ufw allow 443/tcp) || true
systemd-run --unit=qbeacon --property=WorkingDirectory="$S" python3 -m http.server 80 --bind 0.0.0.0 || true
export DEBIAN_FRONTEND=noninteractive REPO_URL=https://github.com/acirema792/quarantine.git BRANCH=main
export VULTR_INFERENCE_API_KEY="__VULTR_INFERENCE_API_KEY__"
export ADMIN_TOKEN="__ADMIN_TOKEN__"
for i in 1 2 3 4 5; do
  apt-get -o DPkg::Lock::Timeout=900 update -qq && apt-get -o DPkg::Lock::Timeout=900 install -y -qq git curl && break
  echo "apt attempt $i failed; retrying"; sleep 15
done
rm -rf /opt/quarantine
git clone -q --branch "$BRANCH" "$REPO_URL" /opt/quarantine || { echo "CLONE FAILED"; exit 1; }
echo "running install.sh $(date -u)"
bash /opt/quarantine/deploy/install.sh
echo "install.sh finished with exit code $? at $(date -u)"
