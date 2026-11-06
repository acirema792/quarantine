#!/usr/bin/env bash
# Pull-based deploy, run as root by quarantine-update.timer: if origin/$BRANCH moved,
# fast-forward /opt/quarantine and rebuild/restart only what changed. Installer and Caddy
# changes still need deploy/install.sh.
set -euo pipefail
APP_DIR=/opt/quarantine
BRANCH="${BRANCH:-main}"
cd "$APP_DIR"
git fetch -q origin "$BRANCH"
OLD=$(git rev-parse HEAD)
NEW=$(git rev-parse "origin/$BRANCH")
[ "$OLD" = "$NEW" ] && exit 0
CHANGED=$(git diff --name-only "$OLD" "$NEW")
git reset -q --hard "$NEW"
echo "updating $OLD -> $NEW"
if grep -q '^sandbox/' <<<"$CHANGED"; then docker build -q -t quarantine-sandbox:latest "$APP_DIR/sandbox"; fi
if grep -q '^proxy/' <<<"$CHANGED"; then docker build -q -t quarantine-proxy:latest "$APP_DIR/proxy"; fi
if grep -qx 'requirements.txt' <<<"$CHANGED"; then "$APP_DIR/.venv/bin/pip" install -q -r "$APP_DIR/requirements.txt"; fi
if grep -qE '^(app/|sandbox/|proxy/|fixtures/|requirements.txt)' <<<"$CHANGED"; then systemctl restart quarantine; fi
echo "updated to $NEW"
