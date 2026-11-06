#!/usr/bin/env bash
# Host firewall for Quarantine; run as root before the service starts (systemd ExecStartPre=+).
#  - sandboxes (SANDBOX_SUBNET_POOL.0.0/16) may talk to their proxy over the bridge, never to the VM
#  - no container may reach the cloud metadata service
set -euo pipefail
POOL="${SANDBOX_SUBNET_POOL:-10.250}.0.0/16"
iptables -C INPUT -s "$POOL" -j DROP 2>/dev/null || iptables -I INPUT -s "$POOL" -j DROP
iptables -C DOCKER-USER -d 169.254.169.254 -j DROP 2>/dev/null || iptables -I DOCKER-USER -d 169.254.169.254 -j DROP
install -d -m 0755 /run/quarantine
echo "iptables -I INPUT -s $POOL -j DROP" > /run/quarantine/firewall.ok
chmod 644 /run/quarantine/firewall.ok
