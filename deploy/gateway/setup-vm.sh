#!/usr/bin/env bash
# One-time preparation of the gateway VM (Debian/Ubuntu): firewall for the sandbox VLAN,
# no forwarding, Docker. Everything else is docker compose. Idempotent.
set -euo pipefail
IFACE=${IFACE:-sbx0}
HERE=$(cd "$(dirname "$0")" && pwd)

command -v docker >/dev/null || { echo "install Docker first: https://docs.docker.com/engine/install/"; exit 1; }
apt-get install -y nftables

cat >/etc/sysctl.d/90-sandbox-gw.conf <<SYS
net.ipv4.ip_forward=0
net.ipv6.conf.${IFACE}.disable_ipv6=1
SYS
sysctl --system >/dev/null

mkdir -p /etc/nftables.d
sed "s/\"sbx0\"/\"${IFACE}\"/g" "$HERE/nftables.conf" >/etc/nftables.d/sandbox-gw.nft
grep -q 'nftables.d/sandbox-gw.nft' /etc/nftables.conf || echo 'include "/etc/nftables.d/sandbox-gw.nft"' >>/etc/nftables.conf
systemctl enable --now nftables
nft -f /etc/nftables.conf

# systemd-resolved must not sit on the VLAN address: sandboxd serves DNS there.
if systemctl is-active --quiet systemd-resolved; then
  mkdir -p /etc/systemd/resolved.conf.d
  printf '[Resolve]\nDNSStubListener=no\n' >/etc/systemd/resolved.conf.d/sandbox.conf
  systemctl restart systemd-resolved
fi
echo "VM ready. Next: cp .env.example .env && edit && docker compose --profile with-postgres up -d"
