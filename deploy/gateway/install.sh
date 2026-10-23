#!/usr/bin/env bash
# Prepares a Debian/Ubuntu gateway VM: Caddy (with the REG.RU DNS module if you use it),
# dnsmasq on the sandbox interface, nftables, sysctl. Review before running; idempotent.
set -euo pipefail
IFACE=${IFACE:-sbx0}
GW_IP=${GW_IP:-10.77.77.1}
HERE=$(cd "$(dirname "$0")" && pwd)

apt-get install -y dnsmasq nftables curl
# Caddy: official package, or build with xcaddy if a DNS module is needed:
#   xcaddy build --with github.com/caddy-dns/regru   (check the module before trusting it)
command -v caddy >/dev/null || { echo "install caddy first (https://caddyserver.com/docs/install)"; exit 1; }

# no forwarding at all; the VLAN is a dead end except for Caddy
cat >/etc/sysctl.d/90-sandbox-gw.conf <<SYS
net.ipv4.ip_forward=0
net.ipv6.conf.${IFACE}.disable_ipv6=1
SYS
sysctl --system >/dev/null

install -m 0644 "$HERE/nftables.conf" /etc/nftables.d/sandbox-gw.nft 2>/dev/null || install -D -m 0644 "$HERE/nftables.conf" /etc/nftables.d/sandbox-gw.nft
grep -q 'nftables.d/sandbox-gw.nft' /etc/nftables.conf || echo 'include "/etc/nftables.d/sandbox-gw.nft"' >>/etc/nftables.conf
systemctl enable --now nftables && nft -f /etc/nftables.conf

install -D -m 0644 "$HERE/dnsmasq.d-sandbox.conf" /etc/dnsmasq.d/sandbox.conf
sed -i "s/10.77.77.1/${GW_IP}/g; s/interface=sbx0/interface=${IFACE}/" /etc/dnsmasq.d/sandbox.conf
systemctl enable --now dnsmasq && systemctl restart dnsmasq

install -D -m 0644 "$HERE/Caddyfile" /etc/caddy/Caddyfile
mkdir -p /var/log/caddy && chown caddy:caddy /var/log/caddy
echo "copy sandboxd's var/ca/ca.crt to /etc/caddy/agent-ca.crt, then: caddy validate --config /etc/caddy/Caddyfile && systemctl reload caddy"
echo "export Caddy's root for the pods: cp /var/lib/caddy/.local/share/caddy/pki/authorities/local/root.crt <sandboxd>/gateway-root.crt"
