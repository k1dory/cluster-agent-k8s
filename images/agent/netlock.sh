#!/bin/sh
# Pod network lock, run as an init container with NET_ADMIN (the main container has no
# capabilities, so these rules cannot be undone from inside the sandbox).
#
# The sandbox VLAN is shared by every pod and node; macvlan "private" only isolates pods on
# the same node. These rules make the gateway the only peer this pod can talk to: DNS, HTTPS
# and the registrar port, nothing else, in particular no other pod and no IPv6.
set -eu
GW="${GATEWAY_IP:?GATEWAY_IP is not set}"
/usr/sbin/nft -f - <<NFT
flush ruleset
table inet sandbox {
	chain output {
		type filter hook output priority 0; policy drop;
		oif lo accept
		meta nfproto ipv6 drop
		# replies to connections the gateway opened (preview proxy → application port)
		ct state established,related accept
		ip daddr $GW udp dport 53 accept
		ip daddr $GW tcp dport { 53, 443, 8443 } accept
		ip daddr $GW icmp type echo-request accept
		counter drop
	}
	chain input {
		type filter hook input priority 0; policy drop;
		iif lo accept
		meta nfproto ipv6 drop
		ct state established,related accept
		# only the gateway may open connections to this pod (the preview proxy); no other pod can
		ip saddr $GW ct state new accept
		counter drop
	}
	chain forward {
		type filter hook forward priority 0; policy drop;
	}
}
NFT
echo "netlock: egress restricted to $GW (53/443/8443)"
