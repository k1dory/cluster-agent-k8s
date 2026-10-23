# Gateway VM

One VM with two interfaces: LAN/Internet and `sbx0` on the sandbox VLAN (`10.77.77.1/25`).

| Piece | File | Job |
|---|---|---|
| Caddy | `Caddyfile` | TLS termination for allowlisted names, agent client-cert check, `forward_auth` → sandboxd, secret injection, registrar on :8443, preview ingress |
| dnsmasq | `dnsmasq.d-sandbox.conf` | the pods' only resolver; allowlist → gateway IP, rest NXDOMAIN |
| nftables | `nftables.conf` | pods reach the gateway on 53/443/8443 only; no forwarding |
| sandboxd | runs in k8s or on this VM, listens `127.0.0.1:8081` for Caddy | policy, identities, orchestration |

Adding an external host = three edits: a site block in `Caddyfile`, an `address=` line in dnsmasq, a rule in a policy file.

Pods trust Caddy's internal root (handed over by the Registrar at bootstrap); Caddy trusts the agent CA root from sandboxd (`/etc/caddy/agent-ca.crt`).
