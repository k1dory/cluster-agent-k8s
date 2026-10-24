# Gateway VM

One VM with two interfaces: LAN/Internet and `sbx0` on the sandbox VLAN (default `10.77.77.1/25`).
Nothing on it is configured by hand except the firewall:

1. `./setup-vm.sh` (nftables: pods reach this VM on 53/443/8443 only, no forwarding; Docker).
2. `cp .env.example .env`, fill it in.
3. `docker compose --profile with-postgres up -d` (drop the profile if you have Postgres elsewhere).

What runs:

| Container | Job |
|---|---|
| caddy | starts with `Caddyfile.bootstrap` (admin on localhost only); the real configuration is pushed by sandboxd |
| sandboxd | renders the Caddy config from the policies, pushes it on every policy change, fetches Caddy's internal root for the pods, serves DNS on the VLAN address, runs the control plane |
| postgres | optional, state of sandboxes/runs/identities |

Several gateway VMs can run the same compose stack against one Postgres (`ca.source: db` in
`sandboxd.yaml`, a VIP or DNS round-robin in front): the control plane is replica-safe and the
reconciler runs on whichever replica holds the leadership lease.

Adding an external host is one edit in a policy file. sandboxd re-renders the Caddy site
block, the DNS answer and the header stripping from it. The rendered Caddyfile is kept at
`/var/lib/sandboxd/Caddyfile` inside the sandboxd volume for inspection (`sandboxd policy render` prints it too).
