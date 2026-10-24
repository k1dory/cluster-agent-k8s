# agent-sandbox

Run coding agents in isolated Kubernetes pods: one network interface per pod, an mTLS egress
gateway (Caddy) that enforces per-agent host+path policy and injects secrets, and one Go service
(`sandboxd`) that owns identities, sandboxes, runs, the preview proxy and the gateway's configuration.

![How a task flows through the gateway, then the fleet](docs/motion/agent-sandbox.gif)

[MP4 version](docs/motion/agent-sandbox.mp4)

<details><summary>Static architecture diagram</summary>

![Architecture](docs/architecture.svg)

</details>

Policy-as-Code: `policies/*.yaml` is the single source of truth. From it sandboxd renders the
Caddy configuration (one TLS site per host, client-certificate check, header stripping), answers
DNS for exactly those names and decides every request. Nobody edits the gateway by hand.

```
cmd/sandboxd        control plane binary (+ `sandboxd policy validate|test|render`)
cmd/sandboxctl      CLI over the API: create, run, watch, say, cancel, sleep, wake, preview, delete
cmd/agent-init      pod init container: key + CSR → Registrar → certificate, client-cert config
cmd/agent-runner    pod main process: long-polls runs, executes the harness, streams output
api/openapi.yaml    API spec (served at /openapi.yaml, Swagger UI at /docs)
policies/           egress policies per slug, tests.yaml (expectations), schema.json (editor validation)
deploy/gateway/     gateway VM: docker-compose, .env.example, setup-vm.sh (nftables), bootstrap Caddyfile
deploy/helm/        Helm chart: gateway on a cluster node (mode node) or cluster-side pieces only (mode external)
deploy/k8s/         the same, rendered to plain manifests for kubectl apply (-k)
deploy/ansible/     playbooks: cluster.yaml (manifests, Secret, node label, token) and gateway.yaml (the VM)
images/             Dockerfiles for sandboxd, the agent image, an optional Caddy build with a DNS module
internal/           policy, gateway (Caddy render/push, DNS), identity, ca, registrar, authz, orchestrator, kube, ingress, store, httpapi
```

## Install

Three ways to roll out, same result: Helm, `kubectl apply` on rendered manifests, or Ansible.
Two layouts, pick one.

**A. Gateway on a cluster node** (everything through Helm)

1. Cluster with [Multus](https://github.com/k8snetworkplumbingwg/multus-cni) and
   [whereabouts](https://github.com/k8snetworkplumbingwg/whereabouts); worker nodes and one
   gateway node have an interface in the sandbox VLAN. Label the gateway node
   `agent-sandbox.io/gateway=true`, give it `10.77.77.1` on that interface, apply
   `deploy/gateway/nftables.conf` there.
2. Secret `agent-sandbox-secrets` with `SANDBOXD_API_TOKEN`, `DATABASE_URL`, `PREVIEW_TICKET_KEY`.
3. `helm install agent-sandbox deploy/helm/agent-sandbox -f values.yaml` (images, VLAN interface, preview domain),
   or `kubectl apply -f deploy/k8s/secret.example.yaml && kubectl apply -k deploy/k8s`,
   or `ansible-playbook -i inventory.yaml playbooks/cluster.yaml` from `deploy/ansible`.

**B. Gateway VM** (cluster stays untouched except Multus)

1. Same cluster prerequisites; `helm install ... --set gateway.mode=external` creates the
   NetworkAttachmentDefinition, RBAC and a token for sandboxd.
2. On the VM: `deploy/gateway/setup-vm.sh`, `cp .env.example .env`, fill it,
   `docker compose --profile with-postgres up -d`. Or let Ansible do both steps:
   `ansible-playbook -i inventory.yaml playbooks/gateway.yaml`.

In both cases, adding an external service the agents may use is one rule in a policy file.

## Policy workflow

```sh
sandboxd policy validate policies                      # syntax, host inventory, upstream conflicts
sandboxd policy test policies -f policies/tests.yaml   # allow/deny expectations, exit 1 on failure
sandboxd policy render -config sandboxd.yaml           # the Caddyfile that will be pushed
```

`.forgejo/workflows/policies.yaml` (and the GitHub twin) run these on every pull request that
touches `policies/`. After merge, `helm upgrade` (or a `git pull` of the policies directory on the
VM) is enough: sandboxd reloads, re-renders and pushes the gateway configuration within seconds.

## Use it

Everything goes through the API (`/docs` for Swagger UI); `sandboxctl` wraps it:

```sh
export SANDBOXD_URL=https://gw.example.com:8080 SANDBOXD_TOKEN=...
sandboxctl create -name shop -slug backend-dev -owner alice -repo https://git.example.com/org/shop.git
sandboxctl run sb_1234 "add integration tests for the checkout flow"
sandboxctl watch sb_1234                 # live output, status changes, your own messages
sandboxctl say sb_1234 run_5678 "use pytest, not unittest"
sandboxctl preview sb_1234 -port 3000    # https://shop-alice.preview.example.com
sandboxctl sleep sb_1234                 # or wait an hour of silence
```

## Accounting and trace

Every run keeps what the harness reported (tokens, cost, turns), every gateway decision lands in
the event log with the tenant and slug stamped on it, and pod uptime is derived from status
changes. All of it is queried through the API, scoped by tenant, agent slug, sandbox or run:

```sh
sandboxctl usage -tenant acme -since 720h -by slug      # GET /v1/usage?tenant=acme&since=720h&group_by=slug
sandboxctl usage -slug backend-dev -by day
sandboxctl trace -tenant acme -since 24h                # GET /v1/trace: runs, inputs, every egress allow/deny
sandboxctl trace -slug netops -type egress.deny -f      # follow refusals live
```

Runs and events are not deleted with the sandbox, so history stays billable. Model cost comes
from the harness (Claude Code's stream-json `result` line is understood; others print
`{"type":"usage",...}` lines or send a total with `/finish`); compute is `pod_seconds` priced with
`accounting.pod_hour_usd` in the config.

## Run locally (no Kubernetes)

```sh
make dev            # fake runtime, in-memory store, API on 127.0.0.1:8080, token dev-token, DNS on 127.0.0.1:15353
SANDBOXD_TOKEN=dev-token go run ./cmd/sandboxctl create -name shop -slug backend-dev -owner alice
dig @127.0.0.1 -p 15353 git.example.com
open http://127.0.0.1:8080/docs
```

## License

Apache-2.0, see [LICENSE](LICENSE).

