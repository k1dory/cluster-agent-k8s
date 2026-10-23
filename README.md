# agent-sandbox

Run coding agents in isolated Kubernetes pods: one network interface per pod, an mTLS egress
gateway (Caddy) that enforces per-agent host+path policy and injects secrets, and one Go service
(`sandboxd`) that owns identities, sandboxes, runs, the preview proxy and the gateway's configuration.

![Architecture](docs/architecture.svg)

Policy-as-Code: `policies/*.yaml` is the single source of truth. From it sandboxd renders the
Caddy configuration (one TLS site per host, client-certificate check, header stripping), answers
DNS for exactly those names and decides every request. Nobody edits the gateway by hand.

```
cmd/sandboxd        control plane binary (+ `sandboxd policy validate|test|render`)
cmd/agent-init      pod init container: key + CSR → Registrar → certificate, client-cert config
cmd/agent-runner    pod main process: long-polls runs, executes the harness, streams output
api/openapi.yaml    API spec (served at /openapi.yaml, Swagger UI at /docs)
policies/           egress policies per slug, tests.yaml (expectations), schema.json (editor validation)
deploy/gateway/     gateway VM: docker-compose, .env.example, setup-vm.sh (nftables), bootstrap Caddyfile
deploy/helm/        Helm chart: gateway on a cluster node (mode node) or cluster-side pieces only (mode external)
images/             Dockerfiles for sandboxd, the agent image, an optional Caddy build with a DNS module
internal/           policy, gateway (Caddy render/push, DNS), identity, ca, registrar, authz, orchestrator, kube, ingress, store, httpapi
```

## Install

Two layouts, pick one.

**A. Gateway on a cluster node** (everything through Helm)

1. Cluster with [Multus](https://github.com/k8snetworkplumbingwg/multus-cni) and
   [whereabouts](https://github.com/k8snetworkplumbingwg/whereabouts); worker nodes and one
   gateway node have an interface in the sandbox VLAN. Label the gateway node
   `agent-sandbox.io/gateway=true`, give it `10.77.77.1` on that interface, apply
   `deploy/gateway/nftables.conf` there.
2. Secret `agent-sandbox-secrets` with `SANDBOXD_API_TOKEN`, `DATABASE_URL`, `PREVIEW_TICKET_KEY`.
3. `helm install agent-sandbox deploy/helm/agent-sandbox -f values.yaml` (images, VLAN interface, preview domain).

**B. Gateway VM** (cluster stays untouched except Multus)

1. Same cluster prerequisites; `helm install ... --set gateway.mode=external` creates the
   NetworkAttachmentDefinition, RBAC and a token for sandboxd.
2. On the VM: `deploy/gateway/setup-vm.sh`, `cp .env.example .env`, fill it,
   `docker compose --profile with-postgres up -d`.

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

## Run locally (no Kubernetes)

```sh
make dev            # fake runtime, in-memory store, API on 127.0.0.1:8080, token dev-token, DNS on 127.0.0.1:15353
curl -s -H 'Authorization: Bearer dev-token' localhost:8080/v1/sandboxes \
  -d '{"name":"shop","slug":"backend-dev","owner":"lev"}'
dig @127.0.0.1 -p 15353 git.example.com
open http://127.0.0.1:8080/docs
```

## License

Apache-2.0, see [LICENSE](LICENSE).

Design notes, decisions and the threat model live in the wiki, not here.
