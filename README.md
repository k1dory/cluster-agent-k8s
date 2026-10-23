# agent-sandbox

Control plane and gateway wiring for running coding agents in isolated Kubernetes pods:
one network interface per pod, an mTLS egress gateway (Caddy) that enforces per-agent
host+path policy and injects secrets, and a single Go service (`sandboxd`) that owns
identities, sandboxes, runs and the preview proxy.

```
cmd/sandboxd        control plane binary (orchestrator + registrar + authz + API + preview ingress)
cmd/agent-init      pod init container: key + CSR → Registrar → certificate, client-cert config
cmd/agent-runner    pod main process: long-polls runs, executes the harness, streams output
api/openapi.yaml    API spec (served at /openapi.yaml, Swagger UI at /docs)
internal/           policy, identity, ca, registrar, authz, orchestrator, kube, ingress, store, httpapi
policies/           per-slug egress policies (YAML, hot reloaded)
deploy/gateway/     Caddyfile, dnsmasq, nftables, install.sh for the gateway VM
deploy/helm/        Helm chart for sandboxd + NetworkAttachmentDefinition + RBAC
images/             Dockerfiles for sandboxd and the agent image
config/             sandboxd.yaml examples (prod template, local dev)
```

## Run locally (no Kubernetes)

```sh
make dev            # fake runtime, in-memory store, API on 127.0.0.1:8080, token dev-token
curl -s -H 'Authorization: Bearer dev-token' localhost:8080/v1/sandboxes \
  -d '{"name":"shop","slug":"backend-dev","owner":"lev"}'
open http://127.0.0.1:8080/docs
```

## Deploy

1. Cluster with Multus and whereabouts; a VLAN reachable from worker nodes and the gateway VM.
2. Gateway VM: `deploy/gateway/install.sh`, then Caddyfile with your host names.
3. `helm install agent-sandbox deploy/helm/agent-sandbox -f my-values.yaml`
   (secrets: `SANDBOXD_API_TOKEN`, `DATABASE_URL`, `PREVIEW_TICKET_KEY` in an existing Secret).
4. Exchange roots: agent CA root → Caddy `trust_pool`; Caddy internal root → sandboxd `gateway_ca_file`.
5. Build and push the agent image, set `agentImage` in values.

Design notes, decisions and the threat model live in the wiki, not here.
