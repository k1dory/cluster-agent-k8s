# Production acceptance

What has to hold before the platform runs in production, and the check that proves each
point on a real Kubernetes with a real PostgreSQL: `make acceptance` against a cluster of
yours, `make ci-acceptance` against a cluster shaped like production that the check builds
on Docker (kind). Both run `hack/acceptance/run.sh`, phase by phase, and write one report
(`.ci/acceptance/report.md`): every phase passes, fails or is skipped with its evidence, and
the exit status is 1 when anything failed. The CI job `acceptance` runs it on every pull
request and keeps the report as an artifact; before a release, run it against the cluster the
release goes to.

## What is proven

| Phase | Proves | Evidence in the report |
|---|---|---|
| `preflight` | the cluster, Multus, enough labelled gateway nodes, the database, the tools | versions, node names, the database's version |
| `install` | the chart installs with `ACCEPT_REPLICAS` replicas (`ca.source: db`), one per gateway node; every replica is ready (`/readyz`), reports its own name, and exactly one leads (`/v1/version`) | install time, replica names and leader, the build |
| `config` | configuration reaches the platform the way a repository does: the pull request's `plan` writes nothing and is valid; the merge's `apply` carries the commit's SHA under a key stable for the bundle at that commit; `drift` is clean; a tenant key issued through the API acts as the tenant | the commit, the key's tenant |
| `agent` | a sandbox from the applied catalogue reaches `running`; its pod runs on the VLAN (an address in `ACCEPT_VLAN_PREFIX` on the Multus interface), resolves the gateway's names and nothing else; a run finishes, with the harness marker in its output when one is configured | sandbox, pod, node, VLAN address, run |
| `replicas` | the leader's pod deleted: the surviving replica answers every request meanwhile; the lead moves (to the survivor, or to the deleted replica's successor when it starts first); the replaced replica comes back; one leader; the sandbox stays running; an apply through the survivor goes through | requests answered, who leads and after how many seconds |
| `recovery` | the agent pod deleted: the reconciler puts the sandbox in `error`, `wake` starts a fresh pod, a run finishes on it. The database stopped: every replica reports unready (503, no traffic) and alive (200, no restart); back when the database is; the sandbox untouched | pod names, readiness during the outage, restart counts |
| `upgrade` | `helm upgrade` to other images (`ACCEPT_UPGRADE_TAG`) with a changed value: replicas back, one leader; sandboxes and catalogue revisions unchanged; the agent pod untouched (the control plane's rollout never touches agents); the tenant key works; a run finishes | images, the pod's uid before and after |
| `backup` | `pg_dump`, then a document and a key the backup does not know; the control plane stopped, the database restored from the dump, the control plane back: what came after the backup is gone, what was before it is there (environment, sandbox, key); a run finishes on the existing agent pod, whose certificate the restored CA still vouches for | what was gone and what stayed |
| `teardown` | the release uninstalled, agent pods and volumes removed (`ACCEPT_KEEP=1` keeps everything for a look) | |

A failed `preflight` or `install` ends the run (nothing after them can be judged); any other
failure is recorded and the run goes on, so one report covers everything.

## Against your cluster

```sh
export KUBECONFIG=~/.kube/prod-acceptance
export ACCEPT_VALUES=values-acceptance.yaml          # your values: images, gateway address and nodes, network, preview domain
export ACCEPT_DATABASE_URL='postgres://sandbox:…@db.example.com:5432/sandbox_acceptance?sslmode=require'
export ACCEPT_DB_EXEC='psql-wrapper'                  # a command prefix that runs psql/pg_dump against that database, stdin passed through
export ACCEPT_IMAGE_TAG=1.6.0 ACCEPT_UPGRADE_TAG=1.6.1 # the release under acceptance, and the next tag the upgrade phase moves to
make acceptance                                      # or: make acceptance PHASES="preflight install config agent"
```

Inputs (environment variables; `hack/acceptance/lib.sh` is the list):

| Variable | Meaning | Default |
|---|---|---|
| `KUBECONFIG` | the cluster | kubectl's own |
| `ACCEPT_NAMESPACE`, `ACCEPT_RELEASE` | where the release goes; a namespace of its own, not production's | `agent-sandbox-acceptance`, `agent-sandbox` |
| `ACCEPT_REPLICAS` | replicas, one per labelled gateway node | `2` |
| `ACCEPT_VALUES` | the chart values for this cluster (required) | |
| `ACCEPT_IMAGE_TAG`, `ACCEPT_UPGRADE_TAG` | the images installed; the images the upgrade phase moves to (empty: the same images with a changed value) | `acc`, empty |
| `ACCEPT_DATABASE_URL` | the control plane's DSN (required); a database of its own, not production's: the backup phase restores it | |
| `ACCEPT_DB_EXEC` | a command prefix that runs `psql`/`pg_dump` against that database with stdin passed through, e.g. `kubectl -n db exec -i statefulset/postgres --` or `ssh db-host` (required); `ACCEPT_DB_USER`, `ACCEPT_DB_NAME` name the role and database | `sandbox`, `sandbox` |
| `ACCEPT_DB_OUTAGE`, `ACCEPT_DB_RESTORE` | shell commands that stop the database and bring it back (the recovery phase); unset: that half is skipped with the reason | unset |
| `ACCEPT_API_URLS` | the replicas' API, space-separated, when the pods' addresses are not reachable from here (behind a VIP, a bastion) | the pods' addresses (hostNetwork: the nodes') on `ACCEPT_API_PORT` (8080) |
| `ACCEPT_HARNESS_MARKER` | text a finished run must have printed; empty: the run's completion is the check (a real harness with a real LLM key) | empty |
| `ACCEPT_VLAN_PREFIX` | the pods' VLAN addresses start with this | `10.77.77.` |
| `ACCEPT_TENANT`, `ACCEPT_ADMIN_TOKEN` | the tenant the run configures; the admin token (generated when unset) | `acme`, generated |
| `ACCEPT_CREDENTIALS_KEY`, `ACCEPT_PREVIEW_TICKET_KEY` | the Secret's `CREDENTIALS_KEY` (tenant credentials, `install` checks the API is on at every replica) and `PREVIEW_TICKET_KEY`; unset, a second install keeps what the Secret has | kept |
| `ACCEPT_WAIT` | seconds a wait may take (a pod ready, a run finished) | `300` |
| `ACCEPT_KEEP` | leave the release (and, under kind, the cluster) up at the end | unset |
| `ACCEPT_SANDBOXCTL` | the CLI to use (built from the checkout when unset) | built |

The values file is the one you deploy with, except: `gateway.replicas` and `sandboxd.ca.source`
are set by the run (`db` is required for replicas), `image.tag` and `agentImage.tag` come from
`ACCEPT_IMAGE_TAG`, and the agent needs a harness it can run (`agent.harnessCommand`): the
real one with its key in the policy, or `echo "acceptance: $SANDBOX_TASK"` with
`ACCEPT_HARNESS_MARKER='acceptance: '` when no LLM is wanted. Gateway nodes are labelled
`agent-sandbox.io/gateway=true`; taint them `agent-sandbox.io/gateway=true:NoSchedule` and set
`tolerations` for the gateway pod, so that no agent lands on a gateway node (a macvlan pod on
the node that holds the gateway address cannot reach it).

## Shaped like production, on Docker

`make ci-acceptance` (`hack/acceptance/kind.sh`) builds the cluster, runs every phase and
tears the cluster down (`ACCEPT_KEEP=1` leaves it; `hack/acceptance/kind.sh run <phase>` runs
one phase again):

- kind, one control plane and three workers; the sandbox VLAN is a Docker network that every
  worker joins as `eth1`: the first two workers are the gateway nodes (labelled, tainted;
  `10.77.77.1` and `10.77.77.2`), the third runs the agents;
- Multus (thick plugin) and whereabouts, the versions pinned in `hack/ci/versions.env` with
  kind, its node image, kubectl and the reference CNI plugins (kind's nodes ship without
  `macvlan`; your nodes need it under `/opt/cni/bin` too, which a distribution's CNI plugins
  package provides);
- PostgreSQL in the cluster on a persistent volume (`hack/acceptance/postgres.yaml`), stopped
  and started by the recovery phase;
- the three images built from the checkout and loaded into the nodes, plus a second tag of the
  same build for the upgrade phase;
- a harness that prints its task (`agent.harnessCommand`), so no LLM key is needed.

What this cluster does not have: a VIP moving between gateway nodes. The replica that holds
`10.77.77.1` is where the pods' traffic goes; the phase that deletes a replica's pod gets it
back on the same node with the same address. On your cluster, with keepalived (or the VLAN's
own VRRP) in front of the gateway nodes, the same phase covers a node that goes away: every
replica binds the gateway address with `IP_FREEBIND` and keeps trying, so the standby serves
DNS the moment the address moves to it.

## Operations the phases stand for

- **Replicas.** `gateway.replicas > 1` needs `database_url`, `sandboxd.ca.source: db` and one
  labelled gateway node per replica. The API is active on every replica (point your clients at
  the VIP or at DNS round-robin); the reconciler runs on the one holding the lease, the others
  take over within a lease period. `GET /v1/version` says which replica answered and whether it
  leads; `GET /readyz` is the readiness probe (the store answers), `GET /healthz` the liveness.
- **Upgrade.** `helm upgrade` with the new tags. The Deployment's strategy is Recreate: the
  control plane is away for the seconds the new pods take to be ready (agents keep running;
  their identities and the gateway configuration do not depend on the control plane being up;
  a run's `/finish` is retried until acknowledged). Migrations run at start, are idempotent and
  are safe to run from several replicas. Nothing on the gateway nodes' disks matters with
  `ca.source: db`.
- **Backup.** With `ca.source: db` the database holds everything the control plane needs:
  catalogue, sandboxes, runs, keys, applies, the agent CA and the gateway root. `pg_dump` is the
  backup; restore with the control plane stopped (`kubectl scale deploy/<release>-sandboxd
  --replicas=0`), then start it. Workspace volumes (`ws-<sandbox>`, one PVC per sandbox) are
  outside the database: back them up with your volume tooling if the agents' files matter; a
  restored database with a missing volume gives that sandbox a fresh workspace on its next
  wake. Caddy's data (`caddy-data`) is scratch. The recovery point is the dump; the recovery
  time is the restore plus the replicas' start.
- **Failure.** An agent pod lost: the reconciler marks the run failed and the sandbox `error`
  with the reason, `wake` starts a fresh pod. The database lost: replicas go unready and keep
  running, no agent is affected, everything resumes when it is back. A replica lost: the others
  answer, the lease moves.
