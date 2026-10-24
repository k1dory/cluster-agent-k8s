# Declarative catalogue

The same documents go through the API (`PUT /v1/environments/{name}`, `PUT /v1/agents/{name}`,
JSON) and through files (`sandboxctl apply -f`, YAML; several documents separated by `---` are
applied in order). Unknown fields are errors, every apply appends a revision,
`expected_revision` makes an update conditional. Deleting an item keeps its history and its
revision numbers: a recreated `python-dev` continues at the next number, never as `python-dev@1`.

```sh
sandboxctl plan -f examples/catalog/bundle.yaml                  # what would change, nothing written
sandboxctl apply -f examples/catalog/bundle.yaml                 # plan, then apply: one transaction per step; the Git commit is recorded
sandboxctl drift                                                 # items changed or deleted by hand since an apply wrote them
sandboxctl rollback -apply apply_7c1e5a9b02d4                    # back to the revisions that apply replaced, as a new apply
sandboxctl create -name shop -owner alice -agent backend         # sandbox: backend@1 on python-dev@1
sandboxctl run sb_1234 "add integration tests for the checkout flow"
sandboxctl get agent backend                                     # current revision
sandboxctl revisions environment python-dev                      # history
```

The sandbox carries `agent_ref`, `agent_revision`, `environment_ref`, `environment_revision`
(`shared/name` when the item is a shared one) and the rendered `launch`; each run records the
revisions it executed under. Editing a
definition never changes a sandbox or a run that already exists: new sandboxes get the new
revisions, existing ones keep theirs until they are recreated (step 3 adds controlled
re-application of changed revisions).

## Connections, bindings, tenant settings

`connection-github.yaml` names an external service with the headers the gateway adds; the
credential is a `secret:` reference, never a value. `binding-backend.yaml` is the admin's grant
of a policy slug to a tenant (with an expiry and per-slug limits); `tenant-settings.yaml` sets
the tenant's quota and the environments its agents may use. All three are versioned and keep
their history like the catalogue.

`connection-mcp.yaml` is a host no policy file names: the admin listed it under the tenant's
settings (`hosts`), so the tenant's connection is the whole rule for it (upstream, paths, MCP
restrictions) and agents naming the connection get it as an MCP server. See
[docs/self-service.md](../../docs/self-service.md).

```sh
sandboxctl apply -f examples/catalog/connection-github.yaml                 # tenant token: own scope
sandboxctl apply -f examples/catalog/connection-mcp.yaml                    # tenant token: a self-service MCP host
sandboxctl apply -f examples/catalog/binding-backend.yaml -tenant acme      # admin
sandboxctl apply -f examples/catalog/tenant-settings.yaml -tenant acme      # admin
sandboxctl list bindings                                                     # a tenant sees its own
sandboxctl settings acme
sandboxctl remove binding backend-dev -tenant acme                          # revoke now
```
