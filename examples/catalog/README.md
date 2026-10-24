# Declarative catalogue

The same documents go through the API (`PUT /v1/environments/{name}`, `PUT /v1/agents/{name}`,
JSON) and through files (`sandboxctl apply -f`, YAML; several documents separated by `---` are
applied in order). Unknown fields are errors, every apply appends a revision,
`expected_revision` makes an update conditional. Deleting an item keeps its history and its
revision numbers: a recreated `python-dev` continues at the next number, never as `python-dev@1`.

```sh
sandboxctl apply -f examples/catalog/environment-python.yaml     # revision 1 of python-dev
sandboxctl apply -f examples/catalog/agent-backend.yaml          # revision 1 of backend
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
