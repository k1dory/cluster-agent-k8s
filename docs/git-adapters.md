# Git adapters: a settings change is one pull request

The platform is configured by bundles of documents (agents, environments, connections; for the
admin also bindings and tenant settings). This document describes the adapters that make a Git
repository of such bundles the place where configuration changes happen: a pull request shows
exactly what would change, the merge applies it with the commit as the source of every new
revision, and a scheduled job tells when the platform moved away from what was merged.

Nothing in the adapters is specific to the platform's own repository. A tenant keeps its bundles
in its own repository with its own key; the admin keeps bindings, settings and shared items in
another with the admin token. Both use the same workflow file.

## The pieces

- `sandboxctl plan -markdown`, `apply -markdown`, `drift -markdown`: the same results as the
  table output, rendered for a pull request comment, a job summary or an alert. Every block
  opens with the marker line `<!-- agent-sandbox -->`, so a pipeline finds and updates its own
  comment instead of adding one per push; a command that produced no result (the platform
  unreachable, the token refused, the file unreadable, no SHA to record) prints a failure block
  under the same marker, so the comment never keeps showing the previous push's plan. Values
  stay inside their table cell whatever they contain (pipes, line breaks, backticks). Exit codes
  are unchanged: 2 invalid, 3 would change or did not finish, 1 no result, 0 nothing to do or
  done.
- `sandboxctl apply -key <path>@<commit> -require-commit`: how the templates apply. The key is
  stable for the bundle at that commit, so re-running a job whose apply stopped half-way
  continues the same apply from the failed step instead of starting another (the default key,
  the plan fingerprint, is bound to the state and moves once half the steps are applied).
  `-require-commit` fails the job rather than apply without the merge commit's SHA: a file that
  differs from the commit, a checkout Git cannot read.
- The `sandboxctl` image (`make images`, target `sandboxctl`): the binary with sh, curl, jq and
  git, running as uid 1000, with every directory marked safe for Git. A CI checkout is owned by
  the runner, not by that user; without the setting Git refuses it ("detected dubious
  ownership") and no commit could be recorded. The binary also ships in the control plane
  image (`/sandboxctl`).
- `deploy/git/github/sandbox-config.yml`: a GitHub Actions workflow with three jobs (plan on
  pull request, apply on push to `main`, drift on a schedule). Copy it to the configuration
  repository's `.github/workflows/`, set `SANDBOXD_URL` and `SANDBOXCTL_IMAGE` as variables and
  `SANDBOXD_TOKEN` as a secret.
- `deploy/git/gitlab/.gitlab-ci.yml`: the same three jobs for GitLab CI (merge request, default
  branch, scheduled pipeline), with an optional `GITLAB_TOKEN` for the merge request note. The
  apply job runs on a push to the default branch only: a scheduled pipeline sees every `changes:`
  rule as true, so without the pipeline source in the rule a schedule would apply.

Both templates fail the check on every non-zero exit of sandboxctl, the container that did not
run included (Docker's 125–127 get a block in the comment written by the job itself), and never
put a pipe between sandboxctl and the log, so an exit 3 of `drift` is the job's. On GitLab every
exit code is caught (`|| code=$?`): the job shell would otherwise stop at the first failing
command, and an invalid plan would leave the previous note on the merge request.

## The scenario, step by step

The acme team wants its backend agent to use a new MCP tools server, read-only. Today that is a
change to one file in the acme configuration repository.

1. **The branch.** `bundles/acme.yaml` gains a connection and the agent names it:

   ```yaml
   kind: Connection
   name: tools
   spec:
     type: mcp
     host: mcp.tools.example.com
     paths: ["/mcp", "/mcp/**"]
     mcp: { read_only: true, tools: ["get_*", "list_*"] }
     headers: { Authorization: Bearer secret:tools-token }
   ---
   kind: AgentDefinition
   name: backend
   spec: { policy: backend-dev, environment: python-dev, connections: [github, tools] }
   ```

   The token went in through `sandboxctl credentials set tools-token` (never into Git); the host
   is one the admin listed under acme's settings (`hosts`), in the admin's own repository, by
   the same kind of pull request.

2. **The pull request.** The `plan` job runs `sandboxctl plan -f bundles/acme.yaml -markdown`
   with acme's key and posts the result as the pull request comment:

   > ### Plan ✅ valid · `bundles/acme.yaml`
   > 1 to create, 1 to update, 2 unchanged, 0 invalid · bundle `19848c27798b5262` · plan `97c0e5316ecd1ae6`
   >
   > | Action | Kind | Tenant | Name | Revision | Changes |
   > |---|---|---|---|---|---|
   > | ➕ create | Connection | acme | `tools` | 0 → 1 | `+spec.host=mcp.tools.example.com, …` |
   > | ✏️ update | AgentDefinition | acme | `backend` | 3 → 4 | `+spec.connections[1]=tools` |
   > | · noop | EnvironmentProfile | acme | `python-dev` | 2 | - |
   > | · noop | Connection | acme | `github` | 1 | - |

   The reviewer reads the diff of the configuration, not of the YAML. Had the host not been
   delegated, had the token not been there, had the policy not been acme's, the plan would say so
   per document and the check would fail: the pull request cannot be merged with an invalid
   bundle. The plan writes nothing. Every push to the branch updates the same comment.

3. **The merge.** The `apply` job runs `sandboxctl apply -f bundles/acme.yaml -ref main
   -repo … -key bundles/acme.yaml@<sha> -require-commit -markdown`. The bundle is planned again
   against the state at that moment (the plan's fingerprint is bound to the state, not only to
   the file), applied one transaction per step, and the merge commit's SHA is recorded on every
   revision it writes, because the file in the checkout equals its committed bytes; were it not
   (or could Git not read the checkout), the job fails instead of applying without a SHA. The
   job summary shows the steps and the revisions. An apply that stops (the database went away,
   another change raced it, a right was revoked between review and merge) fails the job and
   names the apply id. Re-running the job is the way to continue it: the same key and the same
   bundle find the same apply and continue it from the failed step; the applied steps stay as
   they are, and no step is applied twice. `sandboxctl apply -resume <id>` does the same from a
   terminal.

4. **Afterwards.** The sandboxes created from `backend@4` get the tools server in
   `SANDBOX_MCP_SERVERS`; the gateway serves the host for them and enforces the read-only rule.
   `GET /v1/connections/tools` shows `source.commit`, so "which change is this" is a lookup.

5. **Drift.** The scheduled `drift` job runs `sandboxctl drift -markdown`. If somebody edited
   the connection through the API, the job fails with the item, the author, the field diff and
   the applied revision it moved from. The way back is either `sandboxctl rollback connection
   tools` (a new revision with the last applied content, under the current rights) or a pull
   request that declares the intended state. Reverting the merge commit is the latter: the
   revert's plan shows the configuration going back, and its merge applies it with the revert's
   SHA.

## What the adapters do not do

- They do not store secrets in Git. Credentials go through `sandboxctl credentials set` (BYOK)
  or the operator's secrets provider; bundles reference them as `secret:NAME`.
- They do not bypass the admin. A tenant's pull request can only do what the tenant's key can:
  its own agents, environments and connections, on hosts the admin delegated, with policies the
  admin bound. Bindings and settings change by the admin's pull request in the admin's repository.
- They do not keep state of their own. The platform is the state: the plan compares the bundle
  with the catalogue, the apply records the commit on the revisions, the drift report reads the
  store. A pipeline that lost its logs loses nothing.

## Adapting the templates

Both templates loop over `bundles/*.yaml`; a repository that organises bundles differently
changes the glob. A tenant key needs no `-tenant`; an admin repository sets `SANDBOX_TENANT` for
documents that name none (bundles may also name `tenant:` per document). The apply job runs under
a concurrency group so two merges do not interleave, although each apply is already safe to
retry: the same key and bundle continue the same apply, never redo it. Keep the key as the
templates compute it (bundle path at the commit): a key that changes between runs would turn a
re-run after a partial apply into a second apply.

The scenario is a test: `TestScenarioPullRequestMergeDriftAndResumeUnderAStableKey` in
`cmd/sandboxctl` runs the templates' commands against the real control plane (plan on the pull
request, apply on merge with the SHA recorded, drift after a hand edit, an apply that stops at
its second step and the re-run that completes it under the same key), and the template tests
next to it run the workflows' shell against a stand-in for Docker.
