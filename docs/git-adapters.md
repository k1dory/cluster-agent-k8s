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
  the plan fingerprint, is bound to the state and moves once half the steps are applied). With
  a key, whether the bundle may be applied or continued is the controller's decision alone: a
  bundle with `expected_revision` re-plans as invalid against the state its own first attempt
  wrote, and the re-run still reaches the controller, which knows the apply and continues it
  under its own checks (same bundle, current rights, no outside change to a done step). The
  CLI pronounces on the plan itself only without a key, where nothing could be continued.
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

## Registering the repository instead of installing the workflow

The templates above live in the configuration repository and need Docker, the sandboxctl
image and a secret there. The platform can also read the repository itself: register it once
as a `GitRepository` and ask the platform to check and sync it through the same API everything
else goes through.

```yaml
kind: GitRepository
name: config
spec:
  url: https://github.com/acme/config.git
  ref: main
  paths: ["bundles/*.yaml"]
  credential: config-repo-token
```

- `sandboxctl credentials set config-repo-token` stores the token that opens the repository
  (a tenant credential; the admin may use an operator secret). The registration names it and
  is refused when it does not resolve; the sync resolves it again every time, so a revoked or
  deleted credential stops the next sync with a clear error and nothing applied.
- `sandboxctl set -f gitrepository.yaml` registers the repository: a versioned item like any
  other, with its history, drift and rollback. `url` is https without user information (http
  for a loopback host only, for tests), `ref` a branch or tag (never a SHA), `paths` the bundle
  files or path patterns.
- `sandboxctl gitrepo check config` (`POST /v1/gitrepos/config/check`) resolves the ref and
  records its head, or why the repository could not be read (unreachable, credential refused,
  ref missing). Exit 1 when it could not.
- `sandboxctl gitrepo sync config [-commit <sha>]` (`POST /v1/gitrepos/config/sync`) reads
  the bundle files at the commit (the ref's head by default; a pinned commit must be reachable
  from the ref) and applies each through the apply controller, one apply per bundle file under
  the key `git:config@<commit>:<path>` (`#<generation>` appended from the second transition
  on), with `source.commit` on every revision. The files are applied in path order, each over
  the state the files before it left, so a document may name what an earlier file introduces
  (not a later one), and an item lives in one file: two files describing the same item make
  the sync invalid before anything is written. The documents are applied with the repository's
  authority: a tenant's repository can do what the tenant can, the admin's shared repository
  what the admin can, whoever triggered the sync. Syncing the same commit again finds the same
  applies and writes nothing; an apply that stopped is continued by syncing that commit again.
  Going back to a commit synced earlier (a force push A → B → A, a revert) is a new transition
  of the desired state, counted by the record's `generation`: it gets applies of its own and
  writes A again, with a new revision; only a repeat of the *same* transition (the same commit
  as the last sync) is a no-op. The transition (commit and generation) is recorded as `running`
  before the first write, so a sync that dies or whose summary is lost is continued, never
  mistaken for an earlier transition to the same commit. Exit codes as for `apply`: 0 done, 2 a bundle invalid (nothing
  of it written), 3 an apply stopped, 1 the repository unreadable.
- `sandboxctl gitrepo status config` (`GET /v1/gitrepos/config/status`) shows the last check
  and the last sync: the head, the commit, one line per bundle with its apply id and status.
  The two halves are recorded independently and atomically, so a check running next to a sync
  never erases the sync's commit and apply ids, and a failed sync attempt is recorded as such
  without touching the last check.

The platform reads Git with the git binary over HTTPS (the control plane image carries it),
so any server git talks to works: GitHub, GitLab, Gitea, a plain `git http-backend`. The
credential travels as a request header set through the environment of that one git process,
never in the URL, the command line or a file. Each read works in an empty temporary repository
with its own, empty Git configuration.

### The webhook: plan on pull request, sync on push, with nothing in the repository

Add `webhook_secret: config-hook` to the registration (the name of a credential holding the
secret the provider will sign with) and point the repository's webhook at
`POST https://<platform>/hooks/git/<tenant>/config` (`-` as the tenant for a shared
repository), content type JSON, events *push* and *pull request* (GitHub) or *push* and
*merge request* (GitLab), the same secret on the provider's side. From then on:

- a push to the followed ref syncs its head, exactly as `sandboxctl gitrepo sync` would
  (one apply per bundle under the stable key, `source.commit` on every revision, nothing
  written twice when the same head is pushed again);
- a pull request opened, updated or reopened gets the plan of its head as one comment
  (the same Markdown the CI template posts, updated in place on every push, found by the
  marker line) and a commit status `agent-sandbox/plan`: success when every bundle is valid,
  failure when one is not, error when the repository could not be read. The head is fetched
  from the request's own ref (`refs/pull/N/head`, `refs/merge-requests/N/head`), the comment
  and the status are posted with the repository's `credential` to the API of the registered
  repository's host, never to an address the delivery names;
- everything else (another branch, a deleted ref, a closed request, an event the platform
  does not act on, a delivery naming another repository) is recorded as ignored with the
  reason.

A delivery is accepted only when its signature matches the secret (GitHub's
`X-Hub-Signature-256`, GitLab's `X-Gitlab-Token`); a repository without `webhook_secret`
accepts none. An accepted delivery becomes a persisted job (one per delivery: a redelivery
names the same job), which one replica at a time claims under a lease and runs with the
repository's authority (a tenant's repository does what the tenant may), under the tenant's
cross-replica lock, syncs and pull request plans alike; a replica that dies mid-way leaves a
job another replica picks up once the lease lapses, and the work (a sync, a comment updated in
place) is idempotent, so a repeat is harmless. Deliveries arrive in any order, so a job acts on
what the repository holds *now*, never on what the delivery saw: a push syncs the ref's current
head, and a pull request plan is published for the request's current head only; a delivery
whose commit the ref or the request has moved past is recorded as `superseded` and publishes
nothing, so an older state is never written over a newer one and an older plan never lands over
a newer comment, whichever replica ran which job first.

A job whose work is unfinished is not over: an error (the repository or the provider's API
unreachable, a credential not available) and a stopped apply (the store went away mid-way, a
conflict) alike, it runs again after 30 seconds, then 1, 2 and 4 minutes, five attempts in all,
and then gives up (`failed`); a stopped apply is continued, under the same keys, not started
over. The record says which attempt ended how and when the next one runs. An invalid bundle is
an outcome, not unfinished work, and is not retried. A job
that runs out of its lease (ten minutes) is taken over by the next replica to see it, up to the
same five attempts; the fifth records its failure even though its own time is up. A redelivery
(the provider's "redeliver", the same delivery id) of a delivery whose job ran reports how it
went and changes nothing; of one whose job gave up, or waits for its next attempt, runs the job
again now with its attempts reset, which is the way to run a delivery the platform could not
handle at the time; of one due or running, names the job. The delivery, the decision, the job and the outcome
land in the `hook` half of `gitrepo status`, which follows the delivery accepted last (an
older job that ran late never writes over a newer delivery's summary; its outcome is in the
job and the event), and every delivery, plan and sync is an event (`git.hook`, `git.plan`,
`git.sync`) on the tenant's event stream, so a SOC or SRE integration can follow them without
polling.

The pull request plan follows the sync's contract exactly: the bundle files are planned in
path order, each over the state the files before it would leave (not the live catalogue
alone), so a document may name what an earlier file introduces and a reference to a later file
is reported as invalid, as the sync would refuse it; two files describing the same item are
refused before anything is planned, as the sync refuses them before anything is written; and
the plan stops at the first file that is not valid, where a sync would stop. The comment shows
one section per file. The comment and the commit status are posted independently: a comment
the provider refuses still leaves the status set.

The CI templates and the webhook are two ways to the same controller; a repository may use
either. The templates need Docker and a secret in the repository and show the plan in the
job log too; the webhook needs the platform reachable from the provider and nothing in the
repository.

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

The scenario is a test, twice over. In process: `TestScenarioPullRequestMergeDriftAndResumeUnderAStableKey`
in `cmd/sandboxctl` runs the templates' commands against the real control plane (plan on the
pull request, apply on merge with the SHA recorded, drift after a hand edit, an apply that stops
at its second step and the re-run that completes it under the same key, the same with
`expected_revision` guards), and the template tests next to it run the workflows' shell against
a stand-in for Docker. On a real runner: `hack/e2e-git-adapter.sh` (CI job `git-adapter-e2e`,
`make e2e-git-adapter`) starts the control plane from its image, builds a repository of bundles
owned by the runner's user, and runs the GitHub steps and the GitLab scripts verbatim with the
sandboxctl image: plan, apply with the SHA on every revision, the re-run that writes nothing,
drift after a hand edit, a guarded re-run, the refusal of a file that differs from its commit.
Only a stopped apply is out of its reach (the shipped binary has no fault injection); that path
is the in-process test's.
