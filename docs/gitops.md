# Configuration from Git: provenance, drift, rollback

Agents, environments and connections are versioned documents applied as bundles (`plan`, then
`apply`). This document describes what the platform records about where a revision came from,
how it tells configuration that moved away from what was applied, and how it goes back: always
forward, as a new revision, under the rights the caller holds now.

## Provenance: every revision says where it came from

A revision written by an apply carries a `source`:

```json
{
  "apply":  "apply_7c1e5a9b02d4",
  "bundle": "19848c27798b5262",
  "repo":   "git@example.com:acme/platform.git",
  "ref":    "main",
  "commit": "0123456789abcdef0123456789abcdef01234567",
  "path":   "bundles/acme.yaml"
}
```

`apply` and `bundle` are set by the controller: the apply that wrote the revision and the
fingerprint of the documents it applied. `repo`, `ref`, `commit` and `path` are what the client
attached to the apply (`source` in the JSON body, or `?repo=&ref=&commit=&path=` for a YAML
body). `sandboxctl apply -f bundles/acme.yaml` detects them from the file's Git work tree and
records the commit only when the bytes it applies are exactly what `HEAD` holds for the path
(`git cat-file blob HEAD:path` compared with the file, not `git status`, which an index marked
assume-unchanged or skip-worktree makes lie): a SHA in the catalogue always names exactly the
content that was applied. A modified, staged or untracked file is applied with a warning and
without a commit; `-repo`, `-ref`, `-commit`, `-path` override the detection, `-no-git` records
nothing, and excludes `-repo`, `-ref`, `-commit`, `-path` and `-require-commit` (a SHA that
would not be sent is not a source). `-require-commit` turns the warning into a refusal and is
checked on the source that goes out, not on the flags: a CI job applies with the merge commit's
SHA or not at all. A checkout Git cannot read is an error, not a plain file: a container
running as another user than the one that cloned sees `detected dubious ownership`, and applying
silently without the SHA would lose the provenance (the sandboxctl image marks every directory
safe, because reading CI checkouts is what it is for).

Credentials never reach the record. A repository URL loses its user information
(`https://x:TOKEN@host/…` becomes `https://host/…`; in the scp form only the conventional `git@`
user survives), the commit must be a hex object name, and every field is bounded. `sandboxctl`
cleans what it detects or was given with `-repo`; the controller cleans again on `POST /v1/apply`,
so a client that sends a raw URL is covered too.

A revision written directly through the resource API (`PUT /v1/environments/py`) carries no
source. An unchanged document in a bundle (a noop step) writes no revision, so the item keeps the
provenance of the revision that last changed it; the apply itself still records the commit it was
run from.

An item **belongs** to the apply that wrote its latest revision. That is the whole ownership
model: there is no separate registration, no adoption step, and nothing to clean up. A later
apply that writes the item takes it over, because the desired state moved with it.

## Drift: the platform versus what was applied

`GET /v1/drift` (`sandboxctl drift`) lists, for one scope, every item an apply wrote whose live
state is no longer that revision:

- `changed`: the latest revision was written outside apply (by hand, through the API). The entry
  shows the last applied revision with its source, the current revision with its author, and
  the field diff between the two.
- `deleted`: the item an apply wrote is gone.

An item nobody ever applied is manual, not drift. An item a later apply rewrote is in sync with
that apply. The report is computed from the store alone, so every replica gives the same answer
and no access to Git is needed. `sandboxctl drift` exits 3 when anything drifted, which is what
a scheduled check wants.

The other direction, what Git says now versus what the platform holds, is a plan:
`sandboxctl drift -f bundles/acme.yaml` plans the bundle and exits 2 when the bundle is invalid
(a document or the bundle as a whole) and 3 when anything would be created or updated. Nothing
is written either way.

Exit codes do not depend on the output format: `-json` prints the same object and exits the same
way. Across `plan`, `apply`, `drift` and `rollback`: 0 is "nothing to do or done", 2 is "invalid",
3 is "would change, drifted, or did not finish" (an apply left `conflict`, `failed` or `running`).

## Rollback: a new plan and apply, under today's rights

Rollback never edits history and never restores a revision in place. It builds documents from
stored revisions, plans them and applies them like any bundle, so the result is a new revision
with its own provenance (`source.rollback` names what it restored) and the same guarantees:
one transaction per step, continued by key, refused as a whole when the state moved.

A plan's fingerprint covers what its documents resolved to, not only what they said: each change
carries `resolved`, the fingerprint of the item as it will be written. The same agent document
that named `environment: py` resolves to the shared `py` today and to the tenant's own `py`
tomorrow; the request (its bundle hash) is unchanged, the plan is not, and apply refuses to write
anything but what the plan showed. A continuation checks the same thing for every pending step.

```sh
sandboxctl rollback -apply apply_7c1e5a9b02d4 -plan     # what restoring would change, nothing written
sandboxctl rollback -apply apply_7c1e5a9b02d4           # every item the apply wrote, back to the revision it replaced
sandboxctl rollback environment py                      # one item, back to the last revision an apply wrote
sandboxctl rollback environment py -to 3                # one item, to a revision (a deleted one too)
```

Over the API: `POST /v1/rollback` with `{"apply": "<id>"}` or
`{"kind": "EnvironmentProfile", "name": "py", "revision": 3}` (revision 0: the last applied one),
plus `"dry_run": true` for the plan alone and `"key"` for the idempotency key of the apply it
submits. The answer carries the documents, the plan, the apply when one ran, and `skipped`: what
the target contains that rollback will not restore, with the reason.

Three things follow from "a new plan under the caller's current rights":

1. **A revoked right is never restored.** `PolicyBinding` and `TenantSettings` documents are
   skipped whatever the target contains, and cannot be rolled back on their own. If the agent an
   apply wrote needs a policy the tenant has since lost, the rollback plan is invalid and nothing
   is written: the environment alone would have been fine, but a rollback is one bundle, like the
   apply it undoes. Once the right is granted again, the same rollback goes through.
2. **A creation is not undone.** An item the apply created has no earlier revision to return to;
   it is listed under `skipped` and removed explicitly if it should go. An apply that only created
   things answers 422 `nothing_to_roll_back`.
3. **The state must still be the one planned.** If someone changed an item between the rollback's
   plan and its apply, the apply stops with a conflict and shows exactly what was written, like
   any apply.

## The loop a CI pipeline runs

Ready-made jobs for GitHub Actions and GitLab CI, and the scenario of one settings change as one
pull request, are in [git-adapters.md](git-adapters.md). The bare commands:

```sh
sandboxctl plan  -f bundles/acme.yaml || exit 1          # on the pull request: valid, and what changes
sandboxctl apply -f bundles/acme.yaml                    # on merge: the commit SHA lands in every revision
sandboxctl drift                                         # on a schedule: exit 3 and page when something moved
sandboxctl rollback -apply "$(sandboxctl applies -json | jq -r '.[0].id')"   # when the last apply was wrong
```

`sandboxctl applies` shows each apply with its source, so "which commit is running" is a
lookup, and `GET /v1/environments/py` shows which apply and commit the current revision came from.
