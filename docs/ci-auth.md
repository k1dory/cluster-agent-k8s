# Short-lived CI authentication

A CI job that plans and applies bundles used to hold a tenant API key in the repository's
secrets: long-lived, copied once, leaked with the repository's secrets. It can instead prove
who it is with the OpenID Connect ID token its provider issues to it for the run, and trade it
for a tenant key that expires minutes later. Nothing long-lived is stored in the CI provider;
what may act is written down on the platform, as a resource of the tenant.

## How it works

1. The tenant registers a **CITrust**: the issuer, the audience the job requests its token
   for, and the claims the token must carry.

   ```yaml
   kind: CITrust
   name: github-config-main
   spec:
     issuer: https://token.actions.githubusercontent.com
     audience: https://sandbox.example.com      # the platform's URL, by convention
     claims:
       repository: acme/config
       ref: refs/heads/main
     ttl: 10m
   ```

   `sandboxctl apply -f citrust.yaml`, or `PUT /v1/citrusts/github-config-main`; the trust is a
   versioned resource like any other (revisions, plan, drift). A trust belongs to a tenant;
   the admin's own jobs keep the admin token (the shared scope has no trusts).
2. The job obtains its ID token from the provider, for the audience the trust names, and
   presents it: `POST /v1/auth/ci {"token": …}`, or `sandboxctl auth ci -token … | -github`.
3. The platform fetches the issuer's keys (OpenID discovery, kept per issuer and fetched
   again when a token names a key the set does not hold), verifies the token's signature,
   issuer and expiry, finds the one tenant whose trust names that issuer, carries the
   audience and matches the claims, and stores, in one write, a key of that tenant with the
   trust's `ttl` and the token's use (its `jti`: a replay, or a token copied from a job log,
   opens nothing). The answer is the key and its secret, shown once.
4. The job uses the secret as `SANDBOXD_TOKEN` for the rest of the run. The key is an
   ordinary tenant key: `sandboxctl keys list` shows it with `trust` set and when it was last
   used; it can be revoked like any other; it is pruned once long expired.

Deleting the trust ends it: the next job of that repository gets nothing. A trust is a grant
like a PolicyBinding: `rollback` never restores one that was deleted or narrowed by hand;
register it again deliberately.

## Claims

Each claim the trust names must be present and match, exactly or as a pattern (`*`, `?`,
`[...]` within one segment, so `acme/*` does not match `acme/config/sub`). A list claim matches
when one entry does. `iss`, `aud`, `exp`, `nbf`, `iat` and `jti` are the verification's own and
cannot be named; the issuer and the audience are the trust's fields.

| Provider | issuer | Useful claims |
|---|---|---|
| GitHub Actions | `https://token.actions.githubusercontent.com` | `repository` (`acme/config`), `ref` (`refs/heads/main`, `refs/pull/*/merge`), `repository_owner`, `job_workflow_ref`, `environment` |
| GitLab CI | the instance URL (`https://gitlab.com`) | `project_path` (`acme/config`), `ref` (`main`), `ref_type` (`branch`), `pipeline_source`, `namespace_path` |
| Forgejo / Gitea Actions | the instance URL, when it issues ID tokens | as the instance documents them |

At least one claim is required: a trust that names the issuer alone would let every job of
that provider in. Name the repository, and the ref when only some branches may apply.

## The templates

`deploy/git/github/sandbox-config.yml` requests `id-token: write`; each job's step begins, when
no `SANDBOXD_TOKEN` secret is stored, by running `sandboxctl auth ci -github` from the
sandboxctl image and keeps the key in the step's environment, masked in the log; a refused
exchange fails the job before anything is planned. With a stored key, that key is used as
before. `deploy/git/gitlab/.gitlab-ci.yml` declares `id_tokens:` with the platform's URL as
the audience and exchanges it in `before_script` the same way. A trust for the repository, and
the `SANDBOXD_URL` variable, are then all the repository needs.

## Security properties

- The token is bound to an audience the trust names; a token meant for another service is
  refused. Request the platform's URL as the audience, and name it in the trust.
- A token is exchanged once, on every replica. The key and the token's use (its `jti`) are
  one write: both or neither. A write that failed leaves the token for the job's retry; a
  write whose acknowledgement was lost is resolved by asking the store which key the token
  was recorded for, so the job still gets its key instead of a retry that would find the
  token used.
- A token is accepted up to a minute past its `exp` (clock skew); its use is recorded for a
  minute beyond that, so a replay inside the skew allowance finds the record.
- The key lives `spec.ttl` (default 15m, at most `ci_auth.max_ttl` on the server, one hour by
  default); it is a tenant key with the tenant's rights, never the admin's.
- A job that two tenants' trusts accept gets nothing: an identity is one tenant's or none.
- A refusal says nothing about which trusts exist; the reason is in the server log.
- The issuer's keys are fetched over HTTPS from the issuer itself (its discovery document,
  which must name that issuer); an issuer whose discovery or keys cannot be fetched is a 503,
  never a pass and never a refusal of the token. Keys already fetched serve during an outage;
  a signature the held keys do not verify (a key rotated under the same id, or a token naming
  none) fetches the set again, at most once a minute, so a rotation never needs a restart.
  Each issuer is fetched under its own lock: a slow issuer delays its own tokens and no other.

## Server configuration

```yaml
ci_auth:
  max_ttl: 1h     # caps spec.ttl of every trust (default 1h)
```

CI authentication needs the key service (`api_keys`), which is always on. The exchange route
takes no bearer token.
