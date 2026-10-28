# Shared CI contract

Status: accepted and implemented for the common commands and the three adapters; see
*Adoption* for what has been verified where.

**Checks are implemented once. GitHub, GitLab, Forgejo and local development invoke the same
commands. A fix to a check is made in one place.**

An organization must be able to keep its own copy of the project, use its own runners and
registry, make local changes and receive upstream updates without maintaining a separate
implementation of the checks.

## Ownership of the logic

- `Makefile` exposes the common commands. Shared scripts under `hack/` hold logic that is too
  large for a Make target. Tests, assertions, test selection and exit-code handling belong in
  these common commands, scripts and test packages.
- CI files select events, arrange jobs and dependencies, prepare tools and services, map
  provider variables to common inputs, invoke the commands and publish their reports.
- Provider files must not contain independent implementations of a check, different expected
  results or their own rules for turning a failed check into success.
- Local development invokes the same commands with documented prerequisites and inputs.
  Runner-specific setup may differ; the check and its pass/fail conditions must remain the same.

The common interface must offer both individual check groups and an entry point for the full
required set. Providers may execute groups in parallel. The required groups, supported tool
versions and version matrices have one maintained definition in the repository; changing them
must not require editing independent copies of that definition in three workflow files.

## Required behaviour

1. All supported providers run the same required checks for equivalent changes: build,
   formatting and vet, tests with the race detector, PostgreSQL contracts and migrations,
   policy checks, Caddy integration, Helm and generated manifests, image checks and Git-adapter
   end-to-end tests. The shared definition specifies the actual commands and versions.
2. The same failing input fails locally and on every provider. Logs, report uploads and shell
   wrappers preserve the command's failure. A required service or tool being unavailable is
   reported as an incomplete or failed check, never as a successful full run.
3. A developer may run a documented subset locally. Its result must identify that subset;
   passing it does not mean the full required set passed.
4. Common commands accept explicit inputs rather than reading provider-specific CI variables.
   Workflow adapters map repository, commit, paths and other job context to those inputs.
5. Ordinary build and test runs need no credentials belonging to the upstream project.
   Registry, runner and installation settings are configurable for the organization's copy.
   Publishing and deployment are separate, explicitly configured actions.

## Configuration repositories

The same principle applies to the [Git adapters](git-adapters.md). Configuration pipelines
invoke `sandboxctl` and the platform API for plan, apply and drift. Their validation, policy,
revision and retry semantics stay in the shared CLI and controller. Provider adapters handle
events and report delivery; they do not implement another apply engine.

## Acceptance of CI changes

- A change to an existing check updates its shared implementation and relevant tests once.
  Provider files change only when their orchestration or input mapping needs to change.
- A new required check joins the common set and is invoked by GitHub, GitLab, Forgejo and the
  documented local entry point. Provider coverage must not silently diverge.
- The contributor documents the local command, prerequisites and observed results. A shell
  test of a workflow is not evidence that the workflow ran on that provider's runner.
- Provider parity is accepted after runs on GitHub, GitLab and Forgejo and a local run using
  the shared commands. Any unverified provider or missing prerequisite is stated explicitly.

## Common commands

The shared implementation is the `Makefile` and `hack/ci/`. Each group is one target that ends
with the line `ci: <group>: ok` and exits non-zero otherwise; a tool or service it needs and
cannot find is a failure. `make ci` runs the full required set in order; `make ci-fast` runs
the subset a developer runs before pushing and says so in its last line.

| Target | Checks | Inputs and prerequisites |
|---|---|---|
| `ci-build` | `go build ./...`; the version copies a provider file must carry match `hack/ci/versions.env` and `go.mod` | Go (`go.mod`'s version) |
| `ci-vet` | `go vet`; `gofmt` over the module's Go files as `go list` names them (a module cache inside the tree is not formatted), with gofmt's own failure a failure | Go |
| `ci-unit` | every test under the race detector, in-memory store | Go, python3 with PyYAML (the tests of the e2e script run its preflight, which reads the workflow) |
| `ci-policy` | policies validate, expectations pass, the rendered gateway configuration passes `caddy validate` | Go; `CADDY_BIN`, else the newest supported Caddy is downloaded |
| `ci-postgres` | store, Git job and record contracts, the database-taking tests of `internal/gitsync` and `internal/ciauth` | `SANDBOX_TEST_POSTGRES_URL` (required; the provider maps its service to it) |
| `ci-caddy` | the gateway end to end on a real Caddy and `caddy validate`, per supported version | `CADDY_VERSION=x.y.z` for one version (a provider's matrix), `CADDY_BIN` for a binary of yours, else every version in `versions.env` is downloaded |
| `ci-helm` | chart lint in both layouts; `deploy/k8s` is what the chart renders | `HELM`, else the pinned Helm is downloaded |
| `ci-images` | the three images build; git and nonroot in the control plane; sandboxctl's tools, a checkout owned by another user, `-require-commit`; the agent image's smoke test and network lock | any Docker daemon, local or remote (files move through the API, never a bind mount; the CLI is downloaded when missing), python3; `IMAGE_PREFIX`, `IMAGE_TAG` |
| `ci-e2e-git` | the Git adapters end to end from the images (`hack/e2e-git-adapter.sh`) | a Docker daemon on the job's host that sees the job's files (the templates' steps bind-mount the checkout; the check probes this and refuses a daemon elsewhere), python3 with PyYAML; `IMAGE_PREFIX`, `IMAGE_TAG` |
| `ci-versions` | prints the shared versions | |
| `ci-acceptance` | the production acceptance ([docs/acceptance.md](acceptance.md)) on a kind cluster shaped like production: install with two replicas, the Git path to a running agent on the VLAN, a replica lost, an agent pod and the database lost, an upgrade, a backup restored; not in the required set (twenty minutes, Docker able to run kind) | a Docker daemon on the job's host that can run privileged containers (kind), Go; `ACCEPT_KEEP=1` leaves the cluster |

Versions and matrices (Caddy, Helm, PostgreSQL, the docker CLI) are defined once in
`hack/ci/versions.env`; `hack/ci/versions.sh github` turns them into job outputs, so a
workflow's matrix is read from that file rather than copied. Where a provider file cannot read
it (GitLab's service and job images are literals), `ci-build` verifies the copy.

The provider files call the targets and nothing else: `.github/workflows/ci.yaml` and
`policies.yaml`, `.forgejo/workflows/ci.yaml` and `policies.yaml`, `.gitlab-ci.yml`. They
select events, arrange jobs, set up Go, start the PostgreSQL service and, for the Docker
groups, a daemon, and map those to the inputs above.

## Publishing

Publishing is not a check and is not in `make ci`; it is the explicitly configured action of
rule 5, with the same shape: the logic in `hack/publish-images.sh` and `hack/verify-images.sh`,
the provider file (`.github/workflows/publish.yaml`, on `main` and by hand) mapping its context
to the inputs and keeping the record.

| Target | Does | Inputs |
|---|---|---|
| `publish-images` | builds linux/amd64 `sandboxd`, `sandboxctl` and `agent` with buildx (provenance attestation, mode=max), pushes each to `IMAGE_REPO/<image>:sha-<12 characters of COMMIT>` (that tag only; an existing tag is never rebuilt), signs each digest with cosign, writes `.ci/publish/images.json` (image, digest, arch, commit, harness versions) | `IMAGE_REPO` (required), `COMMIT` (HEAD of a clean checkout), `SOURCE_URL`, `REGISTRY_USER`/`REGISTRY_PASSWORD`, `COSIGN_PRIVATE_KEY`/`COSIGN_PASSWORD` (a missing key fails the run unless `PUBLISH_UNSIGNED=1`), `PUBLISH_MANIFEST`; docker with buildx, python3 |
| `verify-images` | every image of the record carries a signature from `cosign.pub`'s key and its tag still names the recorded digest; needs no credentials for public packages | `PUBLISH_MANIFEST`, `COSIGN_PUBLIC_KEY` (default `cosign.pub`) |

cosign is `COSIGN_VERSION` from `versions.env` (downloaded and checked against the release's
checksums, or `COSIGN_BIN`). The agent image's harnesses (`CLAUDE_CODE_VERSION`,
`CODEX_VERSION`) are pinned there too and passed as build arguments by every build of that image
(`hack/ci/versions.sh build-args`); the image shows them as the labels
`io.agent-sandbox.harness.claude-code.version` and `io.agent-sandbox.harness.codex.version`, and
`ci-images` fails when a label or the installed binary differs from the pin.

A copy of the project publishes to its own registry with its own key: `IMAGE_REPO` and the two
cosign secrets are its settings, and its `cosign.pub` replaces this one. To check an image by
hand:

```
cosign verify --key cosign.pub ghcr.io/OWNER/REPO/agent:sha-0123456789ab
docker inspect --format '{{ json .Config.Labels }}' ghcr.io/OWNER/REPO/agent:sha-0123456789ab
```

## Adoption

Implemented: the common targets and scripts above; GitHub, Forgejo and GitLab adapters that
call them; the GitHub policies workflow and its Forgejo twin on `make ci-policy`.

Verified at adoption (2026-10-25):

- GitHub: the full set runs on every pull request and on `main` (the `ci` workflow).
- Local, in a container without a Docker daemon: `ci-build`, `ci-vet`, `ci-unit`, `ci-policy`,
  `ci-postgres` (PostgreSQL 16), `ci-caddy` (2.8.4, 2.9.1, 2.10.0 downloaded), `ci-helm`
  (v3.16.4 downloaded) pass; `ci-images` and `ci-e2e-git` fail with "no daemon answers", as
  required (never a pass).
- Not verified on their runners: Forgejo and GitLab. Their files parse and call the same
  targets; the runner labels (`docker`, `docker-host`), the docker-in-docker service for the
  images group and the Forgejo `services:` support are to be confirmed on a real instance
  before parity is claimed. The Git-adapter end-to-end needs a runner whose daemon is on the
  job's host (see the targets' prerequisites); `hack/ci/contract_test.go` checks the scripts'
  own contract (no private temporary paths handed to the daemon, no localhost of another
  container, a failing formatter never a pass) with stubs, which is not a run on a provider.
