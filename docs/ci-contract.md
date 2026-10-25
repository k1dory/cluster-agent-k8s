# Shared CI contract

Status: accepted. This is the required design for future CI changes; adoption across all
providers is still in progress.

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

## Adoption

At adoption of this contract, GitHub has the full product CI, Forgejo has a policy workflow,
and GitLab has a configuration-repository template under `deploy/git/gitlab/`. That template
does not build or test this product. Existing Make targets also do not yet cover the complete
CI command set through one common entry point.

Implementation must extract the shared commands from the existing checks, make GitHub invoke
them, and add the full GitLab and Forgejo adapters. This document records the agreement;
it does not claim that this migration has already been implemented or verified.
