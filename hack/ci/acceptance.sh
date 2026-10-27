#!/usr/bin/env bash
# ci-acceptance: the production acceptance (docs/acceptance.md) on a kind cluster shaped like
# production, built on this host's Docker (hack/acceptance/kind.sh): two gateway nodes on a
# VLAN, Multus, PostgreSQL in the cluster, the images built here. Every phase of
# hack/acceptance/run.sh, the report under .ci/acceptance. Needs Docker able to run kind
# (privileged containers) and about twenty minutes; ACCEPT_KEEP=1 leaves the cluster up.
. "$(dirname "$0")/lib.sh"
cd "$ci_root"
ci_docker
cleanup() { [ -n "${ACCEPT_KEEP:-}" ] || hack/acceptance/kind.sh down; }
trap cleanup EXIT
hack/acceptance/kind.sh up
hack/acceptance/kind.sh run
ci_ok acceptance
