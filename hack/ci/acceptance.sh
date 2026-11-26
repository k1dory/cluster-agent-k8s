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
# Four kind nodes share this host's inotify limits; the runner's default number of instances
# (128) runs out and Multus's daemon fails "too many open files" watching /etc/cni/net.d.
if [ "$(uname)" = Linux ] && command -v sudo >/dev/null; then
  sudo sysctl -qw fs.inotify.max_user_instances=8192 fs.inotify.max_user_watches=524288
fi
hack/acceptance/kind.sh up
hack/acceptance/kind.sh run
ci_ok acceptance
