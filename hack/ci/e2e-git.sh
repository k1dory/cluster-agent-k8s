#!/usr/bin/env bash
# ci-e2e-git: the Git adapters end to end on a real runner (hack/e2e-git-adapter.sh): the
# control plane and sandboxctl from their images, a repository of bundles owned by the runner's
# user, the GitHub workflow's steps and the GitLab job scripts verbatim. Needs Docker and
# python3 with PyYAML. IMAGE_PREFIX and IMAGE_TAG as for ci-images (the same images are reused).
. "$(dirname "$0")/lib.sh"
cd "$ci_root"
ci_docker
python3 -c 'import yaml' 2>/dev/null || ci_die "e2e-git: python3 with PyYAML is required (it reads the workflow)"
prefix=${IMAGE_PREFIX:-agent-sandbox} tag=${IMAGE_TAG:-ci}
docker build -f images/sandboxd/Dockerfile -t "$prefix/sandboxd:$tag" .
docker build -f images/sandboxd/Dockerfile --target sandboxctl -t "$prefix/sandboxctl:$tag" .
hack/e2e-git-adapter.sh "$prefix/sandboxd:$tag" "$prefix/sandboxctl:$tag"
ci_ok e2e-git
