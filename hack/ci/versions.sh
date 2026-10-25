#!/usr/bin/env bash
# Prints the shared versions (hack/ci/versions.env): plain, or as job outputs for a workflow
# (`versions.sh github` prints name=value lines for $GITHUB_OUTPUT; Forgejo reads the same), so
# a matrix in a workflow is read from the one definition instead of being a copy of it;
# `versions.sh verify` fails when a copy a provider file must carry has drifted.
#   caddy=["2.8.4","2.9.1","2.10.0"]   helm=v3.16.4   postgres=postgres:16
. "$(dirname "$0")/lib.sh"
case "${1:-plain}" in
  github | forgejo)
    list=$(printf '"%s",' $CADDY_VERSIONS)
    echo "caddy=[${list%,}]"
    echo "helm=$HELM_VERSION"
    echo "postgres=$POSTGRES_IMAGE"
    ;;
  plain)
    echo "go: $(sed -n 's/^go //p' "$ci_root/go.mod") (go.mod)"
    echo "caddy: $CADDY_VERSIONS"
    echo "helm: $HELM_VERSION"
    echo "postgres: $POSTGRES_IMAGE"
    echo "docker cli (when the runner has none): $DOCKER_CLI_VERSION"
    ;;
  verify)
    # Where a provider file cannot read versions.env (GitLab's service and job images are
    # literal), the copy it carries must match, or the build fails: no silent divergence.
    gl="$ci_root/.gitlab-ci.yml"
    grep -q "name: $POSTGRES_IMAGE\b" "$gl" || ci_die "versions: .gitlab-ci.yml's postgres service is not $POSTGRES_IMAGE (hack/ci/versions.env)"
    gomm=$(sed -n 's/^go \([0-9]*\.[0-9]*\).*/\1/p' "$ci_root/go.mod")
    grep -q "image: golang:$gomm\b" "$gl" || ci_die "versions: .gitlab-ci.yml's Go image is not golang:$gomm (go.mod)"
    ;;
  *) ci_die "usage: versions.sh [plain|github|forgejo|verify]" ;;
esac
