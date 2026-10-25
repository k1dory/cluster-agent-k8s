#!/usr/bin/env bash
# Shared by the hack/ci scripts (docs/ci-contract.md): the versions, the tools downloaded once
# into .ci/bin (or taken from the caller: CADDY_BIN, HELM, docker on PATH), and the one way a
# check group reports: its last line is `ci: <group>: ok`; anything else, and a non-zero exit,
# is a failure. A missing tool or service is a failure, never a pass.
set -euo pipefail
ci_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
# shellcheck source=versions.env
. "$ci_root/hack/ci/versions.env"
CI_BIN=${CI_BIN:-$ci_root/.ci/bin}
mkdir -p "$CI_BIN"

ci_die() { echo "ci: $*" >&2; exit 1; }
ci_ok() { echo "ci: $1: ok"; }
ci_os() { uname -s | tr '[:upper:]' '[:lower:]'; }
ci_arch() {
  case "$(uname -m)" in
    x86_64 | amd64) echo amd64 ;;
    aarch64 | arm64) echo arm64 ;;
    *) ci_die "unsupported architecture $(uname -m)" ;;
  esac
}
ci_fetch() { curl -sSfL --retry 3 -o "$2" "$1" || ci_die "download failed: $1"; }

# ci_caddy VERSION prints the path of that Caddy, downloaded once from its GitHub release.
ci_caddy() {
  local v=$1 dir="$CI_BIN/caddy-$1"
  if [ ! -x "$dir/caddy" ]; then
    mkdir -p "$dir"
    ci_fetch "https://github.com/caddyserver/caddy/releases/download/v$v/caddy_${v}_$(ci_os)_$(ci_arch).tar.gz" "$dir/caddy.tgz"
    tar -C "$dir" -xzf "$dir/caddy.tgz" caddy && rm -f "$dir/caddy.tgz"
  fi
  echo "$dir/caddy"
}

# ci_helm prints the path of Helm: HELM when set, else HELM_VERSION downloaded once.
ci_helm() {
  if [ -n "${HELM:-}" ]; then echo "$HELM"; return; fi
  local dir="$CI_BIN/helm-$HELM_VERSION"
  if [ ! -x "$dir/helm" ]; then
    mkdir -p "$dir"
    ci_fetch "https://get.helm.sh/helm-$HELM_VERSION-$(ci_os)-$(ci_arch).tar.gz" "$dir/helm.tgz"
    tar -C "$dir" -xzf "$dir/helm.tgz" --strip-components=1 "$(ci_os)-$(ci_arch)/helm" && rm -f "$dir/helm.tgz"
  fi
  echo "$dir/helm"
}

# ci_docker makes sure a docker CLI is on PATH (the static CLI is downloaded once when the
# runner has none) and that a daemon answers; a check that needs Docker fails here otherwise.
ci_docker() {
  if ! command -v docker >/dev/null; then
    local dir="$CI_BIN/docker-$DOCKER_CLI_VERSION" arch
    case "$(ci_arch)" in amd64) arch=x86_64 ;; arm64) arch=aarch64 ;; esac
    if [ ! -x "$dir/docker" ]; then
      mkdir -p "$dir"
      ci_fetch "https://download.docker.com/linux/static/stable/$arch/docker-$DOCKER_CLI_VERSION.tgz" "$dir/docker.tgz"
      tar -C "$dir" -xzf "$dir/docker.tgz" --strip-components=1 docker/docker && rm -f "$dir/docker.tgz"
    fi
    PATH="$dir:$PATH"
    export PATH
  fi
  docker info >/dev/null 2>&1 || ci_die "docker: no daemon answers (DOCKER_HOST=${DOCKER_HOST:-unset}); this check needs Docker"
}

# ci_caddy_validate CADDY SANDBOXD... renders the gateway configuration the way production
# will see it and has Caddy validate it.
ci_caddy_validate() {
  local caddy=$1 tmp
  shift
  tmp=$(mktemp -d)
  cat > "$tmp/render.yaml" <<CFG
policies_dir: policies
ca: { dir: $tmp/ca }
runtime: fake
gateway: { ip: 10.77.77.1, caddy_admin: "http://127.0.0.1:2019" }
preview: { domain: preview.example.com }
CFG
  "$@" policy render -config "$tmp/render.yaml" > "$tmp/Caddyfile"
  "$caddy" validate --adapter caddyfile --config "$tmp/Caddyfile"
  rm -rf "$tmp"
}
