#!/usr/bin/env bash
# Shared by the hack/ci scripts (docs/ci-contract.md): the versions, the tools downloaded once
# into .ci/bin (or taken from the caller: CADDY_BIN, HELM, docker on PATH), and the one way a
# check group reports: its last line is `ci: <group>: ok`; anything else, and a non-zero exit,
# is a failure. A missing tool or service is a failure, never a pass. CI_ROOT overrides the
# module directory (the contract tests point the scripts at a module of their own).
set -euo pipefail
ci_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ci_root=${CI_ROOT:-$(cd "$ci_dir/../.." && pwd)}
# shellcheck source=versions.env
. "$ci_dir/versions.env"
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

# ci_cosign prints the path of cosign: COSIGN_BIN when set, else COSIGN_VERSION downloaded once
# and checked against the release's checksum list (a truncated or swapped download fails here).
ci_cosign() {
  if [ -n "${COSIGN_BIN:-}" ]; then echo "$COSIGN_BIN"; return; fi
  local dir="$CI_BIN/cosign-$COSIGN_VERSION" name want got
  name="cosign-$(ci_os)-$(ci_arch)"
  if [ ! -x "$dir/cosign" ]; then
    mkdir -p "$dir"
    ci_fetch "https://github.com/sigstore/cosign/releases/download/$COSIGN_VERSION/$name" "$dir/$name"
    ci_fetch "https://github.com/sigstore/cosign/releases/download/$COSIGN_VERSION/cosign_checksums.txt" "$dir/checksums.txt"
    want=$(awk -v n="$name" '$2 == n { print $1 }' "$dir/checksums.txt")
    got=$( (sha256sum "$dir/$name" 2>/dev/null || shasum -a 256 "$dir/$name") | awk '{ print $1 }')
    [ -n "$want" ] && [ "$want" = "$got" ] || { rm -f "$dir/$name"; ci_die "cosign $COSIGN_VERSION: checksum mismatch for $name"; }
    chmod +x "$dir/$name" && mv "$dir/$name" "$dir/cosign"
  fi
  echo "$dir/cosign"
}

# ci_trivy prints the path of Trivy: TRIVY_BIN when set, else TRIVY_VERSION downloaded once,
# checked against the release's checksums (like cosign), extracted and tried in a scratch
# directory and published whole: a failed download or extraction leaves nothing a later run
# would take for a scanner.
ci_trivy() {
  if [ -n "${TRIVY_BIN:-}" ]; then echo "$TRIVY_BIN"; return; fi
  local dir="$CI_BIN/trivy-$TRIVY_VERSION" os arch name want got tmp
  case "$(ci_os)" in linux) os=Linux ;; darwin) os=macOS ;; *) ci_die "trivy: no release for $(ci_os)" ;; esac
  case "$(ci_arch)" in amd64) arch=64bit ;; arm64) arch=ARM64 ;; esac
  name="trivy_${TRIVY_VERSION}_${os}-${arch}.tar.gz"
  if [ ! -x "$dir/trivy" ]; then
    tmp=$(mktemp -d "$CI_BIN/trivy-download.XXXXXX") || ci_die "trivy: cannot create a scratch directory under $CI_BIN"
    ci_fetch "https://github.com/aquasecurity/trivy/releases/download/v$TRIVY_VERSION/$name" "$tmp/$name"
    ci_fetch "https://github.com/aquasecurity/trivy/releases/download/v$TRIVY_VERSION/trivy_${TRIVY_VERSION}_checksums.txt" "$tmp/checksums.txt"
    want=$(awk -v n="$name" '$2 == n { print $1 }' "$tmp/checksums.txt")
    got=$(sha256sum "$tmp/$name" 2>/dev/null | awk '{ print $1 }' || shasum -a 256 "$tmp/$name" | awk '{ print $1 }')
    [ -n "$want" ] && [ "$want" = "$got" ] || { rm -rf "$tmp"; ci_die "trivy $TRIVY_VERSION: checksum mismatch for $name"; }
    tar -C "$tmp" -xzf "$tmp/$name" trivy || { rm -rf "$tmp"; ci_die "trivy $TRIVY_VERSION: cannot extract trivy from $name"; }
    # Tried the way it will be run (ci_trivy_run): no ambient Trivy settings, the repository's
    # configuration file, so a runner's TRIVY_CONFIG or trivy.yaml cannot reject a good download.
    env -i PATH="$PATH" HOME="${HOME:-/tmp}" TMPDIR="${TMPDIR:-/tmp}" "$tmp/trivy" --config "$ci_dir/trivy.yaml" --version >/dev/null 2>&1 \
      || { rm -rf "$tmp"; ci_die "trivy $TRIVY_VERSION: the extracted binary does not run"; }
    mkdir -p "$dir" && mv "$tmp/trivy" "$dir/trivy" && rm -rf "$tmp"
  fi
  echo "$dir/trivy"
}

# ci_trivy_run KIND ARGS... runs Trivy with the repository's configuration file and none of the
# runner's: the environment is emptied of TRIVY_* (only the proxy and Docker settings a job
# needs pass through) and the configuration file is named, so a trivy.yaml or a variable on a
# runner cannot skip the scan or soften its filters. The policy is on the command line.
ci_trivy_run() {
  local kind=$1 trivy
  shift
  trivy=$(ci_trivy) || return 1
  env -i PATH="$PATH" HOME="${HOME:-/tmp}" TMPDIR="${TMPDIR:-/tmp}" \
    ${HTTP_PROXY:+HTTP_PROXY="$HTTP_PROXY"} ${HTTPS_PROXY:+HTTPS_PROXY="$HTTPS_PROXY"} ${NO_PROXY:+NO_PROXY="$NO_PROXY"} \
    ${http_proxy:+http_proxy="$http_proxy"} ${https_proxy:+https_proxy="$https_proxy"} ${no_proxy:+no_proxy="$no_proxy"} \
    ${DOCKER_HOST:+DOCKER_HOST="$DOCKER_HOST"} ${DOCKER_CONTEXT:+DOCKER_CONTEXT="$DOCKER_CONTEXT"} \
    ${DOCKER_CERT_PATH:+DOCKER_CERT_PATH="$DOCKER_CERT_PATH"} ${DOCKER_TLS_VERIFY:+DOCKER_TLS_VERIFY="$DOCKER_TLS_VERIFY"} \
    ${DOCKER_CONFIG:+DOCKER_CONFIG="$DOCKER_CONFIG"} ${DOCKER_API_VERSION:+DOCKER_API_VERSION="$DOCKER_API_VERSION"} \
    TRIVY_CACHE_DIR="${TRIVY_CACHE_DIR:-$CI_BIN/trivy-cache}" \
    "$trivy" "$kind" --config "$ci_dir/trivy.yaml" --quiet --scanners vuln --severity HIGH,CRITICAL \
    --ignorefile "$ci_root/.trivyignore.yaml" "$@"
}

# ci_trivy_scan KIND VERDICT-SKIP TARGET... is the one vulnerability policy every scan uses
# (ci-scan on the module, ci-images on the images). Two passes: the report, every HIGH and
# CRITICAL finding whether or not a fix exists, so an unfixed one is seen and not hidden; then
# the verdict, in which only findings with a fix fail (exit 1), because an unfixed one has
# nothing to bump yet. A finding accepted on purpose lives in .trivyignore.yaml with an expiry.
# VERDICT-SKIP, usually empty, names a directory the verdict leaves out while the report still
# shows it: ci-images passes the tree of a third-party agent image whose fixes are its own
# release. It is an argument, not a variable, so nothing in a runner's environment sets it.
ci_trivy_scan() {
  local kind=$1 skip=$2 out
  shift 2
  ci_trivy_run "$kind" --exit-code 0 "$@" || return 1
  out=$(ci_trivy_run "$kind" --ignore-unfixed --exit-code 1 ${skip:+--skip-dirs "$skip"} "$@" 2>&1) && return 0
  echo "== fixable findings (the verdict)"
  printf '%s\n' "$out" | grep -vE '^[[:space:]]*$|^Legend:|^- ' | tail -60
  return 1
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
