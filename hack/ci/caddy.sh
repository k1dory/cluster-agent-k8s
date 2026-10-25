#!/usr/bin/env bash
# ci-caddy: the gateway path end to end on a real Caddy (render, push, bootstrap, mTLS, policy,
# injection, the agent API: internal/integration) and `caddy validate` of the rendered
# Caddyfile, for every supported Caddy (CADDY_VERSIONS in versions.env), or for one of them
# (CADDY_VERSION=2.9.1: what a provider's matrix passes), or for a binary of the caller's
# (CADDY_BIN=/path/to/caddy). A missing binary is a failure, not a skip.
. "$(dirname "$0")/lib.sh"
cd "$ci_root"
run_one() {
  local caddy=$1 label=$2
  echo "== caddy $label: $("$caddy" version)"
  CADDY_BIN=$caddy SANDBOX_TEST_REQUIRE_EXTERNAL=1 go test ./internal/integration/ -count=1 -v
  ci_caddy_validate "$caddy" go run ./cmd/sandboxd
}
if [ -n "${CADDY_BIN:-}" ] && [ -z "${CADDY_VERSION:-}" ]; then
  run_one "$CADDY_BIN" "$CADDY_BIN"
  ci_ok "caddy ($CADDY_BIN)"
  exit 0
fi
versions=${CADDY_VERSION:-$CADDY_VERSIONS}
for v in $versions; do
  run_one "$(ci_caddy "$v")" "$v"
done
ci_ok "caddy ($versions)"
