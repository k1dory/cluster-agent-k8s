#!/usr/bin/env bash
# ci-policy: the Policy-as-Code gate. The policies validate, the expectations in
# policies/tests.yaml pass, and the gateway configuration rendered the way production will see
# it passes `caddy validate` on the newest supported Caddy (or CADDY_BIN).
. "$(dirname "$0")/lib.sh"
cd "$ci_root"
go build -o "$CI_BIN/sandboxd" ./cmd/sandboxd
"$CI_BIN/sandboxd" policy validate policies
"$CI_BIN/sandboxd" policy test policies -f policies/tests.yaml
caddy=${CADDY_BIN:-$(ci_caddy "${CADDY_VERSIONS##* }")}
ci_caddy_validate "$caddy" "$CI_BIN/sandboxd"
ci_ok policy
