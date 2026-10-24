#!/usr/bin/env bash
# Smoke test of the shipped agent image: the pieces the pod runs, checked inside the image.
#   hack/smoke-image.sh registry.example.com/agent-sandbox/agent:dev
# Builds nothing: build first with `make images` (or docker build -f images/agent/Dockerfile).
set -euo pipefail
IMG="${1:?image reference}"
run() { docker run --rm --entrypoint /bin/sh "$IMG" -lc "$*"; }

echo "== user and tools"
test "$(run id -u)" = "1000"                      # the pod runs as 1000; must be `agent`, not `node`
test "$(run id -un)" = "agent"
run 'claude --version >/dev/null'
run 'git --version >/dev/null && /usr/sbin/nft --version >/dev/null && test -x /usr/local/bin/netlock.sh'
run 'test -x /usr/local/bin/agent-init && test -x /usr/local/bin/agent-runner'

echo "== netlock refuses to run without the gateway address, and installs rules with it"
if docker run --rm --entrypoint /usr/local/bin/netlock.sh "$IMG" 2>/dev/null; then echo "netlock must fail without GATEWAY_IP"; exit 1; fi
docker run --rm --cap-add NET_ADMIN --cap-add NET_RAW --user 0 -e GATEWAY_IP=10.77.77.1 --entrypoint /bin/sh "$IMG" -c \
  '/usr/local/bin/netlock.sh && /usr/sbin/nft list ruleset | grep -q "10.77.77.1" && /usr/sbin/nft list ruleset | grep -q "policy drop" && /usr/sbin/nft list ruleset | grep -q "saddr 10.77.77.1 ct state new accept"'

echo "== agent-init: trusts the published gateway root and fails loudly without a registrar"
docker run --rm --entrypoint /bin/sh "$IMG" -lc 'out=$(/usr/local/bin/agent-init 2>&1 || true); echo "$out" | grep -q "REGISTRAR_URL"'

echo "== agent-runner: needs the identity agent-init writes"
docker run --rm --entrypoint /bin/sh -e API_URL=https://api.sandbox.internal "$IMG" -lc 'out=$(/usr/local/bin/agent-runner 2>&1 || true); echo "$out" | grep -q "client cert"'
echo "image smoke: ok"
