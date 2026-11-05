#!/usr/bin/env bash
# ci-images: the three images build, and what they carry is checked inside them. The control
# plane has git (GitRepository syncs) and runs as nonroot; the sandboxctl image runs, carries
# sh, curl, jq and git, reads a checkout owned by another user than its own (the CI case: the
# runner's checkout against the image's uid 1000) and records its SHA, and `apply
# -require-commit` fails on a modified file; the agent image passes its smoke test and the
# network lock on an isolated Docker network. Needs Docker and python3.
#   IMAGE_PREFIX (default agent-sandbox) and IMAGE_TAG (default ci) name the images built.
. "$(dirname "$0")/lib.sh"
cd "$ci_root"
ci_docker
command -v python3 >/dev/null || ci_die "images: python3 is required (hack/test-netlock.py)"
prefix=${IMAGE_PREFIX:-agent-sandbox} tag=${IMAGE_TAG:-ci}
sandboxd=$prefix/sandboxd:$tag ctl=$prefix/sandboxctl:$tag agent=$prefix/agent:$tag hermes=$prefix/agent-hermes:$tag

echo "== build"
# Each build also records the id of the image it produced (--iidfile): the vulnerability scan
# at the end reads that id, so a tag another job on the same daemon re-pointed meanwhile
# cannot put a different image under the scanner.
iids=$(mktemp -d "${TMPDIR:-/tmp}/agent-sandbox-ci-iid.XXXXXX")
docker build -f images/agent/Dockerfile $("$ci_dir/versions.sh" build-args) -t "$agent" --iidfile "$iids/agent" .
docker build -f images/sandboxd/Dockerfile -t "$sandboxd" --iidfile "$iids/sandboxd" .
docker build -f images/sandboxd/Dockerfile --target sandboxctl -t "$ctl" --iidfile "$iids/sandboxctl" .
docker build -f images/agent-hermes/Dockerfile $("$ci_dir/versions.sh" hermes-build-args) -t "$hermes" --iidfile "$iids/agent-hermes" .

echo "== agent image: the harnesses of versions.env, installed and labelled"
# The label is what an operator reads off a pulled image (docker inspect); the binary is what
# runs. Both must be the pinned version, or the pin is decoration.
harness() { # harness LABEL-NAME COMMAND WANT
  local label seen
  label=$(docker inspect -f "{{ index .Config.Labels \"io.agent-sandbox.harness.$1.version\" }}" "$agent")
  [ "$label" = "$3" ] || ci_die "images: label io.agent-sandbox.harness.$1.version is '$label', versions.env says $3"
  seen=$(docker run --rm --entrypoint /bin/sh "$agent" -lc "$2 --version" 2>&1 || true)
  case "$seen" in *"$3"*) echo "$1 $3" ;; *) ci_die "images: '$2 --version' in the agent image says '$seen', versions.env says $3" ;; esac
}
seen=$(docker run --rm --entrypoint npm "$agent" --version 2>&1 || true)
[ "$seen" = "$NPM_VERSION" ] || ci_die "images: npm in the agent image is '$seen', versions.env says $NPM_VERSION"
echo "npm $NPM_VERSION"
harness claude-code claude "$CLAUDE_CODE_VERSION"
harness codex codex "$CODEX_VERSION"
harness opencode opencode "$OPENCODE_VERSION"
# The ACP adapters speak JSON-RPC on stdio and have no --version: the label and the installed
# package are what pin them.
acp_adapter() { # acp_adapter LABEL-NAME PACKAGE WANT
  local label seen
  label=$(docker inspect -f "{{ index .Config.Labels \"io.agent-sandbox.harness.$1.version\" }}" "$agent")
  [ "$label" = "$3" ] || ci_die "images: label io.agent-sandbox.harness.$1.version is '$label', versions.env says $3"
  seen=$(docker run --rm --entrypoint /bin/sh "$agent" -lc "npm ls -g --depth=0 $2 2>/dev/null; command -v $1" 2>&1 || true)
  case "$seen" in *"$2@$3"*/"$1"*) echo "$1 $3" ;; *) ci_die "images: $2@$3 or the $1 command is missing from the agent image: '$seen'" ;; esac
}
acp_adapter claude-agent-acp @agentclientprotocol/claude-agent-acp "$CLAUDE_AGENT_ACP_VERSION"
acp_adapter codex-acp @agentclientprotocol/codex-acp "$CODEX_ACP_VERSION"

echo "== control plane: git present, nonroot"
docker run --rm --entrypoint git "$sandboxd" --version
test "$(docker run --rm --entrypoint id "$sandboxd" -u)" = 65532 || ci_die "images: sandboxd must run as uid 65532"

echo "== sandboxctl: runs, tools"
# Without a command the binary prints its usage and exits non-zero: that it ran is the check.
usage=$(docker run --rm "$ctl" 2>&1 || true)
printf '%s\n' "${usage%%$'\n'*}"
case "$usage" in *'sandboxctl <command>'*) ;; *) ci_die "images: the sandboxctl image did not run the binary: $usage" ;; esac
tools=$(docker run --rm --entrypoint sh "$ctl" -c 'command -v curl jq git >/dev/null && echo tools-present' || true)
[ "$tools" = tools-present ] || ci_die "images: sandboxctl lacks curl, jq or git"

echo "== sandboxctl: a checkout owned by another user is read and its SHA recorded"
# A copy of the checkout owned by root in a volume: foreign to the image's uid 1000 whoever
# owns the runner's checkout, so the case is the same on every runner and on a laptop. The
# copy goes through the API (docker cp), never a bind mount: a daemon on another host (a
# docker-in-docker service) sees none of this job's files.
vol=agent-sandbox-ci-checkout-$$
docker volume create "$vol" >/dev/null
trap 'docker rm -f "$vol-copy" >/dev/null 2>&1 || true; docker volume rm -f "$vol" >/dev/null 2>&1 || true' EXIT
docker create --name "$vol-copy" -v "$vol:/w" --user 0 --entrypoint sh "$ctl" -c 'chown -R 0:0 /w' >/dev/null
docker cp . "$vol-copy:/w"
docker start -a "$vol-copy" >/dev/null
head=$(git rev-parse HEAD)
seen=$(docker run --rm -v "$vol:/w" -w /w --entrypoint git "$ctl" rev-parse HEAD 2>&1 || true)
[ "$seen" = "$head" ] || ci_die "images: git in the sandboxctl image does not read a checkout owned by another user: $seen"
ctl_apply() { docker run --rm -v "$vol:/w" -w /w -e SANDBOXD_URL=http://127.0.0.1:9 -e SANDBOXD_TOKEN=x "$ctl" apply -f examples/catalog/bundle.yaml -require-commit -markdown 2>&1; }
# apply -require-commit reads the source before it asks the platform: a clean checkout fails at
# the request (exit 1, a marker block, no -require-commit complaint); a modified file fails on
# the missing SHA.
set +e; out=$(ctl_apply); code=$?; set -e
printf '%s\n' "$out"
case "$code:$out" in
  1:*'<!-- agent-sandbox -->'*) case "$out" in *require-commit*) ci_die "images: a clean checkout complained about -require-commit instead of failing at the request" ;; esac ;;
  *) ci_die "images: a clean checkout must fail at the request (exit 1) with a marker block; got exit $code" ;;
esac
docker run --rm -v "$vol:/w" --user 0 --entrypoint sh "$ctl" -c 'echo "# touched" >> /w/examples/catalog/bundle.yaml'
set +e; out=$(ctl_apply); code=$?; set -e
printf '%s\n' "$out"
case "$code:$out" in
  1:*'require-commit: no commit SHA'*) ;;
  *) ci_die "images: a modified file must fail on the missing SHA; got exit $code" ;;
esac

# acp_in_image IMAGE TEST...: the ACP smoke tests of cmd/agent-runner run inside IMAGE against
# its real agents, with no network (docker --network none; loopback stays). The test binary is
# compiled in a build stage and copied, with the shipped examples, into a throwaway image on top
# of IMAGE: everything goes through the daemon's API (no bind mount, no Go on the host). A
# skipped test fails the check: here every named agent must be present.
acp_in_image() {
  local img=$1; shift
  local test_img=$img-acp-test out pattern
  docker build -q -t "$test_img" --build-arg BASE="$img" -f - . >/dev/null <<'DOCKERFILE' || ci_die "images: cannot build the ACP test image on $img"
ARG BASE
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go test -c -o /acp.test ./cmd/agent-runner
FROM ${BASE}
COPY --from=build /acp.test /acp.test
COPY examples /src/examples
WORKDIR /src/cmd/agent-runner
DOCKERFILE
  pattern="^($(IFS='|'; echo "$*"))\$"
  out=$(docker run --rm --network none -e ACP_TEST_NETWORK=none --entrypoint /acp.test "$test_img" \
    -test.run "$pattern" -test.v 2>&1) || {
    # The verdicts and the tests' own messages first (an agent's log can be long), then the tail.
    printf '%s\n' "$out" | grep -E -- '^(=== RUN|--- (FAIL|PASS|SKIP))|(_test|testing)\.go:[0-9]+:|^panic:' | cut -c1-2000
    printf '%s\n' "$out" | tail -40; ci_die "images: ACP smoke tests failed in $img"; }
  docker rmi -f "$test_img" >/dev/null 2>&1 || true
  for t in "$@"; do
    case "$out" in *"--- PASS: $t "*) echo "$t: pass" ;; *) printf '%s\n' "$out" | tail -20; ci_die "images: $t did not pass in $img (skipped?)" ;; esac
  done
}

echo "== agent image: the ACP agents open sessions from the shipped profiles, offline"
acp_in_image "$agent" TestACPCodexExampleCreatesSession TestACPOpenCodeExampleCreatesAndLoadsASession \
  TestACPCodexExampleReachesTheModelThroughTheGateway TestACPOpenCodeExampleAnswersThroughTheGateway \
  TestACPClaudeExampleTakesTheSystemPromptAndMode TestACPCodexChatGPTExampleReachesTheModelThroughTheGateway

echo "== agent-hermes image: Hermes pinned and labelled, a sandbox agent image, its ACP session offline"
label=$(docker inspect -f '{{ index .Config.Labels "io.agent-sandbox.harness.hermes.version" }}' "$hermes")
[ "$label" = "$HERMES_VERSION" ] || ci_die "images: agent-hermes label says '$label', versions.env says $HERMES_VERSION"
SMOKE_HARNESSES=hermes hack/smoke-image.sh "$hermes"
python3 hack/test-netlock.py "$hermes"
acp_in_image "$hermes" TestACPHermesExampleCreatesAndLoadsASession TestACPHermesExampleAnswersThroughTheGateway

echo "== agent image: smoke test and network lock"
hack/smoke-image.sh "$agent"
python3 hack/test-netlock.py "$agent"

echo "== every image: known vulnerabilities (trivy $TRIVY_VERSION; every HIGH and CRITICAL reported, those with a fix fail)"
# The same policy as ci-scan, on what the images carry: the base image's packages, the
# harnesses' npm packages, the Go binaries. Each image is read from this daemon by its id, the
# image built above and no other copy of the tag. Hermes's own tree (/opt/hermes, the agent
# and the tools its image bundles, pinned by digest) is reported but not part of the verdict:
# its fix is a HERMES_VERSION bump, not a change here.
# Each image is exported from the daemon by its recorded id with the docker CLI (so whatever
# the CLI needs to reach the daemon, a TLS context included, is what the scan uses too) and
# scanned from the archive, one at a time: the archive of the largest image is a few GiB.
for name in sandboxd sandboxctl agent agent-hermes; do
  id=$(cat "$iids/$name" 2>/dev/null) && [ -n "$id" ] || ci_die "images: no image id recorded for the $name build"
  skip=""
  [ "$name" = agent-hermes ] && skip=opt/hermes
  echo "-- $prefix/$name:$tag ($id)"
  docker image save -o "$iids/$name.tar" "$id" || ci_die "images: cannot export the $name image built here ($id) from the daemon"
  ci_trivy_scan image "$skip" --input "$iids/$name.tar" \
    || ci_die "images: fixable HIGH or CRITICAL vulnerabilities in $prefix/$name:$tag (upgrade the base image or a harness in hack/ci/versions.env, or accept the finding in .trivyignore.yaml with an expiry)"
  rm -f "$iids/$name.tar"
done
rm -rf "$iids"
ci_ok images
