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
sandboxd=$prefix/sandboxd:$tag ctl=$prefix/sandboxctl:$tag agent=$prefix/agent:$tag

echo "== build"
docker build -f images/agent/Dockerfile -t "$agent" .
docker build -f images/sandboxd/Dockerfile -t "$sandboxd" .
docker build -f images/sandboxd/Dockerfile --target sandboxctl -t "$ctl" .

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

echo "== agent image: smoke test and network lock"
hack/smoke-image.sh "$agent"
python3 hack/test-netlock.py "$agent"
ci_ok images
