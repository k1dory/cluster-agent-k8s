#!/usr/bin/env bash
# The Git adapters end to end on a real runner: the control plane from its image (in-memory
# store, fake runtime), sandboxctl from its image, a Git repository of bundles owned by the
# runner's user (not by uid 1000 of the image), and the workflow's own shell steps taken from
# deploy/git/github/sandbox-config.yml, then the GitLab job scripts inside the image.
#
#   hack/e2e-git-adapter.sh [SANDBOXD_IMAGE] [SANDBOXCTL_IMAGE]
#
# What it proves beyond the in-process tests (cmd/sandboxctl/scenario_test.go): Docker, Git and
# checkout ownership are real; the platform is the shipped binary behind HTTP; the steps are the
# templates' text, not a copy. What it cannot do: stop an apply half-way (no fault injection in
# the shipped binary); that path is the in-process test's.
set -euo pipefail
SANDBOXD_IMAGE=${1:-${SANDBOXD_IMAGE:-agent-sandbox/sandboxd:ci}}
SANDBOXCTL_IMAGE=${2:-${SANDBOXCTL_IMAGE:-agent-sandbox/sandboxctl:ci}}
here=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
port=18080
admin=admin-e2e-token
acme=acme-e2e-token

cleanup() {
  code=$?
  if [ "$code" -ne 0 ]; then echo "--- sandboxd log (tail)"; docker logs sandboxd-e2e 2>&1 | tail -30 || true; fi
  docker rm -f sandboxd-e2e >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
python3 -c 'import yaml' 2>/dev/null || fail "python3 with PyYAML is required to read the workflow"

# --- the platform -----------------------------------------------------------------------------
mkdir -p "$work/var/secrets" "$work/var/ca"
chmod -R 777 "$work/var"
cat > "$work/sandboxd.yaml" <<CFG
listen: { api: ":$port", gateway: "127.0.0.1:18081" }
api_token: $admin
api_tokens: [{ token: $acme, tenant: acme }]
policies_dir: /etc/sandbox/policies
secrets_dir: /var/lib/sandboxd/secrets
ca: { dir: /var/lib/sandboxd/ca }
gateway: { ip: 10.77.77.1, caddyfile_out: /var/lib/sandboxd/Caddyfile }
runtime: fake
agent: { default: agent:e2e, versions: { stable: agent:e2e } }
preview: { domain: preview.localhost, ticket_key: e2e }
CFG
docker run -d --name sandboxd-e2e --network host \
  -v "$work/sandboxd.yaml:/etc/sandbox/sandboxd.yaml:ro" -v "$work/var:/var/lib/sandboxd" "$SANDBOXD_IMAGE" >/dev/null
for _ in $(seq 1 100); do curl -fs "http://127.0.0.1:$port/healthz" >/dev/null 2>&1 && break; sleep 0.2; done
curl -fs "http://127.0.0.1:$port/healthz" >/dev/null || fail "sandboxd did not start"
# The sandboxctl container reaches the host through the bridge gateway, as the templates run it
# (no --network host there; a real SANDBOXD_URL is a routable address).
bridge=$(docker network inspect bridge -f '{{(index .IPAM.Config 0).Gateway}}')
api="http://127.0.0.1:$port"
export SANDBOXD_URL="http://$bridge:$port" SANDBOXD_TOKEN=$acme SANDBOXCTL_IMAGE SANDBOX_TENANT=""
docker run --rm -e SANDBOXD_URL -e SANDBOXD_TOKEN "$SANDBOXCTL_IMAGE" drift >/dev/null || fail "the sandboxctl image cannot reach sandboxd at $SANDBOXD_URL"
echo "sandboxd $SANDBOXD_IMAGE up; sandboxctl $SANDBOXCTL_IMAGE reaches it at $SANDBOXD_URL"

# --- the configuration repository ---------------------------------------------------------------
repo=$work/repo
mkdir -p "$repo/bundles"
git -C "$repo" init -q -b main
git -C "$repo" config user.name e2e
git -C "$repo" config user.email e2e@example.com
commit() { # content message → sha
  printf '%s' "$1" > "$repo/bundles/acme.yaml"
  git -C "$repo" add -A bundles
  git -C "$repo" commit -q -m "$2"
  git -C "$repo" rev-parse HEAD
}
echo "runner uid $(id -u); checkout owned by uid $(stat -c %u "$repo"); sandboxctl runs as uid 1000"

# --- the workflow's steps, verbatim ----------------------------------------------------------------
step() { # job name → the step's run script
  python3 - "$here/deploy/git/github/sandbox-config.yml" "$1" "$2" <<'PY'
import sys, yaml
doc = yaml.safe_load(open(sys.argv[1]))
for s in doc["jobs"][sys.argv[2]]["steps"]:
    if s.get("name") == sys.argv[3]:
        print(s["run"]); break
else:
    sys.exit("no such step")
PY
}
export GITHUB_STEP_SUMMARY=$work/summary.md GITHUB_REF_NAME=main GITHUB_SERVER_URL=https://github.com GITHUB_REPOSITORY=acme/config
run_step() { # job name → $code; output and summary shown
  : > "$GITHUB_STEP_SUMMARY"
  local script; script=$(step "$1" "$2")
  set +e
  (cd "$repo" && bash -c "$script") > "$work/step.out" 2>&1
  code=$?
  set -e
  echo "--- $1 ($2): exit $code"; cat "$work/step.out"
}
summary_has() { grep -qF -- "$1" "$GITHUB_STEP_SUMMARY" || fail "summary lacks '$1'"; }
get() { curl -fs -H "Authorization: Bearer $acme" "$api$1"; }

v1='kind: EnvironmentProfile
name: py
spec: {image: stable}
---
kind: AgentDefinition
name: backend
spec: {policy: backend-dev, environment: py}
'
sha1=$(commit "$v1" "add the backend agent")
export GITHUB_SHA=$sha1

# 1. The pull request: a valid plan, nothing written.
run_step plan "plan every bundle"; [ "$code" -eq 0 ] || fail "plan step exit $code"
summary_has "Plan ✅ valid"; summary_has "2 to create"
curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $acme" "$api/v1/environments/py" | grep -qx 404 || fail "the plan wrote"

# 2. The merge: applied with the commit on every revision, under the stable key.
run_step apply "apply every bundle with this commit as the source"; [ "$code" -eq 0 ] || fail "apply step exit $code"
summary_has "Apply ✅ done"; summary_has "Source: \`$sha1\`"
get /v1/environments/py | jq -e --arg sha "$sha1" '.source.commit == $sha and .source.path == "bundles/acme.yaml" and .source.ref == "main" and .source.repo == "https://github.com/acme/config"' >/dev/null || fail "environment source: $(get /v1/environments/py | jq -c .source)"
get /v1/agents/backend | jq -e --arg sha "$sha1" '.source.commit == $sha' >/dev/null || fail "agent source"
# Re-running the merge job: the same apply, nothing written.
run_step apply "apply every bundle with this commit as the source"; [ "$code" -eq 0 ] || fail "apply re-run exit $code"
[ "$(get /v1/applies | jq length)" -eq 1 ] || fail "a re-run created another apply"
[ "$(get /v1/environments/py/revisions | jq length)" -eq 1 ] || fail "a re-run wrote"

# 3. Drift: none, then a hand edit through the API.
run_step drift "what moved outside apply"; [ "$code" -eq 0 ] || fail "drift exit $code"
summary_has "Drift ✅ none · 2 managed items"
curl -fs -X PUT -H "Authorization: Bearer $acme" -H 'Content-Type: application/json' -d '{"spec":{"image":"stable","runtime_class":"gvisor"}}' "$api/v1/environments/py" >/dev/null
run_step drift "what moved outside apply"; [ "$code" -eq 3 ] || fail "drift after a hand edit: exit $code, want 3"
summary_has "Drift ⚠️ 1 of 2 managed items"; summary_has "runtime_class"

# 4. The next merge, with expected_revision on both documents (the environment is at 2 after the
# hand edit, the agent at 1); the re-run of the job must find the finished apply, not re-plan
# the guards against the state it wrote itself.
v2='kind: EnvironmentProfile
name: py
expected_revision: 2
spec: {image: stable, env: {LOG: debug}}
---
kind: AgentDefinition
name: backend
expected_revision: 1
description: with logs
spec: {policy: backend-dev, environment: py}
'
sha2=$(commit "$v2" "debug logging, guarded")
export GITHUB_SHA=$sha2
run_step apply "apply every bundle with this commit as the source"; [ "$code" -eq 0 ] || fail "guarded apply exit $code"
summary_has "Source: \`$sha2\`"
run_step apply "apply every bundle with this commit as the source"; [ "$code" -eq 0 ] || fail "guarded apply re-run exit $code"
summary_has "Apply ✅ done"
[ "$(get /v1/applies | jq length)" -eq 2 ] || fail "the guarded re-run created another apply"
[ "$(get /v1/environments/py/revisions | jq length)" -eq 3 ] || fail "revisions after the guarded re-run: $(get /v1/environments/py/revisions | jq length)"
run_step drift "what moved outside apply"; [ "$code" -eq 0 ] || fail "drift after the guarded apply: exit $code"

# 5. A file that differs from its commit is never applied without a SHA.
echo "# edited after the commit" >> "$repo/bundles/acme.yaml"
run_step apply "apply every bundle with this commit as the source"; [ "$code" -eq 1 ] || fail "dirty apply exit $code, want 1"
summary_has "require-commit: no commit SHA"
[ "$(get /v1/environments/py/revisions | jq length)" -eq 3 ] || fail "a dirty file was applied"
git -C "$repo" checkout -q -- bundles/acme.yaml

# --- the GitLab jobs, inside the image ---------------------------------------------------------------
# GitLab runs the job in the image itself; its helper clones as another user, which the mounted,
# runner-owned checkout stands for, and leaves the checkout world-writable (the executor's
# default umask), which the chmod stands for: the job writes plans.md next to the bundles. The
# script is the template's, run with sh -e as GitLab does.
chmod -R a+rwX "$repo"
gitlab_script() {
  python3 - "$here/deploy/git/gitlab/.gitlab-ci.yml" "$1" <<'PY'
import sys, yaml
print("set -e\n" + "\n".join(yaml.safe_load(open(sys.argv[1]))[sys.argv[2]]["script"]))
PY
}
run_gitlab() { # job → $code
  set +e
  docker run --rm -e SANDBOXD_URL -e SANDBOXD_TOKEN -e SANDBOX_TENANT -e GITLAB_TOKEN= \
    -e CI_COMMIT_BRANCH=main -e "CI_COMMIT_SHA=$CI_COMMIT_SHA" -e CI_PROJECT_URL=https://gitlab.example/acme/config \
    -v "$repo:/w" -w /w --entrypoint sh "$SANDBOXCTL_IMAGE" -c "$(gitlab_script "$1")" > "$work/step.out" 2>&1
  code=$?
  set -e
  echo "--- gitlab $1: exit $code"; cat "$work/step.out"
}
# The third commit moves the guards along with the state v2 left (environment at 3, agent at 2)
# and changes the agent's description only.
v3=$(printf '%s' "$v2" | sed -e 's/^expected_revision: 2$/expected_revision: 3/' -e 's/^expected_revision: 1$/expected_revision: 2/' -e 's/with logs/with logs, on GitLab/')
sha3=$(commit "$v3
" "gitlab")
export CI_COMMIT_SHA=$sha3
run_gitlab plan; [ "$code" -eq 0 ] || fail "gitlab plan exit $code"
grep -q "0 to create, 1 to update, 1 unchanged" "$work/step.out" || fail "gitlab plan content"
run_gitlab apply; [ "$code" -eq 0 ] || fail "gitlab apply exit $code"
get /v1/agents/backend | jq -e --arg sha "$sha3" '.source.commit == $sha and .source.repo == "https://gitlab.example/acme/config"' >/dev/null || fail "gitlab apply source: $(get /v1/agents/backend | jq -c .source)"
run_gitlab apply; [ "$code" -eq 0 ] || fail "gitlab apply re-run exit $code"
[ "$(get /v1/applies | jq length)" -eq 3 ] || fail "the gitlab re-run created another apply"
run_gitlab drift; [ "$code" -eq 0 ] || fail "gitlab drift exit $code"
grep -q "Drift ✅ none" "$work/step.out" || fail "gitlab drift content"
# The apply job's plan.md/apply.md/drift.md land in the checkout as untracked files; the bundle
# itself stayed what its commit holds, so the SHA was recorded each time.
echo "OK: plan → merge → SHA → drift → guarded re-run → dirty refusal → GitLab, on $SANDBOXD_IMAGE / $SANDBOXCTL_IMAGE"
