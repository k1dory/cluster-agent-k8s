#!/usr/bin/env bash
# Shared by the acceptance scripts (docs/acceptance.md): the inputs, the tools, the report.
# Sourced by run.sh and kind.sh; hack/ci/lib.sh supplies the pinned versions and the downloads.
set -euo pipefail
acc_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
acc_root=$(cd "$acc_dir/../.." && pwd)
# shellcheck source=../ci/lib.sh
. "$acc_root/hack/ci/lib.sh"

# --- inputs (every one an environment variable; docs/acceptance.md lists them) ------------------
ACCEPT_NAMESPACE=${ACCEPT_NAMESPACE:-agent-sandbox-acceptance}
ACCEPT_RELEASE=${ACCEPT_RELEASE:-agent-sandbox}
ACCEPT_REPLICAS=${ACCEPT_REPLICAS:-2}
ACCEPT_TENANT=${ACCEPT_TENANT:-acme}
ACCEPT_OUT=${ACCEPT_OUT:-$acc_root/.ci/acceptance}
ACCEPT_IMAGE_TAG=${ACCEPT_IMAGE_TAG:-acc}
ACCEPT_UPGRADE_TAG=${ACCEPT_UPGRADE_TAG:-}
ACCEPT_VALUES=${ACCEPT_VALUES:-}
ACCEPT_DATABASE_URL=${ACCEPT_DATABASE_URL:-}
ACCEPT_DB_EXEC=${ACCEPT_DB_EXEC:-}
ACCEPT_DB_USER=${ACCEPT_DB_USER:-sandbox}
ACCEPT_DB_NAME=${ACCEPT_DB_NAME:-sandbox}
ACCEPT_DB_OUTAGE=${ACCEPT_DB_OUTAGE:-}
ACCEPT_DB_RESTORE=${ACCEPT_DB_RESTORE:-}
ACCEPT_API_URLS=${ACCEPT_API_URLS:-}
ACCEPT_HARNESS_MARKER=${ACCEPT_HARNESS_MARKER:-}
ACCEPT_VLAN_PREFIX=${ACCEPT_VLAN_PREFIX:-10.77.77.}
ACCEPT_ADMIN_TOKEN=${ACCEPT_ADMIN_TOKEN:-}
# The Secret's keys that must survive a second install: unset, the value already in the Secret
# stays (a fresh PREVIEW_TICKET_KEY only when there is none; no CREDENTIALS_KEY, no credentials API).
ACCEPT_CREDENTIALS_KEY=${ACCEPT_CREDENTIALS_KEY:-}
ACCEPT_PREVIEW_TICKET_KEY=${ACCEPT_PREVIEW_TICKET_KEY:-}
ACCEPT_KEEP=${ACCEPT_KEEP:-}
ACCEPT_WAIT=${ACCEPT_WAIT:-300}
mkdir -p "$ACCEPT_OUT"

# --- the release's Secret ----------------------------------------------------------------------
# acc_secret_data KUBECTL NAMESPACE prints the data of Secret agent-sandbox-secrets as JSON ({}
# when the Secret does not exist). Any other failure to read it fails: an unreadable Secret is
# not an empty one, and taking it for one would rewrite it without the key that decrypts the
# tenants' stored credentials.
acc_secret_data() {
  local out err
  err=$(mktemp)
  if out=$("$1" -n "$2" get secret agent-sandbox-secrets -o json 2>"$err"); then
    rm -f "$err"
    jq -c '.data // {}' <<<"$out"
    return
  fi
  if grep -q '(NotFound)' "$err"; then rm -f "$err"; echo '{}'; return; fi
  out=$(cat "$err"); rm -f "$err"
  acc_fail "cannot read Secret agent-sandbox-secrets in $2 (refusing to rewrite it): $out"
}
# acc_secret_keys DATA sets ACC_CREDENTIALS_KEY and ACC_PREVIEW_TICKET_KEY for the Secret an
# install writes: the explicit input, else the Secret's own value (DATA from acc_secret_data);
# a fresh preview key only when there is none. An explicit CREDENTIALS_KEY that differs from the
# one already in the Secret is refused: the stored credentials are encrypted under the old one.
acc_secret_keys() {
  local have_creds have_preview
  have_creds=$(jq -r '.CREDENTIALS_KEY // empty' <<<"$1" | base64 -d)
  have_preview=$(jq -r '.PREVIEW_TICKET_KEY // empty' <<<"$1" | base64 -d)
  if [ -n "$ACCEPT_CREDENTIALS_KEY" ] && [ -n "$have_creds" ] && [ "$ACCEPT_CREDENTIALS_KEY" != "$have_creds" ]; then
    acc_fail "ACCEPT_CREDENTIALS_KEY differs from the CREDENTIALS_KEY in Secret agent-sandbox-secrets: replacing it makes the stored credentials unreadable (rotate deliberately, not through an install)"
    return 1
  fi
  ACC_CREDENTIALS_KEY=${ACCEPT_CREDENTIALS_KEY:-$have_creds}
  ACC_PREVIEW_TICKET_KEY=${ACCEPT_PREVIEW_TICKET_KEY:-$have_preview}
  ACC_PREVIEW_TICKET_KEY=${ACC_PREVIEW_TICKET_KEY:-$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')}
}

# acc_kept_credentials_key FILE prints the CREDENTIALS_KEY kept in FILE, generating it (0600) the
# first time: one key per kept cluster, so a repeated `kind.sh run install` never re-keys the
# credentials stored in its database.
acc_kept_credentials_key() {
  [ -s "$1" ] || (umask 077; head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$1")
  cat "$1"
}

# acc_contains TEXT: stdin contains TEXT. It reads stdin to its end first: `cmd | grep -q`
# exits at the first match, the writer still writing gets SIGPIPE, and under pipefail the
# pipeline fails although the text was there (an apply that went through, reported failed).
acc_contains() {
  local all
  all=$(cat)
  grep -qF -- "$1" <<<"$all"
}
# acc_run_ended STATUS: the run is over (done, failed, cancelled). Anything else, an empty answer
# from a request that failed included, means not yet: the wait goes on instead of ending early.
acc_run_ended() { case "$1" in done | failed | cancelled) return 0 ;; *) return 1 ;; esac; }

acc_log() { printf '%s acceptance: %s\n' "$(date -u +%H:%M:%S)" "$*"; }
acc_fail() { echo "acceptance: FAIL: $*" >&2; return 1; }

# --- tools -----------------------------------------------------------------------------------------
# acc_kubectl prints the pinned kubectl (KUBECTL when set): the runner's own may be versions
# ahead of the cluster.
acc_kubectl() {
  if [ -n "${KUBECTL:-}" ]; then echo "$KUBECTL"; return; fi
  local dir="$CI_BIN/kubectl-$KUBECTL_VERSION"
  if [ ! -x "$dir/kubectl" ]; then
    mkdir -p "$dir"
    ci_fetch "https://dl.k8s.io/release/$KUBECTL_VERSION/bin/$(ci_os)/$(ci_arch)/kubectl" "$dir/kubectl"
    chmod +x "$dir/kubectl"
  fi
  echo "$dir/kubectl"
}
acc_kind() {
  if [ -n "${KIND:-}" ]; then echo "$KIND"; return; fi
  local dir="$CI_BIN/kind-$KIND_VERSION"
  if [ ! -x "$dir/kind" ]; then
    mkdir -p "$dir"
    ci_fetch "https://kind.sigs.k8s.io/dl/$KIND_VERSION/kind-$(ci_os)-$(ci_arch)" "$dir/kind"
    chmod +x "$dir/kind"
  fi
  echo "$dir/kind"
}
# acc_sandboxctl prints the CLI: ACCEPT_SANDBOXCTL when set, else built from this checkout.
acc_sandboxctl() {
  if [ -n "${ACCEPT_SANDBOXCTL:-}" ]; then echo "$ACCEPT_SANDBOXCTL"; return; fi
  local bin="$CI_BIN/sandboxctl"
  (cd "$acc_root" && go build -o "$bin" ./cmd/sandboxctl) >&2
  echo "$bin"
}

# --- the report ------------------------------------------------------------------------------------
# Every phase ends as pass, fail or skip with its evidence; the report is one Markdown table
# plus the evidence, and the exit status says whether anything failed.
report_file="$ACCEPT_OUT/report.md"
state_file="$ACCEPT_OUT/state.env"
evidence_file="$ACCEPT_OUT/evidence.txt"
results_file="$ACCEPT_OUT/results.txt"
report_init() {
  : > "$evidence_file"
  : > "$results_file"
  [ -f "$state_file" ] || : > "$state_file"
}
evidence() { printf -- '- %s\n' "$*" >> "$evidence_file"; acc_log "$*"; }
# save NAME=VALUE persists a value for the phases that follow (each phase runs in its own shell).
save() { printf '%s=%q\n' "${1%%=*}" "${1#*=}" >> "$state_file"; }
load() { # shellcheck disable=SC1090
  . "$state_file"; }
result() { printf '%s\t%s\t%s\n' "$1" "$2" "$3" >> "$results_file"; }
report_write() {
  {
    echo "# Acceptance report"
    echo
    echo "Namespace \`$ACCEPT_NAMESPACE\`, release \`$ACCEPT_RELEASE\`, $ACCEPT_REPLICAS replicas, images tag \`$ACCEPT_IMAGE_TAG\`, $(date -u +%Y-%m-%dT%H:%M:%SZ)."
    echo
    echo "| Phase | Result | Summary |"
    echo "|---|---|---|"
    while IFS=$'\t' read -r phase res summary; do
      case "$res" in pass) mark="✅ pass" ;; fail) mark="❌ fail" ;; skip) mark="⏭ skip" ;; *) mark="$res" ;; esac
      echo "| $phase | $mark | $summary |"
    done < "$results_file"
    echo
    echo "## Evidence"
    echo
    cat "$evidence_file"
  } > "$report_file"
}

# --- waiting -----------------------------------------------------------------------------------------
# wait_for SECONDS "what" cmd...: runs cmd every 2s until it succeeds; fails after SECONDS.
wait_for() {
  local secs=$1 what=$2 start
  shift 2
  start=$(date +%s)
  until "$@" >/dev/null 2>&1; do
    if [ $(( $(date +%s) - start )) -ge "$secs" ]; then
      acc_fail "timed out after ${secs}s waiting for $what"
      return 1
    fi
    sleep 2
  done
}
