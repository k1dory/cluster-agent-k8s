#!/usr/bin/env bash
# Production acceptance (docs/acceptance.md): the platform on a real Kubernetes with a real
# PostgreSQL, from the Helm chart, through every path an operator relies on: install with
# several replicas; configuration from a Git commit (the pull request's plan, the merge's
# apply with its SHA, drift clean) to a sandbox whose agent runs on the VLAN behind the
# gateway; a replica lost with the leadership moving and the API answering throughout; an
# agent pod lost and the sandbox recovered; the database lost and the replicas unready, then
# back; an upgrade with the state intact and the agents untouched; a backup restored with the
# state of that moment and the identities still valid.
#
#   hack/acceptance/run.sh [--list] [phase...]      (default: every phase, in order)
#
# Inputs are environment variables (hack/acceptance/lib.sh lists them); KUBECONFIG selects the
# cluster. Each phase runs in its own shell and ends as pass, fail or skip with its evidence;
# the report is $ACCEPT_OUT/report.md and the exit status is 1 when any phase failed. A failed
# install ends the run (nothing after it can be judged); any other failure is recorded and the
# run goes on, so one report covers everything. hack/acceptance/kind.sh builds a cluster
# shaped like production and runs this script against it (make ci-acceptance).
. "$(dirname "$0")/lib.sh"
shopt -s inherit_errexit # a failure inside $(...) is a failure

phases="preflight install config agent replicas recovery upgrade backup teardown"
if [ "${1:-}" = "--list" ]; then printf '%s\n' $phases; exit 0; fi
selected=${*:-${ACCEPT_PHASES:-$phases}}

cd "$acc_root"
report_init
exec > >(tee -a "$ACCEPT_OUT/log.txt") 2>&1
kubectl=$(acc_kubectl)
helm=$(ci_helm)
kctl() { "$kubectl" -n "$ACCEPT_NAMESPACE" "$@"; }
db() { # psql/pg_dump against the control plane's database, stdin passed through
  [ -n "$ACCEPT_DB_EXEC" ] || acc_fail "ACCEPT_DB_EXEC is required (a command prefix that runs psql in the database's environment)"
  $ACCEPT_DB_EXEC "$@"
}
# ctl_as TOKEN cmd...: the CLI against the API with that token.
ctl_as() { local tok=$1; shift; SANDBOXD_URL=$API SANDBOXD_TOKEN=$tok "$ctl" "$@"; }
get_json() { curl -sS -m 20 -H "Authorization: Bearer $ADMIN" "$1"; }
http_code() { # URL [token]
  local hdr=()
  [ -n "${2:-}" ] && hdr=(-H "Authorization: Bearer $2")
  curl -sS -m 5 -o /dev/null -w '%{http_code}' "${hdr[@]}" "$1" 2>/dev/null || echo 000
}
# replica_urls prints the API of every replica (hostNetwork: the pod's address is its node's).
replica_urls() {
  if [ -n "$ACCEPT_API_URLS" ]; then printf '%s\n' $ACCEPT_API_URLS; return; fi
  kctl get pods -l "app.kubernetes.io/instance=$ACCEPT_RELEASE" -o jsonpath='{range .items[*]}{.status.podIP}{"\n"}{end}' | sed '/^$/d' | sed "s|^|http://|; s|\$|:${ACCEPT_API_PORT:-8080}|"
}
# version URL prints "<replica> <leader>" as that replica reports itself.
version() { get_json "$1/v1/version" | jq -r '"\(.replica) \(.leader)"'; }
leader_url() { for u in $(replica_urls); do if [ "$(version "$u" | awk '{print $2}')" = true ]; then echo "$u"; return; fi; done; return 1; }
one_leader() { [ "$(for u in $(replica_urls); do version "$u"; done | awk '$2=="true"' | wc -l)" -eq 1 ]; }
all_ready() { for u in $(replica_urls); do [ "$(http_code "$u/readyz")" = 200 ] || return 1; done; }
sandbox_status() { get_json "$API/v1/sandboxes/$1" | jq -r .status; }
run_status() { ctl_as "$TENANT_TOKEN" runs "$1" "$2" | jq -r .status; }
sandbox_pod() { kctl get pods -l "agent-sandbox.io/sandbox=$1" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null; }
sandbox_pod_uid() { kctl get pods -l "agent-sandbox.io/sandbox=$1" -o jsonpath='{.items[0].metadata.uid}' 2>/dev/null; }
pod_phase() { kctl get pod "$1" -o jsonpath='{.status.phase}' 2>/dev/null; }
rollout_ready() { "$kubectl" -n "$ACCEPT_NAMESPACE" rollout status "deploy/$ACCEPT_RELEASE-sandboxd" --timeout=5s >/dev/null 2>&1 && [ "$(kctl get pods -l "app.kubernetes.io/instance=$ACCEPT_RELEASE" -o json | jq '[.items[] | select(.status.phase=="Running") | select(all(.status.containerStatuses[]; .ready))] | length')" -eq "$ACCEPT_REPLICAS" ]; }
# wait_sandbox SANDBOX STATUS waits for the sandbox to reach STATUS; an error state ends the
# wait at once with the platform's reason (the agent did not come up, and why).
wait_sandbox() {
  local sb=$1 want=$2 start status
  start=$(date +%s)
  while :; do
    status=$(get_json "$API/v1/sandboxes/$sb" | jq -r .status)
    [ "$status" = "$want" ] && return 0
    if [ "$status" = error ] && [ "$want" != error ]; then
      acc_fail "sandbox $sb is in error: $(get_json "$API/v1/sandboxes/$sb" | jq -r .error)"
      return 1
    fi
    if [ $(( $(date +%s) - start )) -ge "$ACCEPT_WAIT" ]; then
      acc_fail "timed out after ${ACCEPT_WAIT}s waiting for sandbox $sb $want (it is $status)"
      return 1
    fi
    sleep 3
  done
}
# diagnose PHASE writes what the cluster shows after a failed phase (pods, events, the agent
# pod's containers, the replicas' logs, the sandbox) next to the report, and into the log.
diagnose() {
  local f=$ACCEPT_OUT/diag-$1.txt pod c
  {
    echo "== pods"; kctl get pods -o wide 2>&1
    echo "== events"; kctl get events --sort-by=.lastTimestamp 2>&1 | tail -80
    for pod in $(kctl get pods -l agent-sandbox.io/sandbox -o name 2>/dev/null); do
      echo "== describe $pod"; kctl describe "$pod" 2>&1 | tail -80
      for c in $(kctl get "$pod" -o jsonpath='{range .spec.initContainers[*]}{.name}{"\n"}{end}{range .spec.containers[*]}{.name}{"\n"}{end}' 2>/dev/null); do
        echo "== logs $pod $c"; kctl logs "$pod" -c "$c" --tail=80 2>&1 || true
      done
    done
    for pod in $(kctl get pods -l "app.kubernetes.io/instance=$ACCEPT_RELEASE" -o name 2>/dev/null); do
      echo "== logs $pod sandboxd"; kctl logs "$pod" -c sandboxd --tail=150 2>&1 || true
      echo "== logs $pod caddy"; kctl logs "$pod" -c caddy --tail=40 2>&1 || true
      for c in sandboxd caddy; do
        if [ "$(kctl get "$pod" -o jsonpath="{.status.containerStatuses[?(@.name==\"$c\")].restartCount}" 2>/dev/null)" != 0 ]; then
          echo "== logs $pod $c (previous container)"; kctl logs "$pod" -c "$c" --previous --tail=80 2>&1 || true
        fi
      done
    done
    if [ -n "${SB:-}" ] && [ -n "${API:-}" ]; then echo "== sandbox $SB"; get_json "$API/v1/sandboxes/$SB" 2>&1; echo; fi
    echo "== multus"; "$kubectl" -n kube-system logs ds/kube-multus-ds --tail=40 2>&1 || true
    echo "== whereabouts"; "$kubectl" -n kube-system logs ds/whereabouts --tail=40 2>&1 || true
  } > "$f"
  acc_log "diagnostics for $1 ($f):"
  head -400 "$f"
}
# bundle VARIANT writes the tenant's bundle: an environment and an agent (the policy
# backend-dev of the chart admits every tenant).
bundle() {
  cat <<B
kind: EnvironmentProfile
tenant: $ACCEPT_TENANT
name: py
description: acceptance $1
spec: {image: stable}
---
kind: AgentDefinition
tenant: $ACCEPT_TENANT
name: backend
spec: {policy: backend-dev, environment: py}
B
}
new_run_done() { # SANDBOX: a task runs to the end and, with a marker, prints it
  local run
  run=$(ctl_as "$TENANT_TOKEN" run "$1" "acceptance task $(date +%s)" | jq -r .id)
  wait_for "$ACCEPT_WAIT" "run $run to finish" sh -c "[ \"\$(SANDBOXD_URL=$API SANDBOXD_TOKEN=$TENANT_TOKEN '$ctl' runs '$1' '$run' | jq -r .status)\" != running ] && [ \"\$(SANDBOXD_URL=$API SANDBOXD_TOKEN=$TENANT_TOKEN '$ctl' runs '$1' '$run' | jq -r .status)\" != queued ]"
  [ "$(run_status "$1" "$run")" = done ] || acc_fail "run $run ended $(run_status "$1" "$run")"
  if [ -n "$ACCEPT_HARNESS_MARKER" ]; then
    ctl_as "$TENANT_TOKEN" events "$1" -run "$run" -json | jq -r 'if type=="array" then .[] else . end | select(.type=="run.output") | .data' | grep -qF "$ACCEPT_HARNESS_MARKER" || acc_fail "the run's output lacks the harness marker $ACCEPT_HARNESS_MARKER"
  fi
  echo "$run"
}

# --- phases ---------------------------------------------------------------------------------------
phase_preflight() {
  for t in jq curl git go; do command -v "$t" >/dev/null || acc_fail "$t is required"; done
  "$kubectl" version -o json >/dev/null || acc_fail "the cluster does not answer (KUBECONFIG=${KUBECONFIG:-unset})"
  evidence "cluster: $("$kubectl" version -o json | jq -r .serverVersion.gitVersion), $("$kubectl" get nodes --no-headers | wc -l) nodes"
  [ -n "$ACCEPT_VALUES" ] && [ -f "$ACCEPT_VALUES" ] || acc_fail "ACCEPT_VALUES must name the values file for this cluster (images, gateway, network)"
  [ -n "$ACCEPT_DATABASE_URL" ] || acc_fail "ACCEPT_DATABASE_URL is required (the control plane's DSN)"
  "$kubectl" get crd network-attachment-definitions.k8s.cni.cncf.io >/dev/null || acc_fail "Multus is not installed (no NetworkAttachmentDefinition CRD)"
  local gw
  gw=$("$kubectl" get nodes -l agent-sandbox.io/gateway=true --no-headers | wc -l)
  [ "$gw" -ge "$ACCEPT_REPLICAS" ] || acc_fail "$gw gateway nodes labelled agent-sandbox.io/gateway=true, $ACCEPT_REPLICAS replicas asked"
  evidence "gateway nodes: $("$kubectl" get nodes -l agent-sandbox.io/gateway=true -o jsonpath='{.items[*].metadata.name}')"
  db psql -U "$ACCEPT_DB_USER" -d "$ACCEPT_DB_NAME" -tAc 'select version()' | head -1 | sed 's/^/db: /'
  evidence "database answers: $(db psql -U "$ACCEPT_DB_USER" -d "$ACCEPT_DB_NAME" -tAc 'select version()' | cut -d, -f1)"
  ctl=$(acc_sandboxctl)
  save ctl="$ctl"
  ADMIN=${ACCEPT_ADMIN_TOKEN:-$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')}
  save ADMIN="$ADMIN"
  evidence "tools: $("$kubectl" version --client -o json | jq -r .clientVersion.gitVersion), $("$helm" version --short), sandboxctl built from $(git rev-parse --short HEAD)"
}

phase_install() {
  load
  "$kubectl" get ns "$ACCEPT_NAMESPACE" >/dev/null 2>&1 || "$kubectl" create ns "$ACCEPT_NAMESPACE"
  "$kubectl" -n "$ACCEPT_NAMESPACE" create secret generic agent-sandbox-secrets \
    --from-literal=SANDBOXD_API_TOKEN="$ADMIN" --from-literal=DATABASE_URL="$ACCEPT_DATABASE_URL" \
    --from-literal=PREVIEW_TICKET_KEY="$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')" \
    --dry-run=client -o yaml | "$kubectl" apply -f - >/dev/null
  local start
  start=$(date +%s)
  "$helm" upgrade --install "$ACCEPT_RELEASE" deploy/helm/agent-sandbox -n "$ACCEPT_NAMESPACE" -f "$ACCEPT_VALUES" \
    --set gateway.replicas="$ACCEPT_REPLICAS" --set sandboxd.ca.source=db \
    --set image.tag="$ACCEPT_IMAGE_TAG" --set agentImage.tag="$ACCEPT_IMAGE_TAG" --wait --timeout 8m
  wait_for "$ACCEPT_WAIT" "$ACCEPT_REPLICAS ready replicas" rollout_ready
  local nodes
  nodes=$(kctl get pods -l "app.kubernetes.io/instance=$ACCEPT_RELEASE" -o jsonpath='{range .items[*]}{.spec.nodeName}{"\n"}{end}' | sort -u | wc -l)
  [ "$nodes" -eq "$ACCEPT_REPLICAS" ] || acc_fail "replicas share a node ($nodes distinct)"
  wait_for 60 "every replica ready" all_ready
  wait_for 90 "exactly one leader" one_leader
  API=$(replica_urls | head -1)
  save API="$API"
  local names
  names=$(for u in $(replica_urls); do version "$u"; done)
  [ "$(echo "$names" | awk '{print $1}' | sort -u | wc -l)" -eq "$ACCEPT_REPLICAS" ] || acc_fail "replicas do not report distinct names: $names"
  evidence "installed in $(( $(date +%s) - start ))s: $ACCEPT_REPLICAS replicas on $nodes nodes, ready, one leader: $(echo "$names" | tr '\n' ';')"
  evidence "build: $(get_json "$API/v1/version" | jq -r .sandboxd)"
}

phase_config() {
  load
  local repo=$ACCEPT_OUT/config-repo sha
  rm -rf "$repo"
  mkdir -p "$repo/bundles"
  git -C "$repo" init -q -b main
  git -C "$repo" config user.name acceptance
  git -C "$repo" config user.email acceptance@example.com
  bundle v1 > "$repo/bundles/$ACCEPT_TENANT.yaml"
  # The pull request: a plan, nothing written.
  ctl_as "$ADMIN" plan -f "$repo/bundles/$ACCEPT_TENANT.yaml" -markdown > "$ACCEPT_OUT/plan.md"
  grep -q "Plan ✅ valid" "$ACCEPT_OUT/plan.md" || acc_fail "the plan is not valid: $(cat "$ACCEPT_OUT/plan.md")"
  [ "$(ctl_as "$ADMIN" list environments -tenant "$ACCEPT_TENANT" | grep -c py || true)" -eq 0 ] || acc_fail "plan wrote"
  # The merge: the commit's SHA in every revision, under a key stable for the bundle at that commit.
  git -C "$repo" add -A && git -C "$repo" commit -q -m "configure $ACCEPT_TENANT"
  sha=$(git -C "$repo" rev-parse HEAD)
  (cd "$repo" && ctl_as "$ADMIN" apply -f "bundles/$ACCEPT_TENANT.yaml" -ref main -repo https://git.example.com/acceptance/config -key "bundles/$ACCEPT_TENANT.yaml@$sha" -require-commit -markdown) > "$ACCEPT_OUT/apply.md"
  grep -q "Apply ✅ done" "$ACCEPT_OUT/apply.md" || acc_fail "the apply did not finish: $(cat "$ACCEPT_OUT/apply.md")"
  grep -q "$sha" "$ACCEPT_OUT/apply.md" || acc_fail "the apply does not carry the commit"
  ctl_as "$ADMIN" drift -tenant "$ACCEPT_TENANT" > "$ACCEPT_OUT/drift.txt" || acc_fail "drift after the apply: $(cat "$ACCEPT_OUT/drift.txt")"
  # The tenant's key, issued through the API, acts as the tenant.
  TENANT_TOKEN=$(ctl_as "$ADMIN" keys create -tenant "$ACCEPT_TENANT" -name acceptance -json | jq -r .secret)
  [ -n "$TENANT_TOKEN" ] && [ "$TENANT_TOKEN" != null ] || acc_fail "no tenant key issued"
  [ "$(ctl_as "$TENANT_TOKEN" whoami | jq -r .tenant)" = "$ACCEPT_TENANT" ] || acc_fail "the tenant key does not act as $ACCEPT_TENANT"
  save TENANT_TOKEN="$TENANT_TOKEN"
  save CONFIG_SHA="$sha"
  evidence "plan valid, apply done with source commit $sha, drift clean, tenant key issued and whoami = $ACCEPT_TENANT"
}

phase_agent() {
  load
  local sb pod run
  sb=$(ctl_as "$TENANT_TOKEN" create -name shop -agent backend -owner alice -tenant "$ACCEPT_TENANT" | jq -r .id)
  [ -n "$sb" ] && [ "$sb" != null ] || acc_fail "no sandbox created"
  save SB="$sb"
  wait_sandbox "$sb" running
  pod=$(sandbox_pod "$sb")
  [ "$(pod_phase "$pod")" = Running ] || acc_fail "pod $pod is $(pod_phase "$pod")"
  local vlan
  vlan=$(kctl get pod "$pod" -o jsonpath='{.metadata.annotations.k8s\.v1\.cni\.cncf\.io/network-status}' | jq -r '.[] | .ips[]?' | grep -F "$ACCEPT_VLAN_PREFIX" | head -1 || true)
  [ -n "$vlan" ] || acc_fail "the agent pod has no address on the VLAN ($ACCEPT_VLAN_PREFIX)"
  # The pod resolves the gateway's names and nothing else: its only resolver is the gateway.
  kctl exec "$pod" -c agent -- getent hosts api.sandbox.internal | grep -q "$ACCEPT_VLAN_PREFIX" || acc_fail "the pod does not resolve api.sandbox.internal to the gateway"
  if kctl exec "$pod" -c agent -- getent hosts example.com >/dev/null 2>&1; then acc_fail "the pod resolves a host no policy names"; fi
  run=$(new_run_done "$sb")
  save POD_UID="$(sandbox_pod_uid "$sb")"
  save RUN="$run"
  evidence "sandbox $sb running as pod $pod on $(kctl get pod "$pod" -o jsonpath='{.spec.nodeName}') with VLAN address $vlan; names resolve through the gateway only; run $run done${ACCEPT_HARNESS_MARKER:+ with the harness marker}"
}

phase_replicas() {
  load
  local leader survivor leaderpod start moved failures=0 probes=0
  leader=$(leader_url) || acc_fail "no leader"
  survivor=$(replica_urls | grep -v -F "$leader" | head -1)
  leaderpod=$(kctl get pods -l "app.kubernetes.io/instance=$ACCEPT_RELEASE" -o json | jq -r --arg ip "${leader#http://}" '.items[] | select((.status.podIP + ":8080") == $ip or .status.podIP == ($ip | split(":")[0])) | .metadata.name' | head -1)
  [ -n "$leaderpod" ] || acc_fail "cannot name the leader's pod for $leader"
  start=$(date +%s)
  kctl delete pod "$leaderpod" --wait=false >/dev/null
  # The survivor answers throughout, and takes the lead.
  while [ $(( $(date +%s) - start )) -lt 30 ]; do
    probes=$((probes + 1))
    [ "$(http_code "$survivor/v1/sandboxes" "$ADMIN")" = 200 ] || failures=$((failures + 1))
    sleep 1
  done
  wait_for "$ACCEPT_WAIT" "the survivor leading" sh -c "[ \"\$(curl -sS -m 5 -H 'Authorization: Bearer $ADMIN' $survivor/v1/version | jq -r .leader)\" = true ]"
  moved=$(( $(date +%s) - start ))
  [ "$failures" -eq 0 ] || acc_fail "$failures of $probes requests to the surviving replica failed during the failover"
  wait_for "$ACCEPT_WAIT" "the replaced replica back" rollout_ready
  wait_for 60 "every replica ready" all_ready
  wait_for 60 "exactly one leader" one_leader
  [ "$(sandbox_status "$SB")" = running ] || acc_fail "the sandbox is $(sandbox_status "$SB") after the failover"
  # Work through the survivor while the lead moved: a changed bundle applies.
  local repo=$ACCEPT_OUT/config-repo
  bundle v2 > "$repo/bundles/$ACCEPT_TENANT.yaml"
  git -C "$repo" commit -qam "widen" && (cd "$repo" && SANDBOXD_URL=$survivor SANDBOXD_TOKEN=$ADMIN "$ctl" apply -f "bundles/$ACCEPT_TENANT.yaml" -ref main -repo https://git.example.com/acceptance/config -key "bundles/$ACCEPT_TENANT.yaml@$(git rev-parse HEAD)" -require-commit -markdown) | grep -q "Apply ✅ done" || acc_fail "apply through the survivor"
  evidence "leader pod $leaderpod deleted: the survivor answered $probes/$probes requests and led after ${moved}s; replicas back, one leader; the sandbox stayed running; an apply through the survivor went through"
}

phase_recovery() {
  load
  local pod uid newpod newuid instance restarts
  # The agent pod lost: the reconciler fails the run and marks the sandbox; wake brings a fresh pod.
  # The pod's name is the sandbox's, so the fresh pod carries the old name: its uid and the
  # identity instance the registrar issued tell it apart.
  pod=$(sandbox_pod "$SB")
  uid=$(sandbox_pod_uid "$SB")
  instance=$(get_json "$API/v1/sandboxes/$SB" | jq -r .instance)
  kctl delete pod "$pod" --wait=true >/dev/null
  wait_sandbox "$SB" error
  ctl_as "$TENANT_TOKEN" wake "$SB" >/dev/null
  wait_sandbox "$SB" running
  newpod=$(sandbox_pod "$SB")
  newuid=$(sandbox_pod_uid "$SB")
  [ -n "$newuid" ] && [ "$newuid" != "$uid" ] && [ "$(pod_phase "$newpod")" = Running ] || acc_fail "no fresh pod after wake (pod $newpod uid ${newuid:-none}, before $uid)"
  [ "$(get_json "$API/v1/sandboxes/$SB" | jq -r .instance)" -gt "$instance" ] || acc_fail "the fresh pod did not bootstrap a new identity (instance still $instance)"
  new_run_done "$SB" >/dev/null
  save POD_UID="$newuid"
  evidence "agent pod $pod deleted: sandbox went to error, wake started a fresh pod (uid $newuid, identity instance $instance → $(get_json "$API/v1/sandboxes/$SB" | jq -r .instance)), a run finished on it"
  # The database lost: replicas unready (no traffic), not restarted; back when it is.
  if [ -z "$ACCEPT_DB_OUTAGE" ] || [ -z "$ACCEPT_DB_RESTORE" ]; then
    evidence "database outage: skipped (ACCEPT_DB_OUTAGE/ACCEPT_DB_RESTORE not set for this database)"
    return 0
  fi
  restarts=$(kctl get pods -l "app.kubernetes.io/instance=$ACCEPT_RELEASE" -o jsonpath='{range .items[*]}{range .status.containerStatuses[*]}{.restartCount}{" "}{end}{end}')
  sh -c "$ACCEPT_DB_OUTAGE"
  wait_for 120 "every replica unready" sh -c "for u in $(replica_urls | tr '\n' ' '); do [ \"\$(curl -sS -m 5 -o /dev/null -w '%{http_code}' \$u/readyz)\" = 503 ] || exit 1; done"
  for u in $(replica_urls); do [ "$(http_code "$u/healthz")" = 200 ] || acc_fail "liveness failed during the database outage"; done
  sh -c "$ACCEPT_DB_RESTORE"
  wait_for 180 "every replica ready again" all_ready
  wait_for 60 "exactly one leader" one_leader
  [ "$(kctl get pods -l "app.kubernetes.io/instance=$ACCEPT_RELEASE" -o jsonpath='{range .items[*]}{range .status.containerStatuses[*]}{.restartCount}{" "}{end}{end}')" = "$restarts" ] || acc_fail "a replica was restarted during the database outage"
  [ "$(sandbox_status "$SB")" = running ] || acc_fail "the sandbox is $(sandbox_status "$SB") after the database came back"
  evidence "database outage: every replica reported unready (503) and alive (200), none restarted; ready again after the restore, one leader, the sandbox still running"
}

phase_upgrade() {
  load
  local before_ids before_rev after_ids after_rev before_uid
  [ "$(sandbox_status "$SB")" = running ] || acc_fail "the sandbox is $(sandbox_status "$SB") before the upgrade"
  before_uid=$(sandbox_pod_uid "$SB")
  before_ids=$(get_json "$API/v1/sandboxes" | jq -r 'if type=="array" then . else .items end | .[].id' | sort | tr '\n' ' ')
  before_rev=$(ctl_as "$ADMIN" get environment py -tenant "$ACCEPT_TENANT" | jq -r .revision)
  # The control plane moves to the next images and a changed value; the agent image stays
  # (an agent rollout is a deliberate command, not a side effect of a control-plane upgrade).
  "$helm" upgrade "$ACCEPT_RELEASE" deploy/helm/agent-sandbox -n "$ACCEPT_NAMESPACE" -f "$ACCEPT_VALUES" \
    --set gateway.replicas="$ACCEPT_REPLICAS" --set sandboxd.ca.source=db \
    --set image.tag="${ACCEPT_UPGRADE_TAG:-$ACCEPT_IMAGE_TAG}" --set agentImage.tag="$ACCEPT_IMAGE_TAG" \
    --set sandboxd.sandbox.idleCheckEvery=20s --wait --timeout 8m
  wait_for "$ACCEPT_WAIT" "$ACCEPT_REPLICAS ready replicas" rollout_ready
  wait_for 60 "every replica ready" all_ready
  wait_for 90 "exactly one leader" one_leader
  if [ -n "$ACCEPT_UPGRADE_TAG" ]; then
    [ "$(kctl get pods -l "app.kubernetes.io/instance=$ACCEPT_RELEASE" -o jsonpath='{range .items[*]}{range .spec.containers[?(@.name=="sandboxd")]}{.image}{"\n"}{end}{end}' | grep -c ":$ACCEPT_UPGRADE_TAG\$")" -eq "$ACCEPT_REPLICAS" ] || acc_fail "the replicas do not run $ACCEPT_UPGRADE_TAG"
  fi
  after_ids=$(get_json "$API/v1/sandboxes" | jq -r 'if type=="array" then . else .items end | .[].id' | sort | tr '\n' ' ')
  after_rev=$(ctl_as "$ADMIN" get environment py -tenant "$ACCEPT_TENANT" | jq -r .revision)
  [ "$before_ids" = "$after_ids" ] || acc_fail "sandboxes changed across the upgrade: $before_ids vs $after_ids"
  [ "$before_rev" = "$after_rev" ] || acc_fail "the catalog changed across the upgrade"
  [ "$(sandbox_pod_uid "$SB")" = "$before_uid" ] || acc_fail "the agent pod was replaced by the control-plane upgrade"
  [ "$(ctl_as "$TENANT_TOKEN" whoami | jq -r .tenant)" = "$ACCEPT_TENANT" ] || acc_fail "the tenant key stopped working"
  new_run_done "$SB" >/dev/null
  evidence "upgrade to ${ACCEPT_UPGRADE_TAG:-the same images with a changed value}: replicas back, one leader; sandboxes and catalog revisions unchanged; the agent pod untouched (same uid); the tenant key works; a run finished"
}

phase_backup() {
  load
  local dump=$ACCEPT_OUT/backup.sql repo=$ACCEPT_OUT/config-repo post_key
  db pg_dump -U "$ACCEPT_DB_USER" -d "$ACCEPT_DB_NAME" --clean --if-exists > "$dump"
  [ -s "$dump" ] || acc_fail "empty dump"
  # After the backup: a document and a key that the restore must not know.
  { bundle v2; printf -- '---\nkind: EnvironmentProfile\ntenant: %s\nname: post-dump\nspec: {image: stable}\n' "$ACCEPT_TENANT"; } > "$repo/bundles/$ACCEPT_TENANT.yaml"
  git -C "$repo" commit -qam "post-dump" && (cd "$repo" && ctl_as "$ADMIN" apply -f "bundles/$ACCEPT_TENANT.yaml" -ref main -repo https://git.example.com/acceptance/config -key "bundles/$ACCEPT_TENANT.yaml@$(git rev-parse HEAD)" -require-commit -markdown) | grep -q "Apply ✅ done" || acc_fail "post-dump apply"
  post_key=$(ctl_as "$ADMIN" keys create -tenant "$ACCEPT_TENANT" -name post-dump -json | jq -r .secret)
  # Restore: the control plane stopped, the database replaced by the dump, the control plane back.
  kctl scale "deploy/$ACCEPT_RELEASE-sandboxd" --replicas=0 >/dev/null
  wait_for 120 "replicas gone" sh -c "[ \"\$('$kubectl' -n '$ACCEPT_NAMESPACE' get pods -l app.kubernetes.io/instance=$ACCEPT_RELEASE --no-headers 2>/dev/null | wc -l)\" -eq 0 ]"
  db psql -U "$ACCEPT_DB_USER" -d "$ACCEPT_DB_NAME" -q -v ON_ERROR_STOP=1 < "$dump" >/dev/null
  kctl scale "deploy/$ACCEPT_RELEASE-sandboxd" --replicas="$ACCEPT_REPLICAS" >/dev/null
  wait_for "$ACCEPT_WAIT" "$ACCEPT_REPLICAS ready replicas" rollout_ready
  wait_for 60 "every replica ready" all_ready
  wait_for 90 "exactly one leader" one_leader
  # The state of the backup: what came after it is gone, what was before it is there.
  if ctl_as "$ADMIN" get environment post-dump -tenant "$ACCEPT_TENANT" >/dev/null 2>&1; then acc_fail "the post-dump document survived the restore"; fi
  ctl_as "$ADMIN" get environment py -tenant "$ACCEPT_TENANT" >/dev/null || acc_fail "the environment is gone after the restore"
  get_json "$API/v1/sandboxes" | jq -e --arg id "$SB" 'if type=="array" then . else .items end | .[] | select(.id==$id)' >/dev/null || acc_fail "the sandbox is gone after the restore"
  [ "$(ctl_as "$TENANT_TOKEN" whoami | jq -r .tenant)" = "$ACCEPT_TENANT" ] || acc_fail "the tenant key from before the backup does not work"
  if SANDBOXD_URL=$API SANDBOXD_TOKEN=$post_key "$ctl" whoami >/dev/null 2>&1; then acc_fail "the key issued after the backup still works"; fi
  # The identities: the agent pod from before the restore still has a valid certificate (the
  # CA came back with the database), so a run goes through without a new bootstrap.
  new_run_done "$SB" >/dev/null
  evidence "pg_dump taken, a document and a key added after it, database restored from the dump with the control plane stopped: post-dump document and key gone, pre-dump environment, sandbox and key present, a run finished on the existing agent pod (identity under the restored CA)"
}

phase_teardown() {
  load 2>/dev/null || true
  if [ -n "$ACCEPT_KEEP" ]; then evidence "kept (ACCEPT_KEEP): namespace $ACCEPT_NAMESPACE, release $ACCEPT_RELEASE"; return 0; fi
  "$helm" uninstall "$ACCEPT_RELEASE" -n "$ACCEPT_NAMESPACE" --wait --timeout 3m >/dev/null 2>&1 || true
  kctl delete pods -l agent-sandbox.io/sandbox --ignore-not-found --timeout=120s >/dev/null 2>&1 || true
  # The workspace volumes only (the database of the kind cluster lives in this namespace too).
  kctl delete pvc -l agent-sandbox.io/sandbox --ignore-not-found --timeout=120s >/dev/null 2>&1 || true
  evidence "release uninstalled, agent pods and workspace volumes removed"
}

# --- the run ----------------------------------------------------------------------------------------
# needs PHASE prints the phases that must have passed for PHASE to be judged.
needs() {
  case "$1" in
    install) echo preflight ;;
    config) echo "preflight install" ;;
    agent) echo "preflight install config" ;;
    replicas | recovery) echo "preflight install config agent" ;;
    upgrade | backup) echo "preflight install config agent recovery" ;;
    *) echo "" ;;
  esac
}
failed=0
failed_phases=""
for ph in $selected; do
  case " $phases " in *" $ph "*) ;; *) echo "unknown phase $ph (hack/acceptance/run.sh --list)" >&2; exit 2 ;; esac
  blocked=""
  for dep in $(needs "$ph"); do
    case " $failed_phases " in *" $dep "*) blocked=$dep ;; esac
  done
  if [ -n "$blocked" ]; then
    result "$ph" skip "the $blocked phase failed"
    acc_log "== $ph skipped: the $blocked phase failed"
    continue
  fi
  acc_log "== $ph"
  lines_before=$(wc -l < "$evidence_file")
  # Not inside an if-condition: there bash ignores set -e, and a phase would run on past its
  # first failure, reporting evidence it never gathered.
  set +e
  ( set -e; "phase_$ph" )
  rc=$?
  set -e
  if [ "$rc" -eq 0 ]; then
    result "$ph" pass "$(tail -n +$((lines_before + 1)) "$evidence_file" | head -1 | cut -c3-120)"
  else
    failed=1
    failed_phases="$failed_phases $ph"
    result "$ph" fail "see the log and diag-$ph.txt ($ACCEPT_OUT)"
    acc_log "== $ph FAILED"
    ( load 2>/dev/null; diagnose "$ph" ) || true
  fi
done
report_write
echo
cat "$report_file"
exit $failed
