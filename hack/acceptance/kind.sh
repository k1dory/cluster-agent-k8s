#!/usr/bin/env bash
# A cluster shaped like production on this host's Docker, and the acceptance run against it:
# one control plane, two gateway nodes (labelled, tainted, each with the sandbox VLAN address
# on a second interface) and one node for the agents; Multus with whereabouts for the pods'
# VLAN interface; PostgreSQL inside the cluster on a persistent volume; the three images built
# here and loaded into the nodes. The VLAN is a Docker network: every node joins it as eth1,
# the first gateway node holds 10.77.77.1 (what pods route and resolve through), the second
# stands by. A VIP moving between nodes is not part of this cluster (docs/acceptance.md).
#
#   hack/acceptance/kind.sh up      create the cluster, install the prerequisites, load the images
#   hack/acceptance/kind.sh run     run hack/acceptance/run.sh against it (phases as arguments)
#   hack/acceptance/kind.sh down    delete the cluster and the network
#
# ACCEPT_SKIP_BUILD=1 reuses images built before (IMAGE_PREFIX/ACCEPT_IMAGE_TAG); KIND_CLUSTER
# and KIND_VLAN name the cluster and the network.
. "$(dirname "$0")/lib.sh"
name=${KIND_CLUSTER:-acc}
net=${KIND_VLAN:-sandbox-vlan}
prefix=${IMAGE_PREFIX:-agent-sandbox}
tag=$ACCEPT_IMAGE_TAG
kind=$(acc_kind)
kubectl=$(acc_kubectl)
export KUBECONFIG=$ACCEPT_OUT/kubeconfig
k() { "$kubectl" "$@"; }
manifest() { # NAME URL → the cached file
  local f="$CI_BIN/$1"
  [ -f "$f" ] || ci_fetch "$2" "$f"
  echo "$f"
}
raw=https://raw.githubusercontent.com/k8snetworkplumbingwg

up() {
  ci_docker
  docker network inspect "$net" >/dev/null 2>&1 || docker network create --subnet 10.77.77.0/24 --gateway 10.77.77.254 "$net" >/dev/null
  if ! "$kind" get clusters 2>/dev/null | grep -qx "$name"; then
    "$kind" create cluster --name "$name" --image "$KIND_NODE_IMAGE" --config "$acc_dir/kind-cluster.yaml" --wait 180s
  fi
  "$kind" get kubeconfig --name "$name" > "$KUBECONFIG"
  # The VLAN: every worker a second interface; the first two are the gateway nodes. Every node
  # gets the macvlan plugin (kind's nodes carry only kindnet's plugins).
  local i=0 node workers gateways cni
  cni=$(manifest "cni-plugins-$CNI_PLUGINS_VERSION.tgz" "https://github.com/containernetworking/plugins/releases/download/$CNI_PLUGINS_VERSION/cni-plugins-linux-$(ci_arch)-$CNI_PLUGINS_VERSION.tgz")
  for node in $("$kind" get nodes --name "$name"); do
    # Streamed in: a node's /tmp is a tmpfs mounted over what docker cp would write to.
    docker exec -i "$node" tar -C /opt/cni/bin -xzf - ./macvlan < "$cni"
  done
  workers=$("$kind" get nodes --name "$name" | grep -v control-plane | sort)
  for node in $workers; do
    i=$((i + 1))
    docker network inspect "$net" -f '{{range .Containers}}{{.Name}} {{end}}' | grep -qw "$node" || docker network connect --ip "10.77.77.$i" "$net" "$node"
  done
  gateways=$(echo "$workers" | head -2 | tr '\n' ' ')
  # shellcheck disable=SC2086
  k label nodes $gateways agent-sandbox.io/gateway=true --overwrite >/dev/null
  # shellcheck disable=SC2086
  k taint nodes $gateways agent-sandbox.io/gateway=true:NoSchedule --overwrite >/dev/null
  echo "nodes: gateways $gateways(10.77.77.1, 10.77.77.2), agents $(echo "$workers" | tail -n +3 | tr '\n' ' ')"
  # Multus (the pods' second interface) and whereabouts (its addresses, cluster-wide).
  k apply -f "$(manifest "multus-$MULTUS_VERSION.yml" "$raw/multus-cni/$MULTUS_VERSION/deployments/multus-daemonset-thick.yml")" >/dev/null
  local crd
  for crd in whereabouts.cni.cncf.io_ippools whereabouts.cni.cncf.io_overlappingrangeipreservations; do
    k apply -f "$(manifest "$crd-$WHEREABOUTS_VERSION.yaml" "$raw/whereabouts/$WHEREABOUTS_VERSION/doc/crds/$crd.yaml")" >/dev/null
  done
  k apply -f "$(manifest "whereabouts-$WHEREABOUTS_VERSION.yaml" "$raw/whereabouts/$WHEREABOUTS_VERSION/doc/crds/daemonset-install.yaml")" >/dev/null
  k -n kube-system rollout status ds/kube-multus-ds --timeout=300s
  k -n kube-system rollout status ds/whereabouts --timeout=300s
  # PostgreSQL in the cluster.
  k get ns "$ACCEPT_NAMESPACE" >/dev/null 2>&1 || k create ns "$ACCEPT_NAMESPACE" >/dev/null
  sed "s|__POSTGRES_IMAGE__|$POSTGRES_IMAGE|" "$acc_dir/postgres.yaml" | k -n "$ACCEPT_NAMESPACE" apply -f - >/dev/null
  k -n "$ACCEPT_NAMESPACE" rollout status deploy/postgres --timeout=300s
  # The images, built here, and a second tag of the same build for the upgrade phase.
  if [ -z "${ACCEPT_SKIP_BUILD:-}" ]; then
    make -C "$acc_root" --no-print-directory images REGISTRY="$prefix" TAG="$tag"
  fi
  docker tag "$prefix/sandboxd:$tag" "$prefix/sandboxd:$tag-next"
  docker tag "$prefix/agent:$tag" "$prefix/agent:$tag-next"
  "$kind" load docker-image --name "$name" "$prefix/sandboxd:$tag" "$prefix/sandboxctl:$tag" "$prefix/agent:$tag" "$prefix/sandboxd:$tag-next" "$prefix/agent:$tag-next"
  values > "$ACCEPT_OUT/values-kind.yaml"
  echo "cluster $name ready; KUBECONFIG=$KUBECONFIG; values $ACCEPT_OUT/values-kind.yaml"
}

# values prints the chart values for this cluster: the gateway on the labelled nodes at
# 10.77.77.1, the images loaded into the nodes, a harness that prints its task (no LLM in CI),
# a short reconciler interval, small agent pods.
values() {
  cat <<V
gateway:
  mode: node
  ip: 10.77.77.1
  apiPort: 8080
  nodeSelector: { agent-sandbox.io/gateway: "true" }
tolerations:
  - { key: agent-sandbox.io/gateway, operator: Exists, effect: NoSchedule }
image: { repository: $prefix/sandboxd, pullPolicy: IfNotPresent }
agentImage: { repository: $prefix/agent, pullPolicy: IfNotPresent }
sandboxd:
  sandbox: { defaultIdleTimeout: 1h, readyTimeout: 3m, idleCheckEvery: 15s }
  preview: { domain: preview.acceptance.test, authUrl: "", cookieTtl: 1h, hitsAsActivity: true }
  ca: { source: db }
agent:
  volumeSize: 1Gi
  resources: { cpuRequest: 100m, cpuLimit: "1", memoryRequest: 256Mi, memoryLimit: 1Gi }
  harnessCommand: 'echo "acceptance: \$SANDBOX_TASK"'
  harnessResumeCommand: 'echo "acceptance: \$SANDBOX_RESUME_PROMPT"'
  versions: { stable: $prefix/agent:$tag }
network:
  name: sandbox-vlan
  master: eth1
  mode: private
  ipam:
    type: whereabouts
    range: 10.77.77.0/24
    range_start: 10.77.77.32
    range_end: 10.77.77.200
    gateway: 10.77.77.1
    exclude: ["10.77.77.1/32", "10.77.77.2/32", "10.77.77.3/32", "10.77.77.254/32"]
V
}

run() {
  export ACCEPT_VALUES=$ACCEPT_OUT/values-kind.yaml
  export ACCEPT_DATABASE_URL="postgres://sandbox:sandbox@postgres.$ACCEPT_NAMESPACE.svc.cluster.local:5432/sandbox?sslmode=disable"
  export ACCEPT_DB_EXEC="$kubectl -n $ACCEPT_NAMESPACE exec -i deploy/postgres --"
  export ACCEPT_DB_OUTAGE="$kubectl -n $ACCEPT_NAMESPACE scale deploy/postgres --replicas=0 && $kubectl -n $ACCEPT_NAMESPACE wait --for=delete pod -l app=postgres --timeout=120s"
  export ACCEPT_DB_RESTORE="$kubectl -n $ACCEPT_NAMESPACE scale deploy/postgres --replicas=1 && $kubectl -n $ACCEPT_NAMESPACE rollout status deploy/postgres --timeout=180s"
  export ACCEPT_UPGRADE_TAG="$tag-next"
  export ACCEPT_HARNESS_MARKER="acceptance: "
  export ACCEPT_CREDENTIALS_KEY=${ACCEPT_CREDENTIALS_KEY:-$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')}
  export IMAGE_PREFIX=$prefix
  "$acc_dir/run.sh" "$@"
}

down() {
  "$kind" delete cluster --name "$name" 2>/dev/null || true
  docker network rm "$net" >/dev/null 2>&1 || true
}

case "${1:-}" in
  up) up ;;
  run) shift; run "$@" ;;
  down) down ;;
  *) echo "usage: hack/acceptance/kind.sh up|run [phase...]|down" >&2; exit 2 ;;
esac
