#!/usr/bin/env bash
# ci-helm: the chart lints in both layouts and the rendered manifests under deploy/k8s are what
# the chart renders now (the chart is the single source of truth; `make manifests` regenerates
# them). Helm is HELM when set, else HELM_VERSION downloaded once.
. "$(dirname "$0")/lib.sh"
cd "$ci_root"
helm=$(ci_helm)
echo "== $("$helm" version --short)"
make --no-print-directory helm-lint HELM="$helm"
make --no-print-directory manifests HELM="$helm"
# A deployment's own policies come through values: added next to the chart's files, replacing a
# file of the same name, as text or as a map (the policies ConfigMap is what sandboxd reads).
policy_cm() { "$helm" template t deploy/helm/agent-sandbox "$@" | awk '/^kind: ConfigMap/{c=1} c&&/name: .*-policies$/{p=1} p' ; }
rendered=$(policy_cm --set-string 'policies.extra=slug: extra' --set-string 'policies.default=slug: default # replaced' \
  --set 'policies.mapped.slug=mapped')
for want in 'extra.yaml: |' 'slug: extra' 'slug: default # replaced' 'mapped.yaml: |' 'slug: mapped' 'backend-dev.yaml: |'; do
  grep -qF "$want" <<<"$rendered" || ci_die "helm: values policies: '$want' missing from the policies ConfigMap"
done
[ "$(grep -c 'default.yaml: |' <<<"$rendered")" -eq 1 ] || ci_die "helm: a values policy must replace the chart file of the same name, not duplicate it"
! grep -qF 'backend-dev.yaml' <<<"$(policy_cm --set policiesFromFiles=false --set-string 'policies.only=slug: only')" \
  || ci_die "helm: policiesFromFiles=false still ships the chart's files"
# Observability: the metrics listener, its Service port, pod annotations and container port follow
# metrics.enabled; the ServiceMonitor is rendered only when asked for and its CRD exists; the
# tracing block only when tracing is on.
render() { "$helm" template t deploy/helm/agent-sandbox "$@"; }
has() { grep -qF -- "$1" <<<"$2" || ci_die "helm: $3: '$1' missing"; }
hasnt() { ! grep -qF -- "$1" <<<"$2" || ci_die "helm: $3: '$1' rendered"; }
on=$(render)
for want in 'listen: ":9090"' '{ name: metrics, port: 9090, targetPort: metrics }' 'prometheus.io/scrape: "true"' \
  '{ name: metrics, containerPort: 9090 }' 'name: POD_NAME'; do has "$want" "$on" "metrics on (default)"; done
for unwanted in 'kind: ServiceMonitor' '    tracing:'; do hasnt "$unwanted" "$on" "defaults"; done
off=$(render --set metrics.enabled=false)
has 'listen: ""' "$off" "metrics off"
for unwanted in 'name: metrics' 'prometheus.io/scrape' 'containerPort: 9090'; do hasnt "$unwanted" "$off" "metrics off"; done
hasnt 'kind: ServiceMonitor' "$(render --set metrics.serviceMonitor.enabled=true)" "ServiceMonitor without its CRD"
sm=$(render --set metrics.serviceMonitor.enabled=true --set metrics.serviceMonitor.labels.release=kps --api-versions monitoring.coreos.com/v1)
for want in 'kind: ServiceMonitor' 'release: kps' '- port: metrics' 'interval: 30s'; do has "$want" "$sm" "ServiceMonitor on"; done
hasnt 'kind: ServiceMonitor' "$(render --set metrics.enabled=false --set metrics.serviceMonitor.enabled=true --api-versions monitoring.coreos.com/v1)" "ServiceMonitor with metrics off"
tr=$(render --set tracing.enabled=true --set tracing.endpoint=http://tempo:4318 --set tracing.protocol=grpc --set tracing.samplerRatio=0.2)
for want in '    tracing:' 'enabled: true' 'endpoint: "http://tempo:4318"' 'protocol: "grpc"' 'sampler_ratio: 0.2'; do has "$want" "$tr" "tracing on"; done
! render --set metrics.port=8080 >/dev/null 2>&1 || ci_die "helm: metrics.port on the API port must fail"
git diff --exit-code deploy/k8s || ci_die "helm: the rendered manifests under deploy/k8s are out of date: run make manifests and commit the result"
ci_ok helm
