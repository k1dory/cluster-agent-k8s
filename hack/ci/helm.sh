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
git diff --exit-code deploy/k8s || ci_die "helm: the rendered manifests under deploy/k8s are out of date: run make manifests and commit the result"
ci_ok helm
