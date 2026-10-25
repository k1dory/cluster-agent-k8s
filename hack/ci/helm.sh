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
git diff --exit-code deploy/k8s || ci_die "helm: the rendered manifests under deploy/k8s are out of date: run make manifests and commit the result"
ci_ok helm
