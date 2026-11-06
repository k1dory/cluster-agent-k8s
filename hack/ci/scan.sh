#!/usr/bin/env bash
# ci-scan: known vulnerabilities in what the module depends on. Trivy reads go.mod and go.sum
# (the Go modules every binary is built from) and the lock files of anything else under the
# tree; a HIGH or CRITICAL finding with a fix available fails the check, so the fix is a
# version bump in go.mod. An unfixed finding is reported and does not fail: there is nothing
# to bump yet. A finding accepted on purpose is listed in .trivyignore.yaml with an expiry and
# a statement, and the check fails again when the expiry passes. The built images are scanned
# with the same policy by ci-images (their OS packages and the harnesses' npm packages).
#   TRIVY_BIN names a Trivy of yours; else TRIVY_VERSION (hack/ci/versions.env) is downloaded.
. "$(dirname "$0")/lib.sh"
cd "$ci_root"
[ -f go.mod ] || ci_die "scan: no go.mod in $ci_root"
echo "== dependencies: trivy $TRIVY_VERSION, HIGH and CRITICAL with a fix"
# .ci holds downloaded tools and the Trivy database itself; a module cache kept inside the
# tree (GitLab's GOMODCACHE) is the dependencies' own code, scanned through go.sum already.
ci_trivy_scan fs "" --skip-dirs .ci,.go-mod-cache,node_modules . || ci_die "scan: fixable HIGH or CRITICAL vulnerabilities in the dependencies (bump the module in go.mod, or accept the finding in .trivyignore.yaml with an expiry)"
ci_ok scan
