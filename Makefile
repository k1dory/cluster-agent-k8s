BIN ?= bin
REGISTRY ?= registry.example.com/agent-sandbox
TAG ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo dev)
HELM ?= helm

# --- The shared CI contract (docs/ci-contract.md) ------------------------------------------------
# Every check is one of these targets, implemented here or in hack/ci; GitHub, GitLab, Forgejo
# and a developer's shell run the same targets and get the same pass or fail. Inputs are
# explicit, never a provider's variables: SANDBOX_TEST_POSTGRES_URL (ci-postgres), CADDY_VERSION
# or CADDY_BIN (ci-caddy, ci-policy), HELM (ci-helm), IMAGE_PREFIX and IMAGE_TAG (ci-images,
# ci-e2e-git). Versions and matrices live in hack/ci/versions.env (make ci-versions shows them).
# A group ends with the line `ci: <group>: ok`; a missing tool or service fails it.
CI_GROUPS := build vet unit policy postgres caddy helm images e2e-git

.PHONY: build test vet dev images smoke-image helm-lint policy-test policy-render manifests clean integration \
	ci ci-fast ci-versions ci-acceptance acceptance publish-images verify-images $(addprefix ci-,$(CI_GROUPS))

# The full required set, in order; what a change must pass before it merges.
ci: $(addprefix ci-,$(CI_GROUPS))
	@echo "ci: the full required set ($(CI_GROUPS)): ok"

# The subset a developer runs before pushing (no database, Caddy, Helm or Docker needed, except
# one Caddy download for the policy gate). Passing it is not passing the full set.
ci-fast: ci-build ci-vet ci-unit ci-policy
	@echo "ci: subset fast (build vet unit policy): ok; the full required set is make ci"

# The build, and the one place a provider file may still carry a version (a GitLab service
# image, a Go image tag) is checked against hack/ci/versions.env and go.mod.
ci-build:
	go build ./... && hack/ci/versions.sh verify && echo "ci: build: ok"

ci-vet:
	hack/ci/vet.sh

# Every regression test, under the race detector, on the in-memory store.
ci-unit:
	go test ./... -count=1 -race && echo "ci: unit: ok"

ci-policy:
	hack/ci/policy.sh

ci-postgres:
	hack/ci/postgres.sh

ci-caddy:
	hack/ci/caddy.sh

ci-helm:
	hack/ci/helm.sh

ci-images:
	hack/ci/images.sh

ci-e2e-git:
	hack/ci/e2e-git.sh

ci-versions:
	@hack/ci/versions.sh

# The production acceptance (docs/acceptance.md) on a kind cluster shaped like production,
# built on this host's Docker: not in the required set (twenty minutes, privileged Docker), run
# by the GitHub workflow and by hand before a release.
ci-acceptance:
	hack/ci/acceptance.sh

# The same acceptance against a cluster of yours: KUBECONFIG selects it, ACCEPT_* name the
# values file, the database and the images (docs/acceptance.md).
acceptance:
	hack/acceptance/run.sh $(PHASES)

build:
	mkdir -p $(BIN)
	go build -o $(BIN)/sandboxd ./cmd/sandboxd
	go build -o $(BIN)/agent-init ./cmd/agent-init
	go build -o $(BIN)/agent-runner ./cmd/agent-runner
	go build -o $(BIN)/sandboxctl ./cmd/sandboxctl

test:
	go test ./...

# The gateway path on a real Caddy (needs caddy on PATH or CADDY_BIN=/path/to/caddy); CI runs it
# for Caddy 2.8, 2.9 and 2.10.
integration:
	go test ./internal/integration/ -count=1 -v

vet:
	go vet ./... && gofmt -l . | (! grep .)

# Local run without Kubernetes or Postgres: API on :8080 (token dev-token), docs at /docs.
dev: build
	mkdir -p var/ca var/secrets/shared
	$(BIN)/sandboxd -config config/sandboxd.dev.yaml

images:
	docker build -f images/sandboxd/Dockerfile -t $(REGISTRY)/sandboxd:$(TAG) .
	docker build -f images/sandboxd/Dockerfile --target sandboxctl -t $(REGISTRY)/sandboxctl:$(TAG) .
	docker build -f images/agent/Dockerfile $$(hack/ci/versions.sh build-args) -t $(REGISTRY)/agent:$(TAG) .

# Publishing is a separate, explicitly configured action (docs/ci-contract.md, rule 5), not a
# check: linux/amd64 images of sandboxd, sandboxctl and the agent pushed to IMAGE_REPO under the
# immutable tag sha-<12 characters of COMMIT>, each digest signed with cosign, and a manifest
# (image, digest, arch, commit, harness versions) written for the record. Inputs and their
# failures: hack/publish-images.sh. verify-images checks a manifest's signatures against
# cosign.pub, anonymously when the packages are public.
publish-images:
	hack/publish-images.sh

verify-images:
	hack/verify-images.sh

# Checks inside the built agent image: user 1000 is `agent`, tools present, netlock installs its
# rules, agent-init and agent-runner start and complain about the right things.
smoke-image: images
	hack/smoke-image.sh $(REGISTRY)/agent:$(TAG)
	python3 hack/test-netlock.py $(REGISTRY)/agent:$(TAG)

# The Git adapters end to end: the control plane and sandboxctl from their images, a repository
# of bundles, the workflow's own steps (see hack/e2e-git-adapter.sh).
e2e-git-adapter: images
	hack/e2e-git-adapter.sh $(REGISTRY)/sandboxd:$(TAG) $(REGISTRY)/sandboxctl:$(TAG)

helm-lint:
	cp policies/*.yaml deploy/helm/agent-sandbox/policies/ && rm -f deploy/helm/agent-sandbox/policies/tests.yaml
	$(HELM) lint deploy/helm/agent-sandbox
	$(HELM) lint deploy/helm/agent-sandbox --set gateway.mode=external

# Plain manifests for kubectl apply, rendered from the chart (single source of truth).
manifests:
	cp policies/*.yaml deploy/helm/agent-sandbox/policies/ && rm -f deploy/helm/agent-sandbox/policies/tests.yaml
	$(HELM) template agent-sandbox deploy/helm/agent-sandbox -n agent-sandbox --set createNamespace=true \
	  | sed '/^# Source:/d' | awk -f hack/normalize-yaml.awk > deploy/k8s/gateway-on-node.yaml
	$(HELM) template agent-sandbox deploy/helm/agent-sandbox -n agent-sandbox --set createNamespace=true --set gateway.mode=external \
	  | sed '/^# Source:/d' | awk -f hack/normalize-yaml.awk > deploy/k8s/cluster-only.yaml

# Policy-as-Code gate (the validate and test half of ci-policy).
policy-test: build
	$(BIN)/sandboxd policy validate policies
	$(BIN)/sandboxd policy test policies -f policies/tests.yaml

# Show the Caddyfile sandboxd would push for the dev config.
policy-render: build
	mkdir -p var/ca
	$(BIN)/sandboxd policy render -config config/sandboxd.dev.yaml

clean:
	rm -rf $(BIN) var
