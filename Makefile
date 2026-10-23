BIN ?= bin
REGISTRY ?= registry.example.com/agent-sandbox
TAG ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo dev)

.PHONY: build test vet dev images helm-lint caddy-validate clean

build:
	mkdir -p $(BIN)
	go build -o $(BIN)/sandboxd ./cmd/sandboxd
	go build -o $(BIN)/agent-init ./cmd/agent-init
	go build -o $(BIN)/agent-runner ./cmd/agent-runner

test:
	go test ./...

vet:
	go vet ./... && gofmt -l . | (! grep .)

# Local run without Kubernetes or Postgres: API on :8080 (token dev-token), docs at /docs.
dev: build
	mkdir -p var/ca var/secrets/shared
	$(BIN)/sandboxd -config config/sandboxd.dev.yaml

images:
	docker build -f images/sandboxd/Dockerfile -t $(REGISTRY)/sandboxd:$(TAG) .
	docker build -f images/agent/Dockerfile -t $(REGISTRY)/agent:$(TAG) .

helm-lint:
	cp policies/*.yaml deploy/helm/agent-sandbox/policies/
	helm lint deploy/helm/agent-sandbox

caddy-validate:
	caddy validate --config deploy/gateway/Caddyfile --adapter caddyfile

clean:
	rm -rf $(BIN) var
