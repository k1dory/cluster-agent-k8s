# syntax=docker/dockerfile:1
# Agent image with Hermes Agent (Nous Research, MIT): the official image, pinned by digest
# (HERMES_IMAGE in hack/ci/versions.env), with what makes a sandbox pod of it — agent-init,
# agent-runner, the network lock, the identity environment, user 1000. Hermes is distributed as
# that image (or its shell installer, or Nix); it refuses to build as a wheel, and its image
# carries the pinned runtime it needs (Python 3.14, a fixed SQLite, its package manager's
# tools), so it is the base here rather than something re-installed into images/agent.
# The pod runs `hermes acp` (harness input acp); Hermes's own entrypoint (s6) is not used.
# The base, by digest: global so the second stage's FROM can name it.
ARG HERMES_IMAGE
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/agent-init ./cmd/agent-init \
 && CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/agent-runner ./cmd/agent-runner

FROM ${HERMES_IMAGE}
ARG HERMES_IMAGE
ARG HERMES_VERSION
LABEL io.agent-sandbox.harness.hermes.version="${HERMES_VERSION}" \
      io.agent-sandbox.harness.hermes.image="${HERMES_IMAGE}"
USER root
# nftables: the netlock init container runs from this image too. Hermes's image keeps its own
# user (hermes, 10000); the pod runs as 1000, the `agent` of every agent-sandbox image.
RUN { test -n "${HERMES_VERSION}" || { echo "build arg HERMES_VERSION is required (hack/ci/versions.sh hermes-build-args)" >&2; exit 1; }; } \
 && apt-get -o Acquire::Retries=3 update && apt-get -o Acquire::Retries=3 install -y --no-install-recommends nftables jq ripgrep \
 && rm -rf /var/lib/apt/lists/* \
 && useradd -m -u 1000 -s /bin/bash agent
COPY --from=build /out/agent-init /out/agent-runner /usr/local/bin/
COPY images/agent/netlock.sh /usr/local/bin/netlock.sh
COPY images/agent/profile.sh /etc/profile.d/sandbox.sh
ENV GATEWAY_CA_FILE=/etc/sandbox/gateway-ca/gateway-ca.crt
# Hermes's state (config, .env, skills, memory, sessions) lives in the agent's home on the
# workspace volume: it survives pod restarts like the rest of the sandbox. The image's /opt/data
# volume is not used.
ENV ENV=/etc/profile.d/sandbox.sh \
    BASH_ENV=/etc/profile.d/sandbox.sh \
    GIT_CONFIG_GLOBAL=/certs/gitconfig \
    CURL_HOME=/certs \
    HOME=/workspace/home \
    CERT_DIR=/certs \
    HERMES_HOME=/workspace/home/.hermes \
    HERMES_WRITE_SAFE_ROOT=/workspace
USER 1000:1000
WORKDIR /workspace
ENTRYPOINT ["/usr/local/bin/agent-runner"]
CMD []
