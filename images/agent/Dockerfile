# syntax=docker/dockerfile:1
# Agent image: harness tools + agent-init / agent-runner. Non-root, read-only rootfs at runtime;
# writable paths are /workspace (PVC), /certs (tmpfs) and /tmp.
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/agent-init ./cmd/agent-init \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/agent-runner ./cmd/agent-runner

FROM node:22-bookworm-slim
ARG CLAUDE_CODE_VERSION=latest
# nftables: the netlock init container (pod-level egress firewall) runs from this same image.
RUN apt-get update && apt-get install -y --no-install-recommends \
      git curl ca-certificates python3 python3-venv python3-pip build-essential jq ripgrep openssh-client nftables \
 && rm -rf /var/lib/apt/lists/* \
 && npm install -g @anthropic-ai/claude-code@${CLAUDE_CODE_VERSION} \
 # the base image ships user `node` with UID 1000; the pod runs as 1000, so that identity becomes `agent`
 && userdel -r node \
 && useradd -m -u 1000 -s /bin/bash agent
COPY --from=build /out/agent-init /out/agent-runner /usr/local/bin/
COPY images/agent/netlock.sh /usr/local/bin/netlock.sh
COPY images/agent/profile.sh /etc/profile.d/sandbox.sh
# A gateway root can be baked in for layouts without the ConfigMap mount (compose/VM): put it at this path.
ENV GATEWAY_CA_FILE=/etc/sandbox/gateway-ca/gateway-ca.crt
# Every login shell (agent-runner uses `sh -lc`) sources the identity environment.
ENV ENV=/etc/profile.d/sandbox.sh \
    BASH_ENV=/etc/profile.d/sandbox.sh \
    GIT_CONFIG_GLOBAL=/certs/gitconfig \
    CURL_HOME=/certs \
    HOME=/workspace/home \
    CERT_DIR=/certs
USER 1000:1000
WORKDIR /workspace
ENTRYPOINT ["/usr/local/bin/agent-runner"]
