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
RUN apt-get update && apt-get install -y --no-install-recommends \
      git curl ca-certificates python3 python3-venv python3-pip build-essential jq ripgrep openssh-client \
 && rm -rf /var/lib/apt/lists/* \
 && npm install -g @anthropic-ai/claude-code@${CLAUDE_CODE_VERSION} \
 && useradd -m -u 1000 -s /bin/bash agent
COPY --from=build /out/agent-init /out/agent-runner /usr/local/bin/
COPY images/agent/profile.sh /etc/profile.d/sandbox.sh
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
