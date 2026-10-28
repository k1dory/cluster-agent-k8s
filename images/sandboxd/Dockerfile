# syntax=docker/dockerfile:1
# The Go stage runs on the builder's own platform and cross-compiles for the target's: a
# linux/amd64 image built on an arm64 host does not compile under emulation.
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/sandboxd ./cmd/sandboxd \
 && CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/sandboxctl ./cmd/sandboxctl

# sandboxctl for CI jobs (the Git adapters in deploy/git): a shell, curl and jq next to the binary,
# so a pipeline can post the plan as a comment. Build with `--target sandboxctl`; the default
# target below stays the control plane.
#
# The checkout a CI job mounts or clones is owned by the runner's user, not by sandboxctl (uid
# 1000): Git would refuse it ("detected dubious ownership") and no commit SHA could be recorded.
# This image exists to read CI checkouts, so every directory is a safe one here; `sandboxctl apply
# -require-commit` still fails the job when a SHA cannot be verified for any other reason.
FROM alpine:3.20 AS sandboxctl
RUN apk add --no-cache ca-certificates curl jq git \
 && adduser -D -u 1000 sandboxctl \
 && git config --system safe.directory '*'
COPY --from=build /out/sandboxctl /sandboxctl
USER sandboxctl
ENTRYPOINT ["/sandboxctl"]

# The control plane. It reads registered Git repositories with the git binary (kind
# GitRepository, internal/gitsync), so the image carries git and CA roots and nothing else; the
# process runs as nonroot (uid 65532, as the distroless image it replaced).
FROM alpine:3.20
RUN apk add --no-cache ca-certificates git \
 && adduser -D -H -u 65532 -g nonroot nonroot
COPY --from=build /out/sandboxd /sandboxd
COPY --from=build /out/sandboxctl /sandboxctl
COPY policies /etc/sandbox/policies
USER nonroot
ENTRYPOINT ["/sandboxd"]
CMD ["-config", "/etc/sandbox/sandboxd.yaml"]
