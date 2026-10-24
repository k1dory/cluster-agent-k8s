# syntax=docker/dockerfile:1
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/sandboxd ./cmd/sandboxd \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/sandboxctl ./cmd/sandboxctl

# sandboxctl for CI jobs (the Git adapters in deploy/git): a shell, curl and jq next to the binary,
# so a pipeline can post the plan as a comment. Build with `--target sandboxctl`; the default
# target below stays the control plane.
FROM alpine:3.20 AS sandboxctl
RUN apk add --no-cache ca-certificates curl jq git \
 && adduser -D -u 1000 sandboxctl
COPY --from=build /out/sandboxctl /sandboxctl
USER sandboxctl
ENTRYPOINT ["/sandboxctl"]

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/sandboxd /sandboxd
COPY --from=build /out/sandboxctl /sandboxctl
COPY policies /etc/sandbox/policies
USER nonroot
ENTRYPOINT ["/sandboxd"]
CMD ["-config", "/etc/sandbox/sandboxd.yaml"]
