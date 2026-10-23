# syntax=docker/dockerfile:1
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/sandboxd ./cmd/sandboxd

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/sandboxd /sandboxd
COPY policies /etc/sandbox/policies
USER nonroot
ENTRYPOINT ["/sandboxd"]
CMD ["-config", "/etc/sandbox/sandboxd.yaml"]
