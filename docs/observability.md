# Observability: metrics, traces, logs

sandboxd reports on itself three ways: Prometheus metrics on a listener of its own,
OpenTelemetry traces over OTLP (off by default), and JSON logs that name the trace a line
belongs to.

## Metrics

`metrics.listen` (default `:9090`, `""` turns it off) serves `GET /metrics`. It is never the API,
gateway or ingress listener, and sandboxd refuses a configuration that puts it on one of their
ports. **The endpoint has no authentication.** Keep the port reachable from your Prometheus only:
a NetworkPolicy, a node firewall or a cluster-internal address. In the chart's `node` layout the
pod uses the node's network, so the port is open on the node's addresses. The agent pods' egress
firewall keeps them off it, but other hosts on that network are not.

| Family | Labels | What it is |
|---|---|---|
| `sandboxd_http_requests_total`, `sandboxd_http_request_duration_seconds` | `server` (api, gateway), `route`, `method`, `code` (counter only) | Requests per listener and route pattern. A stream or long poll counts for its whole life. |
| `sandboxd_store_query_duration_seconds`, `sandboxd_store_query_errors_total` | `op` | Postgres queries by operation, such as `select sandboxes` or `update runs`. No row and a caller that gave up are not errors. |
| `sandboxd_sandboxes`, `sandboxd_runs`, `sandboxd_run_queue_depth` | `status` | Sandboxes by status, and the runs not finished yet (queued, running). Read from the store when scraped, at most every 15s per replica. Every replica reports the same shared numbers. |
| `sandboxd_reconcile_duration_seconds`, `sandboxd_reconcile_errors_total` | | One reconciler pass on the replica holding the lease, and the passes that could not list the sandboxes. |
| `sandboxd_kube_requests_total`, `sandboxd_kube_request_duration_seconds` | `verb`, `code` (counter only) | Kubernetes API calls. `code="error"` means no response arrived. A watch is counted but not timed. |
| `sandboxd_gateway_sync_status`, `sandboxd_gateway_sync_failures_total` | | 1 while the last Caddy configuration sync succeeded, 0 while it fails. Absent until the first attempt and on a replica that drives no Caddy. |
| `sandboxd_events_hub_dropped_total` | | Events a slow SSE subscriber missed. It recovers them from the store. |
| `sandboxd_idempotency_takeovers_total` | | Idempotency-Key reservations taken over from an abandoned attempt. |
| `sandboxd_auth_rate_limited_total` | | 429 answers from the per-address authentication limit. |
| `sandboxd_build_info` | `version`, `go_version` | Always 1. |

The Go runtime (`go_*`) and process (`process_*`) collectors are on the same endpoint.

### Label cardinality

A label value comes from a fixed set, never from a request:

- `route` is the pattern the request matched, such as `/v1/sandboxes/{id}`, never the path. A
  path no pattern matches is `unmatched`.
- `method` is a standard HTTP method or `OTHER`.
- `op` is a SQL verb plus a table from the schema. A query naming no schema table carries the verb
  alone, and an unusual verb is `other`.
- `verb` is `get`, `watch`, `create`, `update`, `patch` or `delete`.

No metric carries a tenant, sandbox, run, key or pod id. Those go on spans: spans are sampled and
expire, while a series lives as long as the process. A change that adds a label must keep it to a
bounded set. The telemetry tests fail on any label outside the allowed names.

Alerts worth starting with:

- `sandboxd_gateway_sync_status == 0` for 10 minutes: Caddy keeps an old configuration.
- `rate(sandboxd_reconcile_errors_total[10m]) > 0`.
- `sandboxd_run_queue_depth` growing while `sandboxd_runs{status="running"}` stays flat.
- `rate(sandboxd_store_query_errors_total[5m])` by `op`.

## Traces

```yaml
tracing:
  enabled: true
  endpoint: http://tempo.monitoring:4318   # OTLP/HTTP; grpc: http://otel-collector:4317
  protocol: http                           # http | grpc
  sampler_ratio: 1
  record_statements: false
```

For `http`, an endpoint without a path gets the standard `/v1/traces`, and one with a path is
used as written. With `endpoint` or `protocol` empty, the standard `OTEL_EXPORTER_OTLP_*` variables apply, as do
`OTEL_SERVICE_NAME` and `OTEL_RESOURCE_ATTRIBUTES`. The resource is `service.name=sandboxd`,
`service.version`, and `k8s.pod.name` and `k8s.namespace.name` when `POD_NAME` and
`POD_NAMESPACE` are set (the chart sets them). Tempo and Jaeger both take OTLP directly. Point
`endpoint` at their OTLP port, or at an OpenTelemetry Collector in front of them.

What is traced:

- **Both HTTP listeners.** A server span is named after the route, such as `POST /v1/sandboxes`
  or `POST /agent/runs/{run}/events`. It takes up the caller's W3C `traceparent` and carries
  `request_id`. The probes `/healthz` and `/readyz` are counted but not traced.
- **Orchestrator operations.** Create, Wake, Sleep, Delete, NextRun, Output, Finish and each
  reconciler pass are spans with `sandbox_id` and `run_id`.
- **Postgres.** Each query is a client span with `db.system` and `db.operation`. The SQL text is
  recorded only with `record_statements`, and the arguments never are.
- **Kubernetes API, Caddy admin and other outbound calls.** The Kubernetes API and Caddy calls are
  client spans that send `traceparent` on, so the API server joins the trace when its own tracing
  is on. Git providers, IdPs, OAuth, Vault, Infisical and MCP upstreams get a span with the method,
  host and status only. Their URL is left out, since a query or path can carry a key, and no trace
  context is sent to them.

A query or outbound call made outside any trace is counted in the metrics but gets no span. This
covers the background loops: leases, listeners, the OAuth and Git job pollers. A trace for each
of those every few seconds would bury the traces worth reading.

### One trace per run

The agent runner opens a trace when it takes a run. It sends that trace's `traceparent` with
every call about the run: output, input polls, finish. The gateway's spans for the run, and the
orchestrator and Postgres spans under them, form one trace. Search for it by `run_id`. The runner
exports nothing itself, because the pod reaches only the gateway.

### Sampling

`sampler_ratio` keeps that share of traces, decided on the trace id. The same trace gets the same
answer on every replica and for every call of a run. A `sampled` flag in an incoming
`traceparent` does not override it. An agent pod is not trusted, and a flag on every request
would keep every trace. Spans started inside sandboxd follow their parent.

## Logs

Logs are JSON on stdout. With tracing on, a line logged inside a span carries `trace_id` and
`span_id`, and every request line is logged inside its request's span. The request line also has `rid`, the `X-Request-Id` sandboxd echoes back or
assigns, and the request's span carries the same value as `request_id`. To go from a client's
error to everything it touched:

1. Find the line with the `rid` the client received.
2. Open its `trace_id` in Tempo or Jaeger.

Grafana can link the two when the log data source maps `trace_id` to the tracing data source.

## Helm

```yaml
metrics:
  enabled: true          # metrics.listen, the container port, the Service port "metrics"
  port: 9090
  podAnnotations: true   # prometheus.io/scrape|port|path, for annotation-based discovery
  serviceMonitor:
    enabled: false       # rendered only when monitoring.coreos.com/v1 exists in the cluster
    interval: 30s
    labels: {}           # e.g. release: kube-prometheus-stack
tracing:
  enabled: false
  endpoint: ""
  protocol: http
  samplerRatio: 1
  recordStatements: false
```

With `gateway.mode: external`, sandboxd runs on the gateway VM. Set `metrics:` and `tracing:` in
its `sandboxd.yaml`, and bind `metrics.listen` to an address Prometheus reaches that is not on the
sandbox VLAN.
