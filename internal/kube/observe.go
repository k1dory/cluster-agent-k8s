package kube

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"k8s.io/client-go/rest"

	"agent-sandbox/internal/telemetry"
)

// observe wraps the client's transport: every call to the Kubernetes API is counted by verb
// and code and timed, and one made inside a trace is a client span whose context goes on to
// the API server (which joins it when its own tracing is on).
func observe(cfg *rest.Config) {
	cfg.Wrap(func(rt http.RoundTripper) http.RoundTripper {
		return &metered{next: telemetry.Transport(rt, true)}
	})
}

type metered struct{ next http.RoundTripper }

func (m *metered) RoundTrip(r *http.Request) (*http.Response, error) {
	verb := kubeVerb(r)
	start := time.Now()
	resp, err := m.next.RoundTrip(r)
	code := "error"
	if err == nil {
		code = strconv.Itoa(resp.StatusCode)
	}
	telemetry.KubeRequests.WithLabelValues(verb, code).Inc()
	if verb != "watch" { // a watch lasts as long as the server keeps it open
		telemetry.KubeDuration.WithLabelValues(verb).Observe(time.Since(start).Seconds())
	}
	return resp, err
}

// kubeVerb is the API verb of a request, close to the server's own (get covers list, a GET
// with watch=true is watch): a fixed set, never the resource or its name.
func kubeVerb(r *http.Request) string {
	switch r.Method {
	case http.MethodGet:
		if w := r.URL.Query().Get("watch"); w == "true" || w == "1" {
			return "watch"
		}
		return "get"
	case http.MethodPost:
		return "create"
	case http.MethodPut:
		return "update"
	case http.MethodPatch:
		return "patch"
	case http.MethodDelete:
		return "delete"
	}
	return strings.ToLower(telemetry.Method(r.Method))
}
