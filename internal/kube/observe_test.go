package kube

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"agent-sandbox/internal/telemetry"
	"agent-sandbox/internal/telemetry/telemetrytest"
)

// Calls through the client are counted by verb and code (never by resource or name), and a
// call made inside a trace is a client span whose traceparent reaches the API server.
func TestKubeClientIsMeteredAndTraced(t *testing.T) {
	sr := telemetrytest.Record(t)
	var traceparent string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		traceparent = r.Header.Get("traceparent")
		w.Header().Set("Content-Type", "application/json")
		http.Error(w, `{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"NotFound","code":404}`, http.StatusNotFound)
	}))
	defer srv.Close()
	cfg := &rest.Config{Host: srv.URL}
	observe(cfg)
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	got := telemetry.KubeRequests.WithLabelValues("get", "404")
	before := testutil.ToFloat64(got)
	ctx, parent := telemetry.Tracer().Start(t.Context(), "reconcile")
	_, err = client.CoreV1().Pods("agent-sandbox").Get(ctx, "agent-sb-secret-name", metav1.GetOptions{})
	parent.End()
	if err == nil {
		t.Fatal("the fake API server answered 404")
	}
	if testutil.ToFloat64(got)-before != 1 {
		t.Fatal("the GET is not counted as verb=get code=404")
	}
	if traceparent == "" {
		t.Fatal("no traceparent reached the API server from inside a trace")
	}
	var client1 int
	for _, s := range sr.Ended() {
		if s.Parent().SpanID() == parent.SpanContext().SpanID() {
			client1++
		}
	}
	if client1 != 1 {
		t.Fatalf("client spans under the caller: %d", client1)
	}
	// Outside a trace: counted, no span, nothing propagated.
	n := len(sr.Ended())
	traceparent = ""
	_, _ = client.CoreV1().Pods("agent-sandbox").Get(t.Context(), "x", metav1.GetOptions{})
	if len(sr.Ended()) != n || traceparent != "" || testutil.ToFloat64(got)-before != 2 {
		t.Fatalf("a call outside a trace: %d spans, traceparent %q", len(sr.Ended())-n, traceparent)
	}
}

func TestKubeVerbIsBounded(t *testing.T) {
	for _, c := range []struct{ method, url, want string }{
		{"GET", "/api/v1/namespaces/x/pods/agent-sb-1", "get"},
		{"GET", "/api/v1/namespaces/x/pods?watch=true", "watch"},
		{"POST", "/api/v1/namespaces/x/pods", "create"},
		{"DELETE", "/api/v1/namespaces/x/pods/agent-sb-1", "delete"},
		{"PATCH", "/x", "patch"},
		{"PUT", "/x", "update"},
		{"BREW", "/x", "other"},
	} {
		if got := kubeVerb(httptest.NewRequest(c.method, c.url, nil)); got != c.want {
			t.Errorf("%s %s: %q, want %q", c.method, c.url, got, c.want)
		}
	}
}
