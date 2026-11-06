package gateway

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// A hung admin socket used to block the syncer (and the root fetch) for the life of the
// process: http.DefaultClient has no timeout and the context was the process's.
func TestReviewAdminCallsTimeOut(t *testing.T) {
	release := make(chan struct{})
	hung := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer hung.Close()
	defer close(release)
	old := adminTimeout
	adminTimeout = 200 * time.Millisecond
	defer func() { adminTimeout = old }()

	start := time.Now()
	if err := Push(t.Context(), hung.URL, "{}"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("push to a hung admin must time out: %v", err)
	}
	if _, err := FetchRoot(t.Context(), hung.URL); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("root fetch from a hung admin must time out: %v", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("took %v", d)
	}
}

// HTTP_PROXY must not route the Caddyfile (agent CA, root key paths) through a proxy.
func TestReviewAdminClientIgnoresProxyEnvironment(t *testing.T) {
	tr, ok := adminClient.Transport.(*http.Transport)
	if !ok || tr.Proxy != nil {
		t.Fatalf("admin transport must not consult the proxy environment: %#v", adminClient.Transport)
	}
}
