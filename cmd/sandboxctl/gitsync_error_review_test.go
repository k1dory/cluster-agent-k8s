package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"agent-sandbox/internal/model"
)

// PutGitSync may fail after Git resolved or the apply completed. The server then
// returns HTTP 500 with that record; displaying it must not turn the failure into exit 0.
func TestReviewGitRepoHTTPFailureCannotBecomeSuccess(t *testing.T) {
	for _, sub := range []string{"check", "sync"} {
		t.Run(sub, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]any{
					"error": "status persistence unavailable", "code": "error",
					"sync": model.GitSync{Tenant: "acme", Name: "config", Head: "head", Commit: "head", Status: model.GitSyncDone},
				})
			}))
			defer srv.Close()
			_, stderr, code := ctlChild(t, t.TempDir(), srv.URL, "t", nil, "gitrepo", sub, "config", "-json")
			if code == 0 {
				t.Fatalf("HTTP 500 must fail the CLI even with a completed record: exit=%d stderr=%s", code, stderr)
			}
		})
	}
}
