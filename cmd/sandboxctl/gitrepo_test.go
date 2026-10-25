package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// The gitrepo command: the record is shown whatever the outcome, and the exit code is the
// outcome's (check 0/1; sync 0 done, 2 invalid, 3 stopped, 1 unreadable; status 0).
func TestGitRepoCommandExitCodes(t *testing.T) {
	var mu sync.Mutex
	var status int
	var response string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if !strings.HasPrefix(r.URL.Path, "/v1/gitrepos/config/") {
			w.WriteHeader(404)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		fmt.Fprint(w, response)
	}))
	defer srv.Close()
	record := `{"tenant":"acme","name":"config","head":"%s","checked_at":"2026-10-25T10:00:00Z","check_error":"%s","commit":"%s","status":"%s","error":"%s","synced_at":"2026-10-25T10:00:00Z","bundles":[{"path":"bundles/acme.yaml","apply":"apply_1","status":"%s","changes":2}],"updated_at":"2026-10-25T10:00:00Z"}`
	cases := []struct {
		name     string
		args     []string
		status   int
		body     string
		wantCode int
		wantOut  string
	}{
		{"check_ok", []string{"gitrepo", "check", "config"}, 200, fmt.Sprintf(record, "abc", "", "", "", "", ""), 0, "head abc"},
		{"check_unreachable", []string{"gitrepo", "check", "config"}, 502, `{"error":"the repository could not be read: x","code":"unreachable","sync":` + fmt.Sprintf(record, "", "could not connect", "", "", "", "") + `}`, 1, "error: could not connect"},
		{"sync_done", []string{"gitrepo", "sync", "config"}, 200, fmt.Sprintf(record, "abc", "", "abc", "done", "", "done"), 0, "bundles/acme.yaml  apply_1  done"},
		{"sync_invalid", []string{"gitrepo", "sync", "config", "-commit", "abc"}, 422, `{"error":"a bundle is not valid","code":"invalid_plan","sync":` + fmt.Sprintf(record, "abc", "", "abc", "invalid", "a bundle is not valid: bundles/acme.yaml", "invalid") + `}`, 2, "invalid"},
		{"sync_stopped", []string{"gitrepo", "sync", "config"}, 409, `{"error":"an apply did not finish","code":"stopped","sync":` + fmt.Sprintf(record, "abc", "", "abc", "stopped", "apply_1 is failed", "failed") + `}`, 3, "stopped"},
		{"sync_unreachable", []string{"gitrepo", "sync", "config"}, 502, `{"error":"the repository could not be read","code":"unreachable","sync":` + fmt.Sprintf(record, "", "", "", "error", "could not connect", "") + `}`, 1, "error"},
		{"status", []string{"gitrepo", "status", "config", "-json"}, 200, fmt.Sprintf(record, "abc", "", "abc", "done", "", "done"), 0, `"status": "done"`},
		{"not_found", []string{"gitrepo", "status", "nope"}, 404, `{"error":"not found"}`, 1, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mu.Lock()
			status, response = tc.status, tc.body
			mu.Unlock()
			out, errOut, code := ctlChild(t, t.TempDir(), srv.URL, "t", nil, tc.args...)
			if code != tc.wantCode || !strings.Contains(out, tc.wantOut) {
				t.Errorf("exit %d (want %d)\nstdout:\n%s\nstderr:\n%s", code, tc.wantCode, out, errOut)
			}
		})
	}
}
