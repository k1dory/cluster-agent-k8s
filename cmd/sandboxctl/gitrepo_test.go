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
	rec := func(head, checkErr, commit, status, syncErr, bundleStatus string) string {
		check := ""
		if head != "" || checkErr != "" {
			check = fmt.Sprintf(`"check":{"head":"%s","at":"2026-10-25T10:00:00Z","error":"%s"},`, head, checkErr)
		}
		sync := ""
		if status != "" {
			sync = fmt.Sprintf(`"sync":{"commit":"%s","status":"%s","error":"%s","at":"2026-10-25T10:00:00Z","bundles":[{"path":"bundles/acme.yaml","apply":"apply_1","status":"%s","changes":2}]},`, commit, status, syncErr, bundleStatus)
		}
		return `{"tenant":"acme","name":"config",` + check + sync + `"updated_at":"2026-10-25T10:00:00Z"}`
	}
	wrap := func(code, msg, record string) string {
		return `{"error":"` + msg + `","code":"` + code + `","sync":` + record + `}`
	}
	cases := []struct {
		name     string
		args     []string
		status   int
		body     string
		wantCode int
		wantOut  string
	}{
		{"check_ok", []string{"gitrepo", "check", "config"}, 200, rec("abc", "", "", "", "", ""), 0, "head abc"},
		{"check_unreachable", []string{"gitrepo", "check", "config"}, 502, wrap("unreachable", "the repository could not be read: x", rec("", "could not connect", "", "", "", "")), 1, "error: could not connect"},
		{"sync_done", []string{"gitrepo", "sync", "config"}, 200, rec("abc", "", "abc", "done", "", "done"), 0, "bundles/acme.yaml  apply_1  done"},
		{"sync_invalid", []string{"gitrepo", "sync", "config", "-commit", "abc"}, 422, wrap("invalid_plan", "a bundle is not valid", rec("abc", "", "abc", "invalid", "a bundle is not valid: bundles/acme.yaml", "invalid")), 2, "invalid"},
		{"sync_stopped", []string{"gitrepo", "sync", "config"}, 409, wrap("stopped", "an apply did not finish", rec("abc", "", "abc", "stopped", "apply_1 is failed", "failed")), 3, "stopped"},
		{"sync_unreachable", []string{"gitrepo", "sync", "config"}, 502, wrap("unreachable", "the repository could not be read", rec("", "", "", "error", "could not connect", "")), 1, "error"},
		{"status", []string{"gitrepo", "status", "config", "-json"}, 200, rec("abc", "", "abc", "done", "", "done"), 0, `"status": "done"`},
		{"not_found", []string{"gitrepo", "status", "nope"}, 404, `{"error":"not found"}`, 1, ""},
		// An error answer is never a success, whatever the attached record says: a 500 with a
		// done record, a 502 with a head, a 422 (credential gone) with a done sync half.
		{"500_with_done_record", []string{"gitrepo", "sync", "config"}, 500, wrap("error", "store unavailable", rec("abc", "", "abc", "done", "", "done")), 1, "done"},
		{"502_with_head", []string{"gitrepo", "check", "config"}, 502, wrap("unreachable", "x", rec("abc", "", "", "", "", "")), 1, "head abc"},
		{"422_credential_with_done_sync", []string{"gitrepo", "sync", "config"}, 422, wrap("credential", "the credential is not available", rec("abc", "", "abc", "done", "", "done")), 1, "done"},
		{"status_500_with_record", []string{"gitrepo", "status", "config"}, 500, wrap("error", "boom", rec("abc", "", "abc", "done", "", "done")), 1, ""},
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
