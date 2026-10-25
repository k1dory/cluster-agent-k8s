// Package gittest serves a Git repository over the smart HTTP protocol for tests, with git's
// own http-backend (what GitHub, GitLab, Gitea and a plain git server speak), optionally
// behind HTTP basic authentication.
package gittest

import (
	"crypto/subtle"
	"net/http"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Server is one repository ("acme/config.git") served over HTTP.
type Server struct {
	URL  string // the repository's URL
	Work string // a clone to commit in (branch main)
	srv  *httptest.Server
}

// New starts a server; user empty means no authentication. Skips the test without git.
func New(t *testing.T, user, password string) *Server {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is required")
	}
	backend := filepath.Join(strings.TrimSpace(Git(t, "", "--exec-path")), "git-http-backend")
	if _, err := os.Stat(backend); err != nil {
		t.Skip("git-http-backend is required")
	}
	root := t.TempDir()
	work := filepath.Join(root, "work")
	bare := filepath.Join(root, "repos", "acme", "config.git")
	if err := os.MkdirAll(filepath.Dir(bare), 0o755); err != nil {
		t.Fatal(err)
	}
	Git(t, "", "init", "-q", "--bare", bare)
	Git(t, "", "clone", "-q", bare, work)
	Git(t, work, "checkout", "-q", "-b", "main")
	h := &cgi.Handler{Path: backend, Env: []string{"GIT_PROJECT_ROOT=" + filepath.Join(root, "repos"), "GIT_HTTP_EXPORT_ALL=1"}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if user != "" {
			u, p, ok := r.BasicAuth()
			if !ok || subtle.ConstantTimeCompare([]byte(u), []byte(user)) != 1 || subtle.ConstantTimeCompare([]byte(p), []byte(password)) != 1 {
				w.Header().Set("WWW-Authenticate", `Basic realm="git"`)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return &Server{URL: srv.URL + "/acme/config.git", Work: work, srv: srv}
}

// Commit writes files in the work tree, commits them on main, pushes and returns the SHA.
func (s *Server) Commit(t *testing.T, files map[string]string, msg string) string {
	t.Helper()
	for name, content := range files {
		p := filepath.Join(s.Work, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	Git(t, s.Work, "add", "-A")
	Git(t, s.Work, "commit", "-q", "--allow-empty", "-m", msg)
	Git(t, s.Work, "push", "-q", "origin", "main")
	return strings.TrimSpace(Git(t, s.Work, "rev-parse", "HEAD"))
}

// Close stops the server (the test's cleanup does it too).
func (s *Server) Close() { s.srv.Close() }

// Git runs git in dir with a fixed identity and fails the test on error.
func Git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com", "GIT_CONFIG_NOSYSTEM=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return string(out)
}
