package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func reviewGitBundle(t *testing.T) (string, string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is required")
	}
	root := t.TempDir()
	run(t, root, "init", "-q", "-b", "main")
	file := filepath.Join(root, "bundle.yaml")
	if err := os.WriteFile(file, []byte("kind: EnvironmentProfile\nname: py\nspec: {image: stable}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	run(t, root, "add", "bundle.yaml")
	run(t, root, "commit", "-q", "-m", "test bundle")
	return root, file
}

func TestReviewGitSourceVerifiesContentWithAssumeUnchanged(t *testing.T) {
	root, file := reviewGitBundle(t)
	// A local index optimisation must not turn an edited manifest into committed content.
	run(t, root, "update-index", "--assume-unchanged", "bundle.yaml")
	if err := os.WriteFile(file, []byte("kind: EnvironmentProfile\nname: py\nspec: {image: canary}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	src, ok, dirty, err := gitSource(file, raw)
	if err != nil || !ok {
		t.Fatalf("source detection failed: ok=%v err=%v", ok, err)
	}
	if !dirty || src.Commit != "" {
		t.Errorf("different file content must not carry the commit SHA: dirty=%v commit_present=%v", dirty, src.Commit != "")
	}
}

func TestReviewGitSourceOmitsURLCredentials(t *testing.T) {
	root, file := reviewGitBundle(t)
	remote := &url.URL{Scheme: "https", Host: "git.example.test", Path: "/team/config.git", User: url.UserPassword("fixture-user", "fixture-password")}
	run(t, root, "remote", "add", "origin", remote.String())
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	src, ok, _, err := gitSource(file, raw)
	if err != nil || !ok {
		t.Fatalf("source detection failed: ok=%v err=%v", ok, err)
	}
	parsed, err := url.Parse(src.Repo)
	if err != nil {
		t.Fatal("source repo must remain a valid URL")
	}
	if parsed.User != nil {
		t.Error("repository provenance must not contain URL credentials")
	}
}

func TestReviewGitOpsCLIExitStatus(t *testing.T) {
	// Run the real CLI dispatch in a child so its os.Exit calls become observable outcomes.
	if os.Getenv("SANDBOX_REVIEW_CLI_CHILD") == "1" {
		var args []string
		for i, arg := range os.Args {
			if arg == "--" {
				args = os.Args[i+1:]
				break
			}
		}
		if len(args) == 0 {
			os.Exit(99)
		}
		c := &cli{base: os.Getenv("SANDBOX_REVIEW_CLI_URL"), token: "fixture-token", http: &http.Client{Timeout: 3 * time.Second}}
		if err := c.run(args[0], args[1:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	file := filepath.Join(t.TempDir(), "bundle.yaml")
	if err := os.WriteFile(file, []byte("kind: EnvironmentProfile\nname: py\nspec: {image: stable}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, path, response string
		args                 []string
		wantFailure          bool
	}{
		{"rollback_json_conflict", "/v1/rollback", `{"target":"fixture","plan":{"valid":true},"apply":{"id":"apply_fixture","status":"conflict"}}`, []string{"rollback", "environment", "py", "-json"}, true},
		{"rollback_json_running", "/v1/rollback", `{"target":"fixture","plan":{"valid":true},"apply":{"id":"apply_fixture","status":"running"}}`, []string{"rollback", "environment", "py", "-json"}, true},
		{"rollback_plan_invalid", "/v1/rollback", `{"target":"fixture","plan":{"valid":false,"changes":[],"summary":{"invalid":1}}}`, []string{"rollback", "environment", "py", "-plan"}, true},
		{"drift_bundle_error", "/v1/plan", `{"valid":false,"errors":["duplicate document"],"changes":[],"summary":{"noop":2}}`, []string{"drift", "-f", file, "-json"}, true},
		{"rollback_json_done", "/v1/rollback", `{"target":"fixture","plan":{"valid":true},"apply":{"id":"apply_fixture","status":"done"}}`, []string{"rollback", "environment", "py", "-json"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !json.Valid([]byte(tc.response)) {
				t.Fatal("invalid response fixture")
			}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.URL.Path != tc.path {
					t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, tc.response)
			}))
			defer srv.Close()
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			args := append([]string{"-test.run=^TestReviewGitOpsCLIExitStatus$", "--"}, tc.args...)
			cmd := exec.CommandContext(ctx, os.Args[0], args...)
			cmd.Env = append(os.Environ(), "SANDBOX_REVIEW_CLI_CHILD=1", "SANDBOX_REVIEW_CLI_URL="+srv.URL)
			out, err := cmd.CombinedOutput()
			var exited *exec.ExitError
			if err != nil && !errors.As(err, &exited) {
				t.Fatalf("run CLI: %v", err)
			}
			if ctx.Err() != nil {
				t.Fatal("CLI did not finish")
			}
			if tc.wantFailure && err == nil {
				t.Error("unsuccessful result must have nonzero exit status; CLI returned 0")
			}
			if !tc.wantFailure && err != nil {
				t.Errorf("completed rollback must succeed: %v %s", err, out)
			}
		})
	}
}
