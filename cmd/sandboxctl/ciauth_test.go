package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestCIAuthCLIChild(t *testing.T) {
	if os.Getenv("SANDBOX_CIAUTH_CHILD") != "1" {
		return
	}
	for i, arg := range os.Args {
		if arg == "--" {
			os.Args = append([]string{os.Args[0]}, os.Args[i+1:]...)
			main()
			return
		}
	}
	t.Fatal("missing child arguments")
}

// ciAuthCLI runs `sandboxctl auth ci …` against base without a SANDBOXD_TOKEN, as a CI job
// does, with extra environment; stdout and stderr come back apart (the secret is stdout).
func ciAuthCLI(t *testing.T, base, stdin string, extraEnv []string, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], append([]string{"-test.run=^TestCIAuthCLIChild$", "--", "auth", "ci"}, args...)...)
	for _, e := range os.Environ() {
		name, _, _ := strings.Cut(e, "=")
		switch name {
		case "SANDBOXD_URL", "SANDBOXD_TOKEN", "SANDBOX_CIAUTH_CHILD", "ACTIONS_ID_TOKEN_REQUEST_URL", "ACTIONS_ID_TOKEN_REQUEST_TOKEN":
		default:
			cmd.Env = append(cmd.Env, e)
		}
	}
	cmd.Env = append(cmd.Env, "SANDBOX_CIAUTH_CHILD=1", "SANDBOXD_URL="+base)
	cmd.Env = append(cmd.Env, extraEnv...)
	var out, errb bytes.Buffer
	cmd.Stdin, cmd.Stdout, cmd.Stderr = strings.NewReader(stdin), &out, &errb
	err = cmd.Run()
	if ctx.Err() != nil {
		t.Fatal("CLI timed out")
	}
	// The test binary prints PASS once main returned without exiting.
	return strings.TrimSuffix(out.String(), "PASS\n"), errb.String(), err
}

// The exchange is the one call made without a key: the token goes in the body, nothing in the
// Authorization header; the secret is the whole of stdout (so `$(sandboxctl auth ci …)` is the
// key), the rest goes to stderr; a refused token is a failure with the platform's reason.
func TestCIAuthCLIExchangesTheTokenWithoutAKey(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	platform := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]string
		_ = json.NewDecoder(r.Body).Decode(&req)
		if r.Method != "POST" || r.URL.Path != "/v1/auth/ci" || r.Header.Get("Authorization") != "" {
			t.Errorf("unexpected call %s %s auth=%q", r.Method, r.URL.Path, r.Header.Get("Authorization"))
			w.WriteHeader(400)
			return
		}
		mu.Lock()
		seen = append(seen, req["token"])
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if req["token"] == "stolen" {
			w.WriteHeader(401)
			_, _ = w.Write([]byte(`{"error":"no trust accepts the token","code":"unauthorized"}`))
			return
		}
		w.WriteHeader(201)
		_, _ = w.Write([]byte(`{"id":"key_ci","tenant":"acme","name":"ci.github","trust":"github","expires_at":"2030-01-01T00:00:00Z","secret":"sbk_ci_secret","subject":"repo:acme/config:ref:refs/heads/main"}`))
	}))
	defer platform.Close()
	// GitHub's token service: the job's request token in the header, the audience as asked.
	github := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "bearer job-request-token" {
			w.WriteHeader(401)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"value": "gh-token-for-" + r.URL.Query().Get("audience")})
	}))
	defer github.Close()
	ghEnv := []string{"ACTIONS_ID_TOKEN_REQUEST_URL=" + github.URL + "/token?api-version=2.0", "ACTIONS_ID_TOKEN_REQUEST_TOKEN=job-request-token"}

	stdout, stderr, err := ciAuthCLI(t, platform.URL, "", nil, "-token", "raw-token")
	if err != nil || stdout != "sbk_ci_secret\n" || !strings.Contains(stderr, "key key_ci for tenant acme under trust github") || !strings.Contains(stderr, "2030-01-01") {
		t.Fatalf("-token: err=%v stdout=%q stderr=%q", err, stdout, stderr)
	}
	if stdout, _, err := ciAuthCLI(t, platform.URL, "from-stdin\n", nil, "-token-file", "-"); err != nil || stdout != "sbk_ci_secret\n" {
		t.Fatalf("-token-file -: err=%v stdout=%q", err, stdout)
	}
	if stdout, _, err := ciAuthCLI(t, platform.URL, "", ghEnv, "-github"); err != nil || stdout != "sbk_ci_secret\n" {
		t.Fatalf("-github: err=%v stdout=%q", err, stdout)
	}
	if stdout, _, err := ciAuthCLI(t, platform.URL, "", ghEnv, "-github", "-audience", "https://sandbox.example.com", "-json"); err != nil || !strings.Contains(stdout, `"secret": "sbk_ci_secret"`) || !strings.Contains(stdout, `"trust": "github"`) {
		t.Fatalf("-github -json: err=%v stdout=%q", err, stdout)
	}
	mu.Lock()
	sent := strings.Join(seen, "|")
	mu.Unlock()
	if want := []string{"raw-token", "from-stdin", "gh-token-for-" + platform.URL, "gh-token-for-https://sandbox.example.com"}; sent != strings.Join(want, "|") {
		t.Fatalf("tokens sent: %q", sent)
	}
	if _, stderr, err := ciAuthCLI(t, platform.URL, "", nil, "-github"); err == nil || !strings.Contains(stderr, "ACTIONS_ID_TOKEN_REQUEST_URL") {
		t.Fatalf("-github outside Actions: err=%v stderr=%q", err, stderr)
	}
	stdout, stderr, err = ciAuthCLI(t, platform.URL, "", nil, "-token", "stolen")
	if err == nil || stdout != "" || !strings.Contains(stderr, "no trust accepts the token") {
		t.Fatalf("refused: err=%v stdout=%q stderr=%q", err, stdout, stderr)
	}
}
