package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestReviewCredentialsCLIChild(t *testing.T) {
	if os.Getenv("SANDBOX_CREDENTIALS_REVIEW_CHILD") != "1" {
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

func reviewCredentialsCLI(t *testing.T, base, tokenEnv, stdin string, args ...string) ([]byte, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], append([]string{"-test.run=^TestReviewCredentialsCLIChild$", "--"}, args...)...)
	for _, e := range os.Environ() {
		name, _, _ := strings.Cut(e, "=")
		if name != "SANDBOXD_URL" && name != "SANDBOXD_TOKEN" && name != "SANDBOXCTL_TOKEN" && name != "SANDBOX_CREDENTIALS_REVIEW_CHILD" {
			cmd.Env = append(cmd.Env, e)
		}
	}
	cmd.Env = append(cmd.Env, "SANDBOX_CREDENTIALS_REVIEW_CHILD=1", "SANDBOXD_URL="+base, tokenEnv+"=review-token")
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatal("CLI timed out")
	}
	return out, err
}

func TestReviewCredentialsCLIFlows(t *testing.T) {
	const value = "review-synthetic-credential"
	file := filepath.Join(t.TempDir(), "credential.txt")
	if err := os.WriteFile(file, []byte(value+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, method, path, stdin string
		args                      []string
	}{
		{"stdin", "PUT", "/v1/credentials/model", value + "\n", []string{"set", "model", "-tenant", "acme"}},
		{"file", "PUT", "/v1/credentials/model", "", []string{"set", "model", "-tenant", "acme", "-file", file, "-json"}},
		{"list", "GET", "/v1/credentials", "", []string{"list", "-tenant", "acme", "-json"}},
		{"remove", "DELETE", "/v1/credentials/model", "", []string{"remove", "model", "-tenant", "acme"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != tc.method || r.URL.Path != tc.path || r.URL.Query().Get("tenant") != "acme" {
					t.Error("CLI did not preserve the requested operation and scope")
					w.WriteHeader(400)
					return
				}
				if r.Header.Get("Authorization") != "Bearer review-token" {
					w.WriteHeader(401)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				switch r.Method {
				case "PUT":
					var req map[string]string
					if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req) != 1 || req["value"] != value {
						t.Error("CLI changed the credential read from its input")
					}
					w.WriteHeader(201)
					_, _ = w.Write([]byte(`{"name":"model","version":1,"fingerprint":"fixture"}`))
				case "GET":
					_, _ = w.Write([]byte(`[]`))
				case "DELETE":
					w.WriteHeader(204)
				}
			}))
			defer srv.Close()
			out, err := reviewCredentialsCLI(t, srv.URL, "SANDBOXD_TOKEN", tc.stdin, append([]string{"credentials"}, tc.args...)...)
			if err != nil {
				t.Errorf("CLI operation failed: %v", err)
			}
			if strings.Contains(string(out), value) {
				t.Error("CLI output must contain metadata only")
			}
		})
	}
}

func TestReviewSelfServiceDocumentAuthenticatesCLI(t *testing.T) {
	doc, err := os.ReadFile("../../docs/self-service.md")
	if err != nil {
		t.Fatal(err)
	}
	match := regexp.MustCompile(`(?m)^export ([A-Z_]+_TOKEN)=`).FindSubmatch(doc)
	if len(match) != 2 {
		t.Fatal("self-service guide must explain the token environment variable")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("Authorization") != "Bearer review-token" {
			w.WriteHeader(401)
			_, _ = w.Write([]byte(`{"error":"authentication required","code":"unauthorized"}`))
			return
		}
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()
	if _, err := reviewCredentialsCLI(t, srv.URL, string(match[1]), "", "credentials", "list"); err != nil {
		t.Errorf("following the guide's %s export must authenticate the real CLI: %v", match[1], err)
	}
}
