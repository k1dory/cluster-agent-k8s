package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// `sandboxctl oauth login` starts the sign-in in the requested scope, prints where to approve
// it and with which code, waits until sandboxd reports it active, and says what to reference;
// a sign-in that ends failed is an error with the reason.
func TestOAuthLoginWaitsForTheOutcome(t *testing.T) {
	for _, outcome := range []string{"active", "failed"} {
		t.Run(outcome, func(t *testing.T) {
			var mu sync.Mutex
			gets := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				if r.Header.Get("Authorization") != "Bearer review-token" || r.URL.Query().Get("tenant") != "acme" {
					w.WriteHeader(400)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				pending := `{"name":"chatgpt","provider":"chatgpt","status":"pending","verification_url":"https://auth.example.com/codex/device","user_code":"ABCD-1234"}`
				switch {
				case r.Method == "POST" && r.URL.Path == "/v1/oauth-credentials/chatgpt/login":
					var req map[string]string
					if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req["provider"] != "chatgpt" || len(req) != 1 {
						t.Errorf("login body: %v %v", req, err)
					}
					w.WriteHeader(201)
					_, _ = w.Write([]byte(pending))
				case r.Method == "GET" && r.URL.Path == "/v1/oauth-credentials/chatgpt":
					gets++
					if gets < 2 {
						_, _ = w.Write([]byte(pending))
						return
					}
					if outcome == "active" {
						_, _ = w.Write([]byte(`{"name":"chatgpt","provider":"chatgpt","status":"active","account_id":"acct-42"}`))
					} else {
						_, _ = w.Write([]byte(`{"name":"chatgpt","provider":"chatgpt","status":"failed","error":"sign-in refused: access_denied"}`))
					}
				default:
					t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
					w.WriteHeader(404)
				}
			}))
			defer srv.Close()
			out, err := reviewCredentialsCLI(t, srv.URL, "SANDBOXD_TOKEN", "", "oauth", "login", "chatgpt", "-provider", "chatgpt", "-tenant", "acme", "-every", "10ms")
			s := string(out)
			if !strings.Contains(s, "https://auth.example.com/codex/device") || !strings.Contains(s, "ABCD-1234") {
				t.Fatalf("the URL and the code must be printed:\n%s", s)
			}
			switch outcome {
			case "active":
				if err != nil || !strings.Contains(s, "active") || !strings.Contains(s, "secret:chatgpt.account_id") {
					t.Fatalf("active: %v\n%s", err, s)
				}
			case "failed":
				if err == nil || !strings.Contains(s, "access_denied") {
					t.Fatalf("failed must be an error with the reason: %v\n%s", err, s)
				}
			}
		})
	}
}
