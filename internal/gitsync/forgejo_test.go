package gitsync

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"agent-sandbox/internal/render"
)

// forgejoHeaders is what Forgejo sends: its own headers, Gitea's, and GitHub's copies for tools
// that only know GitHub. gitea=true sends only Gitea's (and GitHub's).
func forgejoHeaders(event, secret string, body []byte, gitea bool) http.Header {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	sig := hex.EncodeToString(mac.Sum(nil))
	h := http.Header{}
	id := fmt.Sprintf("f-%d", deliveries.Add(1))
	if !gitea {
		h.Set("X-Forgejo-Event", event)
		h.Set("X-Forgejo-Delivery", id)
		h.Set("X-Forgejo-Signature", sig)
	}
	h.Set("X-Gitea-Event", event)
	h.Set("X-Gitea-Delivery", id)
	h.Set("X-Gitea-Signature", sig)
	h.Set("X-GitHub-Event", event)
	h.Set("X-GitHub-Delivery", id)
	h.Set("X-Hub-Signature-256", "sha256="+sig)
	return h
}

// A Forgejo (or Gitea) delivery is Forgejo's, though it carries GitHub's headers too: its pull
// request is planned on its own actions ("synchronized") and its plan goes to /api/v1.
func TestForgejoDeliveries(t *testing.T) {
	push := []byte(`{"ref":"refs/heads/main","after":"` + sha1 + `","repository":{"clone_url":"https://forgejo.example/acme/config.git","html_url":"https://forgejo.example/acme/config"}}`)
	for _, gitea := range []bool{false, true} {
		d, err := ParseDelivery(forgejoHeaders("push", "s3cret", push, gitea), push)
		if err != nil || d.Provider != ProviderForgejo || d.Event != EventPush || d.After != sha1 || !strings.HasPrefix(d.ID, "f-") {
			t.Fatalf("push (gitea %v): %v %+v", gitea, err, d)
		}
		if err := Verify(ProviderForgejo, forgejoHeaders("push", "s3cret", push, gitea), push, "s3cret"); err != nil {
			t.Fatalf("signature (gitea %v): %v", gitea, err)
		}
		if err := Verify(ProviderForgejo, forgejoHeaders("push", "other", push, gitea), push, "s3cret"); !errors.Is(err, ErrBadSignature) {
			t.Fatalf("wrong secret (gitea %v): %v", gitea, err)
		}
	}
	// GitHub's copy of the signature is not what is checked: a delivery with only that fails.
	onlyGitHub := forgejoHeaders("push", "s3cret", push, false)
	onlyGitHub.Del("X-Forgejo-Signature")
	onlyGitHub.Del("X-Gitea-Signature")
	if err := Verify(ProviderForgejo, onlyGitHub, push, "s3cret"); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("GitHub's header alone: %v", err)
	}

	pr := []byte(`{"action":"synchronized","number":12,"pull_request":{"number":12,"head":{"sha":"` + sha1 + `","ref":"feature"}},"repository":{"clone_url":"https://forgejo.example/acme/config.git"}}`)
	d, err := ParseDelivery(forgejoHeaders("pull_request", "s", pr, false), pr)
	if err != nil || d.Event != EventPullRequest || d.PR == nil || d.PR.Provider != ProviderForgejo || d.PR.Number != 12 || d.PR.HeadRef != "refs/pull/12/head" {
		t.Fatalf("pull request: %v %+v", err, d)
	}
	for action, want := range map[string]bool{"opened": true, "synchronized": true, "reopened": true, "synchronize": false, "edited": false, "closed": false} {
		if planActions[ProviderForgejo][action] != want {
			t.Errorf("forgejo action %q planned: %v", action, !want)
		}
	}

	// The plan goes to the registered server's /api/v1; a job from before the provider was
	// recorded still goes where it always went (GitHub's API).
	remote := Remote{URL: "https://forgejo.example/acme/config.git"}
	tg, err := TargetOf(remote, *d.PR)
	if err != nil || tg.Provider != ProviderForgejo || tg.APIBase != "https://forgejo.example/api/v1" || tg.Repo != "acme/config" || tg.Number != 12 {
		t.Fatalf("target: %v %+v", err, tg)
	}
	old := *d.PR
	old.Provider = ""
	if tg, err := TargetOf(remote, old); err != nil || tg.Provider != ProviderGitHub {
		t.Fatalf("an old job: %v %+v", err, tg)
	}
}

// Against Forgejo's API: the plan comment is the pull request's issue comment, found unpaged by
// its marker and edited in place; the status is posted with Forgejo's own states; the token goes
// as "token …".
func TestForgejoReporter(t *testing.T) {
	type call struct{ method, path, auth string }
	var mu sync.Mutex
	var calls []call
	comments := map[int64]string{}
	var next int64 = 200
	var status map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		body, _ := io.ReadAll(r.Body)
		calls = append(calls, call{r.Method, r.URL.String(), r.Header.Get("Authorization")})
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == "GET" && r.URL.Path == "/api/v1/repos/acme/config/issues/12/comments":
			if r.URL.RawQuery != "" {
				t.Errorf("Forgejo's comment listing is not paged: %s", r.URL)
			}
			list := []map[string]any{{"id": 1, "body": "a person's comment"}}
			for id, b := range comments {
				list = append(list, map[string]any{"id": id, "body": b})
			}
			_ = json.NewEncoder(w).Encode(list)
		case r.Method == "POST" && r.URL.Path == "/api/v1/repos/acme/config/issues/12/comments":
			var in struct{ Body string }
			_ = json.Unmarshal(body, &in)
			next++
			comments[next] = in.Body
			w.WriteHeader(201)
			fmt.Fprintf(w, `{"id":%d}`, next)
		case r.Method == "PATCH" && strings.HasPrefix(r.URL.Path, "/api/v1/repos/acme/config/issues/comments/"):
			var in struct{ Body string }
			_ = json.Unmarshal(body, &in)
			var id int64
			fmt.Sscanf(strings.TrimPrefix(r.URL.Path, "/api/v1/repos/acme/config/issues/comments/"), "%d", &id)
			if _, ok := comments[id]; !ok {
				w.WriteHeader(404)
				return
			}
			comments[id] = in.Body
			fmt.Fprint(w, `{}`)
		case r.Method == "POST" && r.URL.Path == "/api/v1/repos/acme/config/statuses/"+sha1:
			_ = json.Unmarshal(body, &status)
			w.WriteHeader(201)
			fmt.Fprint(w, `{}`)
		default:
			t.Errorf("unexpected call %s %s", r.Method, r.URL)
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	ctx := context.Background()
	rep := RESTReporter{Client: srv.Client()}
	tg := Target{Provider: ProviderForgejo, APIBase: srv.URL + "/api/v1", Repo: "acme/config", Number: 12, SHA: sha1, Token: "fj-token"}
	for _, b := range []string{"first", "second"} {
		if err := rep.UpsertComment(ctx, tg, render.Marker+"\n"+b); err != nil {
			t.Fatal(err)
		}
	}
	if err := rep.SetStatus(ctx, tg, StatusFailure, "plan: invalid"); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(comments) != 1 {
		t.Fatalf("the comment was not edited in place: %v", comments)
	}
	for _, c := range comments {
		if c != render.Marker+"\nsecond" {
			t.Fatalf("comment: %q", c)
		}
	}
	if status["state"] != StatusFailure || status["context"] != StatusContext || status["description"] != "plan: invalid" {
		t.Fatalf("status: %v", status)
	}
	for _, c := range calls {
		if c.auth != "token fj-token" {
			t.Fatalf("auth header on %s %s: %q", c.method, c.path, c.auth)
		}
	}
}
