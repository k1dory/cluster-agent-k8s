package gitsync

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"agent-sandbox/internal/render"
)

// A Forgejo (Gitea) mounted under a subpath serves its API under that subpath too: the
// repository https://host/code/acme/config.git is /code/api/v1/repos/acme/config, not
// /api/v1/repos/code/acme/config. GitHub's and GitLab's targets are unchanged.
func TestTargetOfForgejoUnderASubpath(t *testing.T) {
	pr := PullRequest{Provider: ProviderForgejo, Number: 12, HeadSHA: sha1}
	for _, c := range []struct{ url, base, repo string }{
		{"https://host/acme/config.git", "https://host/api/v1", "acme/config"},
		{"https://host/code/acme/config.git", "https://host/code/api/v1", "acme/config"},
		{"https://host/code/", "", ""},
		{"https://host:3000/a/b/acme/config/", "https://host:3000/a/b/api/v1", "acme/config"},
		{"http://host/git/acme/config", "http://host/git/api/v1", "acme/config"},
	} {
		tg, err := TargetOf(Remote{URL: c.url, Auth: "tok"}, pr)
		if c.base == "" {
			if err == nil {
				t.Errorf("%s: want an error, got %+v", c.url, tg)
			}
			continue
		}
		if err != nil || tg.APIBase != c.base || tg.Repo != c.repo || tg.Provider != ProviderForgejo {
			t.Errorf("%s: got %+v, %v; want base %s repo %s", c.url, tg, err, c.base, c.repo)
		}
	}
	// GitLab keeps the whole path as the project (nested groups), GitHub Enterprise its /api/v3.
	gl, err := TargetOf(Remote{URL: "https://host/code/acme/config.git"}, PullRequest{Provider: ProviderGitLab, Number: 3})
	if err != nil || gl.APIBase != "https://host/api/v4" || gl.Repo != "code/acme/config" {
		t.Fatalf("gitlab target changed: %+v, %v", gl, err)
	}
	gh, err := TargetOf(Remote{URL: "https://ghe.example/acme/config"}, PullRequest{Provider: ProviderGitHub, Number: 7})
	if err != nil || gh.APIBase != "https://ghe.example/api/v3" || gh.Repo != "acme/config" {
		t.Fatalf("github target changed: %+v, %v", gh, err)
	}
}

// The plan reaches a Forgejo mounted under /code: the comment is posted, then edited in place,
// and the status is set, every call under /code/api/v1 and nothing at the server's root.
func TestForgejoReporterUnderASubpath(t *testing.T) {
	const api = "/code/api/v1/repos/acme/config"
	var mu sync.Mutex
	comments := map[int64]string{}
	var next int64 = 300
	var status map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == "GET" && r.URL.Path == api+"/issues/12/comments":
			list := []map[string]any{}
			for id, b := range comments {
				list = append(list, map[string]any{"id": id, "body": b})
			}
			_ = json.NewEncoder(w).Encode(list)
		case r.Method == "POST" && r.URL.Path == api+"/issues/12/comments":
			var in struct{ Body string }
			_ = json.Unmarshal(body, &in)
			next++
			comments[next] = in.Body
			w.WriteHeader(201)
			fmt.Fprintf(w, `{"id":%d}`, next)
		case r.Method == "PATCH" && strings.HasPrefix(r.URL.Path, api+"/issues/comments/"):
			var in struct{ Body string }
			_ = json.Unmarshal(body, &in)
			var id int64
			fmt.Sscanf(strings.TrimPrefix(r.URL.Path, api+"/issues/comments/"), "%d", &id)
			if _, ok := comments[id]; !ok {
				w.WriteHeader(404)
				return
			}
			comments[id] = in.Body
			fmt.Fprint(w, `{}`)
		case r.Method == "POST" && r.URL.Path == api+"/statuses/"+sha1:
			_ = json.Unmarshal(body, &status)
			w.WriteHeader(201)
			fmt.Fprint(w, `{}`)
		default:
			t.Errorf("call outside the subpath API: %s %s", r.Method, r.URL)
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	tg, err := TargetOf(Remote{URL: srv.URL + "/code/acme/config.git", Auth: "bot:fj-token"},
		PullRequest{Provider: ProviderForgejo, Number: 12, HeadSHA: sha1})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	rep := RESTReporter{Client: srv.Client()}
	for _, b := range []string{"first", "second"} {
		if err := rep.UpsertComment(ctx, tg, render.Marker+"\n"+b); err != nil {
			t.Fatal(err)
		}
	}
	if err := rep.SetStatus(ctx, tg, StatusSuccess, "plan: ok"); err != nil {
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
	if status["state"] != StatusSuccess || status["context"] != StatusContext {
		t.Fatalf("status: %v", status)
	}
}
