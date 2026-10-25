package httpapi

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"

	"agent-sandbox/internal/gitsync"
	"agent-sandbox/internal/model"
	"agent-sandbox/internal/store"
)

type recordingReporter struct {
	mu       sync.Mutex
	comments []string
	statuses []string
}

func (r *recordingReporter) UpsertComment(_ context.Context, t gitsync.Target, body string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.comments = append(r.comments, t.APIBase+" "+t.Repo+" "+body)
	return nil
}

func (r *recordingReporter) SetStatus(_ context.Context, t gitsync.Target, state, description string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.statuses = append(r.statuses, state+": "+description)
	return nil
}

func deliver(t *testing.T, api, path, event, secret string, body []byte) (*http.Response, []byte) {
	t.Helper()
	req, _ := http.NewRequest("POST", api+path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GitHub-Event", event)
	req.Header.Set("X-GitHub-Delivery", "d-"+event)
	if secret != "" {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(body)
		req.Header.Set("X-Hub-Signature-256", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out bytes.Buffer
	_, _ = out.ReadFrom(resp.Body)
	return resp, out.Bytes()
}

// The webhook route on the real stack: no bearer token, the signature is the credential; a
// push syncs, a pull request gets its plan, the outcome is in the status and on the event
// stream; wrong secrets, unknown repositories and repositories without a webhook are refused.
func TestGitWebhookRouteSyncsAndPlans(t *testing.T) {
	s, git, _ := gitStack(t)
	api := s.platform.URL
	rep := &recordingReporter{}
	s.p.GitSync.Reporter, s.p.GitSync.Inline = rep, true
	env := "kind: EnvironmentProfile\nname: py\nspec: {image: stable}\n"
	git.repos["https://git.example.com/alice/config.git"] = &fakeRepo{auth: "tok-alice", heads: map[string]string{"main": shaA, "refs/pull/5/head": shaB},
		files:   map[string]map[string][]byte{shaA: {"bundles/acme.yaml": []byte(env)}, shaB: {"bundles/acme.yaml": []byte(env + "---\nkind: AgentDefinition\nname: backend\nspec: {policy: backend-dev, environment: py}\n")}},
		history: map[string][]string{"main": {shaA}, "refs/pull/5/head": {shaB}}}
	call(t, "PUT", api+"/v1/credentials/config-token", "alice-tok", map[string]string{"value": "tok-alice"}, nil)
	call(t, "PUT", api+"/v1/credentials/hook-secret", "alice-tok", map[string]string{"value": "s3cret"}, nil)
	repo := `{"spec":{"url":"https://git.example.com/alice/config.git","ref":"main","paths":["bundles/*.yaml"],"credential":"config-token","webhook_secret":"hook-secret"}}`
	if code, _ := putDoc(t, api, "alice-tok", "gitrepos", "config", repo); code != 201 {
		t.Fatalf("register: %d", code)
	}
	push := []byte(`{"ref":"refs/heads/main","after":"` + shaA + `","repository":{"clone_url":"https://git.example.com/alice/config.git"}}`)
	// Refusals first: wrong secret, unsigned, unknown repository, the shared scope, no provider header.
	if resp, _ := deliver(t, api, "/hooks/git/alice/config", "push", "wrong", push); resp.StatusCode != 401 {
		t.Fatalf("wrong secret: %d", resp.StatusCode)
	}
	if resp, _ := deliver(t, api, "/hooks/git/alice/config", "push", "", push); resp.StatusCode != 401 {
		t.Fatalf("unsigned: %d", resp.StatusCode)
	}
	if resp, _ := deliver(t, api, "/hooks/git/alice/nope", "push", "s3cret", push); resp.StatusCode != 404 {
		t.Fatalf("unknown repository: %d", resp.StatusCode)
	}
	if resp, _ := deliver(t, api, "/hooks/git/-/config", "push", "s3cret", push); resp.StatusCode != 404 {
		t.Fatalf("the shared scope has no such repository: %d", resp.StatusCode)
	}
	if resp, _ := deliver(t, api, "/hooks/git/bob/config", "push", "s3cret", push); resp.StatusCode != 404 {
		t.Fatalf("another tenant's name: %d", resp.StatusCode)
	}
	req, _ := http.NewRequest("POST", api+"/hooks/git/alice/config", bytes.NewReader(push))
	if resp, err := http.DefaultClient.Do(req); err != nil || resp.StatusCode != 400 {
		t.Fatalf("no provider header: %v %d", err, resp.StatusCode)
	}
	if resp, _ := call(t, "GET", api+"/v1/environments/py", "alice-tok", nil, nil); resp.StatusCode != 404 {
		t.Fatal("a refused delivery wrote")
	}
	// A push: 202, the sync ran with alice's authority, the status and the events say so.
	resp, body := deliver(t, api, "/hooks/git/alice/config", "push", "s3cret", push)
	var h model.GitHook
	_ = json.Unmarshal(body, &h)
	if resp.StatusCode != 202 || h.Action != model.HookActionSync || h.Outcome != model.GitSyncDone || h.Commit != shaA {
		t.Fatalf("push: %d %s", resp.StatusCode, body)
	}
	var env1 model.CatalogItem
	if resp, body := call(t, "GET", api+"/v1/environments/py", "alice-tok", nil, nil); resp.StatusCode != 200 {
		t.Fatalf("synced environment: %d %s", resp.StatusCode, body)
	} else {
		_ = json.Unmarshal(body, &env1)
	}
	if env1.Source == nil || env1.Source.Commit != shaA || env1.Source.Apply == "" {
		t.Fatalf("synced environment source: %+v", env1.Source)
	}
	resp, body = call(t, "GET", api+"/v1/gitrepos/config/status", "alice-tok", nil, nil)
	g := syncOf(t, body)
	if resp.StatusCode != 200 || g.Hook == nil || g.Hook.Provider != "github" || g.Hook.Action != model.HookActionSync || g.Sync == nil || g.Sync.Commit != shaA {
		t.Fatalf("status after the push: %d %s", resp.StatusCode, body)
	}
	// A pull request: 202, the plan is posted to the registered repository's API with the
	// credential, the status set, nothing written.
	pr := []byte(`{"action":"opened","number":5,"pull_request":{"number":5,"head":{"sha":"` + shaB + `"}},"repository":{"clone_url":"https://git.example.com/alice/config.git"}}`)
	resp, body = deliver(t, api, "/hooks/git/alice/config", "pull_request", "s3cret", pr)
	_ = json.Unmarshal(body, &h)
	if resp.StatusCode != 202 || h.Action != model.HookActionPlan || h.Outcome != model.GitSyncDone || h.Number != 5 {
		t.Fatalf("pull request: %d %s", resp.StatusCode, body)
	}
	rep.mu.Lock()
	if len(rep.comments) != 1 || !strings.HasPrefix(rep.comments[0], "https://git.example.com/api/v3 alice/config <!-- agent-sandbox -->") || !strings.Contains(rep.comments[0], "1 to create, 0 to update, 1 unchanged") {
		t.Fatalf("plan comment: %q", rep.comments)
	}
	if len(rep.statuses) != 1 || !strings.HasPrefix(rep.statuses[0], "success: plan: 1 to apply") {
		t.Fatalf("plan status: %q", rep.statuses)
	}
	rep.mu.Unlock()
	if resp, _ := call(t, "GET", api+"/v1/agents/backend", "alice-tok", nil, nil); resp.StatusCode != 404 {
		t.Fatal("a plan wrote")
	}
	// Ignored: another branch, 200 with the reason.
	other := []byte(`{"ref":"refs/heads/feature","after":"` + shaB + `","repository":{"clone_url":"https://git.example.com/alice/config.git"}}`)
	resp, body = deliver(t, api, "/hooks/git/alice/config", "push", "s3cret", other)
	_ = json.Unmarshal(body, &h)
	if resp.StatusCode != 200 || h.Action != model.HookActionIgnored || !strings.Contains(h.Reason, "another ref") {
		t.Fatalf("other branch: %d %s", resp.StatusCode, body)
	}
	// Events on the tenant's stream: git.hook when a delivery is accepted and when its job ends
	// (two acted on, one ignored: five), a git.sync, a git.plan.
	evs, err := s.orch.Store.QueryEvents(context.Background(), store.Filter{Tenant: "alice", Types: []string{"git.hook", "git.sync", "git.plan"}, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	types := map[string]int{}
	for _, e := range evs {
		types[e.Type]++
		if e.SandboxID != "git:config" {
			t.Fatalf("event key: %+v", e)
		}
	}
	if types["git.hook"] != 5 || types["git.sync"] != 1 || types["git.plan"] != 1 {
		t.Fatalf("events: %v", types)
	}
	// A repository without a webhook secret: deliveries are not found, nothing recorded.
	if code, _ := putDoc(t, api, "alice-tok", "gitrepos", "plain", `{"spec":{"url":"https://git.example.com/alice/plain.git","ref":"main","paths":["b.yaml"]}}`); code != 201 {
		t.Fatalf("plain repository: %d", code)
	}
	if resp, _ := deliver(t, api, "/hooks/git/alice/plain", "push", "s3cret", push); resp.StatusCode != 404 {
		t.Fatalf("repository without a webhook: %d", resp.StatusCode)
	}
	// The webhook secret is revoked: 503, nothing happens; a wrong signature stays 401 after restoring it.
	call(t, "DELETE", api+"/v1/credentials/hook-secret", "alice-tok", nil, nil)
	if resp, _ := deliver(t, api, "/hooks/git/alice/config", "push", "s3cret", push); resp.StatusCode != 503 {
		t.Fatalf("revoked webhook secret: %d", resp.StatusCode)
	}
}
