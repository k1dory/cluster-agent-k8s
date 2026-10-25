package httpapi

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"agent-sandbox/internal/app"
	"agent-sandbox/internal/credentials"
	"agent-sandbox/internal/gitsync/gittest"
	"agent-sandbox/internal/model"
	"agent-sandbox/internal/policy"
	"agent-sandbox/internal/secrets"
)

// The whole path with nothing faked: a repository served by git's own http-backend behind
// basic authentication, read by the shipped fetcher (the git binary) that app.Wire installs by
// default, applied by the real controller, with the tenant's BYOK credential.
func TestGitRepositorySyncFromARealGitServer(t *testing.T) {
	srv := gittest.New(t, "x-access-token", "tok-real-1")
	s := newStack(t)
	pols := policy.FromPolicies(&policy.Policy{Slug: "backend-dev", Tenants: []string{"alice"}, Allow: []policy.Rule{{Host: "api.github.com", Paths: []string{"/**"}}}})
	pols.Strict = true
	s.p.Policies = pols
	s.orch.Cfg.Versions = map[string]string{"stable": "reg/agent:1.0"}
	key, _ := credentials.ParseKey(strings.Repeat("ab", 32))
	creds, err := credentials.New(s.orch.Store, key)
	if err != nil {
		t.Fatal(err)
	}
	services, err := app.Wire(context.Background(), app.Deps{Store: s.orch.Store, Policies: pols, Secrets: secrets.Chain{credentials.Resolver{Service: creds}}, Orch: s.orch})
	if err != nil {
		t.Fatal(err)
	}
	services.Install(s.p)
	s.p.Credentials = creds
	api := s.platform.URL

	sha1 := srv.Commit(t, map[string]string{"bundles/acme.yaml": "kind: EnvironmentProfile\nname: py\nspec: {image: stable}\n---\nkind: AgentDefinition\nname: backend\nspec: {policy: backend-dev, environment: py}\n"}, "one")
	call(t, "PUT", api+"/v1/credentials/config-token", "alice-tok", map[string]string{"value": "tok-real-1"}, nil)
	repo := `{"spec":{"url":"` + srv.URL + `","ref":"main","paths":["bundles/*.yaml"],"credential":"config-token"}}`
	if code, _ := putDoc(t, api, "alice-tok", "gitrepos", "config", repo); code != 201 {
		t.Fatalf("register: %d", code)
	}
	resp, body := call(t, "POST", api+"/v1/gitrepos/config/check", "alice-tok", nil, nil)
	if g := syncOf(t, body); resp.StatusCode != 200 || g.Check.Head != sha1 {
		t.Fatalf("check: %d %s", resp.StatusCode, body)
	}
	resp, body = call(t, "POST", api+"/v1/gitrepos/config/sync", "alice-tok", nil, nil)
	g := syncOf(t, body)
	if resp.StatusCode != 200 || g.Sync.Status != model.GitSyncDone || g.Sync.Commit != sha1 || len(g.Sync.Bundles) != 1 || g.Sync.Bundles[0].Changes != 2 {
		t.Fatalf("sync: %d %s", resp.StatusCode, body)
	}
	var agent model.CatalogItem
	_, body = call(t, "GET", api+"/v1/agents/backend", "alice-tok", nil, nil)
	_ = json.Unmarshal(body, &agent)
	if agent.Source == nil || agent.Source.Commit != sha1 || agent.Source.Repo != srv.URL || agent.Source.Path != "bundles/acme.yaml" {
		t.Fatalf("agent source: %+v", agent.Source)
	}
	// A second commit; the old one stays syncable and still writes nothing; the new one applies.
	sha2 := srv.Commit(t, map[string]string{"bundles/acme.yaml": "kind: EnvironmentProfile\nname: py\nspec: {image: stable, env: {LOG: debug}}\n---\nkind: AgentDefinition\nname: backend\nspec: {policy: backend-dev, environment: py}\n"}, "two")
	if resp, body := call(t, "POST", api+"/v1/gitrepos/config/sync", "alice-tok", map[string]string{"commit": sha1}, nil); resp.StatusCode != 200 || syncOf(t, body).Sync.Bundles[0].Apply != g.Sync.Bundles[0].Apply {
		t.Fatalf("re-sync of the first commit: %d %s", resp.StatusCode, body)
	}
	resp, body = call(t, "POST", api+"/v1/gitrepos/config/sync", "alice-tok", nil, nil)
	if g := syncOf(t, body); resp.StatusCode != 200 || g.Sync.Commit != sha2 || g.Sync.Bundles[0].Changes != 1 {
		t.Fatalf("sync of the second commit: %d %s", resp.StatusCode, body)
	}
	var revs []model.CatalogItem
	_, body = call(t, "GET", api+"/v1/environments/py/revisions", "alice-tok", nil, nil)
	_ = json.Unmarshal(body, &revs)
	if len(revs) != 2 || revs[1].Source.Commit != sha2 {
		t.Fatalf("revisions: %s", body)
	}
	// The wrong credential at the real server: 502, the value nowhere in the answer.
	call(t, "PUT", api+"/v1/credentials/config-token", "alice-tok", map[string]string{"value": "tok-wrong"}, nil)
	resp, body = call(t, "POST", api+"/v1/gitrepos/config/check", "alice-tok", nil, nil)
	if g := syncOf(t, body); resp.StatusCode != 502 || !strings.Contains(g.Check.Error, "401") || strings.Contains(string(body), "tok-") {
		t.Fatalf("check with a wrong credential: %d %s", resp.StatusCode, body)
	}
	// The server gone: 502 and the record says so.
	srv.Close()
	call(t, "PUT", api+"/v1/credentials/config-token", "alice-tok", map[string]string{"value": "tok-real-1"}, nil)
	if resp, body := call(t, "POST", api+"/v1/gitrepos/config/sync", "alice-tok", nil, nil); resp.StatusCode != 502 || syncOf(t, body).Sync.Status != model.GitSyncError {
		t.Fatalf("sync against a stopped server: %d %s", resp.StatusCode, body)
	}
}
