package httpapi

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"agent-sandbox/internal/app"
	"agent-sandbox/internal/gitsync"
	"agent-sandbox/internal/model"
	"agent-sandbox/internal/policy"
	"agent-sandbox/internal/secrets"
)

// overLimitGit refuses every file set the way gitsync.CLI does past MaxFiles / MaxTotal.
type overLimitGit struct{ *fakeGit }

func (overLimitGit) Files(context.Context, gitsync.Remote, string, []string) (map[string][]byte, error) {
	return nil, fmt.Errorf("%w: the files matching the paths are more than %d bytes together", gitsync.ErrTooLarge, gitsync.MaxTotal)
}

// A bundle set over the fetch bounds used to surface as 502 "the repository could not be
// read", as if the server were down. It is the repository's content: 422, nothing applied.
func TestOversizedBundleSetIsUnprocessableRound2(t *testing.T) {
	s := newStack(t)
	pols := policy.FromPolicies(&policy.Policy{Slug: "backend-dev", Tenants: []string{"alice"}})
	s.p.Policies = pols
	git := &fakeGit{repos: map[string]*fakeRepo{"https://git.example.com/alice/big.git": {
		heads: map[string]string{"main": shaA}, history: map[string][]string{"main": {shaA}}}}}
	services, err := app.Wire(context.Background(), app.Deps{Store: s.orch.Store, Policies: pols, Secrets: secrets.Static{}, Orch: s.orch, Fetch: overLimitGit{git}})
	if err != nil {
		t.Fatal(err)
	}
	services.Install(s.p)
	api := s.platform.URL
	repo := `{"spec":{"url":"https://git.example.com/alice/big.git","ref":"main","paths":["bundles/*.yaml"]}}`
	if code, _ := putDoc(t, api, "alice-tok", "gitrepos", "big", repo); code != 201 {
		t.Fatalf("register: %d", code)
	}
	resp, body := call(t, "POST", api+"/v1/gitrepos/big/sync", "alice-tok", nil, nil)
	g := syncOf(t, body)
	if resp.StatusCode != 422 || !strings.Contains(string(body), "too large") || g.Sync.Status != model.GitSyncInvalid || len(g.Sync.Bundles) != 0 {
		t.Fatalf("an oversized bundle set: %d %s", resp.StatusCode, body)
	}
}
