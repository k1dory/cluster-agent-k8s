package gitsync

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"agent-sandbox/internal/apply"
	"agent-sandbox/internal/gitrepo"
	"agent-sandbox/internal/model"
	"agent-sandbox/internal/plan"
	"agent-sandbox/internal/policy"
	res "agent-sandbox/internal/resource"
	"agent-sandbox/internal/secrets"
	"agent-sandbox/internal/store"
)

type images struct{}

func (images) ResolveVersion(v string, admin bool) (string, error) {
	if v == "stable" || admin {
		return "registry/agent:" + v, nil
	}
	return "", fmt.Errorf("unknown version %q", v)
}

// breaking fails the apply step of one named item while armed.
type breaking struct {
	store.Store
	mu   sync.Mutex
	item string
}

func (b *breaking) arm(name string) { b.mu.Lock(); b.item = name; b.mu.Unlock() }

func (b *breaking) ApplyStep(ctx context.Context, a *model.Apply, step int, it *model.CatalogItem, expected int) error {
	b.mu.Lock()
	item := b.item
	b.mu.Unlock()
	if it != nil && it.Name == item {
		return errors.New("database went away")
	}
	return b.Store.ApplyStep(ctx, a, step, it, expected)
}

// memFetcher serves one ref and the files of its commits.
type memFetcher struct {
	head  string
	files map[string]map[string][]byte
	auth  string
}

func (m memFetcher) Resolve(_ context.Context, r Remote) (string, error) {
	if r.Auth != m.auth {
		return "", errors.New("the server refused the credential (HTTP 401)")
	}
	return m.head, nil
}

func (m memFetcher) Files(_ context.Context, r Remote, commit string, patterns []string) (map[string][]byte, error) {
	if r.Auth != m.auth {
		return nil, errors.New("the server refused the credential (HTTP 401)")
	}
	files, ok := m.files[commit]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrNotOnRef, commit)
	}
	out := map[string][]byte{}
	for p, b := range files {
		if Matches(p, patterns) {
			out[p] = b
		}
	}
	if len(out) == 0 {
		return nil, ErrNoMatch
	}
	return out, nil
}

const sha1 = "1111111111111111111111111111111111111111"

func newService(t *testing.T, fetch Fetcher) (*Service, *breaking) {
	t.Helper()
	st := &breaking{Store: store.NewMemory()}
	pols := policy.FromPolicies(&policy.Policy{Slug: "backend-dev", Tenants: []string{"acme"}, Allow: []policy.Rule{{Host: "h.example.com", Paths: []string{"/"}}}})
	pols.Strict = true
	sec := secrets.Static{"acme/repo-token": "tok"}
	planner := plan.Deps{Store: st, Policies: pols, Images: images{}, Secrets: sec}
	applier := &apply.Controller{Store: st, Planner: planner, Replica: "r1"}
	repos := gitrepo.New(st, sec)
	return &Service{Store: st, Repos: repos, Secrets: sec, Fetch: fetch, Applier: applier}, st
}

func register(t *testing.T, s *Service, tenant, name, yaml string) {
	t.Helper()
	docs, err := res.ParseYAMLAll([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Repos.Put(context.Background(), tenant, docs[0], tenant == "", "tester"); err != nil {
		t.Fatal(err)
	}
}

// A sync whose second bundle's apply stops: the first bundle is applied, the record says
// which apply stopped, and syncing the same commit again continues that apply without
// re-applying the first bundle or the done step.
func TestSyncStopsAtAStoppedApplyAndContinuesItOnTheNextSyncOfTheCommit(t *testing.T) {
	ctx := context.Background()
	fetch := memFetcher{head: sha1, auth: "tok", files: map[string]map[string][]byte{sha1: {
		"bundles/a-env.yaml":   []byte("kind: EnvironmentProfile\nname: py\nspec: {image: stable}\n"),
		"bundles/b-agent.yaml": []byte("kind: EnvironmentProfile\nname: go\nspec: {image: stable}\n---\nkind: AgentDefinition\nname: backend\nspec: {policy: backend-dev, environment: go}\n"),
		"notes.md":             []byte("x"),
	}}}
	s, st := newService(t, fetch)
	register(t, s, "acme", "config", "kind: GitRepository\nname: config\nspec: {url: https://git.example.com/acme/config.git, ref: main, paths: ['bundles/*.yaml'], credential: repo-token}\n")
	scope := plan.Scope{Tenant: "acme", Subject: "alice"}
	st.arm("backend")
	g, err := s.Sync(ctx, scope, "config", "")
	if !errors.Is(err, ErrStopped) || g.Status != model.GitSyncStopped || len(g.Bundles) != 2 || g.Bundles[0].Status != model.ApplyDone || g.Bundles[1].Status != model.ApplyFailed || g.Commit != sha1 || g.Head != sha1 {
		t.Fatalf("stopped sync: %v %+v", err, g)
	}
	stopped := g.Bundles[1].Apply
	if n := revs(t, st, model.KindEnvironment, "acme", "go"); n != 1 {
		t.Fatalf("the stopped apply's first step should have been written once: %d", n)
	}
	// The record is what Status returns.
	if got, err := s.Status(ctx, scope, "config"); err != nil || got.Status != model.GitSyncStopped || got.Bundles[1].Apply != stopped {
		t.Fatalf("status: %v %+v", err, got)
	}
	// Fixed: the same commit again continues the same applies; nothing is applied twice.
	st.arm("")
	g, err = s.Sync(ctx, scope, "config", sha1)
	if err != nil || g.Status != model.GitSyncDone || g.Bundles[1].Apply != stopped || g.Bundles[1].Status != model.ApplyDone || g.Bundles[1].Changes != 2 {
		t.Fatalf("continued sync: %v %+v", err, g)
	}
	for _, name := range []string{"py", "go"} {
		if n := revs(t, st, model.KindEnvironment, "acme", name); n != 1 {
			t.Fatalf("%s: %d revisions after the continuation", name, n)
		}
	}
	it, err := st.GetItem(ctx, model.KindAgent, "acme", "backend", 0)
	if err != nil || it.Source == nil || it.Source.Commit != sha1 || it.Source.Path != "bundles/b-agent.yaml" || it.Source.Apply != stopped || it.Source.Repo != "https://git.example.com/acme/config.git" {
		t.Fatalf("agent source: %v %+v", err, it)
	}
	// And once more: the same record, no writes.
	if g, err := s.Sync(ctx, scope, "config", ""); err != nil || g.Bundles[0].Apply == "" || g.Bundles[1].Apply != stopped {
		t.Fatalf("third sync: %v %+v", err, g)
	}
	if n := revs(t, st, model.KindAgent, "acme", "backend"); n != 1 {
		t.Fatalf("agent revisions after a third sync: %d", n)
	}
	// Applies carry the key of repository, commit and path.
	a, err := st.GetApplyByKey(ctx, "acme", Key("config", sha1, "bundles/b-agent.yaml"))
	if err != nil || a.ID != stopped || a.Attempt != 2 {
		t.Fatalf("apply by key: %v %+v", err, a)
	}
}

func TestSyncRefusesWhatTheTenantMayNotDoAndRecordsCredentialLoss(t *testing.T) {
	ctx := context.Background()
	fetch := memFetcher{head: sha1, auth: "tok", files: map[string]map[string][]byte{sha1: {
		"bundles/grant.yaml": []byte("kind: PolicyBinding\nname: backend-dev\nspec: {}\n"),
	}}}
	s, st := newService(t, fetch)
	register(t, s, "acme", "config", "kind: GitRepository\nname: config\nspec: {url: https://git.example.com/acme/config.git, ref: main, paths: ['bundles/*.yaml'], credential: repo-token}\n")
	scope := plan.Scope{Tenant: "acme", Subject: "alice"}
	// The admin triggers it: still the tenant's authority, so the grant is refused.
	g, err := s.Sync(ctx, plan.Scope{Tenant: "acme", Admin: true, Subject: "root"}, "config", "")
	if !errors.Is(err, ErrInvalid) || g.Status != model.GitSyncInvalid || !strings.Contains(strings.Join(g.Bundles[0].Errors, " "), "admin only") {
		t.Fatalf("a grant in a tenant's repository: %v %+v", err, g)
	}
	if n := revs(t, st, model.KindBinding, "acme", "backend-dev"); n != 0 {
		t.Fatal("the refused bundle wrote")
	}
	// The credential disappears: ErrCredential, nothing fetched, the record says which name.
	s.Secrets = secrets.Static{}
	g, err = s.Check(ctx, scope, "config")
	if !errors.Is(err, ErrCredential) || !strings.Contains(g.CheckError, `"repo-token"`) || strings.Contains(g.CheckError, "tok") && !strings.Contains(g.CheckError, "token") {
		t.Fatalf("check without the credential: %v %+v", err, g)
	}
	if g, err := s.Sync(ctx, scope, "config", ""); !errors.Is(err, ErrCredential) || g.Status != model.GitSyncError {
		t.Fatalf("sync without the credential: %v %+v", err, g)
	}
	// A wrong credential is the server's refusal.
	s.Secrets = secrets.Static{"acme/repo-token": "wrong"}
	if g, err := s.Check(ctx, scope, "config"); !errors.Is(err, ErrRead) || !strings.Contains(g.CheckError, "401") {
		t.Fatalf("check with a refused credential: %v %+v", err, g)
	}
	// Another tenant: not found; a shared repository: forbidden for the tenant.
	if _, err := s.Check(ctx, plan.Scope{Tenant: "other"}, "config"); !errors.Is(err, res.ErrNotFound) {
		t.Fatalf("another tenant: %v", err)
	}
	register(t, s, "", "platform", "kind: GitRepository\nname: platform\nspec: {url: https://git.example.com/platform/config.git, ref: main, paths: ['bundles/*.yaml']}\n")
	if _, err := s.Sync(ctx, scope, "platform", ""); !errors.Is(err, res.ErrForbidden) {
		t.Fatalf("a tenant syncing the shared repository: %v", err)
	}
	if _, err := s.Sync(ctx, scope, "config", "nope"); !errors.Is(err, res.ErrInvalid) {
		t.Fatalf("a non-SHA: %v", err)
	}
}

func revs(t *testing.T, st store.Catalog, kind, tenant, name string) int {
	t.Helper()
	r, err := st.ListRevisions(context.Background(), kind, tenant, name)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		t.Fatal(err)
	}
	return len(r)
}
