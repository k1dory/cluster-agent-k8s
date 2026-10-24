package connections

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"agent-sandbox/internal/model"
	res "agent-sandbox/internal/resource"
	"agent-sandbox/internal/secrets"
	"agent-sandbox/internal/store"
)

func doc(name, spec string) *res.Document {
	return &res.Document{Name: name, Spec: json.RawMessage(spec)}
}

func TestConnectionsValidateAndNeverStoreSecrets(t *testing.T) {
	ctx := context.Background()
	s := &Service{Store: store.NewMemory(), Secrets: secrets.Static{"acme/github": "ghp_VALUE", "shared/registry": "reg-VALUE"}}
	for _, bad := range []string{
		`{"type":"ftp","host":"a.example.com"}`,
		`{"type":"http","host":"https://a.example.com"}`,
		`{"type":"http","host":"a.example.com:443"}`,
		`{"type":"http","host":"a.example.com","headers":{"Bad Header":"x"}}`,
		`{"type":"http","host":"a.example.com","headers":{"Authorization":"Bearer ghp_LITERAL"}}`, // a value, not a reference
		`{"type":"http","host":"a.example.com","headers":{"X-Api-Key":"ghp_LITERAL"}}`,
		`{"type":"http","host":"a.example.com","headers":{"Authorization":"Bearer secret:missing"}}`, // not resolvable for acme
		`{"type":"http","host":"a.example.com","headers":{"authorization":"secret:github","Authorization":"secret:github"}}`,
		`{"type":"http","host":"a.example.com","extra":1}`,
	} {
		_, err := s.Put(ctx, "acme", doc("c", bad), false, "alice")
		if !errors.Is(err, res.ErrInvalid) {
			t.Errorf("must be invalid: %s → %v", bad, err)
		}
		if err != nil && strings.Contains(err.Error(), "ghp_LITERAL") {
			t.Errorf("the error echoed a credential: %v", err)
		}
	}
	it, err := s.Put(ctx, "acme", doc("github", `{"type":"http","host":"api.github.com","headers":{"authorization":"Bearer secret:github","X-GitHub-Api-Version":"2022-11-28"}}`), false, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(it.Spec), "ghp_") || !strings.Contains(string(it.Spec), `"Authorization":"Bearer secret:github"`) {
		t.Fatalf("stored spec: %s", it.Spec)
	}
	// Shared connections resolve against the shared secrets; a tenant uses its own first.
	if _, err := s.Put(ctx, "", doc("registry", `{"type":"mcp","host":"mcp.registry.example.com","headers":{"X-Auth-Token":"secret:registry"}}`), true, "admin"); err != nil {
		t.Fatal(err)
	}
	if c, err := s.Canonical(ctx, "acme", "registry"); err != nil || c != "shared/registry" {
		t.Fatalf("canonical shared: %q %v", c, err)
	}
	if c, err := s.Canonical(ctx, "acme", "github"); err != nil || c != "github" {
		t.Fatalf("canonical own: %q %v", c, err)
	}
	if _, err := s.Canonical(ctx, "other", "github"); !errors.Is(err, res.ErrNotFound) {
		t.Fatalf("another tenant's connection must be invisible: %v", err)
	}
	if _, err := s.Canonical(ctx, "acme", "github@1"); !errors.Is(err, res.ErrInvalid) {
		t.Fatalf("pinned connection: %v", err)
	}
	// The gateway side resolves the values; the API side never carries them.
	sp, h, err := s.Headers(ctx, "acme", "github")
	if err != nil || sp.Host != "api.github.com" || h["Authorization"] != "Bearer ghp_VALUE" || h["X-Github-Api-Version"] != "2022-11-28" {
		t.Fatalf("headers: %v %+v %v", err, sp, h)
	}
	list, _ := s.List(ctx, "acme")
	revs, _ := s.Revisions(ctx, "acme", "github")
	for _, items := range [][]*model.CatalogItem{list, revs} {
		b, _ := json.Marshal(items)
		if strings.Contains(string(b), "VALUE") {
			t.Fatalf("a secret value leaked: %s", b)
		}
	}
	if err := s.Delete(ctx, "acme", "github"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Canonical(ctx, "acme", "github"); !errors.Is(err, res.ErrNotFound) {
		t.Fatalf("deleted connection must not resolve: %v", err)
	}
}

type sandboxes map[string]*model.Sandbox

func (s sandboxes) GetSandbox(_ context.Context, id string) (*model.Sandbox, error) {
	if sb, ok := s[id]; ok {
		return sb, nil
	}
	return nil, store.ErrNotFound
}

func TestHeadersForGatewayDecision(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	sbs := sandboxes{
		"own":    {ID: "own", Tenant: "acme", Connections: []string{"github", "shared/registry"}},
		"shared": {ID: "shared", Tenant: "acme", Connections: []string{"shared/registry"}},
		"broken": {ID: "broken", Tenant: "acme", Connections: []string{"nokey"}},
	}
	s := New(st, secrets.Static{"acme/github": "ghp_VALUE", "shared/registry": "reg-VALUE"}, sbs)
	for _, d := range []struct{ tenant, name, spec string }{
		{"acme", "github", `{"type":"http","host":"api.github.com","headers":{"Authorization":"Bearer secret:github","X-Version":"1"}}`},
		{"", "registry", `{"type":"mcp","host":"mcp.registry.example.com","headers":{"X-Auth-Token":"secret:registry"}}`},
	} {
		if _, err := s.Put(ctx, d.tenant, doc(d.name, d.spec), d.tenant == "", "x"); err != nil {
			t.Fatal(err)
		}
	}
	// The gateway's strip/copy list knows every live connection's header names per host.
	names, fp := s.HostHeaders()
	if len(names["api.github.com"]) != 2 || names["mcp.registry.example.com"][0] != "X-Auth-Token" || fp == "" {
		t.Fatalf("host headers: %v %s", names, fp)
	}
	h, err := s.HeadersFor(ctx, "own", "acme", "api.github.com")
	if err != nil || h["Authorization"] != "Bearer ghp_VALUE" || h["X-Version"] != "1" || len(h) != 2 {
		t.Fatalf("own host: %v %v", err, h)
	}
	if h, err := s.HeadersFor(ctx, "own", "acme", "mcp.registry.example.com"); err != nil || h["X-Auth-Token"] != "reg-VALUE" {
		t.Fatalf("shared connection through a tenant sandbox: %v %v", err, h)
	}
	if h, err := s.HeadersFor(ctx, "own", "acme", "other.example.com"); err != nil || h != nil {
		t.Fatalf("host without connections: %v %v", err, h)
	}
	if _, err := s.HeadersFor(ctx, "own", "mallory", "api.github.com"); err == nil {
		t.Fatal("identity tenant must be the sandbox's")
	}
	if h, err := s.HeadersFor(ctx, "gone", "acme", "api.github.com"); err != nil || h != nil {
		t.Fatalf("unknown sandbox: %v %v", err, h)
	}
	// A deleted connection adds nothing; an unresolvable one is an error so nothing partial is sent.
	if err := s.Delete(ctx, "acme", "github"); err != nil {
		t.Fatal(err)
	}
	if h, err := s.HeadersFor(ctx, "own", "acme", "api.github.com"); err != nil || h != nil {
		t.Fatalf("deleted connection: %v %v", err, h)
	}
	if names, _ := s.HostHeaders(); len(names["api.github.com"]) != 0 {
		t.Fatalf("deleted connection still in the gateway list: %v", names)
	}
	if _, err := s.Put(ctx, "acme", doc("nokey", `{"type":"http","host":"api.github.com","headers":{"X-Trace":"secret:absent"}}`), false, "x"); err == nil {
		t.Fatal("unresolvable reference accepted at write")
	}
	s.Secrets = nil // the reference was accepted earlier (another provider); now it does not resolve
	if _, err := s.Put(ctx, "acme", doc("nokey", `{"type":"http","host":"api.github.com","headers":{"X-Trace":"secret:absent"}}`), false, "x"); err != nil {
		t.Fatal(err)
	}
	s.Secrets = secrets.Static{}
	if _, err := s.HeadersFor(ctx, "broken", "acme", "api.github.com"); err == nil {
		t.Fatal("unresolvable reference must fail the decision")
	}
}
