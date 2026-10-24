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
