package credentials

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"agent-sandbox/internal/model"
	"agent-sandbox/internal/secrets"
	"agent-sandbox/internal/store"
)

func TestBringYourOwnKey(t *testing.T) {
	ctx := context.Background()
	key, _ := ParseKey(strings.Repeat("ab", 32))
	st := store.NewMemory()
	s, err := New(st, key)
	if err != nil {
		t.Fatal(err)
	}
	// Add: metadata comes back, the value does not, not even in JSON.
	c, created, err := s.Put(ctx, "acme", "anthropic", "sk-ant-SECRET", "key:key_1")
	if err != nil || !created || c.Version != 1 || c.Fingerprint == "" || c.CreatedBy != "key:key_1" || c.CreatedAt.IsZero() {
		t.Fatalf("put: %v %v %+v", err, created, c)
	}
	if b, _ := json.Marshal(c); strings.Contains(string(b), "SECRET") || strings.Contains(string(b), "ciphertext") {
		t.Fatalf("metadata leaks: %s", b)
	}
	// The store holds ciphertext only.
	_, ct, _ := st.GetCredential(ctx, "acme", "anthropic")
	if strings.Contains(string(ct), "SECRET") || len(ct) < 12+len("sk-ant-SECRET") {
		t.Fatalf("ciphertext: %q", ct)
	}
	// The gateway resolves it as a provider; a tenant's own wins over a shared one; other
	// tenants do not see it.
	r := Resolver{Service: s}
	if v, err := r.Get(ctx, "acme", "anthropic"); err != nil || v != "sk-ant-SECRET" {
		t.Fatalf("resolve: %v %q", err, v)
	}
	if _, err := r.Get(ctx, "other", "anthropic"); !errors.Is(err, secrets.ErrNotFound) {
		t.Fatalf("another tenant: %v", err)
	}
	if _, _, err := s.Put(ctx, "", "anthropic", "shared-value", "admin"); err != nil {
		t.Fatal(err)
	}
	if v, _ := r.Get(ctx, "other", "anthropic"); v != "shared-value" {
		t.Fatalf("shared fallback: %q", v)
	}
	if v, _ := r.Get(ctx, "acme", "anthropic"); v != "sk-ant-SECRET" {
		t.Fatalf("own before shared: %q", v)
	}
	// Replace: a new version and fingerprint, the creation record kept, the new value resolved.
	c2, created, err := s.Put(ctx, "acme", "anthropic", "sk-ant-ROTATED", "key:key_2")
	if err != nil || created || c2.Version != 2 || c2.Fingerprint == c.Fingerprint || c2.CreatedBy != "key:key_1" || !c2.CreatedAt.Equal(c.CreatedAt) {
		t.Fatalf("replace: %v %v %+v", err, created, c2)
	}
	if v, _ := r.Get(ctx, "acme", "anthropic"); v != "sk-ant-ROTATED" {
		t.Fatalf("after replace: %q", v)
	}
	// Chained in front of the operator's provider: the tenant's credential wins, the operator's
	// still answers for everything else.
	chain := secrets.Chain{r, secrets.Static{"acme/anthropic": "operator-value", "acme/github": "ghp_operator"}}
	if v, _ := chain.Get(ctx, "acme", "anthropic"); v != "sk-ant-ROTATED" {
		t.Fatalf("chain: tenant credential must win: %q", v)
	}
	if v, _ := chain.Get(ctx, "acme", "github"); v != "ghp_operator" {
		t.Fatalf("chain: operator fallback: %q", v)
	}
	if _, err := chain.Get(ctx, "acme", "nothing"); !errors.Is(err, secrets.ErrNotFound) {
		t.Fatalf("chain: missing: %v", err)
	}
	// Revoke: gone for the resolver at once. The shared credential of the same name shows
	// through first, and once that is gone too, the operator's value.
	if err := s.Delete(ctx, "acme", "anthropic"); err != nil {
		t.Fatal(err)
	}
	if v, _ := chain.Get(ctx, "acme", "anthropic"); v != "shared-value" {
		t.Fatalf("after revoke, shared next: %q", v)
	}
	if err := s.Delete(ctx, "", "anthropic"); err != nil {
		t.Fatal(err)
	}
	if v, _ := chain.Get(ctx, "acme", "anthropic"); v != "operator-value" {
		t.Fatalf("after revoke, operator last: %q", v)
	}
	if err := s.Delete(ctx, "acme", "anthropic"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("delete twice: %v", err)
	}
	// Validation.
	for _, bad := range []struct{ name, value string }{{"", "x"}, {"bad/name", "x"}, {"-lead", "x"}, {strings.Repeat("n", 65), "x"}, {"ok", ""}, {"ok", strings.Repeat("v", MaxValue+1)}} {
		if _, _, err := s.Put(ctx, "acme", bad.name, bad.value, "x"); !errors.Is(err, ErrInvalid) {
			t.Errorf("%q/%d accepted: %v", bad.name, len(bad.value), err)
		}
	}
	// A ciphertext moved to another scope or name does not open; another key does not open it.
	if _, _, err := s.Put(ctx, "acme", "token", "t0ken", "x"); err != nil {
		t.Fatal(err)
	}
	_, ct, _ = st.GetCredential(ctx, "acme", "token")
	moved := storedMeta("mallory", "token")
	if _, err := st.PutCredential(ctx, &moved, ct); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Get(ctx, "mallory", "token"); err == nil || errors.Is(err, secrets.ErrNotFound) {
		t.Fatalf("moved ciphertext must not decrypt: %v", err)
	}
	other, _ := New(st, []byte(strings.Repeat("k", 32)))
	if _, err := (Resolver{Service: other}).Get(ctx, "acme", "token"); err == nil || !strings.Contains(err.Error(), "cannot decrypt") {
		t.Fatalf("another key: %v", err)
	}
	list, _ := s.List(ctx, "acme")
	if len(list) != 1 || list[0].Name != "token" {
		t.Fatalf("list: %+v", list)
	}
}

func TestParseKey(t *testing.T) {
	if k, err := ParseKey(""); err != nil || k != nil {
		t.Fatal("empty disables")
	}
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i)
	}
	if k, err := ParseKey(hex.EncodeToString(raw)); err != nil || len(k) != 32 || k[31] != 31 {
		t.Fatalf("hex: %v", err)
	}
	if k, err := ParseKey("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="); err != nil || len(k) != 32 {
		t.Fatalf("base64: %v", err)
	}
	for _, bad := range []string{"short", strings.Repeat("ab", 16), "not hex not base64!!"} {
		if _, err := ParseKey(bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
	if _, err := New(store.NewMemory(), []byte("short")); err == nil {
		t.Fatal("short key accepted")
	}
}

func storedMeta(tenant, name string) model.Credential {
	return model.Credential{Tenant: tenant, Name: name}
}
