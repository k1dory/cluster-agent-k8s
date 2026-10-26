package store

import (
	"errors"
	"testing"
	"time"

	"agent-sandbox/internal/model"
)

func TestMemoryTrustedKeysAndTokenUses(t *testing.T) {
	trustedKeysAndTokenUses(t, NewMemory())
}

func TestPostgresTrustedKeysAndTokenUses(t *testing.T) {
	trustedKeysAndTokenUses(t, reviewOpenPostgres(t, reviewPostgresURL(t, false)))
}

// A key a CITrust issued keeps the trust's name through every read; the prune removes only
// the trusted keys that expired before the cut, never a person's key and never one still
// valid; a key is deleted outright on request. A token id is used once, with its key, until
// the record expires; an expired record no longer blocks the id.
func trustedKeysAndTokenUses(t *testing.T, st interface {
	APIKeys
	TokenUses
}) {
	t.Helper()
	ctx := t.Context()
	now := time.Now().Truncate(time.Microsecond)
	past, future := now.Add(-time.Hour), now.Add(time.Hour)
	keys := []*model.APIKey{
		{ID: "key_ci_old", Tenant: "acme", Name: "ci.github", Hash: "h1", CreatedAt: now.Add(-2 * time.Hour), ExpiresAt: &past, Trust: "github"},
		{ID: "key_ci_live", Tenant: "acme", Name: "ci.github", Hash: "h2", CreatedAt: now, ExpiresAt: &future, Trust: "github"},
		{ID: "key_person_old", Tenant: "acme", Name: "laptop", Hash: "h3", CreatedAt: now.Add(-2 * time.Hour), ExpiresAt: &past},
		{ID: "key_person", Tenant: "acme", Name: "server", Hash: "h4", CreatedAt: now},
	}
	for _, k := range keys {
		if err := st.CreateAPIKey(ctx, k); err != nil {
			t.Fatal(err)
		}
	}
	got, err := st.GetAPIKey(ctx, "key_ci_live")
	if err != nil || got.Trust != "github" || got.ExpiresAt == nil || !got.ExpiresAt.Equal(future) {
		t.Fatalf("trusted key read back: %+v %v", got, err)
	}
	listed, err := st.ListAPIKeys(ctx, "acme")
	if err != nil {
		t.Fatal(err)
	}
	trusts := map[string]string{}
	for _, k := range listed {
		trusts[k.ID] = k.Trust
	}
	if len(listed) != 4 || trusts["key_ci_old"] != "github" || trusts["key_ci_live"] != "github" || trusts["key_person"] != "" {
		t.Fatalf("list: %+v", trusts)
	}
	n, err := st.PruneTrustedAPIKeys(ctx, now)
	if err != nil || n != 1 {
		t.Fatalf("prune: %d %v", n, err)
	}
	if _, err := st.GetAPIKey(ctx, "key_ci_old"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("the expired trusted key must be gone: %v", err)
	}
	for _, id := range []string{"key_ci_live", "key_person_old", "key_person"} {
		if _, err := st.GetAPIKey(ctx, id); err != nil {
			t.Fatalf("%s must survive the prune: %v", id, err)
		}
	}
	if n, err := st.PruneTrustedAPIKeys(ctx, now); err != nil || n != 0 {
		t.Fatalf("second prune: %d %v", n, err)
	}
	// A key withdrawn outright (its token turned out used): gone, and gone only once.
	if err := st.DeleteAPIKey(ctx, "key_ci_live"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetAPIKey(ctx, "key_ci_live"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a deleted key must be gone: %v", err)
	}
	if err := st.DeleteAPIKey(ctx, "key_ci_live"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleting it again: %v", err)
	}
	if listed, _ := st.ListAPIKeys(ctx, "acme"); len(listed) != 2 {
		t.Fatalf("list after the delete: %d keys", len(listed))
	}

	// A token's use and its key are one write: the second write for the same token stores
	// nothing (no key), another token id is free, and the record names the key it issued.
	k1 := &model.APIKey{ID: "key_tok_1", Tenant: "acme", Name: "ci.github", Hash: "h5", Trust: "github", ExpiresAt: &future}
	if err := st.IssueForToken(ctx, "https://idp#jti-1", future, k1); err != nil {
		t.Fatal(err)
	}
	k2 := &model.APIKey{ID: "key_tok_2", Tenant: "acme", Name: "ci.github", Hash: "h6", Trust: "github", ExpiresAt: &future}
	if err := st.IssueForToken(ctx, "https://idp#jti-1", future, k2); !errors.Is(err, ErrConflict) {
		t.Fatalf("a second use must conflict: %v", err)
	}
	if _, err := st.GetAPIKey(ctx, "key_tok_2"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("the key of a refused use must not be stored: %v", err)
	}
	if owner, err := st.TokenUse(ctx, "https://idp#jti-1"); err != nil || owner != "key_tok_1" {
		t.Fatalf("the record names the key it issued: %q %v", owner, err)
	}
	if owner, err := st.TokenUse(ctx, "https://idp#jti-none"); err != nil || owner != "" {
		t.Fatalf("an unknown token has no key: %q %v", owner, err)
	}
	if err := st.IssueForToken(ctx, "https://idp#jti-2", future, k2); err != nil {
		t.Fatalf("another id is free: %v", err)
	}
	if got, err := st.GetAPIKey(ctx, "key_tok_2"); err != nil || got.Trust != "github" {
		t.Fatalf("the key stored with the use: %+v %v", got, err)
	}
	// A record that expired is dropped on the next write: the id is free again (the token
	// itself is past its exp and the leeway by then, so the exchange refuses it anyway).
	k3 := &model.APIKey{ID: "key_tok_3", Tenant: "acme", Name: "ci.github", Hash: "h7", Trust: "github", ExpiresAt: &future}
	if err := st.IssueForToken(ctx, "https://idp#jti-3", past, k3); err != nil {
		t.Fatal(err)
	}
	k4 := &model.APIKey{ID: "key_tok_4", Tenant: "acme", Name: "ci.github", Hash: "h8", Trust: "github", ExpiresAt: &future}
	if err := st.IssueForToken(ctx, "https://idp#jti-3", future, k4); err != nil {
		t.Fatalf("an expired record must not block the id: %v", err)
	}
	if err := st.IssueForToken(ctx, "https://idp#jti-1", future, &model.APIKey{ID: "key_tok_5", Tenant: "acme", Name: "x", Hash: "h9"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("a live record still blocks: %v", err)
	}
}
