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
// valid. A token id is used once until it expires; an expired record no longer blocks the id.
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

	if err := st.UseToken(ctx, "https://idp#jti-1", future); err != nil {
		t.Fatal(err)
	}
	if err := st.UseToken(ctx, "https://idp#jti-1", future); !errors.Is(err, ErrConflict) {
		t.Fatalf("a second use must conflict: %v", err)
	}
	if err := st.UseToken(ctx, "https://idp#jti-2", future); err != nil {
		t.Fatalf("another id is free: %v", err)
	}
	// A record that expired is dropped on the next use: the id is free again (the token
	// itself is past its exp by then, so the issuer's check refuses it anyway).
	if err := st.UseToken(ctx, "https://idp#jti-3", past); err != nil {
		t.Fatal(err)
	}
	if err := st.UseToken(ctx, "https://idp#jti-3", future); err != nil {
		t.Fatalf("an expired record must not block the id: %v", err)
	}
	if err := st.UseToken(ctx, "https://idp#jti-1", future); !errors.Is(err, ErrConflict) {
		t.Fatalf("a live record still blocks: %v", err)
	}
}
