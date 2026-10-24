package store

import (
	"testing"
	"time"

	"agent-sandbox/internal/model"
)

func TestReviewMemoryKeyRevocationSurvivesTouchAndRetirement(t *testing.T) {
	reviewKeyRevocationSurvivesTouchAndRetirement(t, NewMemory())
}

func TestReviewPostgresKeyRevocationSurvivesTouchAndRetirement(t *testing.T) {
	reviewKeyRevocationSurvivesTouchAndRetirement(t, reviewOpenPostgres(t, reviewPostgresURL(t, false)))
}

func reviewKeyRevocationSurvivesTouchAndRetirement(t *testing.T, st APIKeys) {
	t.Helper()
	ctx := t.Context()
	k := &model.APIKey{ID: "key_review", Tenant: "acme", Name: "fixture", Hash: "fixture-hash", CreatedAt: time.Now()}
	if err := st.CreateAPIKey(ctx, k); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetAPIKey(ctx, k.ID); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := st.RevokeAPIKey(ctx, k.ID, now); err != nil {
		t.Fatal(err)
	}
	// Bookkeeping and retirement can complete after a concurrent revocation.
	if err := st.TouchAPIKey(ctx, k.ID, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := st.RetireAPIKey(ctx, k.ID, "replacement", now.Add(time.Second), time.Hour); err != nil {
		t.Fatal(err)
	}
	after, err := st.GetAPIKey(ctx, k.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.RevokedAt == nil || after.Active(now.Add(time.Second)) {
		t.Error("usage and retirement must preserve the key's revoked state")
	}
}
