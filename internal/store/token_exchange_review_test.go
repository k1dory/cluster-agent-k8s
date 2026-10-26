package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"agent-sandbox/internal/model"
)

// Failure to insert the key must roll back the token's use as well. A later
// retry can then issue the pair, and the original unrelated key stays intact.
func TestReviewTokenExchangeRollsBackAFailedKeyInsert(t *testing.T) {
	for _, backend := range []string{"memory", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			var st Store = NewMemory()
			if backend == "postgres" {
				st = reviewOpenPostgres(t, reviewPostgresURL(t, false))
			}
			ctx := t.Context()
			future := time.Now().Add(time.Hour)
			original := &model.APIKey{ID: "review-existing", Tenant: "acme", Name: "existing", Hash: "original", ExpiresAt: &future}
			if err := st.CreateAPIKey(ctx, original); err != nil {
				t.Fatal(err)
			}
			candidate := &model.APIKey{ID: original.ID, Tenant: "acme", Name: "ci.config", Hash: "candidate", Trust: "config", ExpiresAt: &future}
			const use = "review-token-use"
			if err := st.IssueForToken(ctx, use, future, candidate); err == nil {
				t.Fatal("a duplicate key id must fail")
			}
			if owner, err := st.TokenUse(ctx, use); err != nil || owner != "" {
				t.Fatalf("failed key insert consumed the token: owner=%q err=%v", owner, err)
			}
			got, err := st.GetAPIKey(ctx, original.ID)
			if err != nil || got.Hash != original.Hash || got.Trust != original.Trust {
				t.Fatalf("failed insert changed the existing key: %v", err)
			}
			candidate.ID = "review-new"
			if err := st.IssueForToken(ctx, use, future, candidate); err != nil {
				t.Fatalf("retry with an insertable key: %v", err)
			}
			if owner, err := st.TokenUse(ctx, use); err != nil || owner != candidate.ID {
				t.Fatalf("successful retry did not record its key: owner=%q err=%v", owner, err)
			}
			if keys, err := st.ListAPIKeys(ctx, "acme"); err != nil || len(keys) != 2 {
				t.Fatalf("the original and one new key must remain: count=%d err=%v", len(keys), err)
			}
		})
	}
}

// Upgrading the pre-#38 token_uses table must preserve already-used token ids,
// even though those legacy rows cannot name their original key.
func TestReviewTokenExchangeUpgradeKeepsLegacyUses(t *testing.T) {
	dsn := reviewPostgresURL(t, false)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(context.Background())
	if _, err := conn.Exec(ctx, "CREATE TABLE token_uses (id text PRIMARY KEY, expires_at timestamptz NOT NULL)"); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(time.Hour)
	if _, err := conn.Exec(ctx, "INSERT INTO token_uses (id, expires_at) VALUES ($1, $2)", "review-legacy", future); err != nil {
		t.Fatal(err)
	}
	st := reviewOpenPostgres(t, dsn)
	key := &model.APIKey{ID: "review-upgrade", Tenant: "acme", Name: "ci.config", Hash: "fixture", Trust: "config", ExpiresAt: &future}
	if err := st.IssueForToken(ctx, "review-legacy", future, key); !errors.Is(err, ErrConflict) {
		t.Fatalf("upgrade must preserve the legacy token's use: %v", err)
	}
	if _, err := st.GetAPIKey(ctx, key.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("refused legacy token must not insert a key: %v", err)
	}
	if err := st.IssueForToken(ctx, "review-fresh", future, key); err != nil {
		t.Fatalf("fresh exchange after upgrade: %v", err)
	}
	if owner, err := st.TokenUse(ctx, "review-fresh"); err != nil || owner != key.ID {
		t.Fatalf("new exchange lacks its key association: owner=%q err=%v", owner, err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := reviewOpenPostgres(t, dsn)
	if owner, err := reopened.TokenUse(ctx, "review-fresh"); err != nil || owner != key.ID {
		t.Fatalf("reopen lost the token/key association: owner=%q err=%v", owner, err)
	}
}
