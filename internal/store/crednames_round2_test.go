package store

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"

	"agent-sandbox/internal/model"
)

type namesStore interface {
	Store
	CredentialNames
}

func credentialNameStores(t *testing.T, body func(t *testing.T, s namesStore)) {
	t.Run("memory", func(t *testing.T) { body(t, NewMemory()) })
	t.Run("postgres", func(t *testing.T) { body(t, reviewOpenPostgres(t, reviewPostgresURL(t, false))) })
}

// One namespace per scope on both stores: each kind refuses a name the other holds, and the
// two written at once under one name leave exactly one row.
func TestRound2CredentialNamesAreOneNamespace(t *testing.T) {
	credentialNameStores(t, func(t *testing.T, s namesStore) {
		ctx := context.Background()
		if _, err := s.PutOAuthCredentialIfFree(ctx, &model.OAuthCredential{Tenant: "acme", Name: "gh", Provider: "p", Status: model.OAuthPending}, []byte("x"), []string{"gh", "gh.account_id"}); err != nil {
			t.Fatal(err)
		}
		var taken *NameTakenError
		if _, err := s.PutCredentialIfFree(ctx, &model.Credential{Tenant: "acme", Name: "gh.account_id"}, []byte("x"), []string{"gh"}); !errors.As(err, &taken) || taken.Name != "gh" {
			t.Fatalf("a plain credential over a sign-in's name: %v", err)
		}
		if _, err := s.PutCredentialIfFree(ctx, &model.Credential{Tenant: "other", Name: "gh"}, []byte("x"), []string{"gh"}); err != nil {
			t.Fatalf("another scope's name: %v", err)
		}
		for i := range 20 {
			name := "n" + string(rune('a'+i))
			var wg sync.WaitGroup
			var e1, e2 error
			wg.Add(2)
			go func() {
				defer wg.Done()
				_, e1 = s.PutCredentialIfFree(ctx, &model.Credential{Tenant: "acme", Name: name}, []byte("x"), []string{name})
			}()
			go func() {
				defer wg.Done()
				_, e2 = s.PutOAuthCredentialIfFree(ctx, &model.OAuthCredential{Tenant: "acme", Name: name, Provider: "p", Status: model.OAuthPending}, []byte("x"), []string{name})
			}()
			wg.Wait()
			_, _, p := s.GetCredential(ctx, "acme", name)
			_, _, o := s.GetOAuthCredential(ctx, "acme", name)
			if (e1 == nil) == (e2 == nil) || (p == nil) == (o == nil) {
				t.Fatalf("%s: plain %v (row %v), sign-in %v (row %v)", name, e1, p, e2, o)
			}
		}
	})
}

// The connection holding the scope's lock dies between the absence check and the write (the
// old shape: the lock on one connection, the write on another, so the write survived the
// lock). Check and write are one transaction now: the write goes down with the connection,
// the other kind can then take the name, and exactly one row remains.
func TestRound2PostgresCredentialWriteDiesWithItsLock(t *testing.T) {
	p := reviewOpenPostgres(t, reviewPostgresURL(t, false))
	ctx := context.Background()
	killed := false
	credentialNamesHook = func(ctx context.Context, tx pgx.Tx) {
		if killed {
			return
		}
		killed = true
		var pid int
		if err := tx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
			t.Error(err)
			return
		}
		if _, err := p.pool.Exec(ctx, `SELECT pg_terminate_backend($1)`, pid); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(func() { credentialNamesHook = nil })
	if _, err := p.PutCredentialIfFree(ctx, &model.Credential{Tenant: "acme", Name: "gh"}, []byte("x"), []string{"gh"}); err == nil {
		t.Fatal("a write on a terminated connection succeeded")
	}
	if _, err := p.PutOAuthCredentialIfFree(ctx, &model.OAuthCredential{Tenant: "acme", Name: "gh", Provider: "p", Status: model.OAuthPending}, []byte("x"), []string{"gh", "gh.account_id"}); err != nil {
		t.Fatalf("the sign-in after the lost write: %v", err)
	}
	var plain, signIns int
	if err := p.pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM credentials WHERE tenant='acme' AND name='gh'), (SELECT count(*) FROM oauth_credentials WHERE tenant='acme' AND name='gh')`).Scan(&plain, &signIns); err != nil {
		t.Fatal(err)
	}
	if plain != 0 || signIns != 1 {
		t.Fatalf("rows: %d plain, %d sign-ins; want 0 and 1", plain, signIns)
	}
}
