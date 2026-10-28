package store

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"agent-sandbox/internal/model"
)

// oauthContract is what the sign-in service relies on, run against the memory store always
// and against PostgreSQL in make ci-postgres: a new sign-in replaces the row and bumps its
// generation; due rows are pending or active, past NextAt, with no live lease; one lease
// holder at a time, lapsed leases taken over; a save needs the lease of the same generation
// and releases it.
func oauthContract(t *testing.T, s Store) {
	ctx := context.Background()
	t0 := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	exp := t0.Add(15 * time.Minute)
	c := &model.OAuthCredential{Tenant: "acme", Name: "chatgpt", Provider: "chatgpt", Status: model.OAuthPending,
		VerificationURL: "https://auth.example.com/device", UserCode: "ABCD", LoginExpiresAt: &exp, NextAt: t0.Add(5 * time.Second), CreatedBy: "alice"}
	created, err := s.PutOAuthCredential(ctx, c, []byte("sealed-1"))
	if err != nil || !created || c.Generation != 1 {
		t.Fatalf("put: %v %v %+v", created, err, c)
	}
	got, ct, err := s.GetOAuthCredential(ctx, "acme", "chatgpt")
	if err != nil || string(ct) != "sealed-1" || got.UserCode != "ABCD" || got.LoginExpiresAt == nil || !got.LoginExpiresAt.Equal(exp) || got.CreatedBy != "alice" {
		t.Fatalf("get: %v %+v", err, got)
	}
	if _, _, err := s.GetOAuthCredential(ctx, "other", "chatgpt"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("another tenant's: %v", err)
	}
	if due, _ := s.DueOAuthCredentials(ctx, t0, 10); len(due) != 0 {
		t.Fatalf("due before NextAt: %+v", due)
	}
	due, err := s.DueOAuthCredentials(ctx, t0.Add(5*time.Second), 10)
	if err != nil || len(due) != 1 || due[0].Name != "chatgpt" {
		t.Fatalf("due: %v %+v", err, due)
	}

	// One lease holder at a time; the same owner may take its own lease again.
	now := t0.Add(5 * time.Second)
	leased, ct, err := s.LeaseOAuthCredential(ctx, "acme", "chatgpt", 1, "a", now, now.Add(time.Minute))
	if err != nil || string(ct) != "sealed-1" || leased.LeaseOwner != "a" {
		t.Fatalf("lease: %v %+v", err, leased)
	}
	if _, _, err := s.LeaseOAuthCredential(ctx, "acme", "chatgpt", 1, "b", now, now.Add(time.Minute)); !errors.Is(err, ErrConflict) {
		t.Fatalf("a second owner must conflict: %v", err)
	}
	if _, _, err := s.LeaseOAuthCredential(ctx, "acme", "chatgpt", 1, "a", now, now.Add(time.Minute)); err != nil {
		t.Fatalf("the owner again: %v", err)
	}
	if due, _ := s.DueOAuthCredentials(ctx, now, 10); len(due) != 0 {
		t.Fatalf("a leased row is not due: %+v", due)
	}
	if _, _, err := s.LeaseOAuthCredential(ctx, "acme", "chatgpt", 2, "a", now, now.Add(time.Minute)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("another generation: %v", err)
	}
	if err := s.SaveOAuthCredential(ctx, leased, []byte("x"), "b"); !errors.Is(err, ErrConflict) {
		t.Fatalf("a save without the lease: %v", err)
	}
	// The holder saves: the state is written, the lease released, provider and creation kept.
	rexp := now.Add(time.Hour)
	leased.Status, leased.UserCode, leased.VerificationURL, leased.LoginExpiresAt = model.OAuthActive, "", "", nil
	leased.AccountID, leased.ExpiresAt, leased.RefreshedAt, leased.NextAt = "acct-1", &rexp, &now, rexp.Add(-5*time.Minute)
	leased.Provider = "tampered"
	if err := s.SaveOAuthCredential(ctx, leased, []byte("sealed-2"), "a"); err != nil {
		t.Fatal(err)
	}
	got, ct, _ = s.GetOAuthCredential(ctx, "acme", "chatgpt")
	if got.Status != model.OAuthActive || string(ct) != "sealed-2" || got.AccountID != "acct-1" || got.LeaseOwner != "" || got.UserCode != "" ||
		got.ExpiresAt == nil || !got.ExpiresAt.Equal(rexp) || got.Provider != "chatgpt" || got.CreatedBy != "alice" {
		t.Fatalf("after save: %+v", got)
	}
	if err := s.SaveOAuthCredential(ctx, got, []byte("again"), "a"); !errors.Is(err, ErrConflict) {
		t.Fatalf("a save after the lease was released: %v", err)
	}

	// A lapsed lease is taken over; the old holder's save then conflicts.
	later := rexp.Add(-5 * time.Minute)
	stale, _, err := s.LeaseOAuthCredential(ctx, "acme", "chatgpt", 1, "a", later, later.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if due, _ := s.DueOAuthCredentials(ctx, later.Add(2*time.Minute), 10); len(due) != 1 {
		t.Fatalf("a lapsed lease is due again: %+v", due)
	}
	if _, _, err := s.LeaseOAuthCredential(ctx, "acme", "chatgpt", 1, "b", later.Add(2*time.Minute), later.Add(3*time.Minute)); err != nil {
		t.Fatalf("taking over a lapsed lease: %v", err)
	}
	if err := s.SaveOAuthCredential(ctx, stale, []byte("stale"), "a"); !errors.Is(err, ErrConflict) {
		t.Fatalf("the old holder's save: %v", err)
	}

	// A new sign-in replaces the row whatever its lease: generation bumped, lease dropped,
	// the creation kept; the replica still holding the old lease cannot save over it.
	c2 := &model.OAuthCredential{Tenant: "acme", Name: "chatgpt", Provider: "chatgpt", Status: model.OAuthPending, NextAt: later, CreatedBy: "bob"}
	created, err = s.PutOAuthCredential(ctx, c2, []byte("sealed-3"))
	if err != nil || created || c2.Generation != 2 {
		t.Fatalf("replace: %v %v %+v", created, err, c2)
	}
	if err := s.SaveOAuthCredential(ctx, &model.OAuthCredential{Tenant: "acme", Name: "chatgpt", Generation: 1, Status: model.OAuthActive}, nil, "b"); !errors.Is(err, ErrConflict) {
		t.Fatalf("a save for the replaced sign-in: %v", err)
	}
	got, _, _ = s.GetOAuthCredential(ctx, "acme", "chatgpt")
	if got.Generation != 2 || got.LeaseOwner != "" || got.Status != model.OAuthPending || got.AccountID != "" || got.ExpiresAt != nil {
		t.Fatalf("after replace: %+v", got)
	}

	// Failed rows are never due; list is per scope, by name; delete.
	f := &model.OAuthCredential{Tenant: "acme", Name: "a-failed", Provider: "chatgpt", Status: model.OAuthFailed, NextAt: t0}
	if _, err := s.PutOAuthCredential(ctx, f, []byte("x")); err != nil {
		t.Fatal(err)
	}
	for _, d := range must(s.DueOAuthCredentials(ctx, later.Add(time.Hour), 10)) {
		if d.Status == model.OAuthFailed {
			t.Fatalf("a failed row is due: %+v", d)
		}
	}
	list, _ := s.ListOAuthCredentials(ctx, "acme")
	if len(list) != 2 || list[0].Name != "a-failed" || list[1].Name != "chatgpt" {
		t.Fatalf("list: %+v", list)
	}
	if err := s.DeleteOAuthCredential(ctx, "acme", "a-failed"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteOAuthCredential(ctx, "acme", "a-failed"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete twice: %v", err)
	}

	// Many owners racing for one row: exactly one gets it.
	var wg sync.WaitGroup
	var mu sync.Mutex
	won := 0
	race := later.Add(time.Hour)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, _, err := s.LeaseOAuthCredential(ctx, "acme", "chatgpt", 2, string(rune('a'+i))+"-racer", race, race.Add(time.Minute))
			if err == nil {
				mu.Lock()
				won++
				mu.Unlock()
			} else if !errors.Is(err, ErrConflict) {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	if won != 1 {
		t.Fatalf("%d owners took the lease", won)
	}
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func TestOAuthCredentialsMemory(t *testing.T) { oauthContract(t, NewMemory()) }

func TestOAuthCredentialsPostgres(t *testing.T) {
	oauthContract(t, reviewOpenPostgres(t, reviewPostgresURL(t, false)))
}
