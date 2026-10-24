package apikeys

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"agent-sandbox/internal/store"
)

func TestIssueAuthenticateRotateRevoke(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	s := &Service{Store: store.NewMemory(), Now: func() time.Time { return now }}
	k, secret, err := s.Create(ctx, "acme", "ci", 0, "admin-token")
	if err != nil || !strings.HasPrefix(secret, Prefix) || !strings.HasPrefix(k.ID, "key_") || k.Hash == "" || k.ExpiresAt != nil {
		t.Fatalf("create: %v %+v %s", err, k, secret)
	}
	if secret == k.Hash || strings.Contains(k.Hash, strings.TrimPrefix(secret, Prefix)[13:]) {
		t.Fatal("the secret is stored in clear")
	}
	// The secret authenticates; near misses do not, and the reason is not distinguished.
	got, err := s.Authenticate(ctx, secret)
	if err != nil || got.ID != k.ID || got.Tenant != "acme" || got.LastUsedAt == nil {
		t.Fatalf("authenticate: %v %+v", err, got)
	}
	for _, bad := range []string{secret[:len(secret)-1] + "0", secret + "x", Prefix + "000000000000_" + strings.Repeat("0", 44), "sbk_short", "", "t0k"} {
		if _, err := s.Authenticate(ctx, bad); !errors.Is(err, ErrBadKey) {
			t.Fatalf("%q accepted: %v", bad, err)
		}
	}
	// Last use is recorded at most once per interval.
	first := *got.LastUsedAt
	now = now.Add(10 * time.Second)
	got, _ = s.Authenticate(ctx, secret)
	if !got.LastUsedAt.Equal(first) {
		t.Fatal("every request wrote last_used_at")
	}
	now = now.Add(2 * time.Minute)
	got, _ = s.Authenticate(ctx, secret)
	if got.LastUsedAt.Equal(first) {
		t.Fatal("last_used_at never advanced")
	}
	// Rotation with a grace period: both keys work until it ends, then only the new one.
	next, nextSecret, err := s.Rotate(ctx, k.ID, 0, time.Hour, "key:"+k.ID)
	if err != nil || next.ID == k.ID || next.Tenant != "acme" || next.Name != "ci" || nextSecret == secret {
		t.Fatalf("rotate: %v %+v", err, next)
	}
	old, _ := s.Get(ctx, k.ID)
	if old.RotatedTo != next.ID || old.ExpiresAt == nil || !old.ExpiresAt.Equal(now.Add(time.Hour)) || old.RevokedAt != nil {
		t.Fatalf("old key after rotation: %+v", old)
	}
	if _, err := s.Authenticate(ctx, secret); err != nil {
		t.Fatalf("old key within grace: %v", err)
	}
	if _, err := s.Authenticate(ctx, nextSecret); err != nil {
		t.Fatalf("new key: %v", err)
	}
	now = now.Add(2 * time.Hour)
	if _, err := s.Authenticate(ctx, secret); !errors.Is(err, ErrBadKey) {
		t.Fatalf("old key after grace: %v", err)
	}
	if _, err := s.Authenticate(ctx, nextSecret); err != nil {
		t.Fatalf("new key after grace: %v", err)
	}
	// A rotated-out key cannot be rotated again; a revoked key stops at once.
	if _, _, err := s.Rotate(ctx, k.ID, 0, 0, "x"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("rotate an expired key: %v", err)
	}
	if _, err := s.Revoke(ctx, next.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(ctx, nextSecret); !errors.Is(err, ErrBadKey) {
		t.Fatalf("revoked key accepted: %v", err)
	}
	if _, err := s.Revoke(ctx, next.ID); err != nil {
		t.Fatalf("revoking twice: %v", err)
	}
	// Immediate rotation (no grace) revokes the old key in the same call.
	k2, s2, _ := s.Create(ctx, "acme", "deploy", 0, "admin-token")
	if _, _, err := s.Rotate(ctx, k2.ID, 0, 0, "x"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(ctx, s2); !errors.Is(err, ErrBadKey) {
		t.Fatalf("old key after immediate rotation: %v", err)
	}
	// Validation and the server's TTL cap.
	for _, name := range []string{"", strings.Repeat("x", 65), "bad/name", "-leading"} {
		if _, _, err := s.Create(ctx, "acme", name, 0, "x"); !errors.Is(err, ErrInvalid) {
			t.Fatalf("name %q accepted: %v", name, err)
		}
	}
	if _, _, err := s.Create(ctx, "", "ci", 0, "x"); !errors.Is(err, ErrInvalid) {
		t.Fatal("key without a tenant")
	}
	capped := &Service{Store: store.NewMemory(), Now: func() time.Time { return now }, MaxTTL: 24 * time.Hour}
	k3, _, _ := capped.Create(ctx, "acme", "ci", 0, "x")
	k4, _, _ := capped.Create(ctx, "acme", "ci", 30*24*time.Hour, "x")
	k5, _, _ := capped.Create(ctx, "acme", "ci", time.Hour, "x")
	if k3.ExpiresAt == nil || !k3.ExpiresAt.Equal(now.Add(24*time.Hour)) || !k4.ExpiresAt.Equal(now.Add(24*time.Hour)) || !k5.ExpiresAt.Equal(now.Add(time.Hour)) {
		t.Fatalf("ttl cap: %v %v %v", k3.ExpiresAt, k4.ExpiresAt, k5.ExpiresAt)
	}
	list, _ := s.List(ctx, "acme")
	if len(list) != 4 || list[0].CreatedAt.Before(list[len(list)-1].CreatedAt) {
		t.Fatalf("list: %d keys", len(list))
	}
	if other, _ := s.List(ctx, "other"); len(other) != 0 {
		t.Fatal("another tenant's keys listed")
	}
}
