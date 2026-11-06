package httpapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"os"
	"testing"
	"time"

	"agent-sandbox/internal/store"

	"github.com/jackc/pgx/v5"
)

// reviewPostgres opens a PostgreSQL store in a schema of its own, or skips the test without
// SANDBOX_TEST_POSTGRES_URL (it fails instead with SANDBOX_TEST_REQUIRE_EXTERNAL).
func reviewPostgres(t *testing.T) store.Store {
	t.Helper()
	dsn := os.Getenv("SANDBOX_TEST_POSTGRES_URL")
	if dsn == "" {
		if os.Getenv("SANDBOX_TEST_REQUIRE_EXTERNAL") != "" {
			t.Fatal("SANDBOX_TEST_POSTGRES_URL is required")
		}
		t.Skip("set SANDBOX_TEST_POSTGRES_URL for the PostgreSQL contract")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	var nonce [8]byte
	_, _ = rand.Read(nonce[:])
	schema := pgx.Identifier{"httpapi_review_" + hex.EncodeToString(nonce[:])}
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema.Sanitize()); err != nil {
		admin.Close(ctx)
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		if _, err := admin.Exec(c, "DROP SCHEMA "+schema.Sanitize()+" CASCADE"); err != nil {
			t.Errorf("drop review schema: %v", err)
		}
		admin.Close(c)
	})
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("search_path", schema[0])
	u.RawQuery = q.Encode()
	st, err := store.OpenPostgres(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

// A multipart message stored before the content hash existed holds the SHA-256 of its raw
// body. The same retry after the upgrade replays it (the bytes are the same: a retry of that
// one request), on both stores; another upload under the key is still 422.
func TestReviewMultipartReplayOfARecordFromBeforeTheContentHash(t *testing.T) {
	for _, backend := range []string{"memory", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			s := newStack(t)
			if backend == "postgres" {
				s.orch.Store = reviewPostgres(t)
			}
			ct, raw := multipartBody(t, "legacy-boundary-1", "see attached", [2]string{"a.txt", "alpha"})
			sum := sha256.Sum256(raw)
			path := "/v1/sandboxes/sb_legacy/messages"
			stored := []byte(`{"run":{"id":"run_old"},"delivery":"new"}` + "\n")
			key := "alice|POST " + path + "|before-upgrade"
			if _, _, err := s.orch.Store.ReserveIdempotent(context.Background(), key, hex.EncodeToString(sum[:])); err != nil {
				t.Fatal(err)
			}
			if err := s.orch.Store.PutIdempotent(context.Background(), &store.Idempotent{Key: key, BodyHash: hex.EncodeToString(sum[:]), Status: 202, Body: stored}); err != nil {
				t.Fatal(err)
			}
			hdr := map[string]string{"Idempotency-Key": "before-upgrade"}
			resp, body := postRaw(t, s.platform.URL+path, "alice-tok", ct, bytes.NewReader(raw), hdr)
			if resp.StatusCode != 202 || resp.Header.Get("Idempotency-Replayed") != "true" || !bytes.Equal(body, stored) {
				t.Fatalf("retry after the upgrade: %d replayed=%q %s", resp.StatusCode, resp.Header.Get("Idempotency-Replayed"), body)
			}
			ct, other := multipartBody(t, "legacy-boundary-1", "see attached", [2]string{"a.txt", "ALPHA"})
			resp, body = postRaw(t, s.platform.URL+path, "alice-tok", ct, bytes.NewReader(other), hdr)
			wantErr(t, "another upload under the key", resp, body, 422, CodeInvalid)
		})
	}
}
