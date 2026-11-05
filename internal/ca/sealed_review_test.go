package ca

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"strings"
	"testing"

	"agent-sandbox/internal/credentials"
	"agent-sandbox/internal/store"
)

func sealer(t *testing.T) *credentials.Sealer {
	t.Helper()
	key := make([]byte, 32)
	rand.Read(key)
	sl, err := credentials.NewSealer(key)
	if err != nil {
		t.Fatal(err)
	}
	return sl
}

// The CA key went to the blobs table as plaintext PEM while tenant credentials were sealed
// under credentials.key. With the key set it is sealed and still loads.
func TestReviewSharedCAKeyIsSealedAtRest(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	sl := sealer(t)
	a, err := LoadOrCreateShared(ctx, st, sl, nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := st.GetBlob(ctx, BlobName)
	if err != nil {
		t.Fatal(err)
	}
	if !BundleSealed(raw) || bytes.Contains(raw, []byte("BEGIN EC PRIVATE KEY")) {
		t.Fatalf("the stored bundle must not hold the key in clear:\n%s", raw)
	}
	b, err := LoadOrCreateShared(ctx, st, sl, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !a.Cert.Equal(b.Cert) || !a.key.(*ecdsa.PrivateKey).Equal(b.key) {
		t.Fatal("a second load must return the same CA")
	}
	// Moved under another blob name, the ciphertext does not open.
	if _, err := ParseSealedBundle(raw, sl, "gateway-ca"); err == nil {
		t.Fatal("a sealed bundle must be bound to its blob name")
	}
}

// A database written before encryption keeps working and is upgraded in place.
func TestReviewLegacyPlaintextCAIsUpgraded(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	legacy, err := LoadOrCreateShared(ctx, st, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if raw, _ := st.GetBlob(ctx, BlobName); BundleSealed(raw) {
		t.Fatal("without credentials.key the bundle stays as it was")
	}
	sl := sealer(t)
	up, err := LoadOrCreateShared(ctx, st, sl, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !up.Cert.Equal(legacy.Cert) {
		t.Fatal("the upgrade must keep the CA")
	}
	raw, _ := st.GetBlob(ctx, BlobName)
	if !BundleSealed(raw) || bytes.Contains(raw, []byte("BEGIN EC PRIVATE KEY")) {
		t.Fatalf("the legacy bundle must be stored again sealed:\n%s", raw)
	}
	// Once sealed, a replica without the key refuses instead of minting a new CA.
	if _, err := LoadOrCreateShared(ctx, st, nil, nil); err == nil || !strings.Contains(err.Error(), "credentials.key") {
		t.Fatalf("a sealed CA without credentials.key must fail clearly: %v", err)
	}
}

func TestReviewSealedCAWithTheWrongKeyFailsClearly(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	if _, err := LoadOrCreateSharedNamed(ctx, st, "gateway-ca", "gw", sealer(t), nil); err != nil {
		t.Fatal(err)
	}
	_, err := LoadOrCreateSharedNamed(ctx, st, "gateway-ca", "gw", sealer(t), nil)
	if err == nil || !strings.Contains(err.Error(), "wrong credentials.key") || !strings.Contains(err.Error(), "gateway-ca") {
		t.Fatalf("wrong key: %v", err)
	}
}
