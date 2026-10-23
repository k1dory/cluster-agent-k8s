package registrar

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"agent-sandbox/internal/ca"
	"agent-sandbox/internal/identity"
	"agent-sandbox/internal/model"
	"agent-sandbox/internal/store"
)

func newTestRegistrar(t *testing.T) (*Registrar, *store.Memory) {
	t.Helper()
	c, err := ca.Generate("test CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	st := store.NewMemory()
	_ = st.CreateSandbox(context.Background(), &model.Sandbox{ID: "sb1", Slug: "backend-dev", Tenant: "u1", Status: model.StatusRunning, CreatedAt: time.Now()})
	r := &Registrar{CA: c, Store: st, TTL: 30 * time.Minute,
		Resolver: StaticResolver{"tok-pod-a": {Name: "pod-a", SandboxID: "sb1", Slug: "backend-dev", Tenant: "u1"}}}
	return r, st
}

func TestBootstrapIssuesMonotonicInstances(t *testing.T) {
	r, _ := newTestRegistrar(t)
	ctx := context.Background()
	_, csr, _ := ca.NewCSR("backend-dev")
	first, err := r.Bootstrap(ctx, "tok-pod-a", BootstrapRequest{CSR: string(csr)})
	if err != nil {
		t.Fatal(err)
	}
	second, err := r.Bootstrap(ctx, "tok-pod-a", BootstrapRequest{CSR: string(csr)})
	if err != nil {
		t.Fatal(err)
	}
	if first.Instance != 1 || second.Instance != 2 {
		t.Fatalf("instances %d, %d; want 1, 2", first.Instance, second.Instance)
	}
	b, _ := pem.Decode([]byte(second.Cert))
	cert, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	id, err := identity.FromCert(cert)
	if err != nil {
		t.Fatal(err)
	}
	if id.Slug != "backend-dev" || id.Instance != 2 || id.Tenant != "u1" || id.SandboxID != "sb1" {
		t.Fatalf("bad identity %+v", id)
	}
	if _, err := r.Check(ctx, id); err != nil {
		t.Fatalf("fresh identity must pass: %v", err)
	}
	if err := r.RetireSandbox(ctx, "sb1"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Check(ctx, id); err == nil {
		t.Fatal("retired identity must be rejected")
	}
	if _, err := r.Bootstrap(ctx, "bad", BootstrapRequest{CSR: string(csr)}); err == nil {
		t.Fatal("bad token must be rejected")
	}
}
