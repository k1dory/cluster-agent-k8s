package registrar

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"sync"
	"testing"
	"time"

	"agent-sandbox/internal/ca"
	"agent-sandbox/internal/identity"
	"agent-sandbox/internal/model"
	"agent-sandbox/internal/store"
)

// checkCert runs the certificate a bootstrap returned through Registrar.Check, as authz does.
func checkCert(t *testing.T, r *Registrar, res *BootstrapResponse) error {
	t.Helper()
	b, _ := pem.Decode([]byte(res.Cert))
	cert, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	id, err := identity.FromCert(cert)
	if err != nil {
		t.Fatal(err)
	}
	_, err = r.Check(context.Background(), id)
	return err
}

func liveInstances(t *testing.T, r *Registrar, sandbox string) []int {
	t.Helper()
	ins, err := r.Store.ListInstances(context.Background(), sandbox)
	if err != nil {
		t.Fatal(err)
	}
	var live []int
	for _, in := range ins {
		if in.RetiredAt == nil {
			live = append(live, in.N)
		}
	}
	return live
}

// A retry after a lost response (same pod, same CSR) used to add a second live identity; now
// it gets the same identity, and both certificates pass.
func TestReviewRepeatedBootstrapGetsTheSameIdentity(t *testing.T) {
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
	if first.Instance != second.Instance || !first.NotAfter.Equal(second.NotAfter) {
		t.Fatalf("same pod and key, same identity: %d/%v vs %d/%v", first.Instance, first.NotAfter, second.Instance, second.NotAfter)
	}
	for _, res := range []*BootstrapResponse{first, second} {
		if err := checkCert(t, r, res); err != nil {
			t.Fatalf("every certificate returned must be valid: %v", err)
		}
	}
	if live := liveInstances(t, r, "sb1"); len(live) != 1 {
		t.Fatalf("one live identity: %v", live)
	}
	// A new key from the same pod replaces the identity: the earlier certificate stops.
	_, csr2, _ := ca.NewCSR("backend-dev")
	third, err := r.Bootstrap(ctx, "tok-pod-a", BootstrapRequest{CSR: string(csr2)})
	if err != nil || third.Instance == first.Instance {
		t.Fatalf("new key: %v %+v", err, third)
	}
	if err := checkCert(t, r, first); err == nil {
		t.Fatal("the identity of the replaced key must be retired")
	}
	if err := checkCert(t, r, third); err != nil {
		t.Fatal(err)
	}
}

// Racing bootstraps from one pod with its one key: every one succeeds and every certificate
// it returns passes Check (the old code could hand back a certificate it had just retired,
// or fail with a "superseded" error agent-init treats as fatal).
func TestReviewConcurrentBootstrapsAllReturnValidCertificates(t *testing.T) {
	r, _ := newTestRegistrar(t)
	ctx := context.Background()
	_, csr, _ := ca.NewCSR("backend-dev")
	const n = 8
	res := make([]*BootstrapResponse, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() { res[i], errs[i] = r.Bootstrap(ctx, "tok-pod-a", BootstrapRequest{CSR: string(csr)}) })
	}
	wg.Wait()
	for i := range n {
		if errs[i] != nil {
			t.Fatalf("bootstrap %d: %v", i, errs[i])
		}
		if err := checkCert(t, r, res[i]); err != nil {
			t.Fatalf("bootstrap %d returned a certificate that fails Check: %v", i, err)
		}
		if res[i].Instance != res[0].Instance {
			t.Fatalf("one identity for one pod and key: %d vs %d", res[i].Instance, res[0].Instance)
		}
	}
	if live := liveInstances(t, r, "sb1"); len(live) != 1 {
		t.Fatalf("one live identity: %v", live)
	}
}

// A store failure is the platform's, not the request's: it comes back as ErrUnavailable,
// which the HTTP layer answers with a status agent-init retries.
type failingBind struct{ store.Store }

func (failingBind) BindInstance(context.Context, store.InstanceBinding, func(int, *model.Instance) (*model.Instance, error)) (*store.BoundInstance, error) {
	return nil, errors.New("connection reset")
}

func TestReviewBootstrapStoreFailureIsRetryable(t *testing.T) {
	r, st := newTestRegistrar(t)
	r.Store = failingBind{st}
	_, csr, _ := ca.NewCSR("backend-dev")
	if _, err := r.Bootstrap(context.Background(), "tok-pod-a", BootstrapRequest{CSR: string(csr)}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("a store failure must be retryable: %v", err)
	}
	if _, err := r.Bootstrap(context.Background(), "tok-pod-a", BootstrapRequest{CSR: "junk"}); err == nil || errors.Is(err, ErrUnavailable) {
		t.Fatalf("a bad request stays a bad request: %v", err)
	}
}

// The pod's tenant label must be the sandbox's: it goes into the certificate.
func TestReviewBootstrapRefusesAPodOfAnotherTenant(t *testing.T) {
	r, st := newTestRegistrar(t)
	ctx := context.Background()
	_ = st.CreateSandbox(ctx, &model.Sandbox{ID: "sb9", Slug: "backend-dev", Tenant: "victim", Status: model.StatusRunning, CreatedAt: time.Now()})
	r.Resolver = StaticResolver{"tok-x": {Name: "pod-x", SandboxID: "sb9", Slug: "backend-dev", Tenant: "attacker"}}
	_, csr, _ := ca.NewCSR("backend-dev")
	if _, err := r.Bootstrap(ctx, "tok-x", BootstrapRequest{CSR: string(csr)}); err == nil {
		t.Fatal("a pod labelled with another tenant must not get an identity")
	}
}
