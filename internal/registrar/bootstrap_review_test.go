package registrar

import (
	"context"
	"sync"
	"testing"
	"time"

	"agent-sandbox/internal/ca"
	"agent-sandbox/internal/model"
)

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

// A retry after a lost response used to leave two live identities for one pod until the pod
// was deleted; the earlier one is retired now.
func TestReviewRepeatedBootstrapFromThePodRetiresTheEarlierIdentity(t *testing.T) {
	r, _ := newTestRegistrar(t)
	ctx := context.Background()
	_, csr, _ := ca.NewCSR("backend-dev")
	if _, err := r.Bootstrap(ctx, "tok-pod-a", BootstrapRequest{CSR: string(csr)}); err != nil {
		t.Fatal(err)
	}
	second, err := r.Bootstrap(ctx, "tok-pod-a", BootstrapRequest{CSR: string(csr)})
	if err != nil {
		t.Fatal(err)
	}
	if live := liveInstances(t, r, "sb1"); len(live) != 1 || live[0] != second.Instance {
		t.Fatalf("one live identity per pod, the latest: %v (latest %d)", live, second.Instance)
	}
}

// Racing bootstraps from one pod must not retire each other.
func TestReviewConcurrentBootstrapsLeaveOneIdentityLive(t *testing.T) {
	r, _ := newTestRegistrar(t)
	ctx := context.Background()
	_, csr, _ := ca.NewCSR("backend-dev")
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() { _, _ = r.Bootstrap(ctx, "tok-pod-a", BootstrapRequest{CSR: string(csr)}) })
	}
	wg.Wait()
	if live := liveInstances(t, r, "sb1"); len(live) != 1 {
		t.Fatalf("racing bootstraps from one pod must leave exactly one live identity: %v", live)
	}
}

// Another pod of the same sandbox (a rollout) keeps its identity: only the same pod's earlier
// ones are replaced, and the "no longer current" path still issues.
func TestReviewBootstrapLeavesOtherPodsIdentities(t *testing.T) {
	r, _ := newTestRegistrar(t)
	ctx := context.Background()
	r.Resolver = StaticResolver{
		"tok-pod-a": {Name: "pod-a", SandboxID: "sb1", Slug: "backend-dev", Tenant: "u1"},
		"tok-pod-b": {Name: "pod-b", SandboxID: "sb1", Slug: "backend-dev", Tenant: "u1"},
	}
	_, csr, _ := ca.NewCSR("backend-dev")
	if _, err := r.Bootstrap(ctx, "tok-pod-b", BootstrapRequest{CSR: string(csr)}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Bootstrap(ctx, "tok-pod-a", BootstrapRequest{CSR: string(csr)}); err != nil {
		t.Fatalf("a pod that is no longer current still bootstraps: %v", err)
	}
	if live := liveInstances(t, r, "sb1"); len(live) != 2 {
		t.Fatalf("different pods keep their own identities: %v", live)
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
