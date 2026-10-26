package apply

import (
	"bytes"
	"errors"
	"testing"

	"agent-sandbox/internal/model"
	"agent-sandbox/internal/plan"
	res "agent-sandbox/internal/resource"
	"agent-sandbox/internal/store"
)

const reviewCIGrantBundle = `
kind: EnvironmentProfile
name: ci-env
spec: {image: stable}
---
kind: CITrust
name: config-job
spec:
  issuer: https://ci.example.test
  audience: https://sandbox.example.test
  claims: {repository: acme/config, ref: 'refs/heads/*'}
`

// Rolling back an ordinary bundle must preserve a deliberate restriction of
// CI authentication, just as it already preserves PolicyBinding revocations.
func TestReviewRollbackDoesNotRestoreCITrustGrants(t *testing.T) {
	st := store.NewMemory()
	c := controller(st, "review", pols("acme"))
	scope := plan.Scope{Tenant: "acme", Subject: "reviewer"}
	first, err := c.Submit(t.Context(), planned(t, c, reviewCIGrantBundle, scope))
	if err != nil || first.Status != model.ApplyDone {
		t.Fatalf("first bundle: %v", err)
	}
	narrowed := `
kind: EnvironmentProfile
name: ci-env
spec: {image: canary}
---
kind: CITrust
name: config-job
spec:
  issuer: https://ci.example.test
  audience: https://sandbox.example.test
  claims: {repository: acme/config, ref: refs/heads/main}
`
	second, err := c.Submit(t.Context(), planned(t, c, narrowed, scope))
	if err != nil || second.Status != model.ApplyDone {
		t.Fatalf("second bundle: %v", err)
	}
	before := latest(t, st, model.KindCITrust, "acme", "config-job")
	rb, err := c.Rollback(t.Context(), RollbackRequest{Apply: second.ID, Scope: scope})
	if err != nil || rb.Apply == nil || rb.Apply.Status != model.ApplyDone {
		t.Fatalf("rollback of the ordinary environment should still finish: %v", err)
	}
	after := latest(t, st, model.KindCITrust, "acme", "config-job")
	if after.Revision != before.Revision || !bytes.Equal(after.Spec, before.Spec) {
		t.Error("bundle rollback rewrote CITrust; the current authentication restriction must remain")
	}
	skipped := false
	for _, item := range rb.Skipped {
		if item.Kind == model.KindCITrust && item.Name == "config-job" {
			skipped = true
		}
	}
	if !skipped {
		t.Error("rollback must explain that CITrust is a grant requiring an explicit change")
	}
	if env := latest(t, st, model.KindEnvironment, "acme", "ci-env"); !bytes.Contains(env.Spec, []byte(`"image":"stable"`)) {
		t.Error("the environment was not restored")
	}
}

// Removing a trust ends future exchanges. Restoring the grant is an explicit
// catalog write, never an incidental effect of the generic rollback endpoint.
func TestReviewRollbackKeepsADeletedCITrustDeleted(t *testing.T) {
	st := store.NewMemory()
	c := controller(st, "review", pols("acme"))
	scope := plan.Scope{Tenant: "acme", Subject: "reviewer"}
	a, err := c.Submit(t.Context(), planned(t, c, reviewCIGrantBundle, scope))
	if err != nil || a.Status != model.ApplyDone {
		t.Fatalf("initial bundle: %v", err)
	}
	if err := st.DeleteItem(t.Context(), model.KindCITrust, "acme", "config-job"); err != nil {
		t.Fatal(err)
	}
	_, err = c.Rollback(t.Context(), RollbackRequest{Kind: model.KindCITrust, Name: "config-job", Revision: 1, Scope: scope})
	if !errors.Is(err, res.ErrInvalid) {
		t.Errorf("rollback of an authentication grant must be rejected: %v", err)
	}
	if _, err := st.GetItem(t.Context(), model.KindCITrust, "acme", "config-job", 0); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("deleted trust must remain deleted: %v", err)
	}
	if count := revisions(t, st, model.KindCITrust, "acme", "config-job"); count != 1 {
		t.Errorf("refused rollback must append no revision: got %d", count)
	}
}
