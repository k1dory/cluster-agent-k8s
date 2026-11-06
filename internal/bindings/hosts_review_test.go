package bindings

import (
	"testing"

	"agent-sandbox/internal/policy"
	"agent-sandbox/internal/store"
)

// The merged host list is rebuilt when the fingerprint moves and only then; callers that
// merge header names into a host do not change what the next caller sees.
func TestReviewGuardHostsFollowTheFingerprint(t *testing.T) {
	pols := policy.FromPolicies(&policy.Policy{Slug: "dev", Allow: []policy.Rule{{Host: "api.github.com", Paths: []string{"/**"}}}})
	g := &Guard{Set: pols, Bindings: New(store.NewMemory(), pols)}
	g.Headers = ownHosts{hosts: []policy.Host{{Name: "tools.example.com", Upstream: "https://10.0.0.5"}}, fp: "c1"}
	hs := g.Hosts()
	if len(hs) != 2 {
		t.Fatalf("hosts: %+v", hs)
	}
	hs[0].Injected = append(hs[0].Injected, "X-Mutated")
	if again := g.Hosts(); len(again[0].Injected) != 0 {
		t.Fatalf("a caller's change must not leak into the cache: %+v", again[0])
	}
	// Same fingerprint, different list: the cache answers (the fingerprint is the contract).
	g.Headers = ownHosts{hosts: nil, fp: "c1"}
	if len(g.Hosts()) != 2 {
		t.Fatal("an unchanged fingerprint serves the cached list")
	}
	g.Headers = ownHosts{hosts: []policy.Host{{Name: "other.example.com", Upstream: "https://10.0.0.6"}}, fp: "c2"}
	if _, ok := g.HostInfo("tools.example.com"); ok {
		t.Fatal("a moved fingerprint must rebuild the list")
	}
	if _, ok := g.HostInfo("other.example.com"); !ok {
		t.Fatal("the new connection host must be served")
	}
}
