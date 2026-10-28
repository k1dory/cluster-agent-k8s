package connections

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	res "agent-sandbox/internal/resource"
	"agent-sandbox/internal/secrets"
	"agent-sandbox/internal/store"
)

func TestReviewUpstreamHostCanChangeOnTheSameConnection(t *testing.T) {
	for _, kind := range []string{TypeHTTP, TypeMCP} {
		t.Run(kind, func(t *testing.T) {
			ctx := context.Background()
			s := New(store.NewMemory(), secrets.Static{}, nil)
			s.Hosts = repoHosts{allowed: map[string][]string{"acme": {"tools.example.com"}}}
			document := func(enabled bool, revision int) *res.Document {
				t.Helper()
				raw, err := json.Marshal(Spec{Type: kind, Host: "tools.example.com", Upstream: "https://192.0.2.7:8443", UpstreamHost: enabled})
				if err != nil {
					t.Fatal(err)
				}
				return &res.Document{Name: "tools", Spec: raw, ExpectedRevision: &revision}
			}
			if _, err := s.Put(ctx, "acme", document(false, 0), false, "review"); err != nil {
				t.Fatal(err)
			}
			_, previousFingerprint := s.OwnHosts()
			for i, enabled := range []bool{true, false} {
				it, err := s.Put(ctx, "acme", document(enabled, i+1), false, "review")
				if err != nil {
					t.Fatalf("updating the same connection to upstream_host=%v must not conflict with itself: %v", enabled, err)
				}
				hosts, fingerprint := s.OwnHosts()
				if it.Revision != i+2 || len(hosts) != 1 || hosts[0].UpstreamHost != enabled || fingerprint == previousFingerprint {
					t.Fatalf("updated revision and gateway host must reflect the new setting: revision=%d hosts=%+v fingerprint=%q", it.Revision, hosts, fingerprint)
				}
				previousFingerprint = fingerprint
			}
			// A different connection for the same host still has to agree.
			other := document(true, 0)
			other.Name = "other-tools"
			if _, err := s.Put(ctx, "acme", other, false, "review"); !errors.Is(err, res.ErrInvalid) {
				t.Fatalf("a conflicting separate connection must be rejected: %v", err)
			}
		})
	}
}
