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

// A tenant with self-service hosts could store an upstream Caddy refuses (a path, a
// placeholder) and so freeze the gateway's configuration for every tenant.
func TestReviewConnectionRefusesUpstreamCaddyWouldReject(t *testing.T) {
	ctx := context.Background()
	s := New(store.NewMemory(), secrets.Static{}, nil)
	s.Hosts = repoHosts{allowed: map[string][]string{"acme": {"tools.example.com"}}}
	put := func(name, upstream string) error {
		raw, err := json.Marshal(Spec{Type: TypeHTTP, Host: "tools.example.com", Upstream: upstream})
		if err != nil {
			t.Fatal(err)
		}
		_, err = s.Put(ctx, "acme", &res.Document{Name: name, Spec: raw}, false, "review")
		return err
	}
	for i, bad := range []string{"https://10.0.0.5:8443/api", "https://{http.request.host}", "https://10.0.0.5:8443 {", "https://10.0.0.5:8443/"} {
		if err := put("bad"+string(rune('a'+i)), bad); !errors.Is(err, res.ErrInvalid) {
			t.Errorf("%q must be refused as invalid: %v", bad, err)
		}
	}
	if err := put("v6", "https://[fd00::5]:8443"); err != nil {
		t.Fatalf("an IPv6 upstream is a valid upstream: %v", err)
	}
}
