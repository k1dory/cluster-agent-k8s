package citrust

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"agent-sandbox/internal/model"
	res "agent-sandbox/internal/resource"
	"agent-sandbox/internal/store"
)

func doc(t *testing.T, sp any) *res.Document {
	t.Helper()
	b, err := json.Marshal(sp)
	if err != nil {
		t.Fatal(err)
	}
	return &res.Document{Kind: model.KindCITrust, Name: "github-config", Spec: b}
}

func TestValidate(t *testing.T) {
	ctx := context.Background()
	s := New(store.NewMemory(), 0)
	good := Spec{Issuer: "https://token.actions.githubusercontent.com", Audience: "https://sandbox.example.com", Claims: map[string]string{"repository": "acme/config", "ref": "refs/heads/main"}, TTL: "15m"}
	it, err := s.Put(ctx, "acme", doc(t, good), false, "alice")
	if err != nil || it.Kind != model.KindCITrust || it.Tenant != "acme" || it.Revision != 1 {
		t.Fatalf("good trust: %v %+v", err, it)
	}
	if sp, err := Decode(it); err != nil || sp.Claims["ref"] != "refs/heads/main" {
		t.Fatalf("decode: %v %+v", err, sp)
	}
	for name, tc := range map[string]struct {
		spec any
		want string
	}{
		"http_issuer":        {Spec{Issuer: "http://gitlab.example", Audience: "a", Claims: map[string]string{"project_path": "x"}}, "spec.issuer"},
		"issuer_with_query":  {Spec{Issuer: "https://gitlab.example?x=1", Audience: "a", Claims: map[string]string{"project_path": "x"}}, "spec.issuer"},
		"issuer_slash":       {Spec{Issuer: "https://gitlab.example/", Audience: "a", Claims: map[string]string{"project_path": "x"}}, "slash"},
		"no_audience":        {Spec{Issuer: "https://gitlab.example", Claims: map[string]string{"project_path": "x"}}, "spec.audience"},
		"no_claims":          {Spec{Issuer: "https://gitlab.example", Audience: "a"}, "spec.claims"},
		"reserved_claim":     {Spec{Issuer: "https://gitlab.example", Audience: "a", Claims: map[string]string{"aud": "x"}}, "aud"},
		"bad_claim_name":     {Spec{Issuer: "https://gitlab.example", Audience: "a", Claims: map[string]string{"Repo Name": "x"}}, "not a claim name"},
		"empty_value":        {Spec{Issuer: "https://gitlab.example", Audience: "a", Claims: map[string]string{"ref": ""}}, "spec.claims.ref"},
		"bad_pattern":        {Spec{Issuer: "https://gitlab.example", Audience: "a", Claims: map[string]string{"ref": "refs/[heads"}}, "spec.claims.ref"},
		"ttl_too_short":      {Spec{Issuer: "https://gitlab.example", Audience: "a", Claims: map[string]string{"ref": "x"}, TTL: "30s"}, "at least 1m"},
		"ttl_over_cap":       {Spec{Issuer: "https://gitlab.example", Audience: "a", Claims: map[string]string{"ref": "x"}, TTL: "2h"}, "at most 1h0m0s"},
		"ttl_not_a_duration": {Spec{Issuer: "https://gitlab.example", Audience: "a", Claims: map[string]string{"ref": "x"}, TTL: "soon"}, "not a duration"},
		"unknown_field":      {map[string]any{"issuer": "https://gitlab.example", "audience": "a", "claims": map[string]string{"ref": "x"}, "secret": "no"}, "secret"},
	} {
		_, err := s.Validate(ctx, "acme", doc(t, tc.spec), false, "alice")
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v (want %q)", name, err, tc.want)
		}
	}
	// The shared scope has no trusts: an admin's job keeps the admin token.
	if _, err := s.Validate(ctx, "", doc(t, good), true, "admin"); err == nil || !strings.Contains(err.Error(), "belongs to a tenant") {
		t.Fatalf("shared trust: %v", err)
	}
	// The cap is the server's.
	s.MaxTTL = 2 * time.Hour
	if _, err := s.Validate(ctx, "acme", doc(t, Spec{Issuer: "https://gitlab.example", Audience: "a", Claims: map[string]string{"ref": "x"}, TTL: "2h"}), false, "a"); err != nil {
		t.Fatalf("ttl within a higher cap: %v", err)
	}
	// A loopback http issuer is for tests.
	if err := CheckIssuer("http://127.0.0.1:8443"); err != nil {
		t.Fatal(err)
	}
}

func TestMatches(t *testing.T) {
	sp := Spec{Claims: map[string]string{"repository": "acme/*", "ref": "refs/heads/main", "groups": "ops-*"}}
	claims := map[string]any{"repository": "acme/config", "ref": "refs/heads/main", "groups": []any{"devs", "ops-eu"}}
	if ok, why := Matches(sp, claims); !ok {
		t.Fatalf("should match: %s", why)
	}
	for name, change := range map[string]map[string]any{
		"other_org":   {"repository": "evil/config"},
		"nested_path": {"repository": "acme/config/sub"},
		"other_ref":   {"ref": "refs/heads/dev"},
		"no_group":    {"groups": []any{"devs"}},
		"not_a_list":  {"groups": 42},
		"absent":      {"ref": nil},
	} {
		c := map[string]any{}
		for k, v := range claims {
			c[k] = v
		}
		for k, v := range change {
			if v == nil {
				delete(c, k)
			} else {
				c[k] = v
			}
		}
		if ok, why := Matches(sp, c); ok || why == "" {
			t.Errorf("%s: matched", name)
		}
	}
}
