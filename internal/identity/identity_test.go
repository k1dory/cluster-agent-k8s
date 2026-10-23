package identity

import (
	"net/http"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	id := Identity{Slug: "backend-dev", Instance: 42, SandboxID: "sb_1", Tenant: "u_7"}
	got, err := FromURIs(id.URIs())
	if err != nil {
		t.Fatal(err)
	}
	if *got != id {
		t.Fatalf("got %+v want %+v", *got, id)
	}
}

func TestFromSANHeader(t *testing.T) {
	r, _ := http.NewRequest("GET", "/", nil)
	r.Header.Set(HeaderSANs, "spiffe://sandbox/agent/netops/3,spiffe://sandbox/tenant/u_1")
	id, err := FromRequest(r)
	if err != nil {
		t.Fatal(err)
	}
	if id.Slug != "netops" || id.Instance != 3 || id.Tenant != "u_1" {
		t.Fatalf("bad identity %+v", id)
	}
	r.Header.Set(HeaderSANs, "spiffe://other/agent/x/1")
	if _, err := FromRequest(r); err == nil {
		t.Fatal("foreign trust domain must be rejected")
	}
}
