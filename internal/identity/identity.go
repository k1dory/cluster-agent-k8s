// Package identity encodes the agent identity in certificate URI SANs and decodes it
// from the headers Caddy forwards to the authz endpoint.
//
//	spiffe://sandbox/agent/{slug}/{n}
//	spiffe://sandbox/sandbox/{sandbox_id}
//	spiffe://sandbox/tenant/{tenant}
package identity

import (
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// TrustDomain is the SPIFFE trust domain used in URI SANs.
const TrustDomain = "sandbox"

// Header names set by Caddy (see deploy/gateway/Caddyfile).
const (
	HeaderCertDER = "X-Agent-Cert" // {http.request.tls.client.certificate_der_base64}
	HeaderSANs    = "X-Agent-SAN"  // {http.request.tls.client.san.uris}, fallback
)

// Identity is what a certificate says about the caller.
type Identity struct {
	Slug      string `json:"slug"`
	Instance  int    `json:"instance"`
	SandboxID string `json:"sandbox_id"`
	Tenant    string `json:"tenant"`
	Serial    string `json:"serial,omitempty"`
}

// String returns slug/n.
func (id Identity) String() string { return fmt.Sprintf("%s/%d", id.Slug, id.Instance) }

// URIs builds the URI SANs for a certificate.
func (id Identity) URIs() []*url.URL {
	mk := func(p string) *url.URL { return &url.URL{Scheme: "spiffe", Host: TrustDomain, Path: p} }
	out := []*url.URL{mk(fmt.Sprintf("/agent/%s/%d", id.Slug, id.Instance))}
	if id.SandboxID != "" {
		out = append(out, mk("/sandbox/"+id.SandboxID))
	}
	if id.Tenant != "" {
		out = append(out, mk("/tenant/"+id.Tenant))
	}
	return out
}

// FromURIs parses the URI SANs.
func FromURIs(uris []*url.URL) (*Identity, error) {
	var id Identity
	for _, u := range uris {
		if u.Scheme != "spiffe" || u.Host != TrustDomain {
			continue
		}
		parts := strings.Split(strings.Trim(u.Path, "/"), "/")
		switch {
		case len(parts) == 3 && parts[0] == "agent":
			n, err := strconv.Atoi(parts[2])
			if err != nil {
				return nil, fmt.Errorf("bad instance number in %s", u)
			}
			id.Slug, id.Instance = parts[1], n
		case len(parts) == 2 && parts[0] == "sandbox":
			id.SandboxID = parts[1]
		case len(parts) == 2 && parts[0] == "tenant":
			id.Tenant = parts[1]
		}
	}
	if id.Slug == "" || id.Instance == 0 {
		return nil, errors.New("certificate carries no agent URI SAN")
	}
	return &id, nil
}

// FromCert extracts the identity and serial from a certificate.
func FromCert(c *x509.Certificate) (*Identity, error) {
	id, err := FromURIs(c.URIs)
	if err != nil {
		return nil, err
	}
	id.Serial = c.SerialNumber.Text(16)
	return id, nil
}

// FromRequest reads the identity from the gateway headers. The DER header is preferred
// (gives the serial for revocation checks); the SAN list header is a fallback.
func FromRequest(r *http.Request) (*Identity, error) {
	if b64 := r.Header.Get(HeaderCertDER); b64 != "" {
		der, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", HeaderCertDER, err)
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", HeaderCertDER, err)
		}
		return FromCert(c)
	}
	if raw := r.Header.Get(HeaderSANs); raw != "" {
		var uris []*url.URL
		for _, s := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
			if u, err := url.Parse(s); err == nil {
				uris = append(uris, u)
			}
		}
		return FromURIs(uris)
	}
	return nil, errors.New("no client certificate headers")
}
