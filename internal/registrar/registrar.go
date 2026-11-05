// Package registrar issues agent identities at pod start.
//
// Bootstrap: the init container sends a CSR plus its projected ServiceAccount token.
// The token is verified (TokenReview in Kubernetes, a static table in dev), the pod's
// labels say which sandbox/slug/tenant it is, the next instance number is allocated
// atomically and the CA signs a certificate whose URI SANs carry that identity.
// Instance numbers are never reused; when the pod goes away the instance is retired
// and authz rejects the certificate even though it is still within its validity.
package registrar

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"sync"
	"time"

	"agent-sandbox/internal/ca"
	"agent-sandbox/internal/identity"
	"agent-sandbox/internal/model"
	"agent-sandbox/internal/store"
)

// PodInfo is what the resolver learns from a bootstrap token.
type PodInfo struct {
	Name      string
	Namespace string
	SandboxID string
	Slug      string
	Tenant    string
}

// Resolver turns a bootstrap token into pod info. Kubernetes: TokenReview + pod labels.
type Resolver interface {
	Resolve(ctx context.Context, token string) (*PodInfo, error)
}

// StaticResolver maps fixed tokens to pods (development without Kubernetes).
type StaticResolver map[string]PodInfo

func (s StaticResolver) Resolve(_ context.Context, token string) (*PodInfo, error) {
	p, ok := s[token]
	if !ok {
		return nil, ErrUnauthorized
	}
	return &p, nil
}

// ErrUnauthorized is returned for an invalid bootstrap token.
var ErrUnauthorized = errors.New("bootstrap token rejected")

// Registrar is the identity issuer.
type Registrar struct {
	CA        *ca.CA
	Store     store.Store
	Resolver  Resolver
	TTL       time.Duration
	GatewayCA []byte // root of the gateway's server certificates, handed to the pod
	Log       *slog.Logger

	mu sync.RWMutex
}

// SetGatewayCA replaces the gateway root handed to pods (fetched from Caddy at runtime).
func (r *Registrar) SetGatewayCA(pem []byte) {
	r.mu.Lock()
	r.GatewayCA = pem
	r.mu.Unlock()
}

func (r *Registrar) gatewayCA() []byte {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.GatewayCA
}

// BootstrapRequest is the body of POST /bootstrap.
type BootstrapRequest struct {
	CSR string `json:"csr"`
}

// BootstrapResponse is what the init container writes to disk.
type BootstrapResponse struct {
	Instance  int       `json:"instance"`
	Slug      string    `json:"slug"`
	SandboxID string    `json:"sandbox_id"`
	Tenant    string    `json:"tenant"`
	Cert      string    `json:"cert"`       // leaf, PEM
	CA        string    `json:"ca"`         // agent CA root, PEM
	GatewayCA string    `json:"gateway_ca"` // trust this for TLS to the gateway
	NotAfter  time.Time `json:"not_after"`
}

// Bootstrap verifies the token, allocates an instance and signs the CSR.
func (r *Registrar) Bootstrap(ctx context.Context, token string, req BootstrapRequest) (*BootstrapResponse, error) {
	if token == "" {
		return nil, ErrUnauthorized
	}
	pod, err := r.Resolver.Resolve(ctx, token)
	if err != nil {
		return nil, err
	}
	if pod.SandboxID == "" || pod.Slug == "" {
		return nil, fmt.Errorf("pod %s/%s lacks sandbox labels", pod.Namespace, pod.Name)
	}
	sb, err := r.Store.GetSandbox(ctx, pod.SandboxID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, fmt.Errorf("sandbox %s: %w", pod.SandboxID, err)
	} else if err != nil {
		return nil, unavailable(err)
	}
	if sb.Slug != pod.Slug {
		return nil, fmt.Errorf("pod slug %q does not match sandbox slug %q", pod.Slug, sb.Slug)
	}
	// The tenant goes into the certificate and decides whose policies and secrets apply: it
	// must be the sandbox's, not whatever the pod's label says.
	if sb.Tenant != pod.Tenant {
		return nil, fmt.Errorf("pod tenant %q does not match sandbox tenant %q", pod.Tenant, sb.Tenant)
	}
	csr, err := ca.ParseCSR([]byte(req.CSR))
	if err != nil {
		return nil, fmt.Errorf("csr: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("csr signature: %w", err)
	}
	// One identity per pod and key: agent-init sends the same CSR on every attempt, so a retry
	// after a lost response, or one racing the attempt it gave up on, gets the same instance
	// and the same serial and validity, and whichever certificate the pod keeps is valid. The
	// store serialises the bootstraps of a sandbox across replicas (BindInstance); a pod
	// with a new key (its init container restarted) replaces its earlier identity.
	serial, err := serialFor(pod.SandboxID, pod.Name, csr)
	if err != nil {
		return nil, fmt.Errorf("csr: %w", err)
	}
	// The identity never outlives the sandbox: a TTL set on the sandbox (explicitly, or from the
	// OIDC token that created it) caps the certificate too.
	var cap time.Time
	if sb.ExpiresAt != nil {
		cap = *sb.ExpiresAt
	}
	var certPEM []byte
	var cert *x509.Certificate
	bound, err := r.Store.BindInstance(ctx, store.InstanceBinding{SandboxID: pod.SandboxID, PodName: pod.Name, Serial: serial.Text(16)},
		func(n int, existing *model.Instance) (*model.Instance, error) {
			id := identity.Identity{Slug: pod.Slug, Instance: n, SandboxID: pod.SandboxID, Tenant: pod.Tenant, AdminGrant: sb.AdminGrant}
			sr := ca.SignRequest{CSR: csr, CN: pod.Slug, URIs: id.URIs(), TTL: r.TTL, NotAfter: cap, Serial: serial}
			if existing != nil {
				sr.NotBefore, sr.NotAfter = existing.IssuedAt, existing.NotAfter
			}
			var err error
			if cert, certPEM, err = r.CA.Sign(sr); err != nil {
				return nil, err
			}
			if existing != nil {
				return existing, nil
			}
			return &model.Instance{
				SandboxID: pod.SandboxID, Slug: pod.Slug, Tenant: pod.Tenant, PodName: pod.Name,
				Serial: serial.Text(16), IssuedAt: cert.NotBefore, NotAfter: cert.NotAfter,
			}, nil
		})
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, fmt.Errorf("sandbox %s: %w", pod.SandboxID, err)
		}
		return nil, unavailable(err)
	}
	in := bound.Instance
	if bound.Current != pod.Name {
		// The orchestrator already named a newer pod (a rollout replaced this one while it was
		// still starting): the identity we issue is retired with the old pod anyway.
		r.log().Warn("bootstrap from a pod that is no longer current", "pod", pod.Name, "current", bound.Current, "sandbox", sb.ID)
	}
	for _, old := range bound.Retired {
		r.log().Warn("bootstrap with a new key from the same pod: earlier identity retired", "pod", pod.Name, "sandbox", pod.SandboxID, "retired", old, "instance", in.N)
	}
	r.log().Info("identity issued", "slug", pod.Slug, "instance", in.N, "sandbox", pod.SandboxID, "tenant", pod.Tenant, "pod", pod.Name, "serial", in.Serial, "repeated", bound.Reused)
	return &BootstrapResponse{
		Instance: in.N, Slug: pod.Slug, SandboxID: pod.SandboxID, Tenant: pod.Tenant,
		Cert: string(certPEM), CA: string(r.CA.PEM()), GatewayCA: string(r.gatewayCA()), NotAfter: cert.NotAfter,
	}, nil
}

// ErrUnavailable: the bootstrap could not be completed for a reason on the platform's side
// (the store did not answer, a write conflicted); the same request may succeed when retried.
// The HTTP layer answers it with 503 so agent-init retries instead of giving up.
var ErrUnavailable = errors.New("identity issuance temporarily unavailable, retry")

func unavailable(err error) error { return fmt.Errorf("%w: %v", ErrUnavailable, err) }

// serialFor derives the certificate serial from the sandbox, the pod and the CSR's public
// key: the same pod presenting the same key gets the same serial on every attempt. 127 bits
// of SHA-256, positive and non-zero as RFC 5280 asks.
func serialFor(sandboxID, pod string, csr *x509.CertificateRequest) (*big.Int, error) {
	spki, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	fmt.Fprintf(h, "agent-sandbox serial\x00%s\x00%s\x00", sandboxID, pod)
	h.Write(spki)
	sum := h.Sum(nil)[:16]
	sum[0] &= 0x7f
	n := new(big.Int).SetBytes(sum)
	if n.Sign() == 0 {
		n.SetInt64(1)
	}
	return n, nil
}

// RetireSandbox retires every live instance of a sandbox (called when its pod is deleted).
func (r *Registrar) RetireSandbox(ctx context.Context, sandboxID string) error {
	ins, err := r.Store.ListInstances(ctx, sandboxID)
	if err != nil {
		return err
	}
	for _, in := range ins {
		if in.RetiredAt == nil {
			if err := r.Store.RetireInstance(ctx, in.N); err != nil {
				return err
			}
			r.log().Info("identity retired", "slug", in.Slug, "instance", in.N, "sandbox", sandboxID)
		}
	}
	return nil
}

// Check returns the instance for a serial if it is still valid, or an error naming why not.
func (r *Registrar) Check(ctx context.Context, id *identity.Identity) (*model.Instance, error) {
	if id.Serial == "" {
		// SAN-only header: we cannot look the serial up, fall back to the instance table by number.
		ins, err := r.Store.ListInstances(ctx, id.SandboxID)
		if err != nil {
			return nil, err
		}
		for _, in := range ins {
			if in.N == id.Instance {
				return validInstance(in)
			}
		}
		return nil, errors.New("unknown instance")
	}
	in, err := r.Store.InstanceBySerial(ctx, id.Serial)
	if errors.Is(err, store.ErrNotFound) {
		return nil, errors.New("unknown certificate serial")
	}
	if err != nil {
		return nil, err
	}
	if in.N != id.Instance || in.Slug != id.Slug {
		return nil, errors.New("certificate identity does not match issued instance")
	}
	return validInstance(in)
}

func validInstance(in *model.Instance) (*model.Instance, error) {
	if in.RetiredAt != nil {
		return nil, fmt.Errorf("instance %d retired at %s", in.N, in.RetiredAt.Format(time.RFC3339))
	}
	if time.Now().After(in.NotAfter) {
		return nil, fmt.Errorf("instance %d expired", in.N)
	}
	return in, nil
}

// CRL lists retired-but-unexpired serials as a PEM CRL.
func (r *Registrar) CRL(ctx context.Context) ([]byte, error) {
	sbs, err := r.Store.ListSandboxes(ctx)
	if err != nil {
		return nil, err
	}
	var serials []string
	for _, sb := range sbs {
		ins, err := r.Store.ListInstances(ctx, sb.ID)
		if err != nil {
			return nil, err
		}
		for _, in := range ins {
			if in.RetiredAt != nil && time.Now().Before(in.NotAfter) {
				serials = append(serials, in.Serial)
			}
		}
	}
	return r.CA.CRL(serials)
}

func (r *Registrar) log() *slog.Logger {
	if r.Log == nil {
		return slog.Default()
	}
	return r.Log
}
