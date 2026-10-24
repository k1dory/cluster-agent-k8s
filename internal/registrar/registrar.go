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
	"errors"
	"fmt"
	"log/slog"
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
	if err != nil {
		return nil, fmt.Errorf("sandbox %s: %w", pod.SandboxID, err)
	}
	if sb.Slug != pod.Slug {
		return nil, fmt.Errorf("pod slug %q does not match sandbox slug %q", pod.Slug, sb.Slug)
	}
	csr, err := ca.ParseCSR([]byte(req.CSR))
	if err != nil {
		return nil, fmt.Errorf("csr: %w", err)
	}
	n, err := r.Store.NextInstance(ctx)
	if err != nil {
		return nil, err
	}
	id := identity.Identity{Slug: pod.Slug, Instance: n, SandboxID: pod.SandboxID, Tenant: pod.Tenant}
	// The identity never outlives the sandbox: a TTL set on the sandbox (explicitly, or from the
	// OIDC token that created it) caps the certificate too.
	var cap time.Time
	if sb.ExpiresAt != nil {
		cap = *sb.ExpiresAt
	}
	cert, certPEM, err := r.CA.Sign(ca.SignRequest{CSR: csr, CN: pod.Slug, URIs: id.URIs(), TTL: r.TTL, NotAfter: cap})
	if err != nil {
		return nil, err
	}
	in := &model.Instance{
		N: n, SandboxID: pod.SandboxID, Slug: pod.Slug, Tenant: pod.Tenant, PodName: pod.Name,
		Serial: cert.SerialNumber.Text(16), IssuedAt: time.Now(), NotAfter: cert.NotAfter,
	}
	if err := r.Store.CreateInstance(ctx, in); err != nil {
		return nil, err
	}
	// The orchestrator may be writing the same row (pod name, status): reload and retry on conflict.
	for attempt := 0; ; attempt++ {
		sb.Instance = n
		sb.PodName = pod.Name
		err := r.Store.UpdateSandbox(ctx, sb)
		if err == nil {
			break
		}
		if !errors.Is(err, store.ErrConflict) || attempt >= 10 {
			return nil, err
		}
		if sb, err = r.Store.GetSandbox(ctx, pod.SandboxID); err != nil {
			return nil, err
		}
	}
	r.log().Info("identity issued", "slug", pod.Slug, "instance", n, "sandbox", pod.SandboxID, "tenant", pod.Tenant, "pod", pod.Name, "serial", in.Serial)
	return &BootstrapResponse{
		Instance: n, Slug: pod.Slug, SandboxID: pod.SandboxID, Tenant: pod.Tenant,
		Cert: string(certPEM), CA: string(r.CA.PEM()), GatewayCA: string(r.gatewayCA()), NotAfter: cert.NotAfter,
	}, nil
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
