// Package connections is the tenant-scoped catalogue of external services an agent may use:
// an HTTP API or an MCP server, with the headers the gateway adds when the agent talks to it.
// Credentials are never stored: a header carries a `secret:NAME` reference that the gateway
// resolves from the secrets provider at request time, so neither the API, nor the history,
// nor the agent ever sees a value. The admin keeps shared connections (tenant "") every tenant
// may reference; a tenant's references are resolved against its own secrets.
package connections

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"agent-sandbox/internal/model"
	"agent-sandbox/internal/policy"
	res "agent-sandbox/internal/resource"
	"agent-sandbox/internal/secrets"
	"agent-sandbox/internal/store"
)

// Connection types.
const (
	TypeHTTP = "http" // a plain HTTP API behind the gateway's policy
	TypeMCP  = "mcp"  // an MCP server: JSON-RPC inspected by the MCP proxy
)

// Spec is a Connection.
//
// For a host the policy repository serves, the connection only adds headers. For any other
// host the connection is the whole egress rule: the gateway gets a site for it (certificate,
// DNS, forward_auth, the MCP proxy for type mcp), and an agent that names the connection may
// call it on Paths. A tenant may declare such a host only when its settings list it
// (`hosts`); the admin's shared connections may name any host.
type Spec struct {
	Type string `yaml:"type" json:"type"` // http | mcp
	Host string `yaml:"host" json:"host"` // external host name
	// Headers the gateway adds to requests of agents that use this connection. Values are
	// templates: `secret:NAME` is replaced from the tenant's secrets. Credential headers
	// (Authorization, Cookie, anything named like a key or token) must be references.
	Headers map[string]string `yaml:"headers,omitempty" json:"headers,omitempty"`
	// Upstream is where the gateway sends traffic for a host the policy repository does not
	// serve (default https://<host>); ignored for a repository host, whose policy decides.
	Upstream string `yaml:"upstream,omitempty" json:"upstream,omitempty"`
	// Paths an agent may call on such a host (policy path patterns; default "/**").
	Paths []string `yaml:"paths,omitempty" json:"paths,omitempty"`
	// MCP is what the proxy enforces on a type mcp connection for such a host: read_only with
	// an allowlist of tools. Absent: every method and tool passes (the body is still inspected).
	MCP *policy.MCPRule `yaml:"mcp,omitempty" json:"mcp,omitempty"`
}

// HostPolicy says which hosts a connection may name: a repository host (headers only), or a
// host the tenant's settings allow it to serve on its own.
type HostPolicy interface {
	HostInfo(name string) (policy.Host, bool) // the policy repository's hosts
	HostAllowed(tenant, host string) bool     // tenant settings
}

// MCPServer is an MCP endpoint an agent's connections give it (exported to the pod).
type MCPServer = model.MCPServer

var (
	hostRe       = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)
	headerRe     = regexp.MustCompile(`^[A-Za-z0-9-]+$`)
	credentialRe = regexp.MustCompile(`^([A-Za-z]+ )?secret:[A-Za-z0-9_./-]+$`)
	secretRefRe  = regexp.MustCompile(`secret:([A-Za-z0-9_./-]+)`)
	credentialNm = regexp.MustCompile(`(?i)(auth|token|secret|key|password|credential|cookie)`)
)

// Sandboxes is what the gateway side needs from the store: the sandbox an identity names.
type Sandboxes interface {
	GetSandbox(ctx context.Context, id string) (*model.Sandbox, error)
}

// Service validates, stores and resolves connections.
type Service struct {
	Store     store.Catalog
	Secrets   secrets.Provider // optional: when set, every reference must resolve at write time
	Sandboxes Sandboxes        // for HeadersFor (the gateway decision)
	// Hosts decides which hosts a connection may serve on its own. nil: only repository hosts
	// (a connection adds headers and nothing else).
	Hosts HostPolicy
	snap  res.Snapshot // every live connection, for the gateway's header-name and host lists
}

// New returns a service over st; call Refresh (and Watch) so the gateway knows the header names.
func New(st store.Catalog, sec secrets.Provider, sbs Sandboxes) *Service {
	return &Service{Store: st, Secrets: sec, Sandboxes: sbs, snap: res.Snapshot{Store: st, Kind: model.KindConnection}}
}

// Put validates a document and appends it as a new revision in tenant's scope.
func (s *Service) Put(ctx context.Context, tenant string, d *res.Document, admin bool, who string) (*model.CatalogItem, error) {
	it, err := s.Validate(ctx, tenant, d, admin, who)
	if err != nil {
		return nil, err
	}
	if err := s.Store.PutItem(ctx, it, d.Expected()); err != nil {
		return nil, err
	}
	return it, s.refresh(ctx)
}

// Validate checks a document and returns the item it would become, without writing.
func (s *Service) Validate(ctx context.Context, tenant string, d *res.Document, _ bool, who string) (*model.CatalogItem, error) {
	if err := res.CheckDocument(d, model.KindConnection); err != nil {
		return nil, err
	}
	var sp Spec
	if err := res.DecodeStrict(d.Spec, &sp); err != nil {
		return nil, err
	}
	if sp.Type != TypeHTTP && sp.Type != TypeMCP {
		return nil, fmt.Errorf("%w: spec.type must be %s or %s", res.ErrInvalid, TypeHTTP, TypeMCP)
	}
	if !hostRe.MatchString(sp.Host) {
		return nil, fmt.Errorf("%w: spec.host must be a lower-case host name without scheme or port", res.ErrInvalid)
	}
	if err := s.checkOwnHost(tenant, &sp); err != nil {
		return nil, err
	}
	for name, v := range sp.Headers {
		if !headerRe.MatchString(name) {
			return nil, fmt.Errorf("%w: spec.headers: %q is not a header name", res.ErrInvalid, name)
		}
		if credentialNm.MatchString(name) && !credentialRe.MatchString(v) {
			// The value is not echoed: it may be the credential the author should not have written.
			return nil, fmt.Errorf("%w: spec.headers.%s: a credential must be a reference (\"secret:NAME\" or \"Bearer secret:NAME\"), never a value", res.ErrInvalid, http.CanonicalHeaderKey(name))
		}
		if s.Secrets != nil {
			for _, m := range secretRefRe.FindAllStringSubmatch(v, -1) {
				if _, err := s.Secrets.Get(ctx, tenant, m[1]); err != nil {
					return nil, fmt.Errorf("%w: spec.headers.%s: secret %q is not available to tenant %q", res.ErrInvalid, http.CanonicalHeaderKey(name), m[1], tenant)
				}
			}
		}
	}
	spec, err := marshal(sp)
	if err != nil {
		return nil, err
	}
	return &model.CatalogItem{Kind: model.KindConnection, Tenant: tenant, Name: d.Name, Description: d.Description, Spec: spec, CreatedBy: who}, nil
}

// checkOwnHost validates the egress part of a connection for a host the repository does not
// serve, and refuses it when the tenant may not serve that host on its own.
func (s *Service) checkOwnHost(tenant string, sp *Spec) error {
	repoHost := s.Hosts != nil && func() bool { _, ok := s.Hosts.HostInfo(sp.Host); return ok }()
	if repoHost || s.Hosts == nil {
		// The policy repository decides upstream, paths and MCP for this host; a connection
		// declaring them would promise what it cannot deliver.
		if sp.Upstream != "" || len(sp.Paths) > 0 || sp.MCP != nil {
			if repoHost {
				return fmt.Errorf("%w: %s is served by the policy repository: a connection for it adds headers only (no upstream, paths or mcp)", res.ErrInvalid, sp.Host)
			}
			return fmt.Errorf("%w: self-service hosts are not enabled: a connection adds headers only", res.ErrInvalid)
		}
		return nil
	}
	if tenant != "" && !s.Hosts.HostAllowed(tenant, sp.Host) {
		return fmt.Errorf("%w: tenant %s may not reach %s: it is neither served by the policy repository nor listed under the tenant's hosts", res.ErrForbidden, tenant, sp.Host)
	}
	if sp.Upstream != "" {
		u, err := url.Parse(sp.Upstream)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return fmt.Errorf("%w: spec.upstream must be an http(s) URL with a host and nothing else", res.ErrInvalid)
		}
	}
	for _, p := range sp.Paths {
		if !strings.HasPrefix(p, "/") {
			return fmt.Errorf("%w: spec.paths: %q must start with /", res.ErrInvalid, p)
		}
	}
	if sp.MCP != nil && sp.Type != TypeMCP {
		return fmt.Errorf("%w: spec.mcp needs type mcp", res.ErrInvalid)
	}
	// One host, one upstream and one kind across every live connection: the gateway serves a
	// host one way.
	for _, it := range s.snap.All() {
		if it.Tenant == tenant && it.Name == sp.Host {
			continue
		}
		var other Spec
		if err := res.DecodeStrict(it.Spec, &other); err != nil || other.Host != sp.Host {
			continue
		}
		if upstreamOf(&other) != upstreamOf(sp) {
			return fmt.Errorf("%w: %s already goes to %s (connection %s): a host has one upstream", res.ErrInvalid, sp.Host, upstreamOf(&other), res.RefOf(it, tenant))
		}
		if (other.Type == TypeMCP) != (sp.Type == TypeMCP) {
			return fmt.Errorf("%w: %s is already a %s connection (%s): a host has one type", res.ErrInvalid, sp.Host, other.Type, res.RefOf(it, tenant))
		}
	}
	return nil
}

func upstreamOf(sp *Spec) string {
	if sp.Upstream != "" {
		return sp.Upstream
	}
	return "https://" + sp.Host
}

// OwnHosts lists the hosts live connections serve on their own (not the repository's), with
// their upstream, type and header names, and a fingerprint of the list. The guard merges
// them into the policy hosts the gateway, the DNS and the MCP proxy work from.
func (s *Service) OwnHosts() ([]policy.Host, string) {
	byName := map[string]*policy.Host{}
	for _, it := range s.snap.All() {
		var sp Spec
		if err := res.DecodeStrict(it.Spec, &sp); err != nil {
			continue
		}
		if s.Hosts != nil {
			if _, repo := s.Hosts.HostInfo(sp.Host); repo {
				continue
			}
			// A tenant's connection serves its host only while the tenant's settings still list
			// it: the admin withdrawing the host withdraws the site, the DNS answer and the rule.
			if it.Tenant != "" && !s.Hosts.HostAllowed(it.Tenant, sp.Host) {
				continue
			}
		}
		h, ok := byName[sp.Host]
		if !ok {
			h = &policy.Host{Name: sp.Host, Upstream: upstreamOf(&sp), MCP: sp.Type == TypeMCP}
			byName[sp.Host] = h
		}
		for name := range sp.Headers {
			h.Injected = appendUnique(h.Injected, http.CanonicalHeaderKey(name))
		}
	}
	names := make([]string, 0, len(byName))
	for n := range byName {
		names = append(names, n)
	}
	sort.Strings(names)
	hash := sha256.New()
	out := make([]policy.Host, 0, len(names))
	for _, n := range names {
		h := byName[n]
		sort.Strings(h.Injected)
		out = append(out, *h)
		fmt.Fprintf(hash, "%s %s mcp=%v %s\n", h.Name, h.Upstream, h.MCP, strings.Join(h.Injected, ","))
	}
	return out, hex.EncodeToString(hash.Sum(nil))[:12]
}

// RuleFor is the egress rule a sandbox's connections give it for a host the repository does
// not serve: the first connection of the sandbox naming the host whose paths match. Nothing
// for a repository host (its policy decides), nothing for a sandbox without such a connection.
func (s *Service) RuleFor(ctx context.Context, sandboxID, tenant, host, method, reqPath string) (*policy.Rule, bool, error) {
	if s.Sandboxes == nil || sandboxID == "" {
		return nil, false, nil
	}
	if s.Hosts != nil {
		if _, repo := s.Hosts.HostInfo(host); repo {
			return nil, false, nil
		}
	}
	sb, err := s.Sandboxes.GetSandbox(ctx, sandboxID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if sb.Tenant != tenant {
		return nil, false, fmt.Errorf("identity tenant %q is not the sandbox's %q", tenant, sb.Tenant)
	}
	for _, ref := range sb.Connections {
		it, sp, err := s.lookup(ctx, sb.Tenant, ref)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, false, fmt.Errorf("connection %s: %w", ref, err)
		}
		if sp.Host != host {
			continue
		}
		// Delegation is decided now, not when the connection was written: a host the admin
		// removed from the tenant's settings is refused on the next request, whatever the
		// connection says. The admin's shared connections are not delegated and stay.
		if it.Tenant != "" && s.Hosts != nil && !s.Hosts.HostAllowed(it.Tenant, host) {
			continue
		}
		paths := sp.Paths
		if len(paths) == 0 {
			paths = []string{"/**"}
		}
		for _, pat := range paths {
			if policy.PathMatch(pat, reqPath) {
				rule := &policy.Rule{Host: sp.Host, Paths: paths, Upstream: upstreamOf(sp)}
				if sp.Type == TypeMCP {
					rule.MCP = sp.MCP
					if rule.MCP == nil {
						rule.MCP = &policy.MCPRule{}
					}
				}
				return rule, true, nil
			}
		}
	}
	return nil, false, nil
}

// Endpoints lists the MCP servers the connections named by refs (from tenant's scope) give an
// agent: what the pod is told about, so a harness can register them without anyone editing
// its configuration by hand. Unresolvable references are skipped (the launch validated them).
func (s *Service) Endpoints(ctx context.Context, tenant string, refs []string) []MCPServer {
	var out []MCPServer
	for _, ref := range refs {
		sp, err := s.spec(ctx, tenant, ref)
		if err != nil || sp.Type != TypeMCP {
			continue
		}
		p := "/mcp"
		if len(sp.Paths) > 0 && !strings.ContainsAny(sp.Paths[0], "*") {
			p = sp.Paths[0]
		}
		out = append(out, MCPServer{Name: ref, URL: "https://" + sp.Host + p})
	}
	return out
}

func (s *Service) refresh(ctx context.Context) error {
	if s.snap.Store == nil {
		return nil
	}
	return s.snap.Refresh(ctx)
}

// Refresh reloads the set of live connections the gateway's header list is computed from.
func (s *Service) Refresh(ctx context.Context) error { return s.refresh(ctx) }

// Watch keeps that set fresh until ctx ends.
func (s *Service) Watch(ctx context.Context, log *slog.Logger) {
	if s.snap.Store == nil {
		return
	}
	s.snap.Watch(ctx, func(err error) {
		if log != nil {
			log.Error("connections refresh failed, keeping the previous set", "err", err)
		}
	})
}

// HostHeaders lists, per host, the header names any live connection adds, with a fingerprint
// that changes when the list does: the gateway strips those names from agent requests and
// copies them from the decision, so an agent can neither pre-set nor keep one.
func (s *Service) HostHeaders() (map[string][]string, string) {
	out := map[string][]string{}
	for _, it := range s.snap.All() {
		var sp Spec
		if err := res.DecodeStrict(it.Spec, &sp); err != nil {
			continue
		}
		for name := range sp.Headers {
			out[sp.Host] = appendUnique(out[sp.Host], http.CanonicalHeaderKey(name))
		}
	}
	h := sha256.New()
	hosts := make([]string, 0, len(out))
	for host := range out {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	for _, host := range hosts {
		sort.Strings(out[host])
		fmt.Fprintf(h, "%s=%s\n", host, strings.Join(out[host], ","))
	}
	return out, hex.EncodeToString(h.Sum(nil))[:12]
}

func appendUnique(xs []string, x string) []string {
	for _, y := range xs {
		if y == x {
			return xs
		}
	}
	return append(xs, x)
}

// Get returns one connection visible from tenant (own, else shared); revision 0 = latest.
func (s *Service) Get(ctx context.Context, tenant, name string, revision int) (*model.CatalogItem, error) {
	return res.Lookup(ctx, s.Store, model.KindConnection, tenant, res.Ref{Name: name, Rev: revision})
}

// List returns the latest revisions visible from tenant.
func (s *Service) List(ctx context.Context, tenant string) ([]*model.CatalogItem, error) {
	return res.ListVisible(ctx, s.Store, model.KindConnection, tenant)
}

// Revisions lists a connection's history.
func (s *Service) Revisions(ctx context.Context, tenant, name string) ([]*model.CatalogItem, error) {
	return res.Revisions(ctx, s.Store, model.KindConnection, tenant, name)
}

// Delete hides a connection; agents that name it stop resolving it and sandboxes that carry
// it stop getting its headers.
func (s *Service) Delete(ctx context.Context, tenant, name string) error {
	if err := s.Store.DeleteItem(ctx, model.KindConnection, tenant, name); err != nil {
		return err
	}
	return s.refresh(ctx)
}

// Canonical resolves a reference ("name" or "shared/name"; revisions cannot be pinned) from
// tenant's scope and returns the form that names it unambiguously.

// Canonical resolves a reference ("name" or "shared/name"; revisions cannot be pinned) from
// tenant's scope and returns the form that names it unambiguously.
func (s *Service) Canonical(ctx context.Context, tenant, ref string) (string, error) {
	r, err := res.ParseRef(ref)
	if err != nil {
		return "", fmt.Errorf("%w: %v", res.ErrInvalid, err)
	}
	if r.Rev != 0 {
		return "", fmt.Errorf("%w: connections are not pinned by revision", res.ErrInvalid)
	}
	it, err := res.Lookup(ctx, s.Store, model.KindConnection, tenant, r)
	if err != nil {
		return "", err
	}
	return res.RefOf(it, tenant), nil
}

// Headers resolves the connection named by ref from tenant's scope into the headers the
// gateway adds, secrets expanded from tenant's own secrets. For the gateway only: the result
// must never reach an API response or the trace.
func (s *Service) Headers(ctx context.Context, tenant, ref string) (*Spec, map[string]string, error) {
	sp, err := s.spec(ctx, tenant, ref)
	if err != nil {
		return nil, nil, err
	}
	out, err := s.expand(ctx, tenant, sp)
	return sp, out, err
}

// spec looks a connection up from tenant's scope without touching any secret.
func (s *Service) spec(ctx context.Context, tenant, ref string) (*Spec, error) {
	_, sp, err := s.lookup(ctx, tenant, ref)
	return sp, err
}

// lookup is spec with the item it resolved to (whose Tenant says whether it is the tenant's
// own or a shared one).
func (s *Service) lookup(ctx context.Context, tenant, ref string) (*model.CatalogItem, *Spec, error) {
	r, err := res.ParseRef(ref)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", res.ErrInvalid, err)
	}
	it, err := res.Lookup(ctx, s.Store, model.KindConnection, tenant, r)
	if err != nil {
		return nil, nil, err
	}
	var sp Spec
	if err := res.DecodeStrict(it.Spec, &sp); err != nil {
		return nil, nil, err
	}
	return it, &sp, nil
}

// expand resolves the secret references of a connection's headers.
func (s *Service) expand(ctx context.Context, tenant string, sp *Spec) (map[string]string, error) {
	out := map[string]string{}
	for name, tpl := range sp.Headers {
		v, err := secrets.Expand(ctx, s.Secrets, tenant, tpl)
		if err != nil {
			return nil, err
		}
		out[http.CanonicalHeaderKey(name)] = v
	}
	return out, nil
}

// HeadersFor is the gateway side: the headers of the sandbox's connections that name host,
// secrets expanded from the sandbox tenant's own. The identity's tenant must be the sandbox's.
// Only the connections for this host are resolved: a secret that is missing for one service
// never stands in the way of requests to another (the control plane's own API included). A
// connection the sandbox names but which no longer exists adds nothing (the policy still
// decides the request); a reference for this host that cannot be resolved is an error, so
// nothing partial is sent.
func (s *Service) HeadersFor(ctx context.Context, sandboxID, tenant, host string) (map[string]string, error) {
	if s.Sandboxes == nil || sandboxID == "" {
		return nil, nil
	}
	sb, err := s.Sandboxes.GetSandbox(ctx, sandboxID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if sb.Tenant != tenant {
		return nil, fmt.Errorf("identity tenant %q is not the sandbox's %q", tenant, sb.Tenant)
	}
	var out map[string]string
	for _, ref := range sb.Connections {
		sp, err := s.spec(ctx, sb.Tenant, ref)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("connection %s: %w", ref, err)
		}
		if sp.Host != host {
			continue
		}
		h, err := s.expand(ctx, sb.Tenant, sp)
		if err != nil {
			return nil, fmt.Errorf("connection %s: %w", ref, err)
		}
		if out == nil {
			out = map[string]string{}
		}
		for k, v := range h {
			out[k] = v
		}
	}
	return out, nil
}

func marshal(sp Spec) ([]byte, error) {
	// Canonical header names, so two spellings cannot carry two values.
	if len(sp.Headers) > 0 {
		h := make(map[string]string, len(sp.Headers))
		for k, v := range sp.Headers {
			c := http.CanonicalHeaderKey(k)
			if _, dup := h[c]; dup {
				return nil, fmt.Errorf("%w: spec.headers: %s given twice", res.ErrInvalid, c)
			}
			h[c] = strings.TrimSpace(v)
		}
		sp.Headers = h
	}
	return res.Marshal(sp)
}
