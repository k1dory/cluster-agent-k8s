// Package authz answers Caddy's forward_auth: is this agent allowed to make this request,
// and which headers (secrets) should the gateway add before sending it upstream.
package authz

import (
	"context"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"agent-sandbox/internal/identity"
	"agent-sandbox/internal/model"
	"agent-sandbox/internal/policy"
	"agent-sandbox/internal/secrets"
)

// Checker validates that an identity is still live (Registrar.Check).
type Checker interface {
	Check(ctx context.Context, id *identity.Identity) (*model.Instance, error)
}

// Toucher records activity (the orchestrator's idle timer).
type Toucher interface {
	Touch(ctx context.Context, sandboxID string)
}

// Recorder writes gateway decisions into the sandbox trace (the orchestrator).
type Recorder interface {
	RecordEgress(ctx context.Context, sandboxID string, allowed bool, eg model.Egress)
}

// Trace levels for Recorder.
const (
	TraceAll    = "all"    // every decision
	TraceDenied = "denied" // only refusals
	TraceOff    = "off"
)

// Policies is what a decision needs from the policy side: the rule that applies and whether
// the identity's ownership of its slug still holds (the policy set, or the guard that adds
// PolicyBindings to it).
type Policies interface {
	Match(slug, host, method, reqPath string) (*policy.Rule, bool)
	AllowedFor(slug, tenant string) bool
	Revoked(slug, tenant string, adminGrant bool) bool
}

// Handler is the forward_auth endpoint.
type Handler struct {
	Policies Policies
	Secrets  secrets.Provider
	Checker  Checker
	Toucher  Toucher
	Recorder Recorder
	Trace    string          // TraceAll (default), TraceDenied or TraceOff
	Quiet    map[string]bool // hosts never traced (the control plane's own API: the runner polls it constantly)
	Audit    *slog.Logger
}

// Response headers the gateway copies onto the upstream request (keep deploy/gateway/Caddyfile in sync).
const (
	HeaderSlug     = "X-Agent-Slug"
	HeaderInstance = "X-Agent-Instance"
	HeaderTenant   = "X-Agent-Tenant"
	HeaderSandbox  = "X-Agent-Sandbox"
	HeaderAccess   = "X-Agent-Access"
)

// Decision is the outcome of one policy evaluation, shared by the forward_auth endpoint and
// the MCP proxy.
type Decision struct {
	Identity *identity.Identity
	Rule     *policy.Rule
	Headers  map[string]string // everything the gateway adds upstream: identity + injected secrets
	Code     int               // on deny
	Reason   string            // on deny
}

// Allowed reports a positive decision.
func (d *Decision) Allowed() bool { return d.Rule != nil }

// Decide evaluates method+host+path for the identity in the request headers. Secrets are
// resolved before anything is decided, so a denial never carries a partially injected set.
func (h *Handler) Decide(ctx context.Context, r *http.Request, host, method, p string) *Decision {
	id, err := identity.FromRequest(r)
	if err != nil {
		return &Decision{Code: http.StatusForbidden, Reason: "no agent identity: " + err.Error()}
	}
	d := &Decision{Identity: id}
	if h.Checker != nil {
		if _, err := h.Checker.Check(ctx, id); err != nil {
			d.Code, d.Reason = http.StatusForbidden, "identity rejected: "+err.Error()
			return d
		}
	}
	// Ownership is re-checked on every request: when a policy's tenants list changes in git,
	// agents that already run under the slug lose their access at once, not at their next wake.
	if h.Policies.Revoked(id.Slug, id.Tenant, id.AdminGrant) {
		d.Code, d.Reason = http.StatusForbidden, "policy: tenant "+id.Tenant+" no longer owns slug "+id.Slug
		return d
	}
	rule, ok := h.Policies.Match(id.Slug, host, method, p)
	if !ok {
		d.Code, d.Reason = http.StatusForbidden, "policy: no rule for "+method+" "+host+p
		return d
	}
	headers := map[string]string{}
	for name, tpl := range rule.Inject {
		v, err := secrets.Expand(ctx, h.Secrets, id.Tenant, tpl)
		if err != nil {
			// A missing tenant secret is a configuration problem, not an agent fault; 502 keeps it
			// distinguishable. Nothing resolved so far leaves this function.
			d.Code, d.Reason = http.StatusBadGateway, "secret: "+err.Error()
			return d
		}
		headers[http.CanonicalHeaderKey(name)] = v
	}
	headers[HeaderSlug] = id.Slug
	headers[HeaderInstance] = strconv.Itoa(id.Instance)
	headers[HeaderTenant] = id.Tenant
	headers[HeaderSandbox] = id.SandboxID
	if rule.MCP != nil && rule.MCP.ReadOnly {
		headers[HeaderAccess] = "read-only"
	}
	d.Rule, d.Headers = rule, headers
	return d
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	host := r.Header.Get("X-Forwarded-Host")
	uri := r.Header.Get("X-Forwarded-Uri")
	method := r.Header.Get("X-Forwarded-Method")
	src := r.Header.Get("X-Forwarded-For")
	if method == "" {
		method = r.Method
	}
	log := h.Audit
	if log == nil {
		log = slog.Default()
	}
	p := uri
	if u, err := url.ParseRequestURI(uri); err == nil {
		p = u.Path
	}
	d := h.Decide(r.Context(), r, host, method, p)
	h.Record(r.Context(), d, host, method, p)
	if !d.Allowed() {
		attrs := []any{"verdict", "deny", "reason", d.Reason, "host", host, "method", method, "uri", uri, "src", src, "code", d.Code}
		if d.Identity != nil {
			attrs = append(attrs, "agent", d.Identity.String(), "tenant", d.Identity.Tenant, "sandbox", d.Identity.SandboxID)
		}
		log.Warn("egress", attrs...)
		// The response carries no verdict headers: forward_auth copies headers only on 2xx, and
		// even so nothing secret was put on w.
		http.Error(w, d.Reason, d.Code)
		return
	}
	for name, v := range d.Headers {
		w.Header().Set(name, v)
	}
	if h.Toucher != nil && d.Identity.SandboxID != "" {
		h.Toucher.Touch(r.Context(), d.Identity.SandboxID)
	}
	log.Info("egress", "verdict", "allow", "agent", d.Identity.String(), "tenant", d.Identity.Tenant, "sandbox", d.Identity.SandboxID,
		"host", host, "method", method, "uri", uri, "src", src, "took_us", time.Since(start).Microseconds())
	w.WriteHeader(http.StatusOK)
}

// Record writes the decision into the trace according to the trace level.
func (h *Handler) Record(ctx context.Context, d *Decision, host, method, p string) {
	if h.Recorder == nil || d.Identity == nil || h.Trace == TraceOff || h.Quiet[host] || (d.Allowed() && h.Trace == TraceDenied) {
		return
	}
	h.Recorder.RecordEgress(ctx, d.Identity.SandboxID, d.Allowed(), model.Egress{Host: host, Method: method, Path: p, Code: d.Code, Reason: d.Reason})
}
