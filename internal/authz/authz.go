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

// Handler is the forward_auth endpoint.
type Handler struct {
	Policies *policy.Set
	Secrets  secrets.Provider
	Checker  Checker
	Toucher  Toucher
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
	deny := func(code int, reason string, id *identity.Identity) {
		attrs := []any{"verdict", "deny", "reason", reason, "host", host, "method", method, "uri", uri, "src", src, "code", code}
		if id != nil {
			attrs = append(attrs, "agent", id.String(), "tenant", id.Tenant, "sandbox", id.SandboxID)
		}
		log.Warn("egress", attrs...)
		http.Error(w, reason, code)
	}

	id, err := identity.FromRequest(r)
	if err != nil {
		deny(http.StatusForbidden, "no agent identity: "+err.Error(), nil)
		return
	}
	if h.Checker != nil {
		if _, err := h.Checker.Check(r.Context(), id); err != nil {
			deny(http.StatusForbidden, "identity rejected: "+err.Error(), id)
			return
		}
	}
	p := uri
	if u, err := url.ParseRequestURI(uri); err == nil {
		p = u.Path
	}
	rule, ok := h.Policies.Match(id.Slug, host, method, p)
	if !ok {
		deny(http.StatusForbidden, "policy: no rule for "+method+" "+host+p, id)
		return
	}
	for name, tpl := range rule.Inject {
		v, err := secrets.Expand(r.Context(), h.Secrets, id.Tenant, tpl)
		if err != nil {
			// A missing tenant secret is a configuration problem, not an agent fault; 502 keeps it distinguishable.
			deny(http.StatusBadGateway, "secret: "+err.Error(), id)
			return
		}
		w.Header().Set(name, v)
	}
	w.Header().Set(HeaderSlug, id.Slug)
	w.Header().Set(HeaderInstance, strconv.Itoa(id.Instance))
	w.Header().Set(HeaderTenant, id.Tenant)
	w.Header().Set(HeaderSandbox, id.SandboxID)
	if rule.MCP != nil && rule.MCP.ReadOnly {
		w.Header().Set(HeaderAccess, "read-only")
	}
	if h.Toucher != nil && id.SandboxID != "" {
		h.Toucher.Touch(r.Context(), id.SandboxID)
	}
	log.Info("egress", "verdict", "allow", "agent", id.String(), "tenant", id.Tenant, "sandbox", id.SandboxID,
		"host", host, "method", method, "uri", uri, "src", src, "took_us", time.Since(start).Microseconds())
	w.WriteHeader(http.StatusOK)
}
