// Package mcpproxy enforces MCP policy on the request body, which forward_auth cannot see.
//
// Caddy sends requests for hosts whose policy rule carries `mcp:` to this handler instead of
// straight to the upstream (after forward_auth has already run, so the injected secrets are on
// the request). The handler re-evaluates the policy for the identity, reads the JSON-RPC
// body (single call or batch) and refuses `tools/call` for tools the rule does not allow; the
// rest is forwarded unchanged, streaming responses (SSE) included.
package mcpproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"agent-sandbox/internal/authz"
	"agent-sandbox/internal/model"
	"agent-sandbox/internal/policy"
)

// Headers Caddy sets on requests it hands to the proxy (and strips from what the agent sent).
const (
	HeaderUpstream = "X-Sandbox-Mcp-Upstream" // where the request would have gone, e.g. https://mcp.example.com
	HeaderHost     = "X-Sandbox-Mcp-Host"     // the policy host name
)

// MaxBody is how much of a JSON-RPC request body is inspected; larger bodies are refused.
const MaxBody = 4 << 20

// Handler is mounted on the gateway listener as the catch-all route.
type Handler struct {
	Authz *authz.Handler
	Log   *slog.Logger
	// Transport for upstream calls (nil = http.DefaultTransport).
	Transport http.RoundTripper
}

// Methods that never change anything on the MCP server and are always allowed on read-only rules.
var readMethods = map[string]bool{
	"initialize": true, "notifications/initialized": true, "ping": true,
	"tools/list": true, "resources/list": true, "resources/read": true, "resources/templates/list": true,
	"prompts/list": true, "prompts/get": true, "logging/setLevel": true, "completion/complete": true,
	"notifications/cancelled": true, "notifications/progress": true, "notifications/roots/list_changed": true,
}

type rpcCall struct {
	Method string `json:"method"`
	Params struct {
		Name string `json:"name"`
	} `json:"params"`
}

// check returns the reason a body must be refused under rule, or "" when it may pass.
func check(rule *policy.MCPRule, body []byte) string {
	if rule == nil || !rule.ReadOnly {
		return ""
	}
	t := bytes.TrimSpace(body)
	if len(t) == 0 {
		return ""
	}
	var calls []rpcCall
	if t[0] == '[' {
		if err := json.Unmarshal(t, &calls); err != nil {
			return "mcp: unreadable JSON-RPC batch"
		}
	} else {
		var c rpcCall
		if err := json.Unmarshal(t, &c); err != nil {
			return "mcp: unreadable JSON-RPC request"
		}
		calls = []rpcCall{c}
	}
	for _, c := range calls {
		switch {
		case c.Method == "":
			continue // a response or notification without method: nothing to enforce
		case c.Method == "tools/call":
			if !rule.ToolAllowed(c.Params.Name) {
				return fmt.Sprintf("mcp: tool %q is not allowed on a read-only connection", c.Params.Name)
			}
		case readMethods[c.Method]:
		default:
			return fmt.Sprintf("mcp: method %q is not allowed on a read-only connection", c.Method)
		}
	}
	return ""
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log := h.Log
	if log == nil {
		log = slog.Default()
	}
	upstream, host := r.Header.Get(HeaderUpstream), r.Header.Get(HeaderHost)
	if upstream == "" || host == "" {
		http.Error(w, "not an MCP proxy request", http.StatusNotFound)
		return
	}
	// forward_auth already evaluated and traced the request (host, method, path); this second
	// evaluation only rebuilds the rule and the verdict headers, so it is not traced again.
	d := h.Authz.Decide(r.Context(), r, host, r.Method, r.URL.Path)
	if !d.Allowed() {
		http.Error(w, d.Reason, d.Code)
		return
	}
	var body []byte
	if r.Body != nil && r.Method != http.MethodGet && r.Method != http.MethodHead {
		b, err := io.ReadAll(io.LimitReader(r.Body, MaxBody+1))
		if err != nil {
			http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
			return
		}
		if len(b) > MaxBody {
			http.Error(w, "mcp: request body too large to inspect", http.StatusRequestEntityTooLarge)
			return
		}
		body = b
	}
	if reason := check(d.Rule.MCP, body); reason != "" {
		// A refusal on the body is a decision of its own: traced as egress.deny with the reason.
		d.Code, d.Reason, d.Rule = http.StatusForbidden, reason, nil
		h.Authz.Record(r.Context(), d, host, r.Method, r.URL.Path)
		log.Warn("mcp", "verdict", "deny", "reason", reason, "agent", d.Identity.String(), "host", host)
		http.Error(w, reason, http.StatusForbidden)
		return
	}
	target, err := url.Parse(upstream)
	if err != nil || target.Host == "" {
		http.Error(w, "bad upstream", http.StatusBadGateway)
		return
	}
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Host = host // the policy host name, whatever address the upstream listens on
			for k := range pr.Out.Header {
				if strings.HasPrefix(k, "X-Sandbox-Mcp-") || k == "X-Agent-Cert" || k == "X-Agent-San" {
					pr.Out.Header.Del(k)
				}
			}
			for name, v := range d.Headers {
				pr.Out.Header.Set(name, v)
			}
			if body != nil {
				pr.Out.Body = io.NopCloser(bytes.NewReader(body))
				pr.Out.ContentLength = int64(len(body))
			}
		},
		Transport:     h.Transport,
		FlushInterval: -1, // SSE
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if errors.Is(err, context.Canceled) {
				return
			}
			http.Error(w, "mcp upstream: "+err.Error(), http.StatusBadGateway)
		},
	}
	rp.ServeHTTP(w, r)
}

// Egress is kept for symmetry with authz traces: the proxy records through authz.Record.
var _ = model.EventEgressDen
