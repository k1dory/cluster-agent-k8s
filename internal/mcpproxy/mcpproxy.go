// Package mcpproxy enforces MCP policy on the request body, which forward_auth cannot see.
//
// Caddy sends requests for hosts whose policy rule carries `mcp:` to this handler instead of
// straight to the upstream (after forward_auth has already run, so the injected secrets are on
// the request). Nothing about the destination comes from the request: the host name Caddy
// validated against the site's certificate (strict SNI) selects the policy host, and the
// policy's upstream is where the request goes. The handler re-evaluates the policy for the
// identity, parses the JSON-RPC body strictly (single call or batch, exact protocol keys,
// no duplicates or case variants) and refuses `tools/call` for tools the rule does not
// allow; the rest is forwarded unchanged, streaming responses (SSE) included.
package mcpproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"agent-sandbox/internal/authz"
	"agent-sandbox/internal/policy"
)

// Header names an earlier version used to carry the destination from Caddy to the proxy. No
// trusted party sends them any more: the gateway strips them on every site and the proxy never
// reads them. They remain named so tests can prove a forged one changes nothing.
const (
	HeaderUpstream = "X-Sandbox-Mcp-Upstream"
	HeaderHost     = "X-Sandbox-Mcp-Host"
)

// MaxBody is how much of a JSON-RPC request body is inspected; larger bodies are refused.
const MaxBody = 4 << 20

// Hosts answers which policy host a name is and where it goes (the policy set).
type Hosts interface {
	HostInfo(name string) (policy.Host, bool)
}

// Handler is mounted on the gateway listener as the catch-all route.
type Handler struct {
	Authz *authz.Handler
	Hosts Hosts
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

// protocolKeys are the JSON-RPC / MCP keys the verdict depends on. Any key that equals one of
// them case-insensitively but not exactly is refused: Go-style decoders upstream would accept
// `Method`, JavaScript ones would ignore it, and the proxy must not guess which.
var protocolKeys = map[string]bool{"jsonrpc": true, "id": true, "method": true, "params": true, "name": true, "arguments": true}

type call struct {
	method   string
	toolName string
	hasName  bool
}

// parseCalls decodes a JSON-RPC body (one request or a batch) into the fields the policy
// needs, refusing anything ambiguous: duplicate keys, case variants of protocol keys,
// non-object messages, trailing data.
func parseCalls(body []byte) ([]call, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("unreadable JSON-RPC: %w", err)
	}
	var calls []call
	switch d, _ := tok.(json.Delim); d {
	case '{':
		c, err := parseObject(dec, true)
		if err != nil {
			return nil, err
		}
		calls = []call{c}
	case '[':
		for dec.More() {
			if t, err := dec.Token(); err != nil || t != json.Delim('{') {
				return nil, errors.New("batch entries must be objects")
			}
			c, err := parseObject(dec, true)
			if err != nil {
				return nil, err
			}
			calls = append(calls, c)
		}
		if _, err := dec.Token(); err != nil { // ']'
			return nil, err
		}
	default:
		return nil, errors.New("JSON-RPC message must be an object or a batch")
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("trailing data after the JSON-RPC message")
	}
	return calls, nil
}

// parseObject reads an object whose opening brace was consumed. For the request (top=true)
// it collects method and params.name; for params (top=false) only name.
func parseObject(dec *json.Decoder, top bool) (call, error) {
	var c call
	seen := map[string]bool{}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return c, err
		}
		key, _ := t.(string)
		lower := strings.ToLower(key)
		if seen[lower] {
			return c, fmt.Errorf("duplicate key %q", key)
		}
		seen[lower] = true
		if protocolKeys[lower] && key != lower {
			return c, fmt.Errorf("ambiguous key %q (protocol keys are lower-case)", key)
		}
		switch {
		case top && key == "method":
			if err := dec.Decode(&c.method); err != nil {
				return c, errors.New("method must be a string")
			}
		case top && key == "params":
			t, err := dec.Token()
			if err != nil {
				return c, err
			}
			if t == json.Delim('{') {
				p, err := parseObject(dec, false)
				if err != nil {
					return c, err
				}
				c.toolName, c.hasName = p.toolName, p.hasName
			} else if d, ok := t.(json.Delim); ok && d == '[' {
				return c, errors.New("params must be an object")
			}
			// scalar params: nothing to enforce
		case !top && key == "name":
			if err := dec.Decode(&c.toolName); err != nil {
				return c, errors.New("params.name must be a string")
			}
			c.hasName = true
		default:
			var skip json.RawMessage
			if err := dec.Decode(&skip); err != nil {
				return c, err
			}
		}
	}
	if _, err := dec.Token(); err != nil { // '}'
		return c, err
	}
	return c, nil
}

// check returns the reason a body must be refused under rule, or "" when it may pass.
func check(rule *policy.MCPRule, body []byte) string {
	if rule == nil || !rule.ReadOnly {
		return ""
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return ""
	}
	calls, err := parseCalls(body)
	if err != nil {
		return "mcp: " + err.Error()
	}
	for _, c := range calls {
		switch {
		case c.method == "":
			continue // a response or notification without method: nothing to enforce
		case c.method == "tools/call":
			if !c.hasName {
				return "mcp: tools/call without params.name"
			}
			if !rule.ToolAllowed(c.toolName) {
				return fmt.Sprintf("mcp: tool %q is not allowed on a read-only connection", c.toolName)
			}
		case readMethods[c.method]:
		default:
			return fmt.Sprintf("mcp: method %q is not allowed on a read-only connection", c.method)
		}
	}
	return ""
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log := h.Log
	if log == nil {
		log = slog.Default()
	}
	// The destination is the policy host Caddy served this request for (its site block, its
	// certificate, strict SNI), never anything the client sent in a header.
	host := strings.ToLower(r.Host)
	if hh, _, err := net.SplitHostPort(host); err == nil {
		host = hh
	}
	info, ok := h.Hosts.HostInfo(host)
	if !ok || !info.MCP {
		http.Error(w, "no MCP policy host "+host, http.StatusNotFound)
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
	target, err := url.Parse(info.Upstream)
	if err != nil || target.Host == "" {
		http.Error(w, "bad upstream", http.StatusBadGateway)
		return
	}
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Host = host // the policy host name, whatever address the upstream listens on
			for k := range pr.Out.Header {
				if strings.HasPrefix(k, "X-Sandbox-") || k == "X-Agent-Cert" || k == "X-Agent-San" {
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
