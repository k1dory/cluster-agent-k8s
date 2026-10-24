package httpapi

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"agent-sandbox/internal/authz"
	"agent-sandbox/internal/identity"
	"agent-sandbox/internal/model"
	"agent-sandbox/internal/secrets"
)

// The self-service path end to end, with nothing but API calls: the admin lists the hosts
// alice may reach, alice declares an MCP server as a connection and an agent that uses it,
// creates a sandbox, and the gateway serves that host for that sandbox only. Nothing in the
// policy repository or a cluster manifest changed.
func TestSelfServiceMCPConnectionEndToEnd(t *testing.T) {
	s, guard := configStack(t)
	api := s.platform.URL
	ctx := context.Background()
	mcp := `{"spec":{"type":"mcp","host":"mcp.tools.example.com","upstream":"https://10.0.0.5:8443","paths":["/mcp","/mcp/**"],"mcp":{"read_only":true,"tools":["get_*"]},"headers":{"Authorization":"Bearer secret:github"}}}`
	// Until the admin allows the host, alice's connection is refused (403, with the reason);
	// an upstream on a repository host is refused too (422).
	if resp, body := call(t, "PUT", api+"/v1/connections/tools", "alice-tok", mcp, nil); resp.StatusCode != 403 || !strings.Contains(string(body), "neither served by the policy repository nor listed") {
		t.Fatalf("host not allowed: %d %s", resp.StatusCode, body)
	}
	if resp, _ := call(t, "PUT", api+"/v1/connections/gh", "alice-tok", `{"spec":{"type":"http","host":"api.github.com","upstream":"https://evil"}}`, nil); resp.StatusCode != 422 {
		t.Fatalf("upstream on a repository host: %d", resp.StatusCode)
	}
	// The admin lists the host for alice (an API call, not a manifest).
	if resp, body := call(t, "PUT", api+"/v1/tenants/alice/settings", "t0k", `{"spec":{"hosts":["*.tools.example.com"]}}`, nil); resp.StatusCode != 201 {
		t.Fatalf("settings: %d %s", resp.StatusCode, body)
	}
	if resp, body := call(t, "PUT", api+"/v1/connections/tools", "alice-tok", mcp, nil); resp.StatusCode != 201 {
		t.Fatalf("connection: %d %s", resp.StatusCode, body)
	}
	// bob's settings do not list it: his connection is still refused.
	if resp, _ := call(t, "PUT", api+"/v1/connections/tools", "bob-tok", mcp, nil); resp.StatusCode != 403 {
		t.Fatalf("bob: %d", resp.StatusCode)
	}
	// The gateway now knows the host (the guard merges it), with the connection's upstream and
	// header names.
	info, ok := guard.HostInfo("mcp.tools.example.com")
	if !ok || !info.MCP || info.Upstream != "https://10.0.0.5:8443" || strings.Join(info.Injected, ",") != "Authorization" {
		t.Fatalf("host through the guard: %v %+v", ok, info)
	}
	// An agent that uses the connection; a sandbox from it carries the MCP endpoint for the pod.
	if code, _ := putDoc(t, api, "alice-tok", "environments", "py", `{"spec":{"image":"stable"}}`); code != 201 {
		t.Fatal("environment")
	}
	if code, _ := putDoc(t, api, "alice-tok", "agents", "backend", `{"spec":{"policy":"backend-dev","environment":"py","connections":["tools"]}}`); code != 201 {
		t.Fatal("agent")
	}
	resp, body := call(t, "POST", api+"/v1/sandboxes", "alice-tok", map[string]any{"name": "shop", "owner": "alice", "agent_ref": "backend"}, nil)
	var sb model.Sandbox
	_ = json.Unmarshal(body, &sb)
	if resp.StatusCode != 201 || sb.Launch == nil || len(sb.Launch.MCPServers) != 1 || sb.Launch.MCPServers[0].Name != "tools" || sb.Launch.MCPServers[0].URL != "https://mcp.tools.example.com/mcp" {
		t.Fatalf("sandbox launch: %d %s", resp.StatusCode, body)
	}
	resp, body = call(t, "POST", api+"/v1/sandboxes", "alice-tok", map[string]any{"name": "plain", "owner": "alice", "slug": "backend-dev"}, nil)
	var other model.Sandbox
	_ = json.Unmarshal(body, &other)
	if resp.StatusCode != 201 {
		t.Fatalf("plain sandbox: %d %s", resp.StatusCode, body)
	}
	// The gateway decision: the sandbox with the connection may call the host on its paths,
	// read-only, with the header the connection adds; the other sandbox may not.
	az := &authz.Handler{Policies: guard, Secrets: secrets.Static{"alice/github": leaked}}
	decide := func(id, path string) (int, string, string) {
		r := httptest.NewRequest("GET", "/authz", nil)
		r.Header.Set(identity.HeaderSANs, "spiffe://sandbox/agent/backend-dev/1,spiffe://sandbox/tenant/alice,spiffe://sandbox/sandbox/"+id)
		r.Header.Set("X-Forwarded-Host", "mcp.tools.example.com")
		r.Header.Set("X-Forwarded-Method", "POST")
		r.Header.Set("X-Forwarded-Uri", path)
		w := httptest.NewRecorder()
		az.ServeHTTP(w, r)
		return w.Code, w.Header().Get(authz.HeaderAccess), w.Header().Get("Authorization")
	}
	if code, access, auth := decide(sb.ID, "/mcp"); code != 200 || access != "read-only" || auth != "Bearer "+leaked {
		t.Fatalf("connection host: %d %q %q", code, access, auth)
	}
	if code, _, _ := decide(sb.ID, "/admin"); code != 403 {
		t.Fatalf("outside the connection's paths: %d", code)
	}
	if code, _, _ := decide(other.ID, "/mcp"); code != 403 {
		t.Fatalf("sandbox without the connection: %d", code)
	}
	// The admin withdrawing the host stops the existing connection at once, without anyone
	// touching the connection: the delegation is decided per request, not at write time.
	if resp, body := call(t, "PUT", api+"/v1/tenants/alice/settings", "t0k", `{"spec":{"hosts":[]}}`, nil); resp.StatusCode != 200 {
		t.Fatalf("withdraw: %d %s", resp.StatusCode, body)
	}
	if code, _, _ := decide(sb.ID, "/mcp"); code != 403 {
		t.Fatalf("withdrawn host still granted by the existing connection: %d", code)
	}
	if _, ok := guard.HostInfo("mcp.tools.example.com"); ok {
		t.Fatal("withdrawn host still a gateway host")
	}
	if resp, body := call(t, "PUT", api+"/v1/tenants/alice/settings", "t0k", `{"spec":{"hosts":["*.tools.example.com"]}}`, nil); resp.StatusCode != 200 {
		t.Fatalf("re-grant: %d %s", resp.StatusCode, body)
	}
	if code, _, _ := decide(sb.ID, "/mcp"); code != 200 {
		t.Fatalf("re-granted host: %d", code)
	}
	// Revocation: deleting the connection stops it at once too.
	if resp, _ := call(t, "DELETE", api+"/v1/connections/tools", "alice-tok", nil, nil); resp.StatusCode != 204 {
		t.Fatalf("delete connection: %d", resp.StatusCode)
	}
	if code, _, _ := decide(sb.ID, "/mcp"); code != 403 {
		t.Fatalf("deleted connection still grants: %d", code)
	}
	if _, ok := guard.HostInfo("mcp.tools.example.com"); ok {
		t.Fatal("deleted connection still a gateway host")
	}
	// The sandbox record still names the connection; what it resolves to is decided live.
	cur, _ := s.orch.Get(ctx, sb.ID)
	if len(cur.Connections) != 1 {
		t.Fatalf("sandbox connections: %+v", cur.Connections)
	}
}
