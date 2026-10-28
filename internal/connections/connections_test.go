package connections

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"agent-sandbox/internal/model"
	"agent-sandbox/internal/policy"
	res "agent-sandbox/internal/resource"
	"agent-sandbox/internal/secrets"
	"agent-sandbox/internal/store"
)

func doc(name, spec string) *res.Document {
	return &res.Document{Name: name, Spec: json.RawMessage(spec)}
}

func TestConnectionsValidateAndNeverStoreSecrets(t *testing.T) {
	ctx := context.Background()
	s := &Service{Store: store.NewMemory(), Secrets: secrets.Static{"acme/github": "ghp_VALUE", "shared/registry": "reg-VALUE"}}
	for _, bad := range []string{
		`{"type":"ftp","host":"a.example.com"}`,
		`{"type":"http","host":"https://a.example.com"}`,
		`{"type":"http","host":"a.example.com:443"}`,
		`{"type":"http","host":"a.example.com","headers":{"Bad Header":"x"}}`,
		`{"type":"http","host":"a.example.com","headers":{"Authorization":"Bearer ghp_LITERAL"}}`, // a value, not a reference
		`{"type":"http","host":"a.example.com","headers":{"X-Api-Key":"ghp_LITERAL"}}`,
		`{"type":"http","host":"a.example.com","headers":{"Authorization":"Bearer secret:missing"}}`, // not resolvable for acme
		`{"type":"http","host":"a.example.com","headers":{"authorization":"secret:github","Authorization":"secret:github"}}`,
		`{"type":"http","host":"a.example.com","extra":1}`,
	} {
		_, err := s.Put(ctx, "acme", doc("c", bad), false, "alice")
		if !errors.Is(err, res.ErrInvalid) {
			t.Errorf("must be invalid: %s → %v", bad, err)
		}
		if err != nil && strings.Contains(err.Error(), "ghp_LITERAL") {
			t.Errorf("the error echoed a credential: %v", err)
		}
	}
	it, err := s.Put(ctx, "acme", doc("github", `{"type":"http","host":"api.github.com","headers":{"authorization":"Bearer secret:github","X-GitHub-Api-Version":"2022-11-28"}}`), false, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(it.Spec), "ghp_") || !strings.Contains(string(it.Spec), `"Authorization":"Bearer secret:github"`) {
		t.Fatalf("stored spec: %s", it.Spec)
	}
	// Shared connections resolve against the shared secrets; a tenant uses its own first.
	if _, err := s.Put(ctx, "", doc("registry", `{"type":"mcp","host":"mcp.registry.example.com","headers":{"X-Auth-Token":"secret:registry"}}`), true, "admin"); err != nil {
		t.Fatal(err)
	}
	if c, err := s.Canonical(ctx, "acme", "registry"); err != nil || c != "shared/registry" {
		t.Fatalf("canonical shared: %q %v", c, err)
	}
	if c, err := s.Canonical(ctx, "acme", "github"); err != nil || c != "github" {
		t.Fatalf("canonical own: %q %v", c, err)
	}
	if _, err := s.Canonical(ctx, "other", "github"); !errors.Is(err, res.ErrNotFound) {
		t.Fatalf("another tenant's connection must be invisible: %v", err)
	}
	if _, err := s.Canonical(ctx, "acme", "github@1"); !errors.Is(err, res.ErrInvalid) {
		t.Fatalf("pinned connection: %v", err)
	}
	// The gateway side resolves the values; the API side never carries them.
	sp, h, err := s.Headers(ctx, "acme", "github")
	if err != nil || sp.Host != "api.github.com" || h["Authorization"] != "Bearer ghp_VALUE" || h["X-Github-Api-Version"] != "2022-11-28" {
		t.Fatalf("headers: %v %+v %v", err, sp, h)
	}
	list, _ := s.List(ctx, "acme")
	revs, _ := s.Revisions(ctx, "acme", "github")
	for _, items := range [][]*model.CatalogItem{list, revs} {
		b, _ := json.Marshal(items)
		if strings.Contains(string(b), "VALUE") {
			t.Fatalf("a secret value leaked: %s", b)
		}
	}
	if err := s.Delete(ctx, "acme", "github"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Canonical(ctx, "acme", "github"); !errors.Is(err, res.ErrNotFound) {
		t.Fatalf("deleted connection must not resolve: %v", err)
	}
}

type sandboxes map[string]*model.Sandbox

func (s sandboxes) GetSandbox(_ context.Context, id string) (*model.Sandbox, error) {
	if sb, ok := s[id]; ok {
		return sb, nil
	}
	return nil, store.ErrNotFound
}

func TestHeadersForGatewayDecision(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	sbs := sandboxes{
		"own":    {ID: "own", Tenant: "acme", Connections: []string{"github", "shared/registry"}},
		"shared": {ID: "shared", Tenant: "acme", Connections: []string{"shared/registry"}},
		"broken": {ID: "broken", Tenant: "acme", Connections: []string{"nokey"}},
	}
	s := New(st, secrets.Static{"acme/github": "ghp_VALUE", "shared/registry": "reg-VALUE"}, sbs)
	for _, d := range []struct{ tenant, name, spec string }{
		{"acme", "github", `{"type":"http","host":"api.github.com","headers":{"Authorization":"Bearer secret:github","X-Version":"1"}}`},
		{"", "registry", `{"type":"mcp","host":"mcp.registry.example.com","headers":{"X-Auth-Token":"secret:registry"}}`},
	} {
		if _, err := s.Put(ctx, d.tenant, doc(d.name, d.spec), d.tenant == "", "x"); err != nil {
			t.Fatal(err)
		}
	}
	// The gateway's strip/copy list knows every live connection's header names per host.
	names, fp := s.HostHeaders()
	if len(names["api.github.com"]) != 2 || names["mcp.registry.example.com"][0] != "X-Auth-Token" || fp == "" {
		t.Fatalf("host headers: %v %s", names, fp)
	}
	h, err := s.HeadersFor(ctx, "own", "acme", "api.github.com")
	if err != nil || h["Authorization"] != "Bearer ghp_VALUE" || h["X-Version"] != "1" || len(h) != 2 {
		t.Fatalf("own host: %v %v", err, h)
	}
	if h, err := s.HeadersFor(ctx, "own", "acme", "mcp.registry.example.com"); err != nil || h["X-Auth-Token"] != "reg-VALUE" {
		t.Fatalf("shared connection through a tenant sandbox: %v %v", err, h)
	}
	if h, err := s.HeadersFor(ctx, "own", "acme", "other.example.com"); err != nil || h != nil {
		t.Fatalf("host without connections: %v %v", err, h)
	}
	if _, err := s.HeadersFor(ctx, "own", "mallory", "api.github.com"); err == nil {
		t.Fatal("identity tenant must be the sandbox's")
	}
	if h, err := s.HeadersFor(ctx, "gone", "acme", "api.github.com"); err != nil || h != nil {
		t.Fatalf("unknown sandbox: %v %v", err, h)
	}
	// A deleted connection adds nothing; an unresolvable one is an error so nothing partial is sent.
	if err := s.Delete(ctx, "acme", "github"); err != nil {
		t.Fatal(err)
	}
	if h, err := s.HeadersFor(ctx, "own", "acme", "api.github.com"); err != nil || h != nil {
		t.Fatalf("deleted connection: %v %v", err, h)
	}
	if names, _ := s.HostHeaders(); len(names["api.github.com"]) != 0 {
		t.Fatalf("deleted connection still in the gateway list: %v", names)
	}
	if _, err := s.Put(ctx, "acme", doc("nokey", `{"type":"http","host":"api.github.com","headers":{"X-Trace":"secret:absent"}}`), false, "x"); err == nil {
		t.Fatal("unresolvable reference accepted at write")
	}
	s.Secrets = nil // the reference was accepted earlier (another provider); now it does not resolve
	if _, err := s.Put(ctx, "acme", doc("nokey", `{"type":"http","host":"api.github.com","headers":{"X-Trace":"secret:absent"}}`), false, "x"); err != nil {
		t.Fatal(err)
	}
	s.Secrets = secrets.Static{}
	if _, err := s.HeadersFor(ctx, "broken", "acme", "api.github.com"); err == nil {
		t.Fatal("unresolvable reference must fail the decision")
	}
}

// repoHosts is the policy repository's host list for the self-service tests, plus which hosts
// each tenant's settings allow.
type repoHosts struct {
	repo    map[string]policy.Host
	allowed map[string][]string // tenant → hosts
}

func (r repoHosts) HostInfo(name string) (policy.Host, bool) { h, ok := r.repo[name]; return h, ok }
func (r repoHosts) HostAllowed(tenant, host string) bool {
	for _, h := range r.allowed[tenant] {
		if h == host {
			return true
		}
	}
	return false
}

func TestSelfServiceHostsAreTheConnection(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	sbs := sandboxes{
		"with":    {ID: "with", Tenant: "acme", Connections: []string{"tools", "shared/vendor"}},
		"without": {ID: "without", Tenant: "acme", Connections: []string{"shared/vendor"}},
	}
	s := New(st, secrets.Static{"acme/tools": "tok", "shared/vendor": "v"}, sbs)
	s.Hosts = repoHosts{
		repo:    map[string]policy.Host{"api.github.com": {Name: "api.github.com", Upstream: "https://api.github.com"}},
		allowed: map[string][]string{"acme": {"tools.acme.example.com"}},
	}
	// A repository host takes headers only.
	if _, err := s.Put(ctx, "acme", doc("gh", `{"type":"http","host":"api.github.com","upstream":"https://10.0.0.1"}`), false, "x"); !errors.Is(err, res.ErrInvalid) {
		t.Fatalf("upstream on a repository host: %v", err)
	}
	// A host the tenant's settings do not list is refused; a listed one is served.
	if _, err := s.Put(ctx, "acme", doc("bad", `{"type":"mcp","host":"mcp.other.example.com"}`), false, "x"); !errors.Is(err, res.ErrForbidden) {
		t.Fatalf("host outside the tenant's list: %v", err)
	}
	for _, bad := range []string{
		`{"type":"mcp","host":"tools.acme.example.com","upstream":"ftp://x"}`,
		`{"type":"mcp","host":"tools.acme.example.com","upstream":"https://user:pw@x"}`,
		`{"type":"mcp","host":"tools.acme.example.com","paths":["mcp"]}`,
		`{"type":"http","host":"tools.acme.example.com","mcp":{"read_only":true}}`,
		`{"type":"mcp","host":"tools.acme.example.com","upstream_host":true}`,
	} {
		if _, err := s.Put(ctx, "acme", doc("bad", bad), false, "x"); !errors.Is(err, res.ErrInvalid) {
			t.Errorf("%s must be invalid: %v", bad, err)
		}
	}
	if _, err := s.Put(ctx, "acme", doc("tools", `{"type":"mcp","host":"tools.acme.example.com","upstream":"https://10.0.0.5:8443","paths":["/mcp","/mcp/**"],"mcp":{"read_only":true,"tools":["get_*"]},"headers":{"Authorization":"Bearer secret:tools"}}`), false, "alice"); err != nil {
		t.Fatal(err)
	}
	// The admin's shared connections may name any host; a second connection for a host must
	// agree with the first on upstream and kind.
	if _, err := s.Put(ctx, "", doc("vendor", `{"type":"mcp","host":"mcp.vendor.example.com"}`), true, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Put(ctx, "acme", doc("vendor2", `{"type":"mcp","host":"tools.acme.example.com","upstream":"https://10.0.0.6"}`), false, "alice"); !errors.Is(err, res.ErrInvalid) {
		t.Fatalf("conflicting upstream: %v", err)
	}
	if _, err := s.Put(ctx, "acme", doc("vendor2", `{"type":"http","host":"tools.acme.example.com","upstream":"https://10.0.0.5:8443"}`), false, "alice"); !errors.Is(err, res.ErrInvalid) {
		t.Fatalf("conflicting kind: %v", err)
	}
	if _, err := s.Put(ctx, "acme", doc("vendor2", `{"type":"mcp","host":"tools.acme.example.com","upstream":"https://10.0.0.5:8443","upstream_host":true}`), false, "alice"); !errors.Is(err, res.ErrInvalid) {
		t.Fatalf("conflicting Host header: %v", err)
	}
	if _, err := s.Put(ctx, "acme", doc("gh2", `{"type":"http","host":"api.github.com","upstream_host":true}`), false, "x"); !errors.Is(err, res.ErrInvalid) {
		t.Fatalf("upstream_host on a repository host: %v", err)
	}
	// The hosts the gateway must serve beyond the repository's, with their header names.
	own, fp := s.OwnHosts()
	if len(own) != 2 || own[0].Name != "mcp.vendor.example.com" || !own[0].MCP || own[0].Upstream != "https://mcp.vendor.example.com" ||
		own[1].Name != "tools.acme.example.com" || own[1].Upstream != "https://10.0.0.5:8443" || !own[1].MCP || strings.Join(own[1].Injected, ",") != "Authorization" || fp == "" {
		t.Fatalf("own hosts: %+v %s", own, fp)
	}
	// The rule a sandbox gets: only through a connection it carries, only on its paths, with
	// the connection's MCP restriction; a repository host is never answered here.
	rule, ok, err := s.RuleFor(ctx, "with", "acme", "tools.acme.example.com", "POST", "/mcp")
	if err != nil || !ok || rule.Upstream != "https://10.0.0.5:8443" || rule.MCP == nil || !rule.MCP.ReadOnly || !rule.MCP.ToolAllowed("get_x") || rule.MCP.ToolAllowed("delete_x") {
		t.Fatalf("rule: %v %v %+v", err, ok, rule)
	}
	if _, ok, _ := s.RuleFor(ctx, "with", "acme", "tools.acme.example.com", "POST", "/admin"); ok {
		t.Fatal("path outside the connection's paths")
	}
	if _, ok, _ := s.RuleFor(ctx, "without", "acme", "tools.acme.example.com", "POST", "/mcp"); ok {
		t.Fatal("a sandbox without the connection")
	}
	if rule, ok, _ := s.RuleFor(ctx, "without", "acme", "mcp.vendor.example.com", "POST", "/anything"); !ok || rule.MCP == nil || rule.MCP.ReadOnly {
		t.Fatalf("shared mcp connection without restrictions: %v %+v", ok, rule)
	}
	if _, ok, _ := s.RuleFor(ctx, "with", "acme", "api.github.com", "GET", "/"); ok {
		t.Fatal("a repository host is the repository's")
	}
	if _, _, err := s.RuleFor(ctx, "with", "mallory", "tools.acme.example.com", "POST", "/mcp"); err == nil {
		t.Fatal("identity tenant must be the sandbox's")
	}
	// What the pod is told: the MCP endpoints of the agent's connections.
	eps := s.Endpoints(ctx, "acme", []string{"tools", "shared/vendor", "gone"})
	if len(eps) != 2 || eps[0].Name != "tools" || eps[0].URL != "https://tools.acme.example.com/mcp" || eps[1].URL != "https://mcp.vendor.example.com/mcp" {
		t.Fatalf("endpoints: %+v", eps)
	}
	// Deleting the connection withdraws the host and the rule.
	if err := s.Delete(ctx, "acme", "tools"); err != nil {
		t.Fatal(err)
	}
	if own, _ := s.OwnHosts(); len(own) != 1 {
		t.Fatalf("after delete: %+v", own)
	}
	if _, ok, _ := s.RuleFor(ctx, "with", "acme", "tools.acme.example.com", "POST", "/mcp"); ok {
		t.Fatal("deleted connection still grants")
	}
	// Without a host policy, connections add headers only (no self-service at all).
	plain := New(store.NewMemory(), nil, nil)
	if _, err := plain.Put(ctx, "acme", doc("x", `{"type":"mcp","host":"a.example.com","paths":["/"]}`), false, "x"); !errors.Is(err, res.ErrInvalid) {
		t.Fatalf("self-service without a host policy: %v", err)
	}
}

func TestWithdrawingAHostFromTheTenantRevokesItsConnections(t *testing.T) {
	ctx := context.Background()
	sbs := sandboxes{"sb": {ID: "sb", Tenant: "acme", Connections: []string{"tools", "shared/vendor"}}}
	s := New(store.NewMemory(), secrets.Static{}, sbs)
	hosts := &repoHosts{repo: map[string]policy.Host{}, allowed: map[string][]string{"acme": {"tools.acme.example.com"}}}
	s.Hosts = hosts
	if _, err := s.Put(ctx, "acme", doc("tools", `{"type":"mcp","host":"tools.acme.example.com"}`), false, "alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Put(ctx, "", doc("vendor", `{"type":"mcp","host":"mcp.vendor.example.com"}`), true, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.RuleFor(ctx, "sb", "acme", "tools.acme.example.com", "POST", "/mcp"); !ok {
		t.Fatal("delegated host before withdrawal")
	}
	if own, _ := s.OwnHosts(); len(own) != 2 {
		t.Fatalf("own hosts before withdrawal: %+v", own)
	}
	// The admin removes the host from the tenant's settings: the connection still exists, but
	// grants nothing, and the gateway stops serving the host; the shared connection is untouched.
	hosts.allowed["acme"] = nil
	if _, ok, _ := s.RuleFor(ctx, "sb", "acme", "tools.acme.example.com", "POST", "/mcp"); ok {
		t.Fatal("withdrawn host still granted by an existing connection")
	}
	if _, ok, _ := s.RuleFor(ctx, "sb", "acme", "mcp.vendor.example.com", "POST", "/mcp"); !ok {
		t.Fatal("the admin's shared connection is not delegated and must stay")
	}
	own, _ := s.OwnHosts()
	if len(own) != 1 || own[0].Name != "mcp.vendor.example.com" {
		t.Fatalf("own hosts after withdrawal: %+v", own)
	}
	// Granting it again restores the connection without rewriting it.
	hosts.allowed["acme"] = []string{"tools.acme.example.com"}
	if _, ok, _ := s.RuleFor(ctx, "sb", "acme", "tools.acme.example.com", "POST", "/mcp"); !ok {
		t.Fatal("re-granted host")
	}
}
