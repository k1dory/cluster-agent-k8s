package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPathMatch(t *testing.T) {
	cases := []struct {
		pat, p string
		want   bool
	}{
		{"/**", "/anything/at/all", true},
		{"/**", "/", true},
		{"/*/*/info/refs", "/org/repo.git/info/refs", true},
		{"/*/*/info/refs", "/org/repo.git/info/refs?service=git-upload-pack", true},
		{"/*/*/info/refs", "/org/sub/repo.git/info/refs", false},
		{"/**/git-upload-pack", "/org/sub/repo.git/git-upload-pack", true},
		{"/**/git-upload-pack", "/org/repo.git/git-receive-pack", false},
		{"/v1/*", "/v1/messages", true},
		{"/v1/*", "/v1/messages/count_tokens", false},
		{"/v1/**", "/v1/messages/count_tokens", true},
		{"/api/v1/**", "/api/v1/../../admin", false},
		{"/api/v1/**", "/api/v1", true},
	}
	for _, c := range cases {
		if got := PathMatch(c.pat, c.p); got != c.want {
			t.Errorf("PathMatch(%q, %q) = %v, want %v", c.pat, c.p, got, c.want)
		}
	}
}

func TestMatch(t *testing.T) {
	s := FromPolicies(
		&Policy{Slug: "backend-dev", Allow: []Rule{
			{Host: "git.example.com", Paths: []string{"/*/*/info/refs", "/*/*/git-upload-pack", "/*/*/git-receive-pack"}},
			{Host: "*.anthropic.com", Paths: []string{"/v1/**"}, Methods: []string{"POST"}},
		}},
		&Policy{Slug: "default", Allow: []Rule{{Host: "git.example.com", Paths: []string{"/*/*/info/refs"}}}},
	)
	if _, ok := s.Match("backend-dev", "git.example.com:443", "POST", "/org/repo.git/git-receive-pack"); !ok {
		t.Fatal("expected receive-pack allowed for backend-dev")
	}
	if _, ok := s.Match("backend-dev", "api.anthropic.com", "GET", "/v1/messages"); ok {
		t.Fatal("GET to anthropic should be denied by method list")
	}
	if _, ok := s.Match("backend-dev", "evil.example.com", "GET", "/"); ok {
		t.Fatal("unknown host must be denied")
	}
	if _, ok := s.Match("unknown-slug", "git.example.com", "GET", "/org/repo.git/info/refs"); !ok {
		t.Fatal("unknown slug must fall back to default policy")
	}
	if _, ok := s.Match("unknown-slug", "git.example.com", "POST", "/org/repo.git/git-receive-pack"); ok {
		t.Fatal("default policy must not allow push")
	}
}

func TestHostsAndExpectations(t *testing.T) {
	s := FromPolicies(
		&Policy{Slug: "a", Allow: []Rule{
			{Host: "git.example.com", Paths: []string{"/**"}, Inject: map[string]string{"authorization": "x"}},
			{Host: "internal.example.com", Paths: []string{"/**"}, Upstream: "https://10.0.0.5:8443"},
		}},
		&Policy{Slug: "b", Allow: []Rule{{Host: "git.example.com", Paths: []string{"/*/*/info/refs"}}}},
	)
	hs := s.Hosts()
	if len(hs) != 2 || hs[0].Name != "git.example.com" || hs[0].Upstream != "https://git.example.com" || hs[0].Injected[0] != "Authorization" {
		t.Fatalf("hosts: %+v", hs)
	}
	if hs[1].Upstream != "https://10.0.0.5:8443" {
		t.Fatalf("upstream override lost: %+v", hs[1])
	}
	if _, err := hostsOf(map[string]*Policy{
		"x": {Slug: "x", Allow: []Rule{{Host: "h", Paths: []string{"/"}, Upstream: "https://1"}}},
		"y": {Slug: "y", Allow: []Rule{{Host: "h", Paths: []string{"/"}, Upstream: "https://2"}}},
	}); err == nil {
		t.Fatal("conflicting upstreams must be rejected")
	}
	res, err := s.RunTests([]Expectation{{Slug: "b",
		Allow: []string{"git.example.com/org/repo.git/info/refs", "GET https://git.example.com/o/r/info/refs?service=x"},
		Deny:  []string{"POST git.example.com/org/repo.git/git-receive-pack", "internal.example.com/"}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range res {
		if !r.Pass() {
			t.Errorf("%s %s: want %v got %v (%s)", r.Slug, r.Line, r.Want, r.Got, r.Reason)
		}
	}
	bad := &Policy{Slug: "bad", Allow: []Rule{{Host: "*.example.com", Paths: []string{"/"}}}}
	if err := bad.Validate(); err == nil {
		t.Fatal("wildcard host must be rejected")
	}
}

func TestTenantOwnership(t *testing.T) {
	s := FromPolicies(
		&Policy{Slug: "backend-dev", Tenants: []string{"acme"}, Allow: []Rule{{Host: "git.example.com", Paths: []string{"/**"}}}},
		&Policy{Slug: "shared", Tenants: []string{"*"}, Allow: []Rule{{Host: "git.example.com", Paths: []string{"/**"}}}},
		&Policy{Slug: "open", Allow: []Rule{{Host: "git.example.com", Paths: []string{"/**"}}}},
		&Policy{Slug: "default", Allow: []Rule{{Host: "git.example.com", Paths: []string{"/**"}}}},
	)
	cases := []struct {
		slug, tenant string
		strict, want bool
	}{
		{"backend-dev", "acme", false, true},
		{"backend-dev", "evil", false, false},
		{"shared", "anyone", false, true},
		{"shared", "anyone", true, true},
		{"open", "anyone", false, true},
		{"open", "anyone", true, false}, // no tenants list: admin-only in strict mode
		{"unknown", "anyone", false, true},
		{"unknown", "anyone", true, false}, // no fallback to default in strict mode
	}
	for _, c := range cases {
		s.Strict = c.strict
		if got := s.AllowedFor(c.slug, c.tenant); got != c.want {
			t.Errorf("AllowedFor(%s, %s, strict=%v) = %v, want %v", c.slug, c.tenant, c.strict, got, c.want)
		}
	}
	if h := s.ContentHash("backend-dev"); h == "" || h == s.ContentHash("shared") {
		t.Fatalf("content hashes must identify the policy: %q", h)
	}
	if s.ContentHash("unknown") != s.ContentHash("default") {
		t.Fatal("a slug without a file carries the default policy's hash")
	}
	p := &Policy{Slug: "x", Tenants: []string{"a b"}, Allow: []Rule{{Host: "h.example.com", Paths: []string{"/"}}}}
	if err := p.Validate(); err == nil {
		t.Fatal("tenant names with spaces must be rejected")
	}
}

func TestStrictParseAndDuplicates(t *testing.T) {
	if _, err := Parse([]byte("slug: x\nallow:\n  - host: a.example.com\n    paths: [\"/\"]\n    methdos: [GET]\n")); err == nil {
		t.Fatal("a misspelled field must be an error, not a wider rule")
	}
	p, err := Parse([]byte("slug: x\nallow:\n  - host: a.example.com\n    paths: [\"/\"]\n    methods: [GET]\n    mcp: { read_only: true, tools: [\"get_*\", \"search\"] }\n"))
	if err != nil {
		t.Fatal(err)
	}
	m := p.Allow[0].MCP
	if !m.ToolAllowed("get_user") || !m.ToolAllowed("search") || m.ToolAllowed("delete_user") {
		t.Fatal("tools allowlist")
	}
	if (&MCPRule{ReadOnly: true}).ToolAllowed("anything") || !(&MCPRule{}).ToolAllowed("anything") {
		t.Fatal("read_only without tools denies every call; read-write allows all")
	}
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "a.yaml"), []byte("slug: same\nallow:\n  - host: a.example.com\n    paths: [\"/\"]\n"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "b.yaml"), []byte("slug: same\nallow:\n  - host: b.example.com\n    paths: [\"/\"]\n"), 0o644)
	if _, err := Load(dir); err == nil || !strings.Contains(err.Error(), "already defined") {
		t.Fatalf("duplicate slugs across files must be refused: %v", err)
	}
}
