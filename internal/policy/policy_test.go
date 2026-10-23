package policy

import "testing"

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
