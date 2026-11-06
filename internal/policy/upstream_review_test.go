package policy

import (
	"strings"
	"testing"
)

func TestReviewValidateUpstream(t *testing.T) {
	for _, ok := range []string{
		"https://10.0.0.5:8443", "http://10.0.0.5", "https://netbox.example.com", "https://[fd00::5]:8443",
		"https://[2001:db8::1]", "https://svc.internal.:443", "https://my_host.local",
		"http://[::ffff:10.0.0.5]:8080", "https://[::ffff:a00:5]",
	} {
		if err := ValidateUpstream(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"https://10.0.0.5:8443/api", "https://10.0.0.5/", "https://h.example.com?x=1", "https://h.example.com#f",
		"https://user:pw@h.example.com", "ftp://h.example.com", "https://", "https://{env.X}", "https://h.example.com {",
		"https://h}.example.com", "https://h.example.com:0", "https://h.example.com:99999", "https://h.example.com:",
		"https://[10.0.0.5]", "https://[fe80::1%25eth0]:8443", "https://-bad.example.com", "10.0.0.5:8443", "https:h.example.com", "https://h .com",
		"https://h.example.com\n}", "", "http://h.example.com:443", "https://h.example.com:80", "http://[fd00::1]:443", "HTTPS://10.0.0.5:8443", "Http://h.example.com",
	} {
		if err := ValidateUpstream(bad); err == nil {
			t.Errorf("%q must be refused", bad)
		}
	}
}

// A policy with a path in its upstream used to pass Validate (prefix check only) and freeze the
// gateway when Caddy refused the rendered configuration.
func TestReviewPolicyRefusesUpstreamWithPath(t *testing.T) {
	p := &Policy{Slug: "dev", Allow: []Rule{{Host: "netbox.example.com", Paths: []string{"/**"}, Upstream: "https://10.0.0.5:8443/api"}}}
	err := p.Validate()
	if err == nil || !strings.Contains(err.Error(), "no path") {
		t.Fatalf("validate: %v", err)
	}
	p.Allow[0].Upstream = "https://[fd00::5]:8443"
	if err := p.Validate(); err != nil {
		t.Fatalf("an IPv6 upstream is fine: %v", err)
	}
}
