package policy

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// ValidateUpstream checks an upstream the gateway will hand to Caddy's reverse_proxy: an
// http(s) URL naming a host and optionally a port, nothing else. Caddy refuses a path, a query
// or userinfo in an upstream address and the whole /load with it, keeping its last good
// configuration while every later policy change is silently not applied; a brace or a space is
// read as a placeholder or a new token in the generated Caddyfile. One bad upstream must not
// freeze every host's configuration, so policies and connections both refuse it here.
func ValidateUpstream(s string) error {
	if s == "" {
		return errors.New("upstream is empty")
	}
	if strings.ContainsAny(s, "{}\"'`#\\ \t\r\n") {
		return fmt.Errorf("upstream %q contains a character the gateway configuration cannot carry", s)
	}
	u, err := url.Parse(s)
	if err != nil {
		return fmt.Errorf("upstream %q: %v", s, err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return fmt.Errorf("upstream %q must start with http:// or https://", s)
	}
	if u.Opaque != "" || u.Host == "" {
		return fmt.Errorf("upstream %q has no host", s)
	}
	if u.User != nil {
		return fmt.Errorf("upstream %q must not carry credentials (inject a header instead)", s)
	}
	if u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return fmt.Errorf("upstream %q must be scheme://host[:port] only: no path, query or fragment", s)
	}
	host, port := u.Hostname(), u.Port()
	if strings.HasSuffix(u.Host, ":") {
		return fmt.Errorf("upstream %q has an empty port", s)
	}
	if port != "" {
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
			return fmt.Errorf("upstream %q: port %q is not a port number", s, port)
		}
	}
	if strings.HasPrefix(u.Host, "[") {
		// A bracketed literal must be an IPv6 address (the zone form is meaningless here).
		if ip := net.ParseIP(host); ip == nil || ip.To4() != nil {
			return fmt.Errorf("upstream %q: %q is not an IPv6 address", s, host)
		}
		return nil
	}
	if net.ParseIP(host) != nil {
		return nil
	}
	if !isDNSName(host) {
		return fmt.Errorf("upstream %q: %q is not a DNS name or IP address", s, host)
	}
	return nil
}

// UpstreamHostname is the host part of a valid upstream (an IPv6 literal without brackets).
func UpstreamHostname(s string) string {
	u, err := url.Parse(s)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

func isDNSName(h string) bool {
	h = strings.TrimSuffix(h, ".")
	if h == "" || len(h) > 253 {
		return false
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
				return false
			}
		}
	}
	return true
}
