// Package policy loads per-slug egress rules and answers "may this agent reach host+path".
//
// A rule is matched by host (exact or *.suffix), optional method list and path glob.
// Globs: `*` matches one path segment (or part of it), `**` matches any number of segments.
// Policy is deny by default: no matching rule means 403 at the gateway.
package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// MCPRule marks an MCP endpoint; read_only is forwarded to the MCP server as a header,
// because the gateway cannot see the JSON-RPC body in forward_auth.
type MCPRule struct {
	ReadOnly bool `yaml:"read_only" json:"read_only"`
}

// Rule allows one host (and a set of paths) for the slug.
type Rule struct {
	Host    string            `yaml:"host" json:"host"`
	Paths   []string          `yaml:"paths" json:"paths"`
	Methods []string          `yaml:"methods,omitempty" json:"methods,omitempty"`
	Inject  map[string]string `yaml:"inject,omitempty" json:"inject,omitempty"`
	MCP     *MCPRule          `yaml:"mcp,omitempty" json:"mcp,omitempty"`
	// Upstream overrides where the gateway sends traffic for this host (default https://<host>).
	// Useful for internal services reachable only by IP, e.g. https://10.0.0.5:8443.
	Upstream string `yaml:"upstream,omitempty" json:"upstream,omitempty"`
}

// Policy metadata lets a repository of policies carry ownership and review notes.
type Meta struct {
	Owner       string `yaml:"owner,omitempty" json:"owner,omitempty"`
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
}

// Policy is the egress policy of one slug. Slug "default" applies to slugs without a file.
//
// Tenants is the ownership list: which tenants may create sandboxes (and roll out agents) with
// this slug. "*" means every tenant. An empty list means the slug is open in permissive mode
// and admin-only in strict mode (see Set.Strict). The admin token is never restricted.
type Policy struct {
	Slug    string   `yaml:"slug" json:"slug"`
	Meta    Meta     `yaml:"meta,omitempty" json:"meta,omitempty"`
	Tenants []string `yaml:"tenants,omitempty" json:"tenants,omitempty"`
	Allow   []Rule   `yaml:"allow" json:"allow"`
}

// OwnedBy reports whether tenant may use this policy. strict decides what an absent tenants
// list means: open (false) or admin-only (true).
func (p *Policy) OwnedBy(tenant string, strict bool) bool {
	if len(p.Tenants) == 0 {
		return !strict
	}
	for _, t := range p.Tenants {
		if t == "*" || t == tenant {
			return true
		}
	}
	return false
}

// Host is one external name the gateway must serve, with its upstream.
type Host struct {
	Name     string
	Upstream string
	// Injected header names across all slugs: the gateway strips them from incoming requests
	// so an agent cannot supply its own.
	Injected []string
}

// Set is the loaded collection of policies with hot reload.
type Set struct {
	dir string
	// Strict makes a slug without a tenants list admin-only and refuses slugs that have no
	// policy file of their own (no silent fallback to "default" for tenants).
	Strict bool
	mu     sync.RWMutex
	bySlug map[string]*Policy
	raw    map[string][]byte // slug → file content, for environment versioning
	stamp  string
}

// AllowedFor reports whether a tenant may create sandboxes with slug. The policy that would
// apply (the slug's own, else "default") decides; in strict mode the fallback is not offered.
func (s *Set) AllowedFor(slug, tenant string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.bySlug[slug]
	if !ok {
		if s.Strict {
			return false
		}
		if p, ok = s.bySlug["default"]; !ok {
			return false
		}
	}
	return p.OwnedBy(tenant, s.Strict)
}

// ContentHash identifies the policy content that applies to slug (own file or default), so a
// sandbox can carry the version of the rules it was started under. Empty when none applies.
func (s *Set) ContentHash(slug string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.bySlug[slug]
	if !ok {
		if p, ok = s.bySlug["default"]; !ok {
			return ""
		}
	}
	raw, ok := s.raw[p.Slug]
	if !ok {
		raw, _ = json.Marshal(p) // FromPolicies: no file, hash the structure
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:6])
}

// Load reads every *.yaml in dir.
func Load(dir string) (*Set, error) {
	s := &Set{dir: dir}
	if err := s.reload(); err != nil {
		return nil, err
	}
	return s, nil
}

// FromPolicies builds a Set without files (tests).
func FromPolicies(ps ...*Policy) *Set {
	s := &Set{bySlug: map[string]*Policy{}, raw: map[string][]byte{}}
	for _, p := range ps {
		s.bySlug[p.Slug] = p
		s.stamp += p.Slug + ";"
	}
	return s
}

func (s *Set) reload() error {
	files, err := filepath.Glob(filepath.Join(s.dir, "*.yaml"))
	if err != nil {
		return err
	}
	sort.Strings(files)
	bySlug := map[string]*Policy{}
	rawBySlug := map[string][]byte{}
	var stamp strings.Builder
	for _, f := range files {
		if !isPolicyFile(f) {
			continue
		}
		st, err := os.Stat(f)
		if err != nil {
			return err
		}
		fmt.Fprintf(&stamp, "%s:%d:%d;", f, st.Size(), st.ModTime().UnixNano())
		raw, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		var p Policy
		if err := yaml.Unmarshal(raw, &p); err != nil {
			return fmt.Errorf("%s: %w", f, err)
		}
		if p.Slug == "" {
			p.Slug = strings.TrimSuffix(filepath.Base(f), ".yaml")
		}
		if err := p.Validate(); err != nil {
			return fmt.Errorf("%s: %w", f, err)
		}
		bySlug[p.Slug] = &p
		rawBySlug[p.Slug] = raw
	}
	if _, err := hostsOf(bySlug); err != nil {
		return err
	}
	s.mu.Lock()
	s.bySlug = bySlug
	s.raw = rawBySlug
	s.stamp = stamp.String()
	s.mu.Unlock()
	return nil
}

// Validate checks that every rule is well formed.
func (p *Policy) Validate() error {
	for i, t := range p.Tenants {
		if t == "" || strings.ContainsAny(t, " \t") {
			return fmt.Errorf("tenants[%d]: %q is not a tenant name", i, t)
		}
	}
	for i, r := range p.Allow {
		if r.Host == "" {
			return fmt.Errorf("allow[%d]: host is required", i)
		}
		if strings.ContainsAny(r.Host, "*/: ") {
			return fmt.Errorf("allow[%d]: host %q must be a plain DNS name (the gateway issues one certificate per name)", i, r.Host)
		}
		if r.Upstream != "" && !strings.HasPrefix(r.Upstream, "https://") && !strings.HasPrefix(r.Upstream, "http://") {
			return fmt.Errorf("allow[%d] (%s): upstream must start with http:// or https://", i, r.Host)
		}
		for _, m := range r.Methods {
			if m != strings.ToUpper(m) {
				return fmt.Errorf("allow[%d] (%s): method %q must be upper-case", i, r.Host, m)
			}
		}
		if len(r.Paths) == 0 {
			return fmt.Errorf("allow[%d] (%s): paths is required, use \"/**\" to allow everything", i, r.Host)
		}
		for _, pat := range r.Paths {
			if !strings.HasPrefix(pat, "/") {
				return fmt.Errorf("allow[%d] (%s): path %q must start with /", i, r.Host, pat)
			}
		}
	}
	return nil
}

// Watch polls the directory and reloads on change until ctx is done. Errors are reported via onErr.
func (s *Set) Watch(stop <-chan struct{}, every time.Duration, onErr func(error)) {
	if s.dir == "" {
		return
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			s.mu.RLock()
			old := s.stamp
			s.mu.RUnlock()
			if err := s.reloadIfChanged(old); err != nil && onErr != nil {
				onErr(err)
			}
		}
	}
}

func (s *Set) reloadIfChanged(old string) error {
	files, _ := filepath.Glob(filepath.Join(s.dir, "*.yaml"))
	sort.Strings(files)
	var stamp strings.Builder
	for _, f := range files {
		if !isPolicyFile(f) {
			continue
		}
		st, err := os.Stat(f)
		if err != nil {
			continue
		}
		fmt.Fprintf(&stamp, "%s:%d:%d;", f, st.Size(), st.ModTime().UnixNano())
	}
	if stamp.String() == old {
		return nil
	}
	return s.reload()
}

// Get returns the policy for slug, falling back to "default".
func (s *Set) Get(slug string) (*Policy, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if p, ok := s.bySlug[slug]; ok {
		return p, true
	}
	p, ok := s.bySlug["default"]
	return p, ok
}

// Slugs lists loaded policy names.
func (s *Set) Slugs() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.bySlug))
	for k := range s.bySlug {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Match returns the first rule allowing method+host+path for slug.
func (s *Set) Match(slug, host, method, reqPath string) (*Rule, bool) {
	p, ok := s.Get(slug)
	if !ok {
		return nil, false
	}
	host = strings.ToLower(stripPort(host))
	for i := range p.Allow {
		r := &p.Allow[i]
		if !hostMatch(r.Host, host) || !methodMatch(r.Methods, method) {
			continue
		}
		for _, pat := range r.Paths {
			if PathMatch(pat, reqPath) {
				return r, true
			}
		}
	}
	return nil, false
}

func stripPort(h string) string {
	if i := strings.LastIndex(h, ":"); i > 0 && !strings.Contains(h[i:], "]") {
		return h[:i]
	}
	return h
}

func hostMatch(pattern, host string) bool {
	pattern = strings.ToLower(pattern)
	if strings.HasPrefix(pattern, "*.") {
		return strings.HasSuffix(host, pattern[1:]) && len(host) > len(pattern)-1
	}
	return pattern == host
}

func methodMatch(methods []string, m string) bool {
	if len(methods) == 0 {
		return true
	}
	for _, x := range methods {
		if strings.EqualFold(x, m) {
			return true
		}
	}
	return false
}

// PathMatch matches a request path against a glob with `*` (within a segment) and `**` (any segments).
func PathMatch(pattern, p string) bool {
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	p = path.Clean("/" + p)
	ps := strings.Split(strings.Trim(pattern, "/"), "/")
	rs := strings.Split(strings.Trim(p, "/"), "/")
	if pattern == "/" || pattern == "" {
		return p == "/"
	}
	if p == "/" {
		rs = nil
	}
	return matchSegs(ps, rs)
}

func matchSegs(ps, rs []string) bool {
	for len(ps) > 0 {
		if ps[0] == "**" {
			if len(ps) == 1 {
				return true
			}
			for i := 0; i <= len(rs); i++ {
				if matchSegs(ps[1:], rs[i:]) {
					return true
				}
			}
			return false
		}
		if len(rs) == 0 {
			return false
		}
		if ok, _ := path.Match(ps[0], rs[0]); !ok {
			return false
		}
		ps, rs = ps[1:], rs[1:]
	}
	return len(rs) == 0
}

// Hosts returns every host the gateway must serve, sorted, with a consistent upstream.
func (s *Set) Hosts() []Host {
	s.mu.RLock()
	defer s.mu.RUnlock()
	hs, _ := hostsOf(s.bySlug)
	return hs
}

func hostsOf(bySlug map[string]*Policy) ([]Host, error) {
	byName := map[string]*Host{}
	for _, p := range bySlug {
		for _, r := range p.Allow {
			name := strings.ToLower(r.Host)
			up := r.Upstream
			if up == "" {
				up = "https://" + name
			}
			h, ok := byName[name]
			if !ok {
				h = &Host{Name: name, Upstream: up}
				byName[name] = h
			} else if h.Upstream != up {
				return nil, fmt.Errorf("host %s has conflicting upstreams %q and %q (slug %s)", name, h.Upstream, up, p.Slug)
			}
			for hdr := range r.Inject {
				h.Injected = appendUnique(h.Injected, http.CanonicalHeaderKey(hdr))
			}
		}
	}
	out := make([]Host, 0, len(byName))
	for _, h := range byName {
		sort.Strings(h.Injected)
		out = append(out, *h)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func appendUnique(xs []string, x string) []string {
	for _, y := range xs {
		if y == x {
			return xs
		}
	}
	return append(xs, x)
}

// Fingerprint changes whenever the loaded policies change (used to re-sync the gateway).
func (s *Set) Fingerprint() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.stamp
}

// isPolicyFile excludes the expectations file and dot/underscore-prefixed helpers that may
// live next to the policies (tests.yaml, _template.yaml).
func isPolicyFile(path string) bool {
	b := filepath.Base(path)
	if b == "tests.yaml" || strings.HasSuffix(b, ".test.yaml") || strings.HasPrefix(b, "_") || strings.HasPrefix(b, ".") {
		return false
	}
	return true
}
