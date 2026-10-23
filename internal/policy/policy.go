// Package policy loads per-slug egress rules and answers "may this agent reach host+path".
//
// A rule is matched by host (exact or *.suffix), optional method list and path glob.
// Globs: `*` matches one path segment (or part of it), `**` matches any number of segments.
// Policy is deny by default: no matching rule means 403 at the gateway.
package policy

import (
	"fmt"
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
}

// Policy is the egress policy of one slug. Slug "default" applies to slugs without a file.
type Policy struct {
	Slug  string `yaml:"slug" json:"slug"`
	Allow []Rule `yaml:"allow" json:"allow"`
}

// Set is the loaded collection of policies with hot reload.
type Set struct {
	dir    string
	mu     sync.RWMutex
	bySlug map[string]*Policy
	stamp  string
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
	s := &Set{bySlug: map[string]*Policy{}}
	for _, p := range ps {
		s.bySlug[p.Slug] = p
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
	var stamp strings.Builder
	for _, f := range files {
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
	}
	s.mu.Lock()
	s.bySlug = bySlug
	s.stamp = stamp.String()
	s.mu.Unlock()
	return nil
}

// Validate checks that every rule is well formed.
func (p *Policy) Validate() error {
	for i, r := range p.Allow {
		if r.Host == "" {
			return fmt.Errorf("allow[%d]: host is required", i)
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
