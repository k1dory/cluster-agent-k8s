package policy

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Expectation is one case in a policy test file:
//
//   - slug: backend-dev
//     allow: ["POST git.example.com/org/repo.git/git-receive-pack"]
//     deny:  ["GET evil.example.com/"]
//
// Each entry is "METHOD host/path". Method is optional (defaults to GET).
type Expectation struct {
	Slug  string   `yaml:"slug"`
	Allow []string `yaml:"allow"`
	Deny  []string `yaml:"deny"`
}

// TestResult is the outcome of one expectation line.
type TestResult struct {
	Slug   string
	Line   string
	Want   bool
	Got    bool
	Reason string
}

// Pass reports whether the line behaved as expected.
func (r TestResult) Pass() bool { return r.Want == r.Got }

// LoadExpectations reads a test file.
func LoadExpectations(path string) ([]Expectation, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var ex []Expectation
	if err := yaml.Unmarshal(raw, &ex); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return ex, nil
}

// RunTests evaluates expectations against the set.
func (s *Set) RunTests(ex []Expectation) ([]TestResult, error) {
	var out []TestResult
	for _, e := range ex {
		if e.Slug == "" {
			return nil, fmt.Errorf("expectation without slug")
		}
		for _, want := range []bool{true, false} {
			lines := e.Allow
			if !want {
				lines = e.Deny
			}
			for _, line := range lines {
				method, host, path, err := parseLine(line)
				if err != nil {
					return nil, fmt.Errorf("slug %s: %w", e.Slug, err)
				}
				rule, ok := s.Match(e.Slug, host, method, path)
				res := TestResult{Slug: e.Slug, Line: line, Want: want, Got: ok}
				if ok {
					res.Reason = fmt.Sprintf("matched host %s paths %v", rule.Host, rule.Paths)
				} else {
					res.Reason = "no matching rule"
				}
				out = append(out, res)
			}
		}
	}
	return out, nil
}

func parseLine(line string) (method, host, path string, err error) {
	fields := strings.Fields(line)
	method = "GET"
	var target string
	switch len(fields) {
	case 1:
		target = fields[0]
	case 2:
		method, target = strings.ToUpper(fields[0]), fields[1]
	default:
		return "", "", "", fmt.Errorf("bad line %q: want \"METHOD host/path\"", line)
	}
	target = strings.TrimPrefix(strings.TrimPrefix(target, "https://"), "http://")
	i := strings.Index(target, "/")
	if i < 0 {
		return method, target, "/", nil
	}
	return method, target[:i], target[i:], nil
}
