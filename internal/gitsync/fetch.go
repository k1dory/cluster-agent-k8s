// Package gitsync reads bundles from a registered GitRepository and applies them through the
// apply controller: the platform's side of "a settings change is one pull request", without a
// workflow installed in the repository. Reading Git is behind one narrow interface (Fetcher);
// the shipped implementation shells out to git over HTTPS, so any server git talks to works,
// a self-hosted one included.
package gitsync

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Remote is a repository to read: the URL, the ref followed and the credential that opens it
// (`user:password`, or a bare token used as the password; empty for a public repository).
type Remote struct {
	URL  string
	Ref  string
	Auth string
}

// Fetcher reads a remote repository.
type Fetcher interface {
	// Resolve returns the commit the ref points at (a tag's commit, not the tag object), or an
	// error when the repository cannot be read or the ref does not exist.
	Resolve(ctx context.Context, r Remote) (string, error)
	// Files returns the files at commit whose repository path matches one of the patterns
	// (path.Match on the whole path, or equality), keyed by path. The commit must be the ref's
	// head or reachable from it (ErrNotOnRef otherwise); ErrNoMatch when nothing matches.
	Files(ctx context.Context, r Remote, commit string, patterns []string) (map[string][]byte, error)
}

var (
	// ErrNotOnRef: the commit is not in the ref's history (or no longer: a force push).
	ErrNotOnRef = errors.New("the commit is not reachable from the ref")
	// ErrNoMatch: the repository holds no file matching the paths at that commit.
	ErrNoMatch = errors.New("no bundle file matches the paths")
	// ErrNoRef: the ref does not exist in the repository.
	ErrNoRef = errors.New("the ref does not exist in the repository")

	shaRe = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

// MaxFile bounds one bundle file.
const MaxFile = 1 << 20

// CLI reads repositories with the git binary over HTTPS. Each call works in a temporary
// directory with its own, empty Git configuration: no credential helper, no cached state. The
// credential travels in an environment-borne config entry (http.extraHeader), never in the URL
// or the command line.
type CLI struct {
	Git     string        // binary (default "git")
	Timeout time.Duration // per call (default 2 minutes)
	// Deepen bounds how far back the ref's history is fetched looking for a commit that is not
	// its head: Deepen steps of 100 commits (default 10, so 1000 commits).
	Deepen int
}

func (c CLI) git() string {
	if c.Git != "" {
		return c.Git
	}
	return "git"
}

func (c CLI) timeout() time.Duration {
	if c.Timeout > 0 {
		return c.Timeout
	}
	return 2 * time.Minute
}

// env is the isolated environment of a git call, with the credential as a request header.
func env(dir string, r Remote) []string {
	e := []string{"HOME=" + dir, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=" + dir + "/gitconfig", "GIT_TERMINAL_PROMPT=0",
		"GIT_ASKPASS=", "SSH_ASKPASS=", "PATH=" + os.Getenv("PATH"), "LC_ALL=C"}
	for _, k := range []string{"HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "https_proxy", "http_proxy", "no_proxy", "SSL_CERT_FILE", "SSL_CERT_DIR", "GIT_SSL_CAINFO"} {
		if v := os.Getenv(k); v != "" {
			e = append(e, k+"="+v)
		}
	}
	if r.Auth != "" {
		auth := r.Auth
		if !strings.Contains(auth, ":") {
			auth = "x-access-token:" + auth // a bare token: the user name is conventional
		}
		e = append(e, "GIT_CONFIG_COUNT=1", "GIT_CONFIG_KEY_0=http.extraHeader",
			"GIT_CONFIG_VALUE_0=Authorization: Basic "+base64.StdEncoding.EncodeToString([]byte(auth)))
	}
	return e
}

// run executes git in dir and returns stdout; the error carries git's first message line.
func (c CLI) run(ctx context.Context, dir string, r Remote, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout())
	defer cancel()
	cmd := exec.CommandContext(ctx, c.git(), args...)
	cmd.Dir, cmd.Env = dir, env(dir, r)
	var out, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("git %s: timed out after %s", args[0], c.timeout())
		}
		msg := firstLine(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		// Without a terminal git would ask for a password; here that means the server refused
		// the credential (or wants one). One message for that, whatever git phrased.
		for _, hint := range []string{"terminal prompts disabled", "Authentication failed", "askpass", "HTTP 401", "401 Unauthorized"} {
			if strings.Contains(stderr.String(), hint) {
				msg = "the server refused the credential (HTTP 401): check the repository's credential"
				break
			}
		}
		return nil, fmt.Errorf("git %s: %s", args[0], msg)
	}
	return out.Bytes(), nil
}

func firstLine(s string) string {
	for _, l := range strings.Split(strings.TrimSpace(s), "\n") {
		l = strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(l, "fatal: "), "error: "))
		if l != "" && !strings.HasPrefix(l, "remote:") || strings.Contains(l, "HTTP") {
			return l
		}
	}
	return strings.TrimSpace(s)
}

func (c CLI) workdir() (string, func(), error) {
	dir, err := os.MkdirTemp("", "gitsync-")
	if err != nil {
		return "", nil, err
	}
	if err := os.WriteFile(dir+"/gitconfig", nil, 0o600); err != nil {
		os.RemoveAll(dir)
		return "", nil, err
	}
	return dir, func() { os.RemoveAll(dir) }, nil
}

// Resolve: ls-remote for the ref, preferring the branch, then the tag's peeled commit.
func (c CLI) Resolve(ctx context.Context, r Remote) (string, error) {
	dir, done, err := c.workdir()
	if err != nil {
		return "", err
	}
	defer done()
	out, err := c.run(ctx, dir, r, "ls-remote", "--", r.URL, "refs/heads/"+r.Ref, "refs/tags/"+r.Ref, "refs/tags/"+r.Ref+"^{}")
	if err != nil {
		return "", err
	}
	refs := map[string]string{}
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if sha, name, ok := strings.Cut(l, "\t"); ok {
			refs[strings.TrimSpace(name)] = strings.TrimSpace(sha)
		}
	}
	for _, name := range []string{"refs/heads/" + r.Ref, "refs/tags/" + r.Ref + "^{}", "refs/tags/" + r.Ref} {
		if sha := refs[name]; shaRe.MatchString(sha) {
			return sha, nil
		}
	}
	return "", fmt.Errorf("%w: %s", ErrNoRef, r.Ref)
}

// Files: a shallow fetch of the ref into an empty repository, deepened until the commit is
// found (or given up), then the tree at the commit filtered by the patterns.
func (c CLI) Files(ctx context.Context, r Remote, commit string, patterns []string) (map[string][]byte, error) {
	if !shaRe.MatchString(commit) {
		return nil, fmt.Errorf("%q is not a commit SHA", commit)
	}
	dir, done, err := c.workdir()
	if err != nil {
		return nil, err
	}
	defer done()
	if _, err := c.run(ctx, dir, r, "init", "-q", "--bare", "repo"); err != nil {
		return nil, err
	}
	repo := dir + "/repo"
	if _, err := c.run(ctx, repo, r, "fetch", "-q", "--no-tags", "--depth=1", "--", r.URL, "+"+r.Ref+":refs/sync/head"); err != nil {
		if strings.Contains(err.Error(), "couldn't find remote ref") {
			return nil, fmt.Errorf("%w: %s", ErrNoRef, r.Ref)
		}
		return nil, err
	}
	onRef := func() bool {
		_, err := c.run(ctx, repo, r, "merge-base", "--is-ancestor", commit, "refs/sync/head")
		return err == nil
	}
	steps := c.Deepen
	if steps <= 0 {
		steps = 10
	}
	for i := 0; !onRef(); i++ {
		if i >= steps {
			return nil, fmt.Errorf("%w: %s is not in the last %d commits of %s", ErrNotOnRef, commit, steps*100, r.Ref)
		}
		out, err := c.run(ctx, repo, r, "fetch", "-q", "--no-tags", "--deepen=100", "--", r.URL, "+"+r.Ref+":refs/sync/head")
		if err != nil {
			return nil, err
		}
		_ = out
		if _, err := c.run(ctx, repo, r, "rev-parse", "--is-shallow-repository"); err == nil {
			if b, _ := c.run(ctx, repo, r, "rev-parse", "--is-shallow-repository"); strings.TrimSpace(string(b)) == "false" && !onRef() {
				return nil, fmt.Errorf("%w: %s", ErrNotOnRef, commit)
			}
		}
	}
	out, err := c.run(ctx, repo, r, "ls-tree", "-r", "--name-only", "-z", commit)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, n := range strings.Split(string(out), "\x00") {
		if n != "" && Matches(n, patterns) {
			names = append(names, n)
		}
	}
	if len(names) == 0 {
		return nil, ErrNoMatch
	}
	sort.Strings(names)
	files := make(map[string][]byte, len(names))
	for _, n := range names {
		b, err := c.run(ctx, repo, r, "cat-file", "blob", commit+":"+n)
		if err != nil {
			return nil, err
		}
		if len(b) > MaxFile {
			return nil, fmt.Errorf("%s: %d bytes, more than a bundle may be (%d)", n, len(b), MaxFile)
		}
		files[n] = b
	}
	return files, nil
}

// Matches reports whether a repository path is one of the patterns (equality, or path.Match
// over the whole path).
func Matches(name string, patterns []string) bool {
	for _, p := range patterns {
		if p == name {
			return true
		}
		if ok, err := path.Match(p, name); err == nil && ok {
			return true
		}
	}
	return false
}
