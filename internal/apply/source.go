package apply

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"agent-sandbox/internal/model"
	res "agent-sandbox/internal/resource"
)

var commitRE = regexp.MustCompile(`^[0-9a-f]{7,64}$`)

// CleanSource makes a source safe to keep forever: credentials are stripped from the
// repository URL (a token pasted into `https://x:TOKEN@host/…` or a CI's `remote get-url` must
// never land in the catalogue's history), the commit must be a hex object name, and every field
// is bounded. sandboxctl cleans what it detects; the controller cleans again, so a client that
// sends a raw URL is covered too.
func CleanSource(s *model.Source) error {
	for name, v := range map[string]string{"repo": s.Repo, "ref": s.Ref, "commit": s.Commit, "path": s.Path} {
		if len(v) > 512 {
			return fmt.Errorf("%w: source.%s is longer than 512 bytes", res.ErrInvalid, name)
		}
	}
	s.Commit = strings.ToLower(strings.TrimSpace(s.Commit))
	if s.Commit != "" && !commitRE.MatchString(s.Commit) {
		return fmt.Errorf("%w: source.commit %q is not a Git object name", res.ErrInvalid, s.Commit)
	}
	repo, err := StripCredentials(strings.TrimSpace(s.Repo))
	if err != nil {
		return err
	}
	s.Repo = repo
	return nil
}

// StripCredentials removes user information from a repository URL. A URL with a scheme loses
// its userinfo entirely; the scp-like form `user@host:path` keeps the user only when it is the
// conventional `git` (anything else there may be a token).
func StripCredentials(repo string) (string, error) {
	if repo == "" {
		return "", nil
	}
	if strings.Contains(repo, "://") {
		u, err := url.Parse(repo)
		if err != nil {
			return "", fmt.Errorf("%w: source.repo is not a URL: %v", res.ErrInvalid, err)
		}
		u.User = nil
		return u.String(), nil
	}
	// scp-like: everything before the first "@" is user information when it names no path.
	if at := strings.Index(repo, "@"); at >= 0 && !strings.Contains(repo[:at], "/") {
		if user := repo[:at]; user != "git" {
			return repo[at+1:], nil
		}
	}
	return repo, nil
}
