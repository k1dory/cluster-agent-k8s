package gitsync

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"agent-sandbox/internal/render"
)

// Reporter posts the plan of a pull (merge) request back to the provider: one comment per
// request, updated in place, and one commit status. The narrow interface the webhook handler
// depends on; GitHub, GitLab and Forgejo (Gitea) implement it over their REST APIs.
type Reporter interface {
	// UpsertComment posts body as the platform's comment on the request, or replaces the one
	// it posted before (found by the marker line).
	UpsertComment(ctx context.Context, t Target, body string) error
	// SetStatus sets the commit status "agent-sandbox/plan" on the request's head.
	SetStatus(ctx context.Context, t Target, state, description string) error
}

// Commit status states, as the platform names them; each provider maps them to its own.
const (
	StatusSuccess = "success"
	StatusFailure = "failure"
	StatusError   = "error"
	StatusPending = "pending"
)

// StatusContext is the name of the commit status the platform sets.
const StatusContext = "agent-sandbox/plan"

// Target is one pull (merge) request at a provider's API.
type Target struct {
	Provider string
	APIBase  string // https://api.github.com, https://ghe.example/api/v3, https://gitlab.example/api/v4, https://forgejo.example[/subpath]/api/v1
	Repo     string // owner/name (GitHub, Forgejo) or the project path (GitLab)
	Number   int
	SHA      string
	Token    string
}

// TargetOf derives the API target of a pull request from the registered repository URL and
// its credential, never from the delivery: a webhook cannot send the platform's comments
// anywhere but to the registered repository's own server. The delivery's provider only picks
// the API on that server: GitHub's (api.github.com, or /api/v3 on GitHub Enterprise Server),
// GitLab's (/api/v4) or Forgejo's and Gitea's (/api/v1, under the subpath the server is mounted
// at, if any). A pull request that names no provider (a job persisted before it was recorded)
// is told by its head ref, which cannot tell Forgejo from GitHub: such a job is taken for
// GitHub's, as it always was.
func TargetOf(r Remote, pr PullRequest) (Target, error) {
	u, err := url.Parse(r.URL)
	if err != nil || u.Host == "" {
		return Target{}, fmt.Errorf("repository URL %q", r.URL)
	}
	repo := strings.TrimSuffix(strings.Trim(u.Path, "/"), ".git")
	if repo == "" || !strings.Contains(repo, "/") {
		return Target{}, fmt.Errorf("repository URL %q has no owner/name path", r.URL)
	}
	t := Target{Repo: repo, Number: pr.Number, SHA: pr.HeadSHA, Token: tokenOf(r.Auth)}
	origin := u.Scheme + "://" + u.Host
	provider := pr.Provider
	if provider == "" {
		switch {
		case strings.HasPrefix(pr.HeadRef, "refs/pull/"):
			provider = ProviderGitHub
		case strings.HasPrefix(pr.HeadRef, "refs/merge-requests/"):
			provider = ProviderGitLab
		default:
			return Target{}, fmt.Errorf("pull request ref %q names no provider", pr.HeadRef)
		}
	}
	t.Provider = provider
	switch provider {
	case ProviderGitHub:
		if strings.EqualFold(u.Hostname(), "github.com") {
			t.APIBase = "https://api.github.com"
		} else {
			t.APIBase = origin + "/api/v3" // GitHub Enterprise Server
		}
	case ProviderGitLab:
		t.APIBase = origin + "/api/v4"
	case ProviderForgejo:
		// Forgejo and Gitea have no nested groups: a repository is always owner/name, the last
		// two segments of its path. Whatever comes before them is the subpath the server is
		// mounted under (ROOT_URL https://host/code/), and its API lives under it as well:
		// https://host/code/acme/config.git is https://host/code/api/v1/repos/acme/config.
		segs := strings.Split(repo, "/")
		prefix := strings.Join(segs[:len(segs)-2], "/")
		t.Repo = strings.Join(segs[len(segs)-2:], "/")
		if prefix != "" {
			origin += "/" + prefix
		}
		t.APIBase = origin + "/api/v1"
	default:
		return Target{}, fmt.Errorf("unknown provider %q", provider)
	}
	return t, nil
}

// tokenOf is the token part of a credential (`user:token` or a bare token).
func tokenOf(auth string) string {
	if _, tok, ok := strings.Cut(auth, ":"); ok {
		return tok
	}
	return auth
}

// RESTReporter reports through the providers' REST APIs with a plain HTTP client.
type RESTReporter struct {
	Client *http.Client
}

func (r RESTReporter) client() *http.Client {
	if r.Client != nil {
		return r.Client
	}
	return &http.Client{Timeout: 30 * time.Second}
}

// call makes one JSON request; the body goes out as JSON, the answer comes back as bytes.
func (r RESTReporter) call(ctx context.Context, t Target, method, path string, body any) ([]byte, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, t.APIBase+path, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	switch t.Provider {
	case ProviderGitHub:
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("Authorization", "Bearer "+t.Token)
	case ProviderGitLab:
		req.Header.Set("PRIVATE-TOKEN", t.Token)
	case ProviderForgejo:
		// An access token, in the form Forgejo's API documents (it takes "bearer" as well).
		req.Header.Set("Authorization", "token "+t.Token)
	}
	resp, err := r.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode >= 300 {
		// The provider's message, without echoing anything but its first line.
		msg := strings.TrimSpace(string(data))
		if i := strings.IndexByte(msg, '\n'); i > 0 {
			msg = msg[:i]
		}
		if len(msg) > 200 {
			msg = msg[:200]
		}
		return nil, fmt.Errorf("%s %s: %s: %s", method, path, resp.Status, msg)
	}
	return data, nil
}

// maxPages bounds the comment listing (100 per page): a request with more comments than that
// gets a new comment rather than an unbounded walk.
const maxPages = 50

// findMarked walks the pages of a comment listing and returns the id of the platform's comment
// (the one opening with the marker), or 0. A listing that is not paged (Forgejo's and Gitea's
// issue comments come all in one answer, whatever the query says) is read once.
func (r RESTReporter) findMarked(ctx context.Context, t Target, list string, paged bool) (int64, error) {
	for page := 1; page <= maxPages; page++ {
		path := list
		if paged {
			path = fmt.Sprintf("%s&page=%d", list, page)
		}
		data, err := r.call(ctx, t, http.MethodGet, path, nil)
		if err != nil {
			return 0, err
		}
		var items []struct {
			ID   int64  `json:"id"`
			Body string `json:"body"`
		}
		if err := json.Unmarshal(data, &items); err != nil {
			return 0, fmt.Errorf("comments: %w", err)
		}
		for _, c := range items {
			if strings.HasPrefix(c.Body, render.Marker) {
				return c.ID, nil
			}
		}
		if !paged || len(items) < 100 {
			return 0, nil
		}
	}
	return 0, nil
}

func (r RESTReporter) UpsertComment(ctx context.Context, t Target, body string) error {
	switch t.Provider {
	case ProviderGitHub:
		id, err := r.findMarked(ctx, t, fmt.Sprintf("/repos/%s/issues/%d/comments?per_page=100", t.Repo, t.Number), true)
		if err != nil {
			return err
		}
		if id != 0 {
			_, err := r.call(ctx, t, http.MethodPatch, fmt.Sprintf("/repos/%s/issues/comments/%d", t.Repo, id), map[string]string{"body": body})
			return err
		}
		_, err = r.call(ctx, t, http.MethodPost, fmt.Sprintf("/repos/%s/issues/%d/comments", t.Repo, t.Number), map[string]string{"body": body})
		return err
	case ProviderGitLab:
		project := url.PathEscape(t.Repo)
		id, err := r.findMarked(ctx, t, fmt.Sprintf("/projects/%s/merge_requests/%d/notes?per_page=100", project, t.Number), true)
		if err != nil {
			return err
		}
		if id != 0 {
			_, err := r.call(ctx, t, http.MethodPut, fmt.Sprintf("/projects/%s/merge_requests/%d/notes/%d", project, t.Number, id), map[string]string{"body": body})
			return err
		}
		_, err = r.call(ctx, t, http.MethodPost, fmt.Sprintf("/projects/%s/merge_requests/%d/notes", project, t.Number), map[string]string{"body": body})
		return err
	case ProviderForgejo:
		// A pull request is an issue to Forgejo: its comments are the issue's
		// (GET/POST /repos/{owner}/{repo}/issues/{index}/comments, listed unpaged), one is
		// edited by its id (PATCH /repos/{owner}/{repo}/issues/comments/{id}).
		id, err := r.findMarked(ctx, t, fmt.Sprintf("/repos/%s/issues/%d/comments", t.Repo, t.Number), false)
		if err != nil {
			return err
		}
		if id != 0 {
			_, err := r.call(ctx, t, http.MethodPatch, fmt.Sprintf("/repos/%s/issues/comments/%d", t.Repo, id), map[string]string{"body": body})
			return err
		}
		_, err = r.call(ctx, t, http.MethodPost, fmt.Sprintf("/repos/%s/issues/%d/comments", t.Repo, t.Number), map[string]string{"body": body})
		return err
	}
	return errors.New("unknown provider " + t.Provider)
}

func (r RESTReporter) SetStatus(ctx context.Context, t Target, state, description string) error {
	switch t.Provider {
	case ProviderGitHub:
		_, err := r.call(ctx, t, http.MethodPost, fmt.Sprintf("/repos/%s/statuses/%s", t.Repo, t.SHA),
			map[string]string{"state": state, "context": StatusContext, "description": description})
		return err
	case ProviderGitLab:
		gl := map[string]string{StatusSuccess: "success", StatusFailure: "failed", StatusError: "failed", StatusPending: "pending"}[state]
		_, err := r.call(ctx, t, http.MethodPost, fmt.Sprintf("/projects/%s/statuses/%s", url.PathEscape(t.Repo), t.SHA),
			map[string]string{"state": gl, "name": StatusContext, "description": description})
		return err
	case ProviderForgejo:
		// POST /repos/{owner}/{repo}/statuses/{sha}; Forgejo's states (pending, success, error,
		// failure, warning, skipped) include the platform's as they are.
		_, err := r.call(ctx, t, http.MethodPost, fmt.Sprintf("/repos/%s/statuses/%s", t.Repo, t.SHA),
			map[string]string{"state": state, "context": StatusContext, "description": description})
		return err
	}
	return errors.New("unknown provider " + t.Provider)
}
