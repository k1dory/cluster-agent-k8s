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
// depends on; GitHub and GitLab implement it over their REST APIs.
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
	APIBase  string // https://api.github.com, https://ghe.example/api/v3, https://gitlab.example/api/v4
	Repo     string // owner/name (GitHub) or the project path (GitLab)
	Number   int
	SHA      string
	Token    string
}

// TargetOf derives the API target of a pull request from the registered repository URL and
// its credential, never from the delivery: a webhook cannot send the platform's comments
// anywhere but to the registered repository's own server.
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
	switch {
	case strings.HasPrefix(pr.HeadRef, "refs/pull/"):
		t.Provider = ProviderGitHub
		if strings.EqualFold(u.Hostname(), "github.com") {
			t.APIBase = "https://api.github.com"
		} else {
			t.APIBase = origin + "/api/v3" // GitHub Enterprise Server
		}
	case strings.HasPrefix(pr.HeadRef, "refs/merge-requests/"):
		t.Provider = ProviderGitLab
		t.APIBase = origin + "/api/v4"
	default:
		return Target{}, fmt.Errorf("pull request ref %q names no provider", pr.HeadRef)
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

func (r RESTReporter) UpsertComment(ctx context.Context, t Target, body string) error {
	switch t.Provider {
	case ProviderGitHub:
		list := fmt.Sprintf("/repos/%s/issues/%d/comments?per_page=100", t.Repo, t.Number)
		data, err := r.call(ctx, t, http.MethodGet, list, nil)
		if err != nil {
			return err
		}
		var comments []struct {
			ID   int64  `json:"id"`
			Body string `json:"body"`
		}
		if err := json.Unmarshal(data, &comments); err != nil {
			return fmt.Errorf("comments: %w", err)
		}
		for _, c := range comments {
			if strings.HasPrefix(c.Body, render.Marker) {
				_, err := r.call(ctx, t, http.MethodPatch, fmt.Sprintf("/repos/%s/issues/comments/%d", t.Repo, c.ID), map[string]string{"body": body})
				return err
			}
		}
		_, err = r.call(ctx, t, http.MethodPost, fmt.Sprintf("/repos/%s/issues/%d/comments", t.Repo, t.Number), map[string]string{"body": body})
		return err
	case ProviderGitLab:
		project := url.PathEscape(t.Repo)
		list := fmt.Sprintf("/projects/%s/merge_requests/%d/notes?per_page=100", project, t.Number)
		data, err := r.call(ctx, t, http.MethodGet, list, nil)
		if err != nil {
			return err
		}
		var notes []struct {
			ID   int64  `json:"id"`
			Body string `json:"body"`
		}
		if err := json.Unmarshal(data, &notes); err != nil {
			return fmt.Errorf("notes: %w", err)
		}
		for _, n := range notes {
			if strings.HasPrefix(n.Body, render.Marker) {
				_, err := r.call(ctx, t, http.MethodPut, fmt.Sprintf("/projects/%s/merge_requests/%d/notes/%d", project, t.Number, n.ID), map[string]string{"body": body})
				return err
			}
		}
		_, err = r.call(ctx, t, http.MethodPost, fmt.Sprintf("/projects/%s/merge_requests/%d/notes", project, t.Number), map[string]string{"body": body})
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
	}
	return errors.New("unknown provider " + t.Provider)
}
