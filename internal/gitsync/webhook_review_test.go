package gitsync

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"agent-sandbox/internal/apply"
	"agent-sandbox/internal/gitsync/gittest"
	"agent-sandbox/internal/model"
	"agent-sandbox/internal/plan"
	"agent-sandbox/internal/secrets"
)

const reviewHookURL = "https://git.example.com/acme/config.git"
const reviewHookSecret = "review-fixture"

func reviewHookService(t *testing.T, fetch Fetcher, repoURL string) (*Service, *breaking, *fakeReporter) {
	t.Helper()
	s, st := newService(t, fetch)
	s.Secrets = secrets.Static{"acme/hook-secret": reviewHookSecret}
	s.Repos.Secrets = s.Secrets
	rep := &fakeReporter{}
	s.Reporter, s.Inline = rep, true
	register(t, s, "acme", "config", fmt.Sprintf("kind: GitRepository\nname: config\nspec: {url: %s, ref: main, paths: ['bundles/*.yaml'], webhook_secret: hook-secret}\n", repoURL))
	return s, st, rep
}

func reviewDelivery(t *testing.T, s *Service, event, id string, payload any) *model.GitHook {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	headers := githubHeaders(event, reviewHookSecret, body)
	headers.Set("X-GitHub-Delivery", id)
	h, err := s.Hook(t.Context(), "acme", "config", headers, body)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func reviewPush(repoURL, sha, ref string) any {
	return map[string]any{"ref": ref, "after": sha, "repository": map[string]string{"clone_url": repoURL}}
}

func reviewPR(sha string) any {
	return map[string]any{
		"action": "opened", "number": 7,
		"pull_request": map[string]any{"number": 7, "head": map[string]string{"sha": sha}},
		"repository":   map[string]string{"clone_url": reviewHookURL},
	}
}

// Webhook arrival order need not match commit order. An older push that arrives
// for the first time must not roll back an already applied newer commit.
func TestReviewHookLatePushDoesNotRollBackNewerCommit(t *testing.T) {
	git := gittest.New(t, "", "")
	old := git.Commit(t, map[string]string{"bundles/env.yaml": "kind: EnvironmentProfile\nname: py\ndescription: older\nspec: {image: stable}\n"}, "older")
	head := git.Commit(t, map[string]string{"bundles/env.yaml": "kind: EnvironmentProfile\nname: py\ndescription: current\nspec: {image: stable}\n"}, "current")
	s, st, _ := reviewHookService(t, CLI{}, git.URL)
	h := reviewDelivery(t, s, "push", "newer-push", reviewPush(git.URL, head, "refs/heads/main"))
	if h.Outcome != model.GitSyncDone {
		t.Fatalf("newer push: %+v", h)
	}
	reviewDelivery(t, s, "push", "late-older-push", reviewPush(git.URL, old, "refs/heads/main"))
	it, err := st.GetItem(t.Context(), model.KindEnvironment, "acme", "py", 0)
	if err != nil {
		t.Fatal(err)
	}
	if it.Description != "current" || it.Source == nil || it.Source.Commit != head {
		t.Errorf("late delivery replaced the newer configuration: description=%q source=%+v", it.Description, it.Source)
	}
	if n := revs(t, st, model.KindEnvironment, "acme", "py"); n != 1 {
		t.Errorf("late delivery must not add an older revision: got %d revisions", n)
	}
}

// A completed delivery remains completed across another delivery and another
// service instance; deduplication cannot be just the last hook or a local mutex.
func TestReviewHookRedeliveryIsDeduplicatedAcrossInstances(t *testing.T) {
	fetch := memFetcher{head: sha1, files: map[string]map[string][]byte{sha1: {
		"bundles/env.yaml": []byte("kind: EnvironmentProfile\nname: py\nspec: {image: stable}\n"),
	}}}
	s, st, rep := reviewHookService(t, fetch, reviewHookURL)
	first := reviewDelivery(t, s, "pull_request", "completed-pr-delivery", reviewPR(sha1))
	if first.Outcome != model.GitSyncDone {
		t.Fatalf("first plan: %+v", first)
	}
	key := "github acme/config #7"
	wantComments, wantStatuses := len(rep.comments[key]), len(rep.statuses[key])
	reviewDelivery(t, s, "push", "unrelated-delivery", reviewPush(reviewHookURL, sha1, "refs/heads/feature"))
	restarted := &Service{
		Store: st, Repos: s.Repos, Secrets: s.Secrets, Fetch: fetch, Reporter: rep, Inline: true,
		Applier: &apply.Controller{Store: st, Planner: s.Applier.Planner, Replica: "second-instance"},
	}
	reviewDelivery(t, restarted, "pull_request", "completed-pr-delivery", reviewPR(sha1))
	rep.mu.Lock()
	defer rep.mu.Unlock()
	if len(rep.comments[key]) != wantComments || len(rep.statuses[key]) != wantStatuses {
		t.Fatalf("a completed delivery repeated publication after changing instance: comments=%d statuses=%d", len(rep.comments[key]), len(rep.statuses[key]))
	}
}

// Sync applies files in order. A read-only PR preview must use the same virtual
// state when a later file refers to a resource introduced by an earlier one.
func TestReviewHookPlanAccountsForEarlierBundleFiles(t *testing.T) {
	fetch := memFetcher{head: sha1, files: map[string]map[string][]byte{sha1: {
		"bundles/00-env.yaml":   []byte("kind: EnvironmentProfile\nname: py\nspec: {image: stable}\n"),
		"bundles/10-agent.yaml": []byte("kind: AgentDefinition\nname: backend\nspec: {policy: backend-dev, environment: py}\n"),
	}}}
	s, st, _ := reviewHookService(t, fetch, reviewHookURL)
	h := reviewDelivery(t, s, "pull_request", "two-files", reviewPR(sha1))
	if h.Outcome != model.GitSyncDone {
		t.Errorf("valid dependency across bundle files was rejected by preview: %+v", h)
	}
	if revs(t, st, model.KindEnvironment, "acme", "py") != 0 || revs(t, st, model.KindAgent, "acme", "backend") != 0 {
		t.Fatal("preview must not write catalogue resources")
	}
	// Control: the very same files do apply successfully, in the declared path order.
	g, err := s.Sync(t.Context(), plan.Scope{Tenant: "acme", Subject: "review"}, "config", sha1)
	if err != nil || g.Sync == nil || g.Sync.Status != model.GitSyncDone {
		t.Fatalf("control sync: record=%+v err=%v", g, err)
	}
}

type reviewUnavailableComments struct{ *fakeReporter }

func (r reviewUnavailableComments) UpsertComment(context.Context, Target, string) error {
	return errors.New("comments temporarily unavailable")
}

// Failure of the comment endpoint must not leave a prior successful commit
// status unchanged when the current plan is invalid.
func TestReviewHookPublishesFailureStatusWhenCommentFails(t *testing.T) {
	fetch := memFetcher{head: sha1, files: map[string]map[string][]byte{sha1: {
		"bundles/env.yaml": []byte("kind: EnvironmentProfile\nname: py\nspec: {image: unavailable-version}\n"),
	}}}
	s, _, rep := reviewHookService(t, fetch, reviewHookURL)
	s.Reporter = reviewUnavailableComments{rep}
	reviewDelivery(t, s, "pull_request", "comment-failure", reviewPR(sha1))
	rep.mu.Lock()
	defer rep.mu.Unlock()
	states := rep.statuses["github acme/config #7"]
	if len(states) == 0 || (!strings.HasPrefix(states[len(states)-1], StatusFailure+":") && !strings.HasPrefix(states[len(states)-1], StatusError+":")) {
		t.Fatalf("an invalid plan and a failed comment must publish a failed status: %v", states)
	}
}
