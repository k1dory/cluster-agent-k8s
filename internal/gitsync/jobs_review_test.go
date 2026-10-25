package gitsync

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"agent-sandbox/internal/model"
	"agent-sandbox/internal/plan"
	"agent-sandbox/internal/store"

	"github.com/jackc/pgx/v5"
)

func reviewEnvironment(description string) []byte {
	return []byte("kind: EnvironmentProfile\nname: py\ndescription: " + description + "\nspec: {image: stable}\n")
}

// Returning the ref to a commit previously applied is a new desired-state
// transition, not a retry of the old successful apply.
func TestReviewForcePushBackToPreviouslyAppliedCommit(t *testing.T) {
	fetch := &refFetcher{heads: map[string]string{"main": sha1}, files: map[string]map[string][]byte{
		sha1: {"bundles/env.yaml": reviewEnvironment("first")},
		sha2: {"bundles/env.yaml": reviewEnvironment("second")},
	}}
	s, st, _ := reviewHookService(t, fetch, reviewHookURL)
	for i, commit := range []string{sha1, sha2, sha1} {
		fetch.heads["main"] = commit
		h := reviewDelivery(t, s, "push", []string{"first", "second", "force-back"}[i], reviewPush(reviewHookURL, commit, "refs/heads/main"))
		if h.Outcome != model.GitSyncDone {
			t.Fatalf("push %d: %+v", i, h)
		}
	}
	it, err := st.GetItem(t.Context(), model.KindEnvironment, "acme", "py", 0)
	if err != nil {
		t.Fatal(err)
	}
	if it.Description != "first" || it.Source == nil || it.Source.Commit != sha1 || it.Revision != 3 {
		t.Fatalf("force push was reported done without restoring desired state: description=%q revision=%d source=%+v", it.Description, it.Revision, it.Source)
	}
}

// The preview must agree with Sync, including forward dependencies and duplicate
// resources split across files. Combining files changes the planner's semantics.
func TestReviewPreviewAndSyncAgreeOnFileSemantics(t *testing.T) {
	for _, tc := range []struct {
		name  string
		files map[string][]byte
	}{
		{"dependency_in_later_file", map[string][]byte{
			"bundles/00-agent.yaml": []byte("kind: AgentDefinition\nname: backend\nspec: {policy: backend-dev, environment: py}\n"),
			"bundles/10-env.yaml":   reviewEnvironment("first"),
		}},
		{"duplicate_between_files", map[string][]byte{
			"bundles/00-env.yaml": reviewEnvironment("first"),
			"bundles/10-env.yaml": reviewEnvironment("second"),
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fetch := memFetcher{head: sha1, files: map[string]map[string][]byte{sha1: tc.files}}
			s, _, _ := reviewHookService(t, fetch, reviewHookURL)
			h := reviewDelivery(t, s, "pull_request", "file-semantics", reviewPR(sha1))
			g, err := s.Sync(t.Context(), plan.Scope{Tenant: "acme", Subject: "review"}, "config", sha1)
			if g == nil || g.Sync == nil {
				t.Fatalf("missing sync result: %v", err)
			}
			if h.Outcome != g.Sync.Status {
				t.Fatalf("preview=%s but actual sync=%s (%v)", h.Outcome, g.Sync.Status, err)
			}
		})
	}
}

func TestReviewCompletedRedeliveryPreservesHookOutcome(t *testing.T) {
	fetch := memFetcher{head: sha1, files: map[string]map[string][]byte{sha1: {"bundles/env.yaml": reviewEnvironment("first")}}}
	s, st, _ := reviewHookService(t, fetch, reviewHookURL)
	first := reviewDelivery(t, s, "push", "completed", reviewPush(reviewHookURL, sha1, "refs/heads/main"))
	if first.Outcome != model.GitSyncDone {
		t.Fatalf("initial delivery: %+v", first)
	}
	reviewDelivery(t, s, "push", "completed", reviewPush(reviewHookURL, sha1, "refs/heads/main"))
	g, err := s.Status(t.Context(), plan.Scope{Tenant: "acme"}, "config")
	if err != nil {
		t.Fatal(err)
	}
	j, err := st.GetGitJob(t.Context(), first.Job)
	if err != nil {
		t.Fatal(err)
	}
	if g.Hook == nil || g.Hook.Outcome != j.Outcome || g.Hook.Job != j.ID {
		t.Fatalf("redelivery erased the terminal hook result: hook=%+v job_status=%s job_outcome=%s", g.Hook, j.Status, j.Outcome)
	}
}

type reviewInterruptedFetch struct {
	Fetcher
	unavailable bool
}

func (f *reviewInterruptedFetch) Resolve(ctx context.Context, r Remote) (string, error) {
	if f.unavailable {
		return "", errors.New("temporary Git service outage")
	}
	return f.Fetcher.Resolve(ctx, r)
}

// A temporary outage must leave an accepted action recoverable. A provider's
// redelivery after recovery should not keep returning an inert failed job.
func TestReviewRedeliveryCanRecoverTemporaryGitOutage(t *testing.T) {
	fetch := &reviewInterruptedFetch{Fetcher: memFetcher{head: sha1, files: map[string]map[string][]byte{sha1: {"bundles/env.yaml": reviewEnvironment("first")}}}, unavailable: true}
	s, st, _ := reviewHookService(t, fetch, reviewHookURL)
	first := reviewDelivery(t, s, "push", "outage", reviewPush(reviewHookURL, sha1, "refs/heads/main"))
	if first.Outcome != model.GitSyncError {
		t.Fatalf("expected initial read failure: %+v", first)
	}
	fetch.unavailable = false
	reviewDelivery(t, s, "push", "outage", reviewPush(reviewHookURL, sha1, "refs/heads/main"))
	if _, err := st.GetItem(t.Context(), model.KindEnvironment, "acme", "py", 0); err != nil {
		job, _ := st.GetGitJob(t.Context(), first.Job)
		t.Fatalf("accepted delivery cannot recover after Git returns: item=%v job_status=%s attempts=%d error=%s", err, job.Status, job.Attempts, job.Error)
	}
}

type reviewPausedPRFetch struct {
	Fetcher
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (f *reviewPausedPRFetch) Files(ctx context.Context, r Remote, commit string, patterns []string) (map[string][]byte, error) {
	if commit == sha1 {
		f.once.Do(func() { close(f.entered) })
		select {
		case <-f.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return f.Fetcher.Files(ctx, r, commit, patterns)
}

// Two different deliveries for the same PR can finish in reverse order on two
// replicas. An older plan must not replace the comment about the newer head.
func TestReviewTwoReplicasKeepLatestPRComment(t *testing.T) {
	fetch := &reviewPausedPRFetch{Fetcher: memFetcher{head: sha2, files: map[string]map[string][]byte{
		sha1: {"bundles/env.yaml": reviewEnvironment("older-plan")},
		sha2: {"bundles/env.yaml": reviewEnvironment("newer-plan")},
	}}, entered: make(chan struct{}), release: make(chan struct{})}
	one, _, rep := reviewHookService(t, fetch, reviewHookURL)
	one.Inline, one.Replica = false, "review-one"
	two := *one
	two.Replica = "review-two"
	reviewDelivery(t, one, "pull_request", "older-pr", reviewPR(sha1))
	olderDone := make(chan struct{})
	go func() {
		defer close(olderDone)
		_, _ = one.RunOnce(t.Context())
	}()
	select {
	case <-fetch.entered:
	case <-time.After(5 * time.Second):
		close(fetch.release)
		<-olderDone
		t.Fatal("older plan did not reach the fetch barrier")
	}
	reviewDelivery(t, &two, "pull_request", "newer-pr", reviewPR(sha2))
	newerDone := make(chan struct{})
	go func() { defer close(newerDone); _, _ = two.RunOnce(t.Context()) }()
	select {
	case <-newerDone:
		// The newer work finished before the older fetch was released.
	case <-time.After(100 * time.Millisecond):
		// An implementation serializing the PR waits here, then publishes in order.
	}
	close(fetch.release)
	<-olderDone
	<-newerDone
	rep.mu.Lock()
	defer rep.mu.Unlock()
	comments := rep.comments["github acme/config #7"]
	if len(comments) == 0 || !strings.Contains(comments[len(comments)-1], "newer-plan") {
		t.Fatalf("latest PR comment describes an older head: %v", comments)
	}
}

// PostgreSQL refuses operations on an expired context; the in-memory job store
// ignores it. Model that boundary explicitly to check exhaustion of the lease.
type reviewContextAwareJobs struct{ store.GitJobs }

func (j reviewContextAwareJobs) FinishGitJob(ctx context.Context, id, owner string, run int, status, outcome, message string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return j.GitJobs.FinishGitJob(ctx, id, owner, run, status, outcome, message)
}

func (j reviewContextAwareJobs) RetryGitJob(ctx context.Context, id, owner string, run int, notBefore time.Time, message string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return j.GitJobs.RetryGitJob(ctx, id, owner, run, notBefore, message)
}

type reviewDeadlineFetch struct{ Fetcher }

func (f reviewDeadlineFetch) Resolve(ctx context.Context, _ Remote) (string, error) {
	<-ctx.Done()
	return "", ctx.Err()
}

func TestReviewJobAttemptLimitSurvivesExpiredContext(t *testing.T) {
	t.Run("context_aware_store", func(t *testing.T) { reviewAttemptLimit(t, nil) })
	t.Run("postgres", func(t *testing.T) {
		dsn := os.Getenv("SANDBOX_TEST_POSTGRES_URL")
		if dsn == "" {
			if os.Getenv("SANDBOX_TEST_REQUIRE_EXTERNAL") != "" {
				t.Fatal("PostgreSQL required but SANDBOX_TEST_POSTGRES_URL is empty")
			}
			t.Skip("SANDBOX_TEST_POSTGRES_URL not set")
		}
		ctx := t.Context()
		conn, err := pgx.Connect(ctx, dsn)
		if err != nil {
			t.Fatal(err)
		}
		schema := pgx.Identifier{fmt.Sprintf("review_gitjobs_%d", time.Now().UnixNano())}.Sanitize()
		if _, err := conn.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
			_ = conn.Close(context.Background())
			t.Fatal(err)
		}
		t.Cleanup(func() {
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if _, err := conn.Exec(cleanup, "DROP SCHEMA "+schema+" CASCADE"); err != nil {
				t.Errorf("cleanup test schema: %v", err)
			}
			_ = conn.Close(cleanup)
		})
		u, err := url.Parse(dsn)
		if err != nil {
			t.Fatal(err)
		}
		q := u.Query()
		q.Set("search_path", schema)
		u.RawQuery = q.Encode()
		pg, err := store.OpenPostgres(ctx, u.String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = pg.Close() })
		reviewAttemptLimit(t, pg)
	})
}

func reviewAttemptLimit(t *testing.T, postgres store.Store) {
	t.Helper()
	s, st, _ := reviewHookService(t, reviewDeadlineFetch{}, reviewHookURL)
	s.Inline, s.Replica, s.Lease = false, "review-timeout", 20*time.Millisecond
	s.Jobs = reviewContextAwareJobs{GitJobs: st}
	if postgres != nil {
		st.Store = postgres
		s.Jobs = postgres
		register(t, s, "acme", "config", "kind: GitRepository\nname: config\nspec: {url: "+reviewHookURL+", ref: main, paths: ['bundles/*.yaml'], webhook_secret: hook-secret}\n")
	}
	h := reviewDelivery(t, s, "push", "timeouts", reviewPush(reviewHookURL, sha1, "refs/heads/main"))
	for i := 0; i < MaxAttempts; i++ {
		if ran, err := s.RunOnce(t.Context()); err != nil || !ran {
			t.Fatalf("attempt %d did not run: %v %v", i+1, ran, err)
		}
	}
	job, err := st.GetGitJob(t.Context(), h.Job)
	if err != nil {
		t.Fatal(err)
	}
	if job.Status != model.GitJobFailed {
		t.Errorf("job exhausted %d attempts but stayed %s", job.Attempts, job.Status)
	}
	if next, err := st.ClaimGitJob(t.Context(), "later", time.Now().Add(time.Hour), time.Minute); !errors.Is(err, store.ErrNotFound) {
		if next != nil {
			t.Errorf("exhausted job is still claimable: attempts=%d status=%s err=%v", next.Attempts, next.Status, err)
		} else {
			t.Errorf("claim exhausted job: %v", err)
		}
	}
}
