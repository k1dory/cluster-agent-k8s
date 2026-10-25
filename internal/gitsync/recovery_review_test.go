package gitsync

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"agent-sandbox/internal/model"
	"agent-sandbox/internal/plan"
	"agent-sandbox/internal/store"
)

type reviewUnavailableResolve struct {
	Fetcher
	unavailable atomic.Bool
}

func (f *reviewUnavailableResolve) Resolve(ctx context.Context, r Remote) (string, error) {
	if f.unavailable.Load() {
		return "", errors.New("temporary Git read failure")
	}
	return f.Fetcher.Resolve(ctx, r)
}

// Failing to discover a head is not a new desired-state transition. A later
// successful read of the same head must still resume the interrupted Apply.
func TestReviewResolveFailurePreservesInterruptedTransition(t *testing.T) {
	bundle := []byte("kind: EnvironmentProfile\nname: py\nexpected_revision: 0\nspec: {image: stable}\n---\nkind: AgentDefinition\nname: backend\nexpected_revision: 0\nspec: {policy: backend-dev, environment: py}\n")
	fetch := &reviewUnavailableResolve{Fetcher: memFetcher{head: sha1, files: map[string]map[string][]byte{sha1: {"bundles/all.yaml": bundle}}}}
	s, st, _ := reviewHookService(t, fetch, reviewHookURL)
	scope := plan.Scope{Tenant: "acme", Subject: "review"}
	st.arm("backend")
	first, err := s.Sync(t.Context(), scope, "config", "")
	if !errors.Is(err, ErrStopped) || first == nil || first.Sync == nil || len(first.Sync.Bundles) != 1 {
		t.Fatalf("fixture should stop after the environment is written: result=%+v err=%v", first, err)
	}
	initialApply := first.Sync.Bundles[0].Apply
	initialGeneration := first.Sync.Generation
	if revs(t, st, model.KindEnvironment, "acme", "py") != 1 {
		t.Fatal("fixture: first step was not committed")
	}
	fetch.unavailable.Store(true)
	if _, err := s.Sync(t.Context(), scope, "config", ""); !errors.Is(err, ErrRead) {
		t.Fatalf("expected a temporary head-resolution failure: %v", err)
	}
	fetch.unavailable.Store(false)
	st.arm("")
	resumed, err := s.Sync(t.Context(), scope, "config", "")
	if err != nil || resumed == nil || resumed.Sync == nil || resumed.Sync.Status != model.GitSyncDone {
		if resumed != nil {
			t.Fatalf("same head cannot resume after the read outage: sync=%+v err=%v", resumed.Sync, err)
		}
		t.Fatalf("same head cannot resume after the read outage: %v", err)
	}
	if resumed.Sync.Generation != initialGeneration || len(resumed.Sync.Bundles) != 1 || resumed.Sync.Bundles[0].Apply != initialApply {
		t.Fatalf("the read outage changed the transition identity: before=%d/%s after=%+v", initialGeneration, initialApply, resumed.Sync)
	}
	if revs(t, st, model.KindEnvironment, "acme", "py") != 1 || revs(t, st, model.KindAgent, "acme", "backend") != 1 {
		t.Fatal("resume must finish the agent without rewriting the environment")
	}
}

type reviewDropSuccessfulHook struct{ store.Store }

func (s reviewDropSuccessfulHook) RecordGitHookIf(ctx context.Context, tenant, name string, hook model.GitHook, job string) (bool, error) {
	if hook.Outcome == model.GitSyncDone {
		return false, errors.New("temporary failure saving the final hook result")
	}
	return s.Store.RecordGitHookIf(ctx, tenant, name, hook, job)
}

// The first failed attempt already left a non-empty hook outcome. If the final
// summary write is lost, Status must recover from the now-successful durable job.
func TestReviewStatusRecoversTerminalJobOverEarlierError(t *testing.T) {
	fetch := &reviewUnavailableResolve{Fetcher: memFetcher{head: sha1, files: map[string]map[string][]byte{sha1: {"bundles/env.yaml": reviewEnvironment("ready")}}}}
	fetch.unavailable.Store(true)
	s, st, _ := reviewHookService(t, fetch, reviewHookURL)
	h := reviewDelivery(t, s, "push", "recover-final-hook", reviewPush(reviewHookURL, sha1, "refs/heads/main"))
	if h.Outcome != model.GitSyncError {
		t.Fatalf("fixture: first attempt should leave an error summary: %+v", h)
	}
	st.Store = reviewDropSuccessfulHook{Store: st.Store}
	fetch.unavailable.Store(false)
	s.Now = func() time.Time { return time.Now().Add(time.Hour) }
	if ran, err := s.RunOnce(t.Context()); !ran || err != nil {
		t.Fatalf("retry did not run: ran=%v err=%v", ran, err)
	}
	job, err := st.GetGitJob(t.Context(), h.Job)
	if err != nil || job.Status != model.GitJobDone || job.Outcome != model.GitSyncDone {
		t.Fatalf("fixture: job did not finish successfully: job=%+v err=%v", job, err)
	}
	g, err := s.Status(t.Context(), plan.Scope{Tenant: "acme"}, "config")
	if err != nil {
		t.Fatal(err)
	}
	if g.Hook == nil || g.Hook.Outcome != model.GitSyncDone || g.Hook.Error != "" {
		t.Fatalf("status kept an earlier attempt's error despite the terminal job: hook=%+v job_status=%s job_outcome=%s", g.Hook, job.Status, job.Outcome)
	}
}

type reviewPendingHookBarrier struct {
	store.Store
	entered chan struct{}
	release chan struct{}
	armed   atomic.Bool
}

func (s *reviewPendingHookBarrier) RecordGitHookIf(ctx context.Context, tenant, name string, hook model.GitHook, job string) (bool, error) {
	if hook.Outcome == model.GitSyncError && s.armed.Swap(false) {
		close(s.entered)
		select {
		case <-s.release:
		case <-ctx.Done():
			return false, ctx.Err()
		}
	}
	return s.Store.RecordGitHookIf(ctx, tenant, name, hook, job)
}

// Scheduling a retry releases the job before the old attempt writes its hook.
// The same job ID must not let that old write overwrite the next attempt's result.
func TestReviewOlderAttemptCannotOverwriteSuccessfulRetry(t *testing.T) {
	fetch := &reviewUnavailableResolve{Fetcher: memFetcher{head: sha1, files: map[string]map[string][]byte{sha1: {"bundles/env.yaml": reviewEnvironment("ready")}}}}
	fetch.unavailable.Store(true)
	one, st, _ := reviewHookService(t, fetch, reviewHookURL)
	one.Inline, one.Replica = false, "review-first"
	barrier := &reviewPendingHookBarrier{Store: st.Store, entered: make(chan struct{}), release: make(chan struct{})}
	st.Store = barrier
	barrier.armed.Store(true)
	h := reviewDelivery(t, one, "push", "same-job-retry", reviewPush(reviewHookURL, sha1, "refs/heads/main"))
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(barrier.release) }) }
	firstFinished := make(chan struct{})
	go func() {
		defer close(firstFinished)
		_, _ = one.RunOnce(t.Context())
	}()
	defer func() { unblock(); <-firstFinished }()
	select {
	case <-barrier.entered:
	case <-firstFinished:
		// Atomic job-and-hook finalization need not make a separate summary write.
	case <-time.After(5 * time.Second):
		t.Fatal("first attempt did not reach its summary write")
	}
	fetch.unavailable.Store(false)
	two := *one
	two.Replica = "review-second"
	two.Now = func() time.Time { return time.Now().Add(time.Hour) }
	if ran, err := two.RunOnce(t.Context()); err != nil || !ran {
		t.Fatalf("next attempt did not run: ran=%v err=%v", ran, err)
	}
	job, err := st.GetGitJob(t.Context(), h.Job)
	if err != nil || job.Status != model.GitJobDone || job.Outcome != model.GitSyncDone {
		t.Fatalf("fixture: retry did not complete: job=%+v err=%v", job, err)
	}
	unblock()
	<-firstFinished
	g, err := st.GetGitSync(t.Context(), "acme", "config")
	if err != nil {
		t.Fatal(err)
	}
	if g.Hook == nil || g.Hook.Outcome != model.GitSyncDone || g.Hook.Error != "" {
		t.Fatalf("earlier attempt overwrote the successful retry of the same job: hook=%+v attempts=%d job_status=%s", g.Hook, job.Attempts, job.Status)
	}
}
