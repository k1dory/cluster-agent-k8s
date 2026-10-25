package gitsync

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"agent-sandbox/internal/model"
	"agent-sandbox/internal/plan"
	"agent-sandbox/internal/store"
)

type reviewLostSyncResult struct {
	store.Store
	reject string
}

func (s *reviewLostSyncResult) RecordGitSync(ctx context.Context, tenant, name string, result model.GitSyncResult) error {
	if result.Commit == s.reject {
		// Allow recording the transition before it mutates the catalogue: that is
		// a valid fix. Lose only the final result, after B has actually been written.
		it, err := s.Store.GetItem(ctx, model.KindEnvironment, tenant, "py", 0)
		if err == nil && it.Description == "second" {
			return errors.New("temporary failure saving the sync result")
		}
	}
	return s.Store.RecordGitSync(ctx, tenant, name, result)
}

// The desired-state generation must survive an unavailable final status write.
// Applying B changes the catalogue even when its result cannot be recorded.
func TestReviewGenerationSurvivesLostSyncResult(t *testing.T) {
	fetch := &refFetcher{heads: map[string]string{"main": sha1}, files: map[string]map[string][]byte{
		sha1: {"bundles/env.yaml": reviewEnvironment("first")},
		sha2: {"bundles/env.yaml": reviewEnvironment("second")},
	}}
	s, st, _ := reviewHookService(t, fetch, reviewHookURL)
	scope := plan.Scope{Tenant: "acme", Subject: "review"}
	if _, err := s.Sync(t.Context(), scope, "config", sha1); err != nil {
		t.Fatal(err)
	}
	fault := &reviewLostSyncResult{Store: st.Store, reject: sha2}
	st.Store = fault
	fetch.heads["main"] = sha2
	if _, err := s.Sync(t.Context(), scope, "config", sha2); err == nil {
		t.Fatal("expected failure recording B")
	}
	it, err := st.GetItem(t.Context(), model.KindEnvironment, "acme", "py", 0)
	if err != nil || it.Description != "second" {
		t.Fatalf("fixture: B must have been committed before its result was lost: item=%+v err=%v", it, err)
	}
	fault.reject = ""
	fetch.heads["main"] = sha1
	result, err := s.Sync(t.Context(), scope, "config", sha1)
	if err != nil || result.Sync.Status != model.GitSyncDone {
		t.Fatalf("return to A: result=%+v err=%v", result, err)
	}
	it, err = st.GetItem(t.Context(), model.KindEnvironment, "acme", "py", 0)
	if err != nil || it.Description != "first" || it.Revision != 3 || it.Source.Commit != sha1 {
		t.Fatalf("sync claims A is applied, but catalogue still holds B: item=%+v err=%v", it, err)
	}
}

// A failed ApplyStep is a recoverable execution error, not a completed delivery.
func TestReviewStoppedApplyIsRetriedAfterStoreRecovery(t *testing.T) {
	fetch := memFetcher{head: sha1, files: map[string]map[string][]byte{sha1: {"bundles/env.yaml": reviewEnvironment("first")}}}
	s, st, _ := reviewHookService(t, fetch, reviewHookURL)
	st.arm("py")
	h := reviewDelivery(t, s, "push", "apply-outage", reviewPush(reviewHookURL, sha1, "refs/heads/main"))
	if h.Outcome != model.GitSyncStopped {
		t.Fatalf("fixture should stop inside Apply: %+v", h)
	}
	st.arm("")
	s.Now = func() time.Time { return time.Now().Add(time.Hour) }
	_, _ = s.RunOnce(t.Context())
	if _, err := st.GetItem(t.Context(), model.KindEnvironment, "acme", "py", 0); err != nil {
		job, _ := st.GetGitJob(t.Context(), h.Job)
		t.Fatalf("store recovered but accepted work cannot resume: job_status=%s outcome=%s attempts=%d item=%v", job.Status, job.Outcome, job.Attempts, err)
	}
}

type reviewSummaryBarrier struct {
	store.Store
	armed   atomic.Bool
	entered chan struct{}
	release chan struct{}
}

func (s *reviewSummaryBarrier) GetGitSync(ctx context.Context, tenant, name string) (*model.GitSync, error) {
	g, err := s.Store.GetGitSync(ctx, tenant, name)
	if s.armed.Swap(false) {
		close(s.entered)
		select {
		case <-s.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return g, err
}

// A new delivery can be accepted between conclude's read and its summary write.
func TestReviewSummaryPreservesDeliveryAcceptedDuringFinish(t *testing.T) {
	fetch := memFetcher{head: sha1, files: map[string]map[string][]byte{sha1: {"bundles/env.yaml": reviewEnvironment("first")}}}
	s, st, _ := reviewHookService(t, fetch, reviewHookURL)
	s.Inline, s.Replica = false, "summary-review"
	old := reviewDelivery(t, s, "push", "older", reviewPush(reviewHookURL, sha1, "refs/heads/main"))
	job, err := st.ClaimGitJob(t.Context(), s.Replica, time.Now(), time.Minute)
	if err != nil || job.ID != old.Job {
		t.Fatalf("claim old delivery: %+v %v", job, err)
	}
	it, err := st.GetItem(t.Context(), model.KindGitRepository, "acme", "config", 0)
	if err != nil {
		t.Fatal(err)
	}
	barrier := &reviewSummaryBarrier{Store: st.Store, entered: make(chan struct{}), release: make(chan struct{})}
	st.Store = barrier
	barrier.armed.Store(true)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		done := *old
		done.Outcome = model.GitSyncDone
		s.conclude(t.Context(), it, job, &done, model.GitJobDone, time.Time{})
	}()
	select {
	case <-barrier.entered:
	case <-finished:
		// An atomic implementation may not read the summary separately.
	case <-time.After(5 * time.Second):
		close(barrier.release)
		<-finished
		t.Fatal("finishing the old job did not reach the barrier")
	}
	newer := reviewDelivery(t, s, "push", "newer", reviewPush(reviewHookURL, sha1, "refs/heads/main"))
	close(barrier.release)
	<-finished
	g, err := s.Status(t.Context(), plan.Scope{Tenant: "acme"}, "config")
	if err != nil || g.Hook == nil || g.Hook.Job != newer.Job {
		t.Fatalf("older finish overwrote the latest accepted delivery: hook=%+v latest_job=%s err=%v", g.Hook, newer.Job, err)
	}
}

type reviewSlowSuccessfulFetch struct{ Fetcher }

func (f reviewSlowSuccessfulFetch) Resolve(ctx context.Context, r Remote) (string, error) {
	select {
	case <-time.After(finishTimeout + 50*time.Millisecond):
		return f.Fetcher.Resolve(ctx, r)
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

// The finalization timeout must begin after the work, not 30 seconds before a
// legitimate long-running operation completes. No external endpoint is involved.
func TestReviewSuccessfulLongJobGetsFreshFinishContext(t *testing.T) {
	t.Parallel()
	fetch := reviewSlowSuccessfulFetch{Fetcher: memFetcher{head: sha1, files: map[string]map[string][]byte{sha1: {"bundles/env.yaml": reviewEnvironment("first")}}}}
	s, st, _ := reviewHookService(t, fetch, reviewHookURL)
	s.Inline, s.Lease = false, time.Minute
	s.Jobs = reviewContextAwareJobs{GitJobs: st}
	h := reviewDelivery(t, s, "push", "long-success", reviewPush(reviewHookURL, sha1, "refs/heads/main"))
	if ran, err := s.RunOnce(t.Context()); err != nil || !ran {
		t.Fatalf("run: %v %v", ran, err)
	}
	if _, err := st.GetItem(t.Context(), model.KindEnvironment, "acme", "py", 0); err != nil {
		t.Fatalf("fixture should apply successfully: %v", err)
	}
	job, err := st.GetGitJob(t.Context(), h.Job)
	if err != nil || job.Status != model.GitJobDone {
		t.Fatalf("successful work could not finalize: status=%s attempts=%d err=%v", job.Status, job.Attempts, err)
	}
}
