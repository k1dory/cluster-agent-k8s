package gitsync

import (
	"sync"
	"testing"
	"time"

	"agent-sandbox/internal/model"
)

// Redelivery starts a fresh retry budget while the previous attempt may still be
// saving its summary. Reusing an attempt number must not give that old write
// authority over the new execution's result.
func TestReviewRedeliveryFencesPreviousExecutionSummary(t *testing.T) {
	fetch := &reviewUnavailableResolve{Fetcher: memFetcher{head: sha1, files: map[string]map[string][]byte{
		sha1: {"bundles/env.yaml": reviewEnvironment("ready")},
	}}}
	fetch.unavailable.Store(true)
	one, st, _ := reviewHookService(t, fetch, reviewHookURL)
	one.Inline, one.Replica, one.Retry = false, "review-redelivery-first", time.Minute
	barrier := &reviewPendingHookBarrier{Store: st.Store, entered: make(chan struct{}), release: make(chan struct{})}
	st.Store = barrier
	barrier.armed.Store(true)
	payload := reviewPush(reviewHookURL, sha1, "refs/heads/main")
	accepted := reviewDelivery(t, one, "push", "redelivered-summary", payload)
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
		// An atomic finalization can remove the separate summary write entirely.
	case <-time.After(5 * time.Second):
		t.Fatal("first execution did not finish or reach its summary write")
	}

	fetch.unavailable.Store(false)
	two := *one
	two.Replica = "review-redelivery-second"
	replayed := reviewDelivery(t, &two, "push", "redelivered-summary", payload)
	if replayed.Job != accepted.Job {
		t.Fatalf("redelivery must name the original job: first=%s repeated=%s", accepted.Job, replayed.Job)
	}
	if ran, err := two.RunOnce(t.Context()); err != nil || !ran {
		t.Fatalf("redelivered execution did not run: ran=%v err=%v", ran, err)
	}
	job, err := st.GetGitJob(t.Context(), accepted.Job)
	if err != nil || job.Status != model.GitJobDone || job.Outcome != model.GitSyncDone {
		t.Fatalf("fixture: redelivered job did not complete: job=%+v err=%v", job, err)
	}
	before, err := st.GetGitSync(t.Context(), "acme", "config")
	if err != nil || before.Hook == nil || before.Hook.Outcome != model.GitSyncDone {
		t.Fatalf("fixture: successful summary was not saved: record=%+v err=%v", before, err)
	}

	unblock()
	<-firstFinished
	after, err := st.GetGitSync(t.Context(), "acme", "config")
	if err != nil {
		t.Fatal(err)
	}
	if after.Hook == nil || after.Hook.Outcome != model.GitSyncDone || after.Hook.Error != "" {
		t.Fatalf("the previous execution overwrote the redelivery's success: hook=%+v job_status=%s job_attempts=%d", after.Hook, job.Status, job.Attempts)
	}
}
