package gitsync

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"agent-sandbox/internal/model"
	"agent-sandbox/internal/plan"
	"agent-sandbox/internal/secrets"
	"agent-sandbox/internal/store"
)

const repoURL = "https://git.example.com/acme/config.git"

// hookService is a service with a registered repository that takes webhooks, runs the
// accepted job in the request (Inline) and reports to a fake.
func hookService(t *testing.T, fetch Fetcher) (*Service, *breaking, *fakeReporter) {
	t.Helper()
	s, st := newService(t, fetch)
	s.Secrets = secrets.Static{"acme/repo-token": "tok", "acme/hook-secret": "s3cret"}
	s.Repos.Secrets = s.Secrets
	rep := &fakeReporter{}
	s.Reporter, s.Inline = rep, true
	register(t, s, "acme", "config", "kind: GitRepository\nname: config\nspec: {url: "+repoURL+", ref: main, paths: ['bundles/*.yaml'], credential: repo-token, webhook_secret: hook-secret}\n")
	return s, st, rep
}

func pushBody(sha string) []byte {
	return []byte(`{"ref":"refs/heads/main","after":"` + sha + `","repository":{"clone_url":"` + repoURL + `"}}`)
}

func prBody(number int, sha string) []byte {
	return []byte(fmt.Sprintf(`{"action":"synchronize","number":%d,"pull_request":{"number":%d,"head":{"sha":"%s"}},"repository":{"clone_url":"%s"}}`, number, number, sha, repoURL))
}

func deliver(t *testing.T, s *Service, event string, body []byte) *model.GitHook {
	t.Helper()
	h, err := s.Hook(context.Background(), "acme", "config", githubHeaders(event, "s3cret", body), body)
	if err != nil {
		t.Fatalf("%s: %v", event, err)
	}
	return h
}

func envYAML(description string) string {
	return "kind: EnvironmentProfile\nname: py\ndescription: " + description + "\nspec: {image: stable}\n"
}

// A force push back to a commit synced before (A → B → A) is a transition of its own: the
// catalogue goes back to A with a new revision, never a done apply of the first time returned
// with the catalogue left at B. The same commit again within a transition still writes nothing.
func TestAReturnToACommitSyncedBeforeIsAppliedAgain(t *testing.T) {
	ctx := context.Background()
	fetch := &refFetcher{auth: "tok", heads: map[string]string{"main": sha1}, files: map[string]map[string][]byte{
		sha1: {"bundles/a.yaml": []byte(envYAML("first"))}, sha2: {"bundles/a.yaml": []byte(envYAML("second"))}}}
	s, st, _ := hookService(t, fetch)
	want := func(step, sha, description string, revision, generation int) {
		t.Helper()
		it, err := st.GetItem(ctx, model.KindEnvironment, "acme", "py", 0)
		if err != nil || it.Description != description || it.Revision != revision || it.Source == nil || it.Source.Commit != sha {
			t.Fatalf("%s: %v %+v (source %+v)", step, err, it, it.Source)
		}
		g, _ := s.Status(ctx, plan.Scope{Tenant: "acme"}, "config")
		if g.Sync == nil || g.Sync.Commit != sha || g.Sync.Status != model.GitSyncDone || g.Sync.Generation != generation {
			t.Fatalf("%s: record %+v", step, g.Sync)
		}
	}
	if h := deliver(t, s, "push", pushBody(sha1)); h.Outcome != model.GitSyncDone {
		t.Fatalf("A: %+v", h)
	}
	want("A", sha1, "first", 1, 0)
	fetch.heads["main"] = sha2
	if h := deliver(t, s, "push", pushBody(sha2)); h.Outcome != model.GitSyncDone {
		t.Fatalf("B: %+v", h)
	}
	want("B", sha2, "second", 2, 1)
	fetch.heads["main"] = sha1 // the force push back
	if h := deliver(t, s, "push", pushBody(sha1)); h.Outcome != model.GitSyncDone {
		t.Fatalf("A again: %+v", h)
	}
	want("A again", sha1, "first", 3, 2)
	first, err := st.GetApplyByKey(ctx, "acme", Key("config", sha1, "bundles/a.yaml", 0))
	back, err2 := st.GetApplyByKey(ctx, "acme", Key("config", sha1, "bundles/a.yaml", 2))
	if err != nil || err2 != nil || first.ID == back.ID || back.Steps[0].Revision != 3 {
		t.Fatalf("the return is an apply of its own: %v %v %+v %+v", err, err2, first, back)
	}
	// The same commit once more (a redelivered push, a manual sync): nothing new.
	if h := deliver(t, s, "push", pushBody(sha1)); h.Outcome != model.GitSyncDone {
		t.Fatalf("A a third time: %+v", h)
	}
	if g, err := s.Sync(ctx, plan.Scope{Tenant: "acme", Subject: "alice"}, "config", sha1); err != nil || g.Sync.Generation != 2 || g.Sync.Bundles[0].Apply != back.ID {
		t.Fatalf("a manual sync of the same commit: %v %+v", err, g.Sync)
	}
	want("A repeated", sha1, "first", 3, 2)
	if n := revs(t, st, model.KindEnvironment, "acme", "py"); n != 3 {
		t.Fatalf("revisions: %d", n)
	}
}

// A pull request preview and a sync follow one contract: files in path order, each over what
// the files before it introduce (not after), and an item in one file only. What the preview
// calls valid, the sync applies; what it refuses, the sync refuses before writing anything.
func TestPreviewAndSyncAgreeOnFileOrderAndDuplicates(t *testing.T) {
	ctx := context.Background()
	env := "kind: EnvironmentProfile\nname: py\nspec: {image: stable}\n"
	agent := "kind: AgentDefinition\nname: backend\nspec: {policy: backend-dev, environment: py}\n"
	for name, tc := range map[string]struct {
		files   map[string][]byte
		outcome string
		written int // environment revisions after the sync
		comment string
	}{
		"dependency_in_earlier_file": {map[string][]byte{"bundles/00-env.yaml": []byte(env), "bundles/10-agent.yaml": []byte(agent)}, model.GitSyncDone, 1, "`bundles/10-agent.yaml`"},
		"dependency_in_later_file":   {map[string][]byte{"bundles/00-agent.yaml": []byte(agent), "bundles/10-env.yaml": []byte(env)}, model.GitSyncInvalid, 0, "not planned: a sync stops"},
		"duplicate_between_files":    {map[string][]byte{"bundles/00-env.yaml": []byte(env), "bundles/10-env.yaml": []byte(envYAML("again"))}, model.GitSyncInvalid, 0, "both describe EnvironmentProfile acme/py"},
	} {
		t.Run(name, func(t *testing.T) {
			fetch := &refFetcher{auth: "tok", heads: map[string]string{"main": sha2, "refs/pull/7/head": sha2}, files: map[string]map[string][]byte{sha2: tc.files}}
			s, st, rep := hookService(t, fetch)
			h := deliver(t, s, "pull_request", prBody(7, sha2))
			if h.Outcome != tc.outcome {
				t.Fatalf("preview: %+v", h)
			}
			if c := rep.comments["github acme/config #7"]; len(c) != 1 || !strings.Contains(c[0], tc.comment) {
				t.Fatalf("comment: %q", c)
			}
			if n := revs(t, st, model.KindEnvironment, "acme", "py"); n != 0 {
				t.Fatal("a preview wrote")
			}
			g, err := s.Sync(ctx, plan.Scope{Tenant: "acme", Subject: "alice"}, "config", sha2)
			if g == nil || g.Sync == nil || g.Sync.Status != tc.outcome {
				t.Fatalf("sync disagrees with the preview: %v %+v", err, g)
			}
			if n := revs(t, st, model.KindEnvironment, "acme", "py"); n != tc.written {
				t.Fatalf("environment revisions after the sync: %d", n)
			}
			if tc.outcome == model.GitSyncInvalid && (errors.Is(err, ErrInvalid) == false || revs(t, st, model.KindAgent, "acme", "backend") != 0) {
				t.Fatalf("an invalid sync wrote, or did not say so: %v", err)
			}
		})
	}
}

// Two jobs for one pull request (two pushes to it) may run on two replicas in any order: the
// plan of a head the request has moved past is never published over the plan of the current
// head, and each preview runs under the tenant's lock like a sync.
func TestAnOlderPullRequestPlanNeverLandsOverANewerOne(t *testing.T) {
	for _, order := range []string{"older_first", "newer_first"} {
		t.Run(order, func(t *testing.T) {
			ctx := context.Background()
			fetch := &refFetcher{auth: "tok", heads: map[string]string{"refs/pull/7/head": sha2}, files: map[string]map[string][]byte{
				sha1: {"bundles/a.yaml": []byte(envYAML("older"))}, sha2: {"bundles/a.yaml": []byte(envYAML("newer"))}}}
			s, st, rep := hookService(t, fetch)
			s.Inline = false
			var locks atomic.Int32
			s.Lock = func(ctx context.Context, tenant string, fn func(ctx context.Context) error) error {
				locks.Add(1)
				return st.WithTenantLock(ctx, tenant, fn)
			}
			heads := []string{sha1, sha2}
			if order == "newer_first" {
				heads = []string{sha2, sha1}
			}
			var jobs []string
			for _, sha := range heads {
				jobs = append(jobs, deliver(t, s, "pull_request", prBody(7, sha)).Job)
			}
			two := *s
			two.Replica = "two"
			for i, r := range []*Service{s, &two} { // jobs run oldest first: one on each replica
				if ran, err := r.RunOnce(ctx); err != nil || !ran {
					t.Fatalf("job %d: %v %v", i, ran, err)
				}
			}
			key := "github acme/config #7"
			if c := rep.comments[key]; len(c) != 1 || !strings.Contains(c[0], "newer") || strings.Contains(c[0], "older") {
				t.Fatalf("%s: the comment must be the current head's plan, once: %q", order, c)
			}
			if st := rep.statuses[key]; len(st) != 1 {
				t.Fatalf("statuses: %q", st)
			}
			for _, id := range jobs {
				j, _ := st.GetGitJob(ctx, id)
				if j.Status != model.GitJobDone {
					t.Fatalf("job %s: %+v", id, j)
				}
				if j.Outcome == model.HookSuperseded && !strings.Contains(string(j.Payload), sha1) {
					t.Fatalf("the superseded job must be the older head's: %+v", j)
				}
			}
			if locks.Load() != 2 {
				t.Fatalf("previews under the tenant lock: %d of 2", locks.Load())
			}
			// The record follows the delivery accepted last, with its outcome: the newer head's
			// plan when it came last, else the older delivery's "superseded" with the reason.
			g, _ := s.Status(ctx, plan.Scope{Tenant: "acme"}, "config")
			last, wantOutcome := heads[1], model.GitSyncDone
			if last == sha1 {
				wantOutcome = model.HookSuperseded
			}
			if g.Hook == nil || g.Hook.Commit != last || g.Hook.Outcome != wantOutcome || (wantOutcome == model.HookSuperseded && !strings.Contains(g.Hook.Reason, "head is now "+sha2)) {
				t.Fatalf("%s: the record must show the delivery accepted last: %+v", order, g.Hook)
			}
		})
	}
}

// A redelivery of a delivery whose job ran reports how it went and leaves the record as it is:
// an acceptance never replaces an outcome, and an older job's never a newer job's summary.
func TestARedeliveryOfAFinishedJobReportsItsOutcomeAndKeepsTheRecord(t *testing.T) {
	ctx := context.Background()
	fetch := &refFetcher{auth: "tok", heads: map[string]string{"main": sha1, "refs/pull/7/head": sha2}, files: map[string]map[string][]byte{
		sha1: {"bundles/a.yaml": []byte(envYAML("main"))}, sha2: {"bundles/a.yaml": []byte(envYAML("pr"))}}}
	s, st, rep := hookService(t, fetch)
	body := prBody(7, sha2)
	hdr := githubHeaders("pull_request", "s3cret", body)
	first, err := s.Hook(ctx, "acme", "config", hdr, body)
	if err != nil || first.Outcome != model.GitSyncDone {
		t.Fatalf("first: %v %+v", err, first)
	}
	key := "github acme/config #7"
	for _, inst := range []*Service{s, {Store: st, Repos: s.Repos, Secrets: s.Secrets, Fetch: fetch, Reporter: rep, Applier: s.Applier, Inline: true}} {
		again, err := inst.Hook(ctx, "acme", "config", hdr, body)
		if err != nil || again.Job != first.Job || again.Outcome != model.GitSyncDone || !strings.Contains(again.Reason, "already ran") {
			t.Fatalf("redelivery: %v %+v", err, again)
		}
		g, _ := s.Status(ctx, plan.Scope{Tenant: "acme"}, "config")
		if g.Hook.Job != first.Job || g.Hook.Outcome != model.GitSyncDone || g.Hook.Reason != "" {
			t.Fatalf("the record after a redelivery: %+v", g.Hook)
		}
		if len(rep.comments[key]) != 1 || len(rep.statuses[key]) != 1 {
			t.Fatalf("a redelivery published again: %d comments, %d statuses", len(rep.comments[key]), len(rep.statuses[key]))
		}
	}
	// A newer delivery (a push) is handled; the old pull request's redelivery leaves its summary.
	push := deliver(t, s, "push", pushBody(sha1))
	if push.Outcome != model.GitSyncDone {
		t.Fatalf("push: %+v", push)
	}
	if again, err := s.Hook(ctx, "acme", "config", hdr, body); err != nil || again.Outcome != model.GitSyncDone {
		t.Fatalf("redelivery after a newer job: %v %+v", err, again)
	}
	if g, _ := s.Status(ctx, plan.Scope{Tenant: "acme"}, "config"); g.Hook.Job != push.Job || g.Hook.Action != model.HookActionSync {
		t.Fatalf("an older job's redelivery replaced the newer job's summary: %+v", g.Hook)
	}
	// A job that ended but whose outcome never reached the record (the replica died in
	// between) still shows it: the status completes the hook from the job.
	if err := st.RecordGitHook(ctx, "acme", "config", model.GitHook{Provider: "github", Event: "push", Action: model.HookActionSync, Job: push.Job, At: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if g, _ := s.Status(ctx, plan.Scope{Tenant: "acme"}, "config"); g.Hook.Outcome != model.GitSyncDone {
		t.Fatalf("the outcome of a finished job must show: %+v", g.Hook)
	}
}

// flakyFetcher fails Resolve a given number of times, then serves.
type flakyFetcher struct {
	*refFetcher
	fails atomic.Int32
	calls atomic.Int32
}

func (f *flakyFetcher) Resolve(ctx context.Context, r Remote) (string, error) {
	f.calls.Add(1)
	if f.fails.Load() > 0 {
		f.fails.Add(-1)
		return "", errors.New("connection reset by peer")
	}
	return f.refFetcher.Resolve(ctx, r)
}

// An error (the repository unreachable) is not the end of a delivery: the job runs again
// after a wait that doubles, up to MaxAttempts, then gives up; a redelivery of a delivery
// whose job gave up queues it anew. An invalid bundle is an outcome, not an error: no retry.
func TestATemporaryErrorIsRetriedAndARedeliveryRequeuesAFailedJob(t *testing.T) {
	ctx := context.Background()
	base := &refFetcher{auth: "tok", heads: map[string]string{"main": sha1}, files: map[string]map[string][]byte{sha1: {"bundles/a.yaml": []byte(envYAML("x"))}}}
	fetch := &flakyFetcher{refFetcher: base}
	s, st, _ := hookService(t, fetch)
	now := time.Now()
	s.Now = func() time.Time { return now }
	fetch.fails.Store(1)
	h := deliver(t, s, "push", pushBody(sha1))
	if h.Outcome != model.GitSyncError || !strings.Contains(h.Reason, "attempt 1 of 5") || !strings.Contains(h.Error, "connection reset") {
		t.Fatalf("first attempt: %+v", h)
	}
	job, _ := st.GetGitJob(ctx, h.Job)
	if job.Status != model.GitJobPending || job.Attempts != 1 || job.LeaseUntil == nil || !job.LeaseUntil.Equal(now.Add(30*time.Second)) {
		t.Fatalf("job after a temporary error: %+v", job)
	}
	if ran, _ := s.RunOnce(ctx); ran {
		t.Fatal("a retry ran before its time")
	}
	now = now.Add(31 * time.Second)
	if ran, err := s.RunOnce(ctx); err != nil || !ran {
		t.Fatalf("the retry: %v %v", ran, err)
	}
	job, _ = st.GetGitJob(ctx, h.Job)
	if job.Status != model.GitJobDone || job.Outcome != model.GitSyncDone || job.Attempts != 2 {
		t.Fatalf("job after the retry: %+v", job)
	}
	if g, _ := s.Status(ctx, plan.Scope{Tenant: "acme"}, "config"); g.Hook.Outcome != model.GitSyncDone || g.Hook.Job != h.Job || revs(t, st, model.KindEnvironment, "acme", "py") != 1 {
		t.Fatalf("after the retry: %+v", g.Hook)
	}
	// An outage longer than the attempts: the job gives up (waits of 30s, 1m, 2m, 4m), and
	// the redelivery, once the repository is back, runs it again.
	base.heads["main"] = sha2
	base.files[sha2] = map[string][]byte{"bundles/a.yaml": []byte(envYAML("y"))}
	fetch.fails.Store(100)
	calls := fetch.calls.Load()
	body := pushBody(sha2)
	hdr := githubHeaders("push", "s3cret", body)
	h2, err := s.Hook(ctx, "acme", "config", hdr, body)
	if err != nil || h2.Outcome != model.GitSyncError {
		t.Fatalf("outage: %v %+v", err, h2)
	}
	for i := 0; i < 20; i++ {
		now = now.Add(5 * time.Minute)
		if ran, _ := s.RunOnce(ctx); !ran {
			break
		}
	}
	job, _ = st.GetGitJob(ctx, h2.Job)
	if job.Status != model.GitJobFailed || job.Attempts != MaxAttempts || !strings.Contains(job.Error, "gave up after 5 attempts") || fetch.calls.Load()-calls != MaxAttempts {
		t.Fatalf("job after the outage: %+v (%d resolves)", job, fetch.calls.Load()-calls)
	}
	if g, _ := s.Status(ctx, plan.Scope{Tenant: "acme"}, "config"); g.Hook.Outcome != model.GitSyncError || !strings.Contains(g.Hook.Error, "gave up") {
		t.Fatalf("record after giving up: %+v", g.Hook)
	}
	fetch.fails.Store(0)
	s.Inline = false
	again, err := s.Hook(ctx, "acme", "config", hdr, body)
	if err != nil || again.Job != h2.Job || again.Outcome != "" || !strings.Contains(again.Reason, "runs again") {
		t.Fatalf("redelivery after the outage: %v %+v", err, again)
	}
	if job, _ = st.GetGitJob(ctx, h2.Job); job.Status != model.GitJobPending || job.Attempts != 0 {
		t.Fatalf("the requeued job: %+v", job)
	}
	if ran, err := s.RunOnce(ctx); err != nil || !ran {
		t.Fatalf("the requeued job runs: %v %v", ran, err)
	}
	s.Inline = true
	job, _ = st.GetGitJob(ctx, h2.Job)
	if job.Status != model.GitJobDone || job.Attempts != 1 || revs(t, st, model.KindEnvironment, "acme", "py") != 2 {
		t.Fatalf("job after the redelivery: %+v", job)
	}
	if g, _ := s.Status(ctx, plan.Scope{Tenant: "acme"}, "config"); g.Hook.Job != h2.Job || g.Hook.Outcome != model.GitSyncDone {
		t.Fatalf("record after the redelivery ran: %+v", g.Hook)
	}
	// An invalid bundle: done with that outcome on the first attempt, no retry.
	base.heads["main"] = "3333333333333333333333333333333333333333"
	base.files["3333333333333333333333333333333333333333"] = map[string][]byte{"bundles/a.yaml": []byte("kind: PolicyBinding\nname: backend-dev\nspec: {}\n")}
	h3 := deliver(t, s, "push", pushBody("3333333333333333333333333333333333333333"))
	if job, _ := st.GetGitJob(ctx, h3.Job); h3.Outcome != model.GitSyncInvalid || job.Status != model.GitJobDone || job.Attempts != 1 {
		t.Fatalf("an invalid bundle: %+v %+v", h3, job)
	}
}

// stuckFetcher blocks Resolve until the context ends: a job that never finishes within its lease.
type stuckFetcher struct {
	*refFetcher
	calls atomic.Int32
}

func (f *stuckFetcher) Resolve(ctx context.Context, r Remote) (string, error) {
	f.calls.Add(1)
	<-ctx.Done()
	return "", ctx.Err()
}

// ctxStore refuses writes under a context that ended, as PostgreSQL does, and can be "down".
type ctxStore struct {
	store.Store
	down atomic.Bool
}

func (w *ctxStore) FinishGitJob(ctx context.Context, id, owner string, attempt int, status, outcome, errMsg string) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if w.down.Load() {
		return errors.New("the database is down")
	}
	return w.Store.FinishGitJob(ctx, id, owner, attempt, status, outcome, errMsg)
}

func (w *ctxStore) RetryGitJob(ctx context.Context, id, owner string, attempt int, notBefore time.Time, errMsg string) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return w.Store.RetryGitJob(ctx, id, owner, attempt, notBefore, errMsg)
}

func (w *ctxStore) RecordGitHook(ctx context.Context, tenant, name string, h model.GitHook) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return w.Store.RecordGitHook(ctx, tenant, name, h)
}

// A job that runs out of its lease every time ends after MaxAttempts: the last attempt records
// the failure although the work's context has ended, and a job whose last attempt could not
// even record that (the database was down) is ended by the next claim without running again.
func TestAttemptsAreBoundedWhenTheLeaseRunsOut(t *testing.T) {
	ctx := context.Background()
	fetch := &stuckFetcher{refFetcher: &refFetcher{auth: "tok", heads: map[string]string{"main": sha1}, files: map[string]map[string][]byte{sha1: {"bundles/a.yaml": []byte(envYAML("x"))}}}}
	s, st, _ := hookService(t, fetch)
	w := &ctxStore{Store: st}
	s.Store, s.Jobs, s.Lock, s.Inline, s.Lease = w, w, w.WithTenantLock, false, 20*time.Millisecond
	h := deliver(t, s, "push", pushBody(sha1))
	runs := 0
	for ; runs < 10; runs++ {
		if ran, _ := s.RunOnce(ctx); !ran {
			break
		}
	}
	job, _ := st.GetGitJob(ctx, h.Job)
	if runs != MaxAttempts || job.Status != model.GitJobFailed || job.Attempts != MaxAttempts || !strings.Contains(job.Error, "did not finish within its lease") || fetch.calls.Load() != MaxAttempts {
		t.Fatalf("after the lease ran out %d times: %+v (%d resolves)", runs, job, fetch.calls.Load())
	}
	if g, _ := s.Status(ctx, plan.Scope{Tenant: "acme"}, "config"); g.Hook.Outcome != model.GitSyncError || g.Hook.Job != h.Job {
		t.Fatalf("record: %+v", g.Hook)
	}
	// The database refuses the last attempt's finish: the job is left running with a lapsed
	// lease; the next claim (a sixth) ends it without running the work again.
	fetch.calls.Store(0)
	h2 := deliver(t, s, "push", pushBody(sha1))
	w.down.Store(true)
	for i := 0; i < MaxAttempts; i++ {
		if ran, _ := s.RunOnce(ctx); !ran {
			t.Fatalf("attempt %d did not run", i+1)
		}
	}
	job, _ = st.GetGitJob(ctx, h2.Job)
	if job.Status != model.GitJobRunning || job.Attempts != MaxAttempts {
		t.Fatalf("with the database down the last attempt cannot end the job: %+v", job)
	}
	w.down.Store(false)
	if ran, _ := s.RunOnce(ctx); !ran {
		t.Fatal("the lapsed job was not claimed to be ended")
	}
	job, _ = st.GetGitJob(ctx, h2.Job)
	if job.Status != model.GitJobFailed || job.Attempts != MaxAttempts+1 || !strings.Contains(job.Error, "gave up after 5 attempts") || fetch.calls.Load() != MaxAttempts {
		t.Fatalf("the exhausted job: %+v (%d resolves)", job, fetch.calls.Load())
	}
	if ran, _ := s.RunOnce(ctx); ran {
		t.Fatal("an ended job was claimed again")
	}
}

// lossyStore loses the sync summary written after the bundles were applied (a store that went
// away for that one write), never the transition recorded before them.
type lossyStore struct {
	store.Store
	lose atomic.Bool
}

func (w *lossyStore) RecordGitSync(ctx context.Context, tenant, name string, r model.GitSyncResult) error {
	if w.lose.Load() && r.Status != model.GitSyncRunning {
		return errors.New("the database went away")
	}
	return w.Store.RecordGitSync(ctx, tenant, name, r)
}

// The transition (commit and generation) is fixed before the first write, so a sync whose
// summary is lost after it wrote the catalogue is still the last transition: syncing the same
// commit again continues it (nothing written twice), and a return to the commit before it is a
// transition of its own, never the first time's done apply returned with the catalogue elsewhere.
func TestTheTransitionSurvivesALostSyncSummary(t *testing.T) {
	ctx := context.Background()
	fetch := &refFetcher{auth: "tok", heads: map[string]string{"main": sha1}, files: map[string]map[string][]byte{
		sha1: {"bundles/a.yaml": []byte(envYAML("first"))}, sha2: {"bundles/a.yaml": []byte(envYAML("second"))}}}
	s, st, _ := hookService(t, fetch)
	w := &lossyStore{Store: st}
	s.Store = w
	scope := plan.Scope{Tenant: "acme", Subject: "alice"}
	if g, err := s.Sync(ctx, scope, "config", sha1); err != nil || g.Sync.Generation != 0 {
		t.Fatalf("A: %v %+v", err, g)
	}
	fetch.heads["main"] = sha2
	w.lose.Store(true)
	if g, err := s.Sync(ctx, scope, "config", sha2); err == nil || g != nil {
		t.Fatalf("B with its summary lost must say so: %v %+v", err, g)
	}
	w.lose.Store(false)
	if it, _ := st.GetItem(ctx, model.KindEnvironment, "acme", "py", 0); it.Description != "second" || it.Revision != 2 {
		t.Fatalf("B was applied before the summary was lost: %+v", it)
	}
	if g, _ := s.Status(ctx, scope, "config"); g.Sync == nil || g.Sync.Status != model.GitSyncRunning || g.Sync.Commit != sha2 || g.Sync.Generation != 1 {
		t.Fatalf("the transition to B must be on record: %+v", g.Sync)
	}
	// The same commit again: the transition continues, nothing is written twice.
	if g, err := s.Sync(ctx, scope, "config", sha2); err != nil || g.Sync.Status != model.GitSyncDone || g.Sync.Generation != 1 || g.Sync.Bundles[0].Changes != 1 {
		t.Fatalf("B again: %v %+v", err, g.Sync)
	}
	if n := revs(t, st, model.KindEnvironment, "acme", "py"); n != 2 {
		t.Fatalf("a repeat of the transition wrote: %d revisions", n)
	}
	// Back to A: a transition of its own, generation 2, A written again.
	w.lose.Store(true)
	_, _ = s.Sync(ctx, scope, "config", sha2) // the summary lost once more: still the transition to B
	w.lose.Store(false)
	fetch.heads["main"] = sha1
	g, err := s.Sync(ctx, scope, "config", sha1)
	if err != nil || g.Sync.Status != model.GitSyncDone || g.Sync.Generation != 2 {
		t.Fatalf("A after B: %v %+v", err, g.Sync)
	}
	if it, _ := st.GetItem(ctx, model.KindEnvironment, "acme", "py", 0); it.Description != "first" || it.Revision != 3 || it.Source.Commit != sha1 {
		t.Fatalf("the return to A: %+v", it)
	}
}

// deadlineStore records how much of the finishing context is left when a job is finished.
type deadlineStore struct {
	store.Store
	mu   sync.Mutex
	left []time.Duration
}

func (w *deadlineStore) FinishGitJob(ctx context.Context, id, owner string, attempt int, status, outcome, errMsg string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if d, ok := ctx.Deadline(); ok {
		w.mu.Lock()
		w.left = append(w.left, time.Until(d))
		w.mu.Unlock()
	}
	return w.Store.FinishGitJob(ctx, id, owner, attempt, status, outcome, errMsg)
}

// pausingFetcher takes its time: a Git read longer than the finishing window would allow.
type pausingFetcher struct {
	*refFetcher
	pause time.Duration
}

func (f *pausingFetcher) Resolve(ctx context.Context, r Remote) (string, error) {
	time.Sleep(f.pause)
	return f.refFetcher.Resolve(ctx, r)
}

// The context that ends a job is made once the work is over, not when it started: a job whose
// work took longer than the finishing window still records its outcome with the whole window
// ahead of it.
func TestTheFinishingContextStartsWhenTheWorkIsOver(t *testing.T) {
	ctx := context.Background()
	fetch := &pausingFetcher{refFetcher: &refFetcher{auth: "tok", heads: map[string]string{"main": sha1}, files: map[string]map[string][]byte{sha1: {"bundles/a.yaml": []byte(envYAML("x"))}}}, pause: 600 * time.Millisecond}
	s, st, _ := hookService(t, fetch)
	w := &deadlineStore{Store: st}
	s.Store, s.Jobs, s.Lock, s.Inline = w, w, w.WithTenantLock, false
	h := deliver(t, s, "push", pushBody(sha1))
	if ran, err := s.RunOnce(ctx); err != nil || !ran {
		t.Fatalf("run: %v %v", ran, err)
	}
	job, _ := st.GetGitJob(ctx, h.Job)
	if job.Status != model.GitJobDone || job.Outcome != model.GitSyncDone {
		t.Fatalf("a slow job must still end: %+v", job)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.left) != 1 || w.left[0] < finishTimeout-300*time.Millisecond {
		t.Fatalf("the finishing window had already been running during the work: %v of %v left", w.left, finishTimeout)
	}
}

// A stopped apply (the store went away mid-way) is unfinished work, not an outcome: the job
// runs again and continues the same apply; a redelivery of a job that gave up on it requeues it.
func TestAStoppedApplyIsRetriedAndContinued(t *testing.T) {
	ctx := context.Background()
	fetch := &refFetcher{auth: "tok", heads: map[string]string{"main": sha1}, files: map[string]map[string][]byte{sha1: {"bundles/a.yaml": []byte(envYAML("x"))}}}
	s, st, _ := hookService(t, fetch)
	now := time.Now()
	s.Now = func() time.Time { return now }
	st.arm("py")
	h := deliver(t, s, "push", pushBody(sha1))
	if h.Outcome != model.GitSyncStopped || !strings.Contains(h.Reason, "attempt 1 of 5 ended with stopped") {
		t.Fatalf("a stopped apply: %+v", h)
	}
	job, _ := st.GetGitJob(ctx, h.Job)
	if job.Status != model.GitJobPending || job.Attempts != 1 {
		t.Fatalf("job after a stopped apply: %+v", job)
	}
	g, _ := s.Status(ctx, plan.Scope{Tenant: "acme"}, "config")
	stopped := g.Sync.Bundles[0].Apply
	st.arm("")
	now = now.Add(31 * time.Second)
	if ran, err := s.RunOnce(ctx); err != nil || !ran {
		t.Fatalf("the retry: %v %v", ran, err)
	}
	job, _ = st.GetGitJob(ctx, h.Job)
	g, _ = s.Status(ctx, plan.Scope{Tenant: "acme"}, "config")
	if job.Status != model.GitJobDone || job.Outcome != model.GitSyncDone || g.Hook.Outcome != model.GitSyncDone || g.Sync.Bundles[0].Apply != stopped || g.Sync.Status != model.GitSyncDone {
		t.Fatalf("the retry must continue the stopped apply: %+v %+v %+v", job, g.Hook, g.Sync)
	}
	if n := revs(t, st, model.KindEnvironment, "acme", "py"); n != 1 {
		t.Fatalf("revisions: %d", n)
	}
	// A store that stays away: the job gives up after five attempts, with the outcome on record.
	st.arm("py")
	fetch.heads["main"] = sha2
	fetch.files[sha2] = map[string][]byte{"bundles/a.yaml": []byte(envYAML("y"))}
	h2 := deliver(t, s, "push", pushBody(sha2))
	for i := 0; i < 20; i++ {
		now = now.Add(5 * time.Minute)
		if ran, _ := s.RunOnce(ctx); !ran {
			break
		}
	}
	job, _ = st.GetGitJob(ctx, h2.Job)
	if job.Status != model.GitJobFailed || job.Outcome != model.GitSyncStopped || job.Attempts != MaxAttempts || !strings.Contains(job.Error, "gave up after 5 attempts") {
		t.Fatalf("job after giving up: %+v", job)
	}
	if g, _ := s.Status(ctx, plan.Scope{Tenant: "acme"}, "config"); g.Hook.Outcome != model.GitSyncStopped || !strings.Contains(g.Hook.Error, "gave up") {
		t.Fatalf("record after giving up: %+v", g.Hook)
	}
}

// gatedStore holds a job's finish until released: the window between the work and the record.
type gatedStore struct {
	store.Store
	job     string
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (w *gatedStore) FinishGitJob(ctx context.Context, id, owner string, attempt int, status, outcome, errMsg string) error {
	if id == w.job {
		w.once.Do(func() { close(w.entered) })
		<-w.release
	}
	return w.Store.FinishGitJob(ctx, id, owner, attempt, status, outcome, errMsg)
}

// A delivery accepted while an older job is ending keeps the record: the job's outcome is
// written only while the record still carries that job, in one store operation.
func TestAFinishNeverWritesOverADeliveryAcceptedMeanwhile(t *testing.T) {
	ctx := context.Background()
	fetch := &refFetcher{auth: "tok", heads: map[string]string{"main": sha1}, files: map[string]map[string][]byte{
		sha1: {"bundles/a.yaml": []byte(envYAML("x"))}, sha2: {"bundles/a.yaml": []byte(envYAML("y"))}}}
	s, st, _ := hookService(t, fetch)
	s.Inline = false
	first := deliver(t, s, "push", pushBody(sha1))
	w := &gatedStore{Store: st, job: first.Job, entered: make(chan struct{}), release: make(chan struct{})}
	one := *s
	one.Store, one.Jobs, one.Lock = w, w, w.WithTenantLock
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		_, _ = one.RunOnce(ctx)
	}()
	select {
	case <-w.entered:
	case <-time.After(5 * time.Second):
		close(w.release)
		t.Fatal("the first job did not reach its finish")
	}
	// The ref moves and a new delivery is accepted while the first job is ending.
	fetch.heads["main"] = sha2
	second := deliver(t, s, "push", pushBody(sha2))
	close(w.release)
	<-finished
	g, _ := s.Status(ctx, plan.Scope{Tenant: "acme"}, "config")
	if g.Hook == nil || g.Hook.Job != second.Job || g.Hook.Outcome != "" {
		t.Fatalf("the record must keep the delivery accepted last: %+v", g.Hook)
	}
	if job, _ := st.GetGitJob(ctx, first.Job); job.Status != model.GitJobDone || job.Outcome != model.GitSyncDone {
		t.Fatalf("the first job still ends: %+v", job)
	}
	if ran, err := s.RunOnce(ctx); err != nil || !ran {
		t.Fatalf("the second job: %v %v", ran, err)
	}
	if g, _ := s.Status(ctx, plan.Scope{Tenant: "acme"}, "config"); g.Hook.Job != second.Job || g.Hook.Outcome != model.GitSyncDone || g.Hook.Commit != sha2 {
		t.Fatalf("the second job's outcome: %+v", g.Hook)
	}
}
