package gitsync

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"agent-sandbox/internal/model"
)

// overLimitFetcher refuses the file set the way CLI.Files does past MaxFiles / MaxTotal.
type overLimitFetcher struct{ *refFetcher }

func (overLimitFetcher) Files(context.Context, Remote, string, []string) (map[string][]byte, error) {
	return nil, fmt.Errorf("%w: %d files match the paths, more than a sync reads (%d)", ErrTooLarge, MaxFiles+1, MaxFiles)
}

// commentDown fails every comment, as a provider that is down does.
type commentDown struct{ *fakeReporter }

func (commentDown) UpsertComment(context.Context, Target, string) error {
	return errors.New("provider unavailable")
}

// A pull request whose files are over the bounds used to be planned as "the repository could
// not be read": an error status and five retries of a head that is as large every time. It is
// an invalid plan now (failure status, the job done after one attempt), as the sync of that
// commit is; a reporting failure is still retried.
func TestOversizedPullRequestIsAnInvalidPlanRound2(t *testing.T) {
	fetch := overLimitFetcher{&refFetcher{auth: "tok", heads: map[string]string{"main": sha2, "refs/pull/7/head": sha2}}}
	t.Run("plan", func(t *testing.T) {
		s, st, rep := hookService(t, fetch)
		h := deliver(t, s, "pull_request", prBody(7, sha2))
		if h.Outcome != model.GitSyncInvalid {
			t.Fatalf("outcome: %+v", h)
		}
		if c := rep.comments["github acme/config #7"]; len(c) != 1 || !strings.Contains(c[0], "too large") {
			t.Fatalf("comment: %q", c)
		}
		if st := rep.statuses["github acme/config #7"]; len(st) != 1 || !strings.HasPrefix(st[0], StatusFailure+":") {
			t.Fatalf("status: %q", st)
		}
		job, err := st.GetGitJob(t.Context(), h.Job)
		if err != nil || job.Status != model.GitJobDone || job.Attempts != 1 {
			t.Fatalf("job: %v %+v", err, job)
		}
	})
	t.Run("reporting_fails", func(t *testing.T) {
		s, st, _ := hookService(t, fetch)
		s.Reporter = commentDown{&fakeReporter{}}
		h := deliver(t, s, "pull_request", prBody(7, sha2))
		job, err := st.GetGitJob(t.Context(), h.Job)
		if err != nil || job.Status != model.GitJobPending {
			t.Fatalf("a plan that could not be reported is retried: %v %+v", err, job)
		}
	})
}
