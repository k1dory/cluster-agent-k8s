package gitsync

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"agent-sandbox/internal/model"
	"agent-sandbox/internal/plan"
	"agent-sandbox/internal/store"
)

const reviewRepoDocument = "kind: GitRepository\nname: config\nspec: {url: https://git.example.com/acme/config.git, ref: main, paths: ['bundles/*.yaml']}\n"

func reviewFetcher() memFetcher {
	return memFetcher{head: sha1, files: map[string]map[string][]byte{sha1: {
		"bundles/env.yaml": []byte("kind: EnvironmentProfile\nname: py\nspec: {image: stable}\n"),
	}}}
}

type reviewWaitingResolve struct {
	memFetcher
	started chan struct{}
	release chan struct{}
}

func (f *reviewWaitingResolve) Resolve(ctx context.Context, r Remote) (string, error) {
	close(f.started)
	select {
	case <-f.release:
		return f.memFetcher.Resolve(ctx, r)
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

// A slow check and a sync touch different parts of the same status record.
// Completing the check must preserve the sync that completed while Git was read.
func TestReviewGitCheckPreservesConcurrentSyncStatus(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	f := &reviewWaitingResolve{memFetcher: reviewFetcher(), started: make(chan struct{}), release: make(chan struct{})}
	var once sync.Once
	release := func() { once.Do(func() { close(f.release) }) }
	defer release()
	s, _ := newService(t, f)
	register(t, s, "acme", "config", reviewRepoDocument)
	scope := plan.Scope{Tenant: "acme", Subject: "review"}
	checked := make(chan error, 1)
	go func() {
		_, err := s.Check(ctx, scope, "config")
		checked <- err
	}()
	select {
	case <-f.started:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	// Explicit SHA avoids another Resolve: this sync completes before the check.
	g, err := s.Sync(ctx, scope, "config", sha1)
	if err != nil || g.Sync.Status != model.GitSyncDone || len(g.Sync.Bundles) != 1 {
		t.Fatalf("sync: record=%+v err=%v", g, err)
	}
	applyID := g.Sync.Bundles[0].Apply
	release()
	if err := <-checked; err != nil {
		t.Fatal(err)
	}
	got, err := s.Status(ctx, scope, "config")
	if err != nil {
		t.Fatal(err)
	}
	if got.Sync == nil || got.Sync.Status != model.GitSyncDone || got.Sync.Commit != sha1 || got.Sync.At.IsZero() || len(got.Sync.Bundles) != 1 || got.Sync.Bundles[0].Apply != applyID {
		t.Fatalf("a concurrent check erased the completed sync: %+v", got)
	}
}

type reviewUnreadableStatus struct {
	store.GitSyncs
	err error
}

func (s reviewUnreadableStatus) GetGitSync(context.Context, string, string) (*model.GitSync, error) {
	return nil, s.err
}

// A transient read failure is not evidence that no status exists.
func TestReviewGitStatusReadErrorDoesNotReplaceExistingRecord(t *testing.T) {
	s, st := newService(t, reviewFetcher())
	register(t, s, "acme", "config", reviewRepoDocument)
	scope := plan.Scope{Tenant: "acme", Subject: "review"}
	if _, err := s.Sync(t.Context(), scope, "config", sha1); err != nil {
		t.Fatal(err)
	}
	unavailable := errors.New("temporary status read failure")
	s.Store = reviewUnreadableStatus{GitSyncs: st, err: unavailable}
	if _, err := s.Check(t.Context(), scope, "config"); !errors.Is(err, unavailable) {
		t.Errorf("status read failure must be returned; got %v", err)
	}
	got, err := st.GetGitSync(t.Context(), "acme", "config")
	if err != nil || got.Sync == nil || got.Sync.Status != model.GitSyncDone || got.Sync.Commit != sha1 || len(got.Sync.Bundles) != 1 {
		t.Errorf("read failure replaced an existing sync: record=%+v err=%v", got, err)
	}
}
