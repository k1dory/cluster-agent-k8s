package gitsync

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"agent-sandbox/internal/apply"
	"agent-sandbox/internal/gitrepo"
	"agent-sandbox/internal/model"
	"agent-sandbox/internal/plan"
	res "agent-sandbox/internal/resource"
	"agent-sandbox/internal/secrets"
	"agent-sandbox/internal/store"
)

// Outcomes of a sync besides success, for the API's status codes. The returned record carries
// the details either way and is stored before the error is returned.
var (
	ErrRead       = errors.New("the repository could not be read") // 502
	ErrCredential = errors.New("the credential is not available")  // 422
	ErrInvalid    = errors.New("a bundle is not valid")            // 422
	ErrStopped    = errors.New("an apply did not finish")          // 409
)

// Service checks and syncs registered repositories. Applying is the apply controller's: one
// apply per bundle file, under a key of repository, commit and path, so syncing the same commit
// again returns the same applies and writes nothing, and a stopped apply is continued by the
// next sync of that commit.
type Service struct {
	Store   store.GitSyncs
	Repos   *gitrepo.Service
	Secrets secrets.Provider // resolves spec.credential and spec.webhook_secret; nil: unavailable
	Fetch   Fetcher
	Applier *apply.Controller
	Now     func() time.Time
	// Webhooks (see webhook.go): Reporter posts plans on pull requests; Emit publishes
	// git.hook, git.sync and git.plan events (nil: none); HookTimeout bounds a background
	// action (default 10 minutes); Inline runs the action in the request (tests).
	Reporter    Reporter
	Emit        func(ctx context.Context, e model.Event)
	HookTimeout time.Duration
	Inline      bool
	Log         *slog.Logger

	locksMu sync.Mutex
	locks   map[string]*sync.Mutex // one per repository: a sync and a plan never interleave
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// repository loads a repository the caller may act on: its own, or, for the admin, any (the
// shared ones included). A tenant sees a shared repository but may not sync it.
func (s *Service) repository(ctx context.Context, scope plan.Scope, name string) (*model.CatalogItem, gitrepo.Spec, error) {
	it, err := s.Repos.Get(ctx, scope.Tenant, name, 0)
	if err != nil {
		return nil, gitrepo.Spec{}, err
	}
	if it.Tenant != scope.Tenant && !scope.Admin {
		return nil, gitrepo.Spec{}, fmt.Errorf("%w: %s is a shared repository; the admin syncs it", res.ErrForbidden, name)
	}
	sp, err := gitrepo.Decode(it)
	if err != nil {
		return nil, sp, fmt.Errorf("%s: stored spec: %w", name, err)
	}
	return it, sp, nil
}

// record returns the repository's record as stored (what Status shows), or the bare record
// when nothing was stored yet. It is read only after the caller's half was written, so a
// failed read costs no data: the half just written is added by the caller and the read's
// error is returned with it, never mistaken for "no record".
func (s *Service) record(ctx context.Context, it *model.CatalogItem) (*model.GitSync, error) {
	g, err := s.Store.GetGitSync(ctx, it.Tenant, it.Name)
	if err != nil {
		g = &model.GitSync{Tenant: it.Tenant, Name: it.Name}
		if errors.Is(err, store.ErrNotFound) {
			err = nil
		}
	}
	return g, err
}

// remote resolves the credential (if any) into a Remote.
func (s *Service) remote(ctx context.Context, it *model.CatalogItem, sp gitrepo.Spec) (Remote, error) {
	r := Remote{URL: sp.URL, Ref: sp.Ref}
	if sp.Credential == "" {
		return r, nil
	}
	if s.Secrets == nil {
		return r, fmt.Errorf("%w: %q: no secrets provider is configured", ErrCredential, sp.Credential)
	}
	v, err := s.Secrets.Get(ctx, it.Tenant, sp.Credential)
	if err != nil {
		// The value is never part of the message; the name is, so the owner knows what to restore.
		return r, fmt.Errorf("%w: %q is not available to tenant %q (revoked, deleted or never set)", ErrCredential, sp.Credential, it.Tenant)
	}
	r.Auth = v
	return r, nil
}

// Status returns the record of the last check and sync; ErrNotFound when there is none yet.
func (s *Service) Status(ctx context.Context, scope plan.Scope, name string) (*model.GitSync, error) {
	it, _, err := s.repository(ctx, scope, name)
	if err != nil {
		return nil, err
	}
	g, err := s.Store.GetGitSync(ctx, it.Tenant, it.Name)
	if errors.Is(err, store.ErrNotFound) {
		return nil, fmt.Errorf("%w: %s was never checked or synced", res.ErrNotFound, name)
	}
	return g, err
}

// Check resolves the ref and records the head (or why the repository cannot be read) in the
// check half of the record, the sync half untouched. The record is returned with the error,
// so the caller can show both.
func (s *Service) Check(ctx context.Context, scope plan.Scope, name string) (*model.GitSync, error) {
	it, sp, err := s.repository(ctx, scope, name)
	if err != nil {
		return nil, err
	}
	ck := model.GitCheck{At: s.now()}
	r, err := s.remote(ctx, it, sp)
	if err == nil {
		if ck.Head, err = s.Fetch.Resolve(ctx, r); err != nil {
			err = fmt.Errorf("%w: %v", ErrRead, err)
		}
	}
	if err != nil {
		ck.Error = err.Error()
	}
	if perr := s.Store.RecordGitCheck(ctx, it.Tenant, it.Name, ck); perr != nil {
		return nil, perr
	}
	g, rerr := s.record(ctx, it)
	g.Check = &ck
	if rerr != nil {
		return g, rerr
	}
	return g, err
}

// Sync applies the bundles of one commit (the ref's head when commit is empty): every bundle
// file is planned and applied through the controller under the key
// "git:<repository>@<commit>:<path>", in path order, stopping at the first bundle that is
// refused or whose apply does not finish. The outcome is recorded in the sync half of the
// record (the check half too when the head was resolved here) and returned with the error,
// which says which kind of outcome it was (ErrRead, ErrCredential, ErrInvalid, ErrStopped).
func (s *Service) Sync(ctx context.Context, scope plan.Scope, name, commit string) (*model.GitSync, error) {
	it, sp, err := s.repository(ctx, scope, name)
	if err != nil {
		return nil, err
	}
	if commit != "" && !shaRe.MatchString(commit) {
		return nil, fmt.Errorf("%w: %q is not a commit SHA (40 hex digits)", res.ErrInvalid, commit)
	}
	now := s.now()
	result := model.GitSyncResult{Commit: commit, At: now}
	var checked *model.GitCheck
	finish := func(status string, err error) (*model.GitSync, error) {
		result.Status = status
		if err != nil {
			result.Error = err.Error()
		}
		if perr := s.Store.RecordGitSync(ctx, it.Tenant, it.Name, result); perr != nil {
			return nil, perr
		}
		s.emit(ctx, it, "git.sync", result)
		g, rerr := s.record(ctx, it)
		g.Sync = &result
		if checked != nil {
			g.Check = checked
		}
		if rerr != nil {
			return g, rerr
		}
		return g, err
	}
	r, err := s.remote(ctx, it, sp)
	if err != nil {
		return finish(model.GitSyncError, err)
	}
	if commit == "" {
		ck := model.GitCheck{At: now}
		head, err := s.Fetch.Resolve(ctx, r)
		if err != nil {
			ck.Error = fmt.Errorf("%w: %v", ErrRead, err).Error()
		} else {
			ck.Head = head
		}
		if perr := s.Store.RecordGitCheck(ctx, it.Tenant, it.Name, ck); perr != nil {
			return nil, perr
		}
		checked = &ck
		if err != nil {
			return finish(model.GitSyncError, fmt.Errorf("%w: %v", ErrRead, err))
		}
		commit, result.Commit = head, head
	}
	files, err := s.Fetch.Files(ctx, r, commit, sp.Paths)
	if err != nil {
		return finish(model.GitSyncError, fmt.Errorf("%w: %v", ErrRead, err))
	}
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	// The documents are applied with the repository's authority, never the caller's: a tenant's
	// repository can do what the tenant can; the admin's shared repository what the admin can.
	applyScope := plan.Scope{Tenant: it.Tenant, Admin: it.Tenant == "" && scope.Admin, Subject: scope.Subject}
	for _, p := range paths {
		b := model.GitSyncBundle{Path: p}
		docs, err := res.ParseYAMLAll(files[p])
		if err != nil {
			b.Status, b.Errors = model.GitSyncInvalid, []string{err.Error()}
			result.Bundles = append(result.Bundles, b)
			return finish(model.GitSyncInvalid, fmt.Errorf("%w: %s: %v", ErrInvalid, p, err))
		}
		pl, err := s.Applier.Planner.Plan(ctx, docs, applyScope)
		if err != nil {
			result.Bundles = append(result.Bundles, b)
			return finish(model.GitSyncError, fmt.Errorf("%s: plan: %w", p, err))
		}
		a, err := s.Applier.Submit(ctx, apply.Request{Docs: docs, Plan: pl.Fingerprint, Key: Key(it.Name, commit, p), Scope: applyScope,
			Source: &model.Source{Repo: sp.URL, Ref: sp.Ref, Commit: commit, Path: p}})
		var invalid *apply.InvalidPlan
		switch {
		case errors.As(err, &invalid):
			b.Status, b.Errors = model.GitSyncInvalid, planErrors(invalid.Plan)
			result.Bundles = append(result.Bundles, b)
			return finish(model.GitSyncInvalid, fmt.Errorf("%w: %s: %d invalid", ErrInvalid, p, invalid.Plan.Summary.Invalid))
		case err != nil:
			if a != nil {
				b.Apply, b.Status = a.ID, a.Status
			}
			b.Errors = []string{err.Error()}
			result.Bundles = append(result.Bundles, b)
			return finish(model.GitSyncError, fmt.Errorf("%s: %w", p, err))
		}
		b.Apply, b.Status = a.ID, a.Status
		for _, st := range a.Steps {
			if st.Action == plan.ActionCreate || st.Action == plan.ActionUpdate {
				b.Changes++
			}
		}
		if a.Error != "" {
			b.Errors = []string{a.Error}
		}
		result.Bundles = append(result.Bundles, b)
		if a.Status != model.ApplyDone {
			return finish(model.GitSyncStopped, fmt.Errorf("%w: %s: apply %s is %s; sync the same commit again once the cause is fixed", ErrStopped, p, a.ID, a.Status))
		}
	}
	return finish(model.GitSyncDone, nil)
}

// Key is the idempotency key of a bundle's apply: stable for the repository, the commit and
// the path, so a repeated sync of a commit finds its applies.
func Key(repo, commit, path string) string {
	return "git:" + repo + "@" + commit + ":" + path
}

func planErrors(p *plan.Plan) []string {
	var out []string
	out = append(out, p.Errors...)
	for _, c := range p.Changes {
		for _, e := range c.Errors {
			out = append(out, fmt.Sprintf("%s %s: %s", c.Kind, c.Name, e))
		}
	}
	return out
}
