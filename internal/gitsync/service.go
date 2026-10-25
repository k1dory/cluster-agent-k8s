package gitsync

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
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
	// Webhooks (see webhook.go): a delivery becomes a persisted job (Jobs) that one replica at
	// a time claims and runs (Run); Lock serialises the work of a tenant across replicas (the
	// store's tenant lock); Reporter posts plans on pull requests; Emit publishes git.hook,
	// git.sync and git.plan events (nil: none); Replica names this process as a job owner;
	// Lease bounds a job's run before another replica may take it over (default 10 minutes);
	// Retry is the first wait before a job that failed with an error (not an invalid bundle)
	// runs again, doubling per attempt up to MaxAttempts (default 30 seconds); Inline runs the
	// accepted job in the request instead of leaving it to Run (tests).
	Jobs     store.GitJobs
	Lock     func(ctx context.Context, tenant string, fn func(ctx context.Context) error) error
	Reporter Reporter
	Emit     func(ctx context.Context, e model.Event)
	Replica  string
	Lease    time.Duration
	Retry    time.Duration
	Inline   bool
	Log      *slog.Logger
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
	if err != nil {
		return nil, err
	}
	s.fillHook(ctx, g)
	return g, nil
}

// fillHook completes the hook half from its job: a job that ended before its outcome reached
// the record (the replica died in between) still shows how it went.
func (s *Service) fillHook(ctx context.Context, g *model.GitSync) {
	if g == nil || g.Hook == nil || g.Hook.Job == "" || g.Hook.Outcome != "" || s.jobs() == nil {
		return
	}
	j, err := s.jobs().GetGitJob(ctx, g.Hook.Job)
	if err != nil || (j.Status != model.GitJobDone && j.Status != model.GitJobFailed) {
		return
	}
	g.Hook.Outcome, g.Hook.Error = j.Outcome, j.Error
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
	// Resolving the head and applying happen under the tenant's lock, shared by every replica:
	// two syncs of one repository cannot interleave, and a head resolved here is the head when
	// the apply runs.
	var g *model.GitSync
	err = s.locked(ctx, it.Tenant, func(ctx context.Context) error {
		var err error
		g, err = s.sync(ctx, it, sp, scope, commit)
		return err
	})
	return g, err
}

// locked runs fn under the tenant's cross-replica lock: Lock when wired, else the status
// store's own tenant lock when it has one (every store does), else fn alone.
func (s *Service) locked(ctx context.Context, tenant string, fn func(ctx context.Context) error) error {
	if s.Lock != nil {
		return s.Lock(ctx, tenant, fn)
	}
	if l, ok := s.Store.(interface {
		WithTenantLock(ctx context.Context, tenant string, fn func(ctx context.Context) error) error
	}); ok {
		return l.WithTenantLock(ctx, tenant, fn)
	}
	return fn(ctx)
}

func (s *Service) sync(ctx context.Context, it *model.CatalogItem, sp gitrepo.Spec, scope plan.Scope, commit string) (*model.GitSync, error) {
	now := s.now()
	result := model.GitSyncResult{Commit: commit, At: now}
	// The generation: the last sync's, moved on when this one names another commit. The same
	// rule gives the applies their keys and the record its number, so what is recorded is what
	// was keyed, and a sync that fails before it knows its commit still moves on (never back).
	prevCommit, generation, synced := "", 0, false
	if prev, err := s.Store.GetGitSync(ctx, it.Tenant, it.Name); err == nil && prev.Sync != nil {
		prevCommit, generation, synced = prev.Sync.Commit, prev.Sync.Generation, true
	} else if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	generationOf := func(commit string) int {
		if synced && commit != prevCommit {
			return generation + 1
		}
		return generation
	}
	var checked *model.GitCheck
	finish := func(status string, err error) (*model.GitSync, error) {
		result.Status, result.Generation = status, generationOf(result.Commit)
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
	// The documents are applied with the repository's authority, never the caller's: a tenant's
	// repository can do what the tenant can; the admin's shared repository what the admin can.
	applyScope := plan.Scope{Tenant: it.Tenant, Admin: it.Tenant == "" && scope.Admin, Subject: scope.Subject}
	bundles, path, perr := parseBundles(files, applyScope.Tenant)
	if perr != nil {
		result.Bundles = append(result.Bundles, model.GitSyncBundle{Path: path, Status: model.GitSyncInvalid, Errors: []string{perr.Error()}})
		return finish(model.GitSyncInvalid, fmt.Errorf("%w: %s: %v", ErrInvalid, path, perr))
	}
	gen := generationOf(commit)
	// The transition is fixed before the first write: the commit and its generation are the
	// identity of the applies (their keys), so a sync that dies, or whose summary below is
	// lost, is continued under the same generation by the next sync of the commit, and a later
	// return to the commit gets a generation of its own; the summary is never the only carrier.
	if err := s.Store.RecordGitSync(ctx, it.Tenant, it.Name, model.GitSyncResult{Commit: commit, Generation: gen, Status: model.GitSyncRunning, At: now}); err != nil {
		return nil, err
	}
	for _, bf := range bundles {
		p, docs := bf.Path, bf.Docs
		b := model.GitSyncBundle{Path: p}
		pl, err := s.Applier.Planner.Plan(ctx, docs, applyScope)
		if err != nil {
			result.Bundles = append(result.Bundles, b)
			return finish(model.GitSyncError, fmt.Errorf("%s: plan: %w", p, err))
		}
		a, err := s.Applier.Submit(ctx, apply.Request{Docs: docs, Plan: pl.Fingerprint, Key: Key(it.Name, commit, p, gen), Scope: applyScope,
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

// Key is the idempotency key of a bundle's apply: stable for the repository, the commit, the
// path and the sync generation, so a repeated sync of a commit finds its applies, while a
// return to a commit synced in an earlier generation (a force push back) applies it anew.
// Generation 0 keeps the key's earlier form.
func Key(repo, commit, path string, generation int) string {
	k := "git:" + repo + "@" + commit + ":" + path
	if generation > 0 {
		k += "#" + strconv.Itoa(generation)
	}
	return k
}

// bundleFile is one bundle file of a commit, parsed.
type bundleFile struct {
	Path string
	Docs []*res.Document
}

// parseBundles parses the files in path order under the one contract a sync applies and a
// pull request preview shows: file by file, in that order, so a document may name what an
// earlier file introduces (not a later one), and an item lives in one file (two files
// describing it are refused before anything is written). The path and the error name the
// file at fault.
func parseBundles(files map[string][]byte, tenant string) ([]bundleFile, string, error) {
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	owner := map[string]string{} // kind|tenant|name → file
	var out []bundleFile
	for _, p := range paths {
		docs, err := res.ParseYAMLAll(files[p])
		if err != nil {
			return nil, p, err
		}
		for _, d := range docs {
			t := tenant
			if d.Tenant != nil {
				t = *d.Tenant
			}
			k := d.Kind + "|" + t + "|" + d.Name
			if first, dup := owner[k]; dup && first != p {
				return nil, p, fmt.Errorf("files %s and %s both describe %s %s/%s", first, p, d.Kind, t, d.Name)
			}
			owner[k] = p
		}
		out = append(out, bundleFile{Path: p, Docs: docs})
	}
	return out, "", nil
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
