package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"agent-sandbox/internal/gitsync"
	"agent-sandbox/internal/model"
	"agent-sandbox/internal/plan"
	"agent-sandbox/internal/resource"
	"agent-sandbox/internal/store"
)

// Git repositories: the catalogue routes (/v1/gitrepos, see resourceRoutes) register them; the
// three routes here read them. check resolves the ref, sync applies a commit through the apply
// controller, status shows the last of each. A tenant acts on its own repositories, the admin
// on any (?tenant= for a tenant's, none for the shared ones).

// syncBodyLimit bounds the sync request body (a commit SHA and nothing else).
const syncBodyLimit = 4096

func (p *Platform) gitScope(w http.ResponseWriter, r *http.Request) (plan.Scope, bool) {
	if p.GitSync == nil {
		writeErr(w, http.StatusServiceUnavailable, errors.New("gitrepos disabled"))
		return plan.Scope{}, false
	}
	tenant, ok := p.catalogScope(w, r)
	if !ok {
		return plan.Scope{}, false
	}
	pr := principalOf(r)
	return plan.Scope{Tenant: tenant, Admin: pr.admin(), Subject: pr.Subject}, true
}

func (p *Platform) gitCheck(w http.ResponseWriter, r *http.Request) {
	scope, ok := p.gitScope(w, r)
	if !ok {
		return
	}
	g, err := p.GitSync.Check(r.Context(), scope, r.PathValue("name"))
	writeGitSync(w, g, err)
}

func (p *Platform) gitSyncRepo(w http.ResponseWriter, r *http.Request) {
	scope, ok := p.gitScope(w, r)
	if !ok {
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, syncBodyLimit))
	if err != nil {
		writeErr(w, http.StatusRequestEntityTooLarge, fmt.Errorf("body: at most %d bytes", syncBodyLimit))
		return
	}
	commit, err := parseSyncBody(raw)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	g, err := p.GitSync.Sync(r.Context(), scope, r.PathValue("name"), commit)
	writeGitSync(w, g, err)
}

// parseSyncBody checks the whole sync body before Git is asked, to the declared contract: an
// empty body means the head; anything else is exactly one JSON object, with `commit` a string
// when present (null is not a string, and `null` is not an object), no other field, and
// nothing after it.
func parseSyncBody(raw []byte) (string, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return "", nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	var fields map[string]json.RawMessage
	if err := dec.Decode(&fields); err != nil {
		return "", fmt.Errorf("body: %w", err)
	}
	if fields == nil {
		return "", errors.New("body: must be a JSON object (or empty for the ref's head), not null")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return "", errors.New("body: trailing data after the JSON document")
	}
	var commit string
	for k, v := range fields {
		if k != "commit" {
			return "", fmt.Errorf("body: unknown field %q", k)
		}
		if err := json.Unmarshal(v, &commit); err != nil || bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			return "", errors.New("body: commit must be a string (a 40-digit SHA, or empty for the ref's head)")
		}
	}
	return commit, nil
}

func (p *Platform) gitStatus(w http.ResponseWriter, r *http.Request) {
	scope, ok := p.gitScope(w, r)
	if !ok {
		return
	}
	g, err := p.GitSync.Status(r.Context(), scope, r.PathValue("name"))
	writeGitSync(w, g, err)
}

// writeGitSync answers with the record; the status code says how the operation went: 200 done,
// 409 an apply did not finish, 422 the credential is gone or a bundle is not valid, 502 the
// repository could not be read. The record travels with the error, so the client shows both.
func writeGitSync(w http.ResponseWriter, g *model.GitSync, err error) {
	if err == nil {
		writeJSON(w, http.StatusOK, g)
		return
	}
	code, label := 0, ""
	switch {
	case errors.Is(err, gitsync.ErrRead):
		code, label = http.StatusBadGateway, "unreachable"
	case errors.Is(err, gitsync.ErrCredential):
		code, label = http.StatusUnprocessableEntity, "credential"
	case errors.Is(err, gitsync.ErrInvalid):
		code, label = http.StatusUnprocessableEntity, "invalid_plan"
	case errors.Is(err, gitsync.ErrStopped):
		code, label = http.StatusConflict, "stopped"
	case errors.Is(err, resource.ErrNotFound), errors.Is(err, resource.ErrForbidden), errors.Is(err, resource.ErrInvalid), errors.Is(err, resource.ErrConflict):
		writeResourceErr(w, err)
		return
	default:
		code, label = http.StatusInternalServerError, "error"
	}
	writeJSON(w, code, map[string]any{"error": err.Error(), "code": label, "sync": g})
}

// hookBodyLimit bounds a webhook payload (GitHub's run to a few hundred KB).
const hookBodyLimit = 2 << 20

// gitHook is POST /hooks/git/{tenant}/{name}: a GitHub or GitLab webhook delivery for a
// registered repository ("-" for the shared scope). No bearer token: the delivery is
// authenticated by its signature against the repository's webhook secret. 202 when the
// platform acts on it (a sync or a plan runs in the background; the outcome lands in the
// repository's status), 200 when it is recorded as ignored.
func (p *Platform) gitHook(w http.ResponseWriter, r *http.Request) {
	if p.GitSync == nil {
		writeErr(w, http.StatusServiceUnavailable, errors.New("gitrepos disabled"))
		return
	}
	tenant := r.PathValue("tenant")
	if tenant == "-" {
		tenant = ""
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, hookBodyLimit))
	if err != nil {
		writeErr(w, http.StatusRequestEntityTooLarge, fmt.Errorf("body: at most %d bytes", hookBodyLimit))
		return
	}
	h, err := p.GitSync.Hook(r.Context(), tenant, r.PathValue("name"), r.Header, body)
	switch {
	case err == nil:
		writeJSON(w, gitsync.HookHTTPStatus(h), h)
	case errors.Is(err, gitsync.ErrBadSignature):
		writeErr(w, http.StatusUnauthorized, err)
	case errors.Is(err, store.ErrNotFound), errors.Is(err, resource.ErrNotFound):
		// An unknown repository and one without a webhook answer alike: nothing to learn here.
		writeErr(w, http.StatusNotFound, errors.New("no such webhook"))
	case errors.Is(err, gitsync.ErrCredential):
		writeErr(w, http.StatusServiceUnavailable, err)
	case errors.Is(err, resource.ErrInvalid):
		writeErr(w, http.StatusBadRequest, err)
	default:
		writeErr(w, http.StatusInternalServerError, err)
	}
}
