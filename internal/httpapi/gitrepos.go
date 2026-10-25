package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"agent-sandbox/internal/gitsync"
	"agent-sandbox/internal/model"
	"agent-sandbox/internal/plan"
	"agent-sandbox/internal/resource"
)

// Git repositories: the catalogue routes (/v1/gitrepos, see resourceRoutes) register them; the
// three routes here read them. check resolves the ref, sync applies a commit through the apply
// controller, status shows the last of each. A tenant acts on its own repositories, the admin
// on any (?tenant= for a tenant's, none for the shared ones).

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
	var body struct {
		Commit string `json:"commit"`
	}
	if r.ContentLength != 0 && r.Body != nil {
		dec := json.NewDecoder(io.LimitReader(r.Body, 4096))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&body); err != nil && !errors.Is(err, io.EOF) {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
	}
	g, err := p.GitSync.Sync(r.Context(), scope, r.PathValue("name"), body.Commit)
	writeGitSync(w, g, err)
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
