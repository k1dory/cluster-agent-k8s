package httpapi

import (
	"errors"
	"net/http"

	"agent-sandbox/internal/credentials"
	"agent-sandbox/internal/model"
	"agent-sandbox/internal/store"
)

// credentialRoutes: the secrets a tenant brings itself (BYOK). The scope is the catalogue's:
// a tenant works in its own, the admin in a tenant's (?tenant=) or the shared one. The value
// goes in once and never comes out: every response is metadata.
func (p *Platform) credentialRoutes(mux *http.ServeMux) {
	scope := func(w http.ResponseWriter, r *http.Request) (string, bool) {
		if p.Credentials == nil {
			writeErr(w, http.StatusServiceUnavailable, credentials.ErrDisabled)
			return "", false
		}
		return p.catalogScope(w, r)
	}
	mux.HandleFunc("GET /v1/credentials", p.auth(func(w http.ResponseWriter, r *http.Request) {
		tenant, ok := scope(w, r)
		if !ok {
			return
		}
		list, err := p.Credentials.List(r.Context(), tenant)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		if list == nil {
			list = []*model.Credential{}
		}
		writeJSON(w, http.StatusOK, list)
	}))
	mux.HandleFunc("GET /v1/credentials/{name}", p.auth(func(w http.ResponseWriter, r *http.Request) {
		tenant, ok := scope(w, r)
		if !ok {
			return
		}
		c, err := p.Credentials.Get(r.Context(), tenant, r.PathValue("name"))
		if err != nil {
			writeCredentialErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, c)
	}))
	mux.HandleFunc("PUT /v1/credentials/{name}", p.auth(func(w http.ResponseWriter, r *http.Request) {
		tenant, ok := scope(w, r)
		if !ok {
			return
		}
		var req struct {
			Value string `json:"value"`
		}
		// The body limit is on the JSON, which carries the value escaped (up to six bytes per
		// byte) inside a wrapper: a value of exactly MaxValue bytes must pass, the service then
		// judges the value itself.
		if err := decodeStrict(w, r, &req, 6*credentials.MaxValue+1024); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		c, created, err := p.Credentials.Put(r.Context(), tenant, r.PathValue("name"), req.Value, principalOf(r).Subject)
		if err != nil {
			writeCredentialErr(w, err)
			return
		}
		code := http.StatusOK
		if created {
			code = http.StatusCreated
		}
		writeJSON(w, code, c)
	}))
	mux.HandleFunc("DELETE /v1/credentials/{name}", p.auth(func(w http.ResponseWriter, r *http.Request) {
		tenant, ok := scope(w, r)
		if !ok {
			return
		}
		if err := p.Credentials.Delete(r.Context(), tenant, r.PathValue("name")); err != nil {
			writeCredentialErr(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
}

func writeCredentialErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, credentials.ErrInvalid):
		writeErr(w, http.StatusUnprocessableEntity, err)
	case errors.Is(err, store.ErrNotFound):
		writeErr(w, http.StatusNotFound, err)
	default:
		writeErr(w, http.StatusInternalServerError, err)
	}
}
