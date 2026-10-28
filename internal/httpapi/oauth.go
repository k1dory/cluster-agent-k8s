package httpapi

import (
	"errors"
	"net/http"

	"agent-sandbox/internal/credentials"
	"agent-sandbox/internal/model"
	"agent-sandbox/internal/store"
)

// oauthRoutes: the sign-ins a tenant makes so sandboxd holds a subscription (a ChatGPT login)
// and keeps its access token fresh for the gateway. Same scope rules as the credentials: a
// tenant in its own, the admin in a tenant's (?tenant=) or the shared one. Starting a sign-in
// returns where to approve it and the code to type; nothing ever returns a token.
func (p *Platform) oauthRoutes(mux *http.ServeMux) {
	scope := func(w http.ResponseWriter, r *http.Request) (string, bool) {
		if p.OAuth == nil {
			writeErr(w, http.StatusServiceUnavailable, credentials.ErrDisabled)
			return "", false
		}
		return p.catalogScope(w, r)
	}
	mux.HandleFunc("GET /v1/oauth-credentials", p.auth(func(w http.ResponseWriter, r *http.Request) {
		tenant, ok := scope(w, r)
		if !ok {
			return
		}
		list, err := p.OAuth.List(r.Context(), tenant)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		if list == nil {
			list = []*model.OAuthCredential{}
		}
		writeJSON(w, http.StatusOK, list)
	}))
	mux.HandleFunc("GET /v1/oauth-credentials/{name}", p.auth(func(w http.ResponseWriter, r *http.Request) {
		tenant, ok := scope(w, r)
		if !ok {
			return
		}
		c, err := p.OAuth.Get(r.Context(), tenant, r.PathValue("name"))
		if err != nil {
			writeOAuthErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, c)
	}))
	mux.HandleFunc("POST /v1/oauth-credentials/{name}/login", p.auth(func(w http.ResponseWriter, r *http.Request) {
		tenant, ok := scope(w, r)
		if !ok {
			return
		}
		var req struct {
			Provider string `json:"provider"`
		}
		if err := decodeStrict(w, r, &req, 4096); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		c, created, err := p.OAuth.Start(r.Context(), tenant, r.PathValue("name"), req.Provider, principalOf(r).Subject)
		if err != nil {
			writeOAuthErr(w, err)
			return
		}
		code := http.StatusOK
		if created {
			code = http.StatusCreated
		}
		writeJSON(w, code, c)
	}))
	mux.HandleFunc("DELETE /v1/oauth-credentials/{name}", p.auth(func(w http.ResponseWriter, r *http.Request) {
		tenant, ok := scope(w, r)
		if !ok {
			return
		}
		if err := p.OAuth.Delete(r.Context(), tenant, r.PathValue("name")); err != nil {
			writeOAuthErr(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
}

func writeOAuthErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, credentials.ErrInvalid):
		writeErr(w, http.StatusUnprocessableEntity, err)
	case errors.Is(err, credentials.ErrProvider):
		writeErr(w, http.StatusBadGateway, err)
	case errors.Is(err, store.ErrNotFound):
		writeErr(w, http.StatusNotFound, err)
	default:
		writeErr(w, http.StatusInternalServerError, err)
	}
}
