package httpapi

import (
	"errors"
	"net/http"

	"agent-sandbox/internal/ciauth"
	"agent-sandbox/internal/model"
)

// ciAuthRoutes: POST /v1/auth/ci, the only route a CI job calls before it has a key. The
// body carries the provider's ID token; the answer is a short-lived tenant key under the
// CITrust that accepts the token (see internal/ciauth). No bearer: the token is the
// credential. A refusal says nothing about which trusts exist.
func (p *Platform) ciAuthRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/auth/ci", func(w http.ResponseWriter, r *http.Request) {
		if p.CIAuth == nil || p.Keys == nil {
			writeErr(w, http.StatusServiceUnavailable, ciauth.ErrDisabled)
			return
		}
		var body struct {
			Token string `json:"token"`
		}
		if err := decodeStrict(w, r, &body, 2*ciauth.MaxTokenBytes); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		if body.Token == "" {
			writeErr(w, http.StatusBadRequest, errors.New("body: token is required"))
			return
		}
		g, err := p.CIAuth.Exchange(r.Context(), body.Token)
		switch {
		case errors.Is(err, ciauth.ErrRefused):
			writeErr(w, http.StatusUnauthorized, err)
			return
		case errors.Is(err, ciauth.ErrIssuer), errors.Is(err, ciauth.ErrDisabled):
			writeErr(w, http.StatusServiceUnavailable, err)
			return
		case err != nil:
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusCreated, ciGrant{APIKey: *g.Key, Secret: g.Secret, Subject: g.Subject})
	})
}

// ciGrant is the issued key (its trust field names the CITrust that accepted the token) with
// its secret, shown once, and the token's subject.
type ciGrant struct {
	model.APIKey
	Secret  string `json:"secret"`
	Subject string `json:"subject"`
}
