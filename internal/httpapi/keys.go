package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"agent-sandbox/internal/apikeys"
	"agent-sandbox/internal/model"
	"agent-sandbox/internal/store"
)

// keyRoutes: tenant API keys, self-service. The admin manages every tenant's keys; a tenant
// principal (a key, a static token or an OIDC user of that tenant) manages its own tenant's:
// a team adds a key for a new pipeline, rotates it on a schedule and revokes a leaked one
// without anyone touching the server's configuration. The secret appears once, in the
// response that creates or rotates it.
func (p *Platform) keyRoutes(mux *http.ServeMux) {
	own := func(w http.ResponseWriter, r *http.Request) (string, bool) {
		if p.Keys == nil {
			writeErr(w, http.StatusServiceUnavailable, errors.New("api keys disabled"))
			return "", false
		}
		pr := principalOf(r)
		tenant := r.PathValue("tenant")
		if tenant == "" {
			writeErr(w, http.StatusBadRequest, errors.New("tenant is required"))
			return "", false
		}
		if !pr.admin() && tenant != pr.Tenant {
			writeErr(w, http.StatusForbidden, errors.New("token is scoped to tenant "+pr.Tenant))
			return "", false
		}
		return tenant, true
	}
	// keyOf loads the key of the path and checks it belongs to the tenant of the path: another
	// tenant's key is not found, never "forbidden" (ids are not enumerable either way).
	keyOf := func(w http.ResponseWriter, r *http.Request, tenant string) (*model.APIKey, bool) {
		k, err := p.Keys.Get(r.Context(), r.PathValue("id"))
		if err != nil || k.Tenant != tenant {
			writeErr(w, http.StatusNotFound, store.ErrNotFound)
			return nil, false
		}
		return k, true
	}
	mux.HandleFunc("GET /v1/tenants/{tenant}/keys", p.auth(func(w http.ResponseWriter, r *http.Request) {
		tenant, ok := own(w, r)
		if !ok {
			return
		}
		list, err := p.Keys.List(r.Context(), tenant)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		if list == nil {
			list = []*model.APIKey{}
		}
		writeJSON(w, http.StatusOK, list)
	}))
	mux.HandleFunc("POST /v1/tenants/{tenant}/keys", p.auth(func(w http.ResponseWriter, r *http.Request) {
		tenant, ok := own(w, r)
		if !ok {
			return
		}
		var req struct {
			Name string `json:"name"`
			TTL  string `json:"ttl"` // Go duration, e.g. "720h"; "" = no expiry (or the server's cap)
		}
		if err := decodeStrict(w, r, &req, bodyLimit); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		ttl, err := parseTTL(req.TTL)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		k, secret, err := p.Keys.Create(r.Context(), tenant, req.Name, ttl, principalOf(r).Subject)
		if err != nil {
			writeKeyErr(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, issued{APIKey: k, Secret: secret})
	}))
	mux.HandleFunc("GET /v1/tenants/{tenant}/keys/{id}", p.auth(func(w http.ResponseWriter, r *http.Request) {
		tenant, ok := own(w, r)
		if !ok {
			return
		}
		if k, ok := keyOf(w, r, tenant); ok {
			writeJSON(w, http.StatusOK, k)
		}
	}))
	mux.HandleFunc("POST /v1/tenants/{tenant}/keys/{id}/rotate", p.auth(func(w http.ResponseWriter, r *http.Request) {
		tenant, ok := own(w, r)
		if !ok {
			return
		}
		old, ok := keyOf(w, r, tenant)
		if !ok {
			return
		}
		var req struct {
			TTL   string `json:"ttl"`   // of the new key; "" = the old key's remaining lifetime
			Grace string `json:"grace"` // how long the old key keeps working; "" = revoked at once
		}
		if r.ContentLength != 0 {
			if err := decodeStrict(w, r, &req, bodyLimit); err != nil {
				writeErr(w, http.StatusBadRequest, err)
				return
			}
		}
		ttl, err := parseTTL(req.TTL)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		grace, err := parseTTL(req.Grace)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		k, secret, err := p.Keys.Rotate(r.Context(), old.ID, ttl, grace, principalOf(r).Subject)
		if err != nil {
			writeKeyErr(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, issued{APIKey: k, Secret: secret, Replaces: old.ID})
	}))
	mux.HandleFunc("DELETE /v1/tenants/{tenant}/keys/{id}", p.auth(func(w http.ResponseWriter, r *http.Request) {
		tenant, ok := own(w, r)
		if !ok {
			return
		}
		k, ok := keyOf(w, r, tenant)
		if !ok {
			return
		}
		if _, err := p.Keys.Revoke(r.Context(), k.ID); err != nil {
			writeKeyErr(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
}

// issued is a key with its secret: the create and rotate responses only.
type issued struct {
	*model.APIKey
	Secret   string `json:"secret"`
	Replaces string `json:"replaces,omitempty"`
}

// decodeStrict reads exactly one JSON object of at most limit bytes into v: a body that is
// not an object (null, a string, an array), unknown fields, a second document or trailing
// garbage after the object are errors, so nothing is written on a body that was not what the
// client meant to send. The stream is read to its end before the object is decoded.
func decodeStrict(w http.ResponseWriter, r *http.Request, v any, limit int64) error {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, limit))
	var raw json.RawMessage
	if err := dec.Decode(&raw); err != nil {
		return fmt.Errorf("body: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("body: trailing data after the JSON object")
	}
	if b := bytes.TrimSpace(raw); len(b) == 0 || b[0] != '{' {
		return errors.New("body: one JSON object is expected")
	}
	obj := json.NewDecoder(bytes.NewReader(raw))
	obj.DisallowUnknownFields()
	if err := obj.Decode(v); err != nil {
		return fmt.Errorf("body: %w", err)
	}
	return nil
}

// bodyLimit bounds small JSON request bodies (keys, rotation).
const bodyLimit = 1 << 16

func parseTTL(s string) (time.Duration, error) {
	if s == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("duration %q: %w", s, err)
	}
	return d, nil
}

func writeKeyErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, apikeys.ErrInvalid):
		writeErr(w, http.StatusUnprocessableEntity, err)
	case errors.Is(err, store.ErrNotFound):
		writeErr(w, http.StatusNotFound, err)
	case errors.Is(err, store.ErrConflict):
		writeErr(w, http.StatusConflict, err)
	default:
		writeErr(w, http.StatusInternalServerError, err)
	}
}
