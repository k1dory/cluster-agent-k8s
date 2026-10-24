// Package httpapi exposes sandboxd over HTTP: the platform API for clients and the
// gateway-facing API (authz, bootstrap, agent endpoints).
package httpapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"agent-sandbox/api"
	"agent-sandbox/internal/events"
	"agent-sandbox/internal/ingress"
	"agent-sandbox/internal/model"
	"agent-sandbox/internal/orchestrator"
	"agent-sandbox/internal/policy"
	"agent-sandbox/internal/store"
	"agent-sandbox/internal/usage"
)

// Platform is the client-facing API.
type Platform struct {
	Orch     *orchestrator.Orchestrator
	Hub      *events.Hub
	Policies *policy.Set
	Ingress  *ingress.Handler
	Pricing  usage.Pricing
	Token    string            // admin token: every tenant, every sandbox
	Tenants  map[string]string // tenant-scoped tokens: token → tenant
	// Verifier checks bearer tokens that are not static ones (OIDC JWTs). nil disables.
	Verifier TokenVerifier
	// TTLFromToken caps the lifetime of sandboxes created with a short-lived token (and so
	// their agent certificates) at the token's expiry.
	TTLFromToken bool
	Build        string // control-plane version reported by GET /v1/version
	Log          *slog.Logger
}

// Principal is who is calling: the admin (every tenant) or one tenant. Expires is set for
// credentials with a lifetime of their own (OIDC tokens); zero for static tokens.
type Principal struct {
	Tenant  string    `json:"tenant"`
	Admin   bool      `json:"admin"`
	Subject string    `json:"subject,omitempty"`
	Expires time.Time `json:"expires,omitempty"`
}

func (pr Principal) admin() bool { return pr.Admin }

// TokenVerifier resolves a bearer token that is not one of the configured static tokens.
type TokenVerifier interface {
	Verify(ctx context.Context, token string) (Principal, error)
}

type principalKey struct{}

func principalOf(r *http.Request) Principal {
	pr, _ := r.Context().Value(principalKey{}).(Principal)
	return pr
}

// Routes builds the platform mux.
func (p *Platform) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok\n")) })
	mux.HandleFunc("GET /openapi.yaml", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/yaml")
		w.Write(api.OpenAPI)
	})
	mux.HandleFunc("GET /docs", swaggerUI)

	mux.HandleFunc("GET /v1/sandboxes", p.auth(p.list))
	mux.HandleFunc("POST /v1/sandboxes", p.auth(p.idempotent(p.create)))
	mux.HandleFunc("GET /v1/sandboxes/{id}", p.auth(p.get))
	mux.HandleFunc("PATCH /v1/sandboxes/{id}", p.auth(p.update))
	mux.HandleFunc("DELETE /v1/sandboxes/{id}", p.auth(p.delete))
	mux.HandleFunc("POST /v1/sandboxes/{id}/sleep", p.auth(p.sleep))
	mux.HandleFunc("POST /v1/sandboxes/{id}/wake", p.auth(p.wake))
	mux.HandleFunc("POST /v1/sandboxes/{id}/touch", p.auth(p.touch))
	mux.HandleFunc("GET /v1/sandboxes/{id}/runs", p.auth(p.listRuns))
	mux.HandleFunc("POST /v1/sandboxes/{id}/runs", p.auth(p.idempotent(p.createRun)))
	mux.HandleFunc("GET /v1/sandboxes/{id}/runs/{run}", p.auth(p.getRun))
	mux.HandleFunc("POST /v1/sandboxes/{id}/runs/{run}/cancel", p.auth(p.cancelRun))
	mux.HandleFunc("POST /v1/sandboxes/{id}/runs/{run}/input", p.auth(p.input))
	mux.HandleFunc("GET /v1/sandboxes/{id}/events", p.auth(p.events))
	mux.HandleFunc("PUT /v1/sandboxes/{id}/preview", p.auth(p.setPreview))
	mux.HandleFunc("POST /v1/sandboxes/{id}/preview/ticket", p.auth(p.previewTicket))
	mux.HandleFunc("GET /v1/policies", p.auth(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, p.Policies.Slugs())
	}))
	mux.HandleFunc("GET /v1/usage", p.auth(p.usage))
	mux.HandleFunc("GET /v1/trace", p.auth(p.trace))
	mux.HandleFunc("POST /v1/rollouts", p.auth(p.rollout))
	mux.HandleFunc("GET /v1/version", p.auth(p.version))
	mux.HandleFunc("GET /v1/whoami", p.auth(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, principalOf(r))
	}))
	return logRequests(p.Log, jsonMuxErrors(mux))
}

// rollout answers POST /v1/rollouts: move agents to another version (see orchestrator.RolloutRequest).
func (p *Platform) rollout(w http.ResponseWriter, r *http.Request) {
	var req orchestrator.RolloutRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	pr := principalOf(r)
	req.Admin, req.Tenant = pr.admin(), pr.Tenant
	res, err := p.Orch.Rollout(r.Context(), req)
	if err != nil {
		writeOrchErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// version answers GET /v1/version: what this control plane runs and what agents it hands out.
func (p *Platform) version(w http.ResponseWriter, r *http.Request) {
	cfg := p.Orch.Cfg
	envs := map[string]string{}
	if p.Policies != nil {
		for _, slug := range p.Policies.Slugs() {
			envs[slug] = cfg.EnvVersion(&model.Sandbox{Slug: slug, AgentVersion: cfg.DefaultAgentVersion})
		}
	}
	versions := cfg.Versions
	if versions == nil {
		versions = map[string]string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"sandboxd": p.Build,
		"agent":    map[string]any{"default": cfg.DefaultAgentVersion, "versions": versions},
		"env":      envs,
	})
}

// jsonMuxErrors turns the router's own text 404/405 into the API's error shape.
func jsonMuxErrors(mux *http.ServeMux) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h, pattern := mux.Handler(r)
		if pattern != "" {
			mux.ServeHTTP(w, r) // through the mux, so path values are bound
			return
		}
		probe := &statusWriter{ResponseWriter: &discard{header: http.Header{}}, code: 200}
		h.ServeHTTP(probe, r)
		if allow := probe.ResponseWriter.Header().Get("Allow"); allow != "" {
			w.Header().Set("Allow", allow)
		}
		switch probe.code {
		case http.StatusMethodNotAllowed:
			writeErr(w, http.StatusMethodNotAllowed, fmt.Errorf("%s not allowed on %s", r.Method, r.URL.Path))
		default:
			writeErr(w, http.StatusNotFound, fmt.Errorf("no route for %s %s", r.Method, r.URL.Path))
		}
	})
}

type discard struct{ header http.Header }

func (d *discard) Header() http.Header         { return d.header }
func (d *discard) Write(b []byte) (int, error) { return len(b), nil }
func (d *discard) WriteHeader(int)             {}

// SafeNext keeps a post-sign-in redirect on the preview host: one leading slash, no scheme,
// no backslashes or control characters. Anything else becomes "/".
func SafeNext(next string) string {
	if next == "" || next[0] != '/' || strings.HasPrefix(next, "//") || strings.HasPrefix(next, "/\\") {
		return "/"
	}
	for _, c := range next {
		if c < 0x20 || c == 0x7f || c == '\\' {
			return "/"
		}
	}
	if u, err := url.Parse(next); err != nil || u.Host != "" || u.Scheme != "" {
		return "/"
	}
	return next
}

// auth resolves the bearer token to a principal: the admin token sees everything, a tenant
// token is confined to its tenant's sandboxes, runs, events, usage and trace.
func (p *Platform) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if p.Token == "" && len(p.Tenants) == 0 {
			writeErr(w, http.StatusServiceUnavailable, errors.New("API tokens not configured"))
			return
		}
		got := []byte(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		var pr *Principal
		if p.Token != "" && subtle.ConstantTimeCompare(got, []byte(p.Token)) == 1 {
			pr = &Principal{Admin: true, Subject: "admin-token"}
		}
		for tok, tenant := range p.Tenants { // no early exit: timing stays independent of the match position
			if subtle.ConstantTimeCompare(got, []byte(tok)) == 1 && pr == nil {
				pr = &Principal{Tenant: tenant, Subject: "tenant-token"}
			}
		}
		if pr == nil && p.Verifier != nil && strings.Count(string(got), ".") == 2 {
			v, err := p.Verifier.Verify(r.Context(), string(got))
			if err != nil {
				writeErr(w, http.StatusUnauthorized, fmt.Errorf("token: %w", err))
				return
			}
			pr = &v
		}
		if pr == nil {
			writeErr(w, http.StatusUnauthorized, errors.New("bad token"))
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), principalKey{}, *pr)))
	}
}

// sandbox loads the sandbox of the request and enforces tenant ownership.
func (p *Platform) sandbox(w http.ResponseWriter, r *http.Request) (*model.Sandbox, bool) {
	sb, err := p.Orch.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		writeOrchErr(w, err)
		return nil, false
	}
	if pr := principalOf(r); !pr.admin() && sb.Tenant != pr.Tenant {
		writeErr(w, http.StatusForbidden, errors.New("sandbox belongs to another tenant"))
		return nil, false
	}
	return sb, true
}

// tenantScope narrows a requested tenant filter to what the caller may see.
func tenantScope(w http.ResponseWriter, r *http.Request, requested string) (string, bool) {
	pr := principalOf(r)
	if pr.admin() {
		return requested, true
	}
	if requested != "" && requested != pr.Tenant {
		writeErr(w, http.StatusForbidden, errors.New("token is scoped to tenant "+pr.Tenant))
		return "", false
	}
	return pr.Tenant, true
}

// idempotent replays the stored response when the client repeats a request with the same
// Idempotency-Key (per tenant and route, 24h). Only 2xx responses are stored.
func (p *Platform) idempotent(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("Idempotency-Key")
		if key == "" {
			next(w, r)
			return
		}
		if len(key) > 200 {
			writeErr(w, http.StatusBadRequest, errors.New("Idempotency-Key longer than 200 bytes"))
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		sum := sha256.Sum256(body)
		hash := hex.EncodeToString(sum[:])
		full := principalOf(r).Tenant + "|" + r.Method + " " + r.URL.Path + "|" + key
		// The reservation is the lock: concurrent repeats see it and wait, a repeat with another
		// body is refused, and a finished request is replayed from the stored response.
		existing, reserved, err := p.Orch.Store.ReserveIdempotent(r.Context(), full, hash)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		if !reserved {
			switch {
			case existing.BodyHash != hash:
				writeErr(w, http.StatusUnprocessableEntity, errors.New("Idempotency-Key was already used with a different request body"))
			case existing.InProgress():
				w.Header().Set("Retry-After", "1")
				writeErr(w, http.StatusConflict, errors.New("a request with this Idempotency-Key is still in progress"))
			default:
				w.Header().Set("Idempotency-Replayed", "true")
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(existing.Status)
				w.Write(existing.Body)
			}
			return
		}
		rec := &recorder{ResponseWriter: w, code: 200}
		next(rec, r)
		if rec.code >= 200 && rec.code < 300 {
			err = p.Orch.Store.PutIdempotent(r.Context(), &store.Idempotent{Key: full, BodyHash: hash, Status: rec.code, Body: rec.body.Bytes()})
		} else {
			err = p.Orch.Store.ReleaseIdempotent(r.Context(), full)
		}
		if err != nil {
			// The response is already on the wire; the reservation stays until IdempotencyStale,
			// so a fast retry gets 409 rather than a duplicate, and the log says why.
			p.Log.Error("finish idempotent request", "key", key, "err", err)
		}
	}
}

type recorder struct {
	http.ResponseWriter
	code int
	body bytes.Buffer
}

func (rc *recorder) WriteHeader(c int) { rc.code = c; rc.ResponseWriter.WriteHeader(c) }
func (rc *recorder) Write(b []byte) (int, error) {
	rc.body.Write(b)
	return rc.ResponseWriter.Write(b)
}

func (p *Platform) list(w http.ResponseWriter, r *http.Request) {
	q := &query{r: r}
	limit := q.limit(100, 1000)
	f := store.SandboxFilter{Owner: q.str("owner"), Slug: q.str("slug"), Cursor: q.cursor("after"),
		Status: q.oneOf("status", "", "creating", "waking", "running", "stopping", "sleeping", "deleting", "error"),
		Limit:  limit + 1}
	if q.err != nil {
		writeErr(w, http.StatusBadRequest, q.err)
		return
	}
	tenant, ok := tenantScope(w, r, q.str("tenant"))
	if !ok {
		return
	}
	f.Tenant = tenant
	sbs, err := p.Orch.Store.QuerySandboxes(r.Context(), f)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if sbs == nil {
		sbs = []*model.Sandbox{}
	}
	// One extra row tells whether a next page exists; the cursor is the last row returned.
	if len(sbs) > limit {
		sbs = sbs[:limit]
		last := sbs[limit-1]
		w.Header().Set("X-Next-Cursor", store.Cursor{At: last.CreatedAt, ID: last.ID}.Encode())
	}
	writeJSON(w, http.StatusOK, sbs)
}

func (p *Platform) create(w http.ResponseWriter, r *http.Request) {
	var req orchestrator.CreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	pr := principalOf(r)
	if !pr.admin() {
		if req.Tenant != "" && req.Tenant != pr.Tenant {
			writeErr(w, http.StatusForbidden, errors.New("token is scoped to tenant "+pr.Tenant))
			return
		}
		req.Tenant = pr.Tenant
	}
	req.Admin = pr.admin()
	if p.TTLFromToken && !pr.Expires.IsZero() {
		req.ExpiresBefore = pr.Expires
	}
	sb, err := p.Orch.Create(r.Context(), req)
	if err != nil && sb == nil {
		writeOrchErr(w, err)
		return
	}
	// A runtime failure after the record exists is reported through the sandbox itself
	// (status error, error text); the client owns the record and can wake or delete it.
	writeJSON(w, http.StatusCreated, sb)
}

func (p *Platform) get(w http.ResponseWriter, r *http.Request) {
	if sb, ok := p.sandbox(w, r); ok {
		writeJSON(w, http.StatusOK, sb)
	}
}

func (p *Platform) update(w http.ResponseWriter, r *http.Request) {
	if _, ok := p.sandbox(w, r); !ok {
		return
	}
	var req orchestrator.UpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	sb, err := p.Orch.Update(r.Context(), r.PathValue("id"), req)
	if err != nil {
		writeOrchErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, sb)
}

// delete removes the sandbox. 204 means pod, volume and record are gone; 502 means the
// cluster refused and the record stays in status `deleting` for a retry (ours or yours).
func (p *Platform) delete(w http.ResponseWriter, r *http.Request) {
	if _, ok := p.sandbox(w, r); !ok {
		return
	}
	if err := p.Orch.Delete(r.Context(), r.PathValue("id")); err != nil {
		writeOrchErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (p *Platform) sleep(w http.ResponseWriter, r *http.Request) {
	if _, ok := p.sandbox(w, r); !ok {
		return
	}
	q := &query{r: r}
	force := q.boolean("force", false)
	if q.err != nil {
		writeErr(w, http.StatusBadRequest, q.err)
		return
	}
	sb, err := p.Orch.Sleep(r.Context(), r.PathValue("id"), force)
	if err != nil {
		writeOrchErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, sb)
}

func (p *Platform) wake(w http.ResponseWriter, r *http.Request) {
	if _, ok := p.sandbox(w, r); !ok {
		return
	}
	sb, err := p.Orch.Wake(r.Context(), r.PathValue("id"))
	if err != nil {
		writeOrchErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, sb)
}

func (p *Platform) touch(w http.ResponseWriter, r *http.Request) {
	if _, ok := p.sandbox(w, r); !ok {
		return
	}
	p.Orch.Touch(r.Context(), r.PathValue("id"))
	w.WriteHeader(http.StatusNoContent)
}

func (p *Platform) listRuns(w http.ResponseWriter, r *http.Request) {
	if _, ok := p.sandbox(w, r); !ok {
		return
	}
	q := &query{r: r}
	limit := q.limit(100, 1000)
	f := store.Filter{SandboxID: r.PathValue("id"), Cursor: q.cursor("after"), Limit: limit + 1,
		Status: q.oneOf("status", "", "queued", "running", "done", "failed", "cancelled")}
	if q.err != nil {
		writeErr(w, http.StatusBadRequest, q.err)
		return
	}
	runs, err := p.Orch.Store.QueryRuns(r.Context(), f)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if runs == nil {
		runs = []*model.Run{}
	}
	if len(runs) > limit {
		runs = runs[:limit]
		last := runs[limit-1]
		w.Header().Set("X-Next-Cursor", store.Cursor{At: last.CreatedAt, ID: last.ID}.Encode())
	}
	writeJSON(w, http.StatusOK, runs)
}

func (p *Platform) createRun(w http.ResponseWriter, r *http.Request) {
	if _, ok := p.sandbox(w, r); !ok {
		return
	}
	var req struct {
		Task string `json:"task"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	run, err := p.Orch.CreateRun(r.Context(), r.PathValue("id"), req.Task)
	if err != nil {
		writeOrchErr(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, run)
}

func (p *Platform) ownRun(w http.ResponseWriter, r *http.Request) (*model.Run, bool) {
	if _, ok := p.sandbox(w, r); !ok {
		return nil, false
	}
	run, err := p.Orch.Store.GetRun(r.Context(), r.PathValue("run"))
	if err != nil || run.SandboxID != r.PathValue("id") {
		writeErr(w, http.StatusNotFound, fmt.Errorf("run %s: %w", r.PathValue("run"), store.ErrNotFound))
		return nil, false
	}
	return run, true
}

func (p *Platform) getRun(w http.ResponseWriter, r *http.Request) {
	if run, ok := p.ownRun(w, r); ok {
		writeJSON(w, http.StatusOK, run)
	}
}

func (p *Platform) cancelRun(w http.ResponseWriter, r *http.Request) {
	if _, ok := p.ownRun(w, r); !ok {
		return
	}
	run, err := p.Orch.CancelRun(r.Context(), r.PathValue("id"), r.PathValue("run"))
	if err != nil {
		writeOrchErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, run)
}

func (p *Platform) input(w http.ResponseWriter, r *http.Request) {
	if _, ok := p.sandbox(w, r); !ok {
		return
	}
	var req struct {
		Text string `json:"text"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if err := p.Orch.Input(r.Context(), r.PathValue("id"), r.PathValue("run"), req.Text); err != nil {
		writeOrchErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// events streams persisted events after ?after (or Last-Event-ID) and then live ones.
// With stream=false it returns one JSON page; X-Next-Cursor is set when the page is full.
func (p *Platform) events(w http.ResponseWriter, r *http.Request) {
	if _, ok := p.sandbox(w, r); !ok {
		return
	}
	id := r.PathValue("id")
	q := &query{r: r}
	f := store.Filter{SandboxID: id, RunID: q.str("run"), AfterID: q.int64("after", 0)}
	if v := r.Header.Get("Last-Event-ID"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			writeErr(w, http.StatusBadRequest, errors.New("Last-Event-ID must be an integer"))
			return
		}
		f.AfterID = n
	}
	stream := q.boolean("stream", true)
	limit := q.limit(1000, 5000)
	if q.err != nil {
		writeErr(w, http.StatusBadRequest, q.err)
		return
	}
	if !stream {
		f.Limit = limit + 1
		evs, err := p.Orch.Store.QueryEvents(r.Context(), f)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		if evs == nil {
			evs = []*model.Event{}
		}
		if len(evs) > limit {
			evs = evs[:limit]
			w.Header().Set("X-Next-Cursor", strconv.FormatInt(evs[limit-1].ID, 10))
		}
		writeJSON(w, http.StatusOK, evs)
		return
	}
	fl, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, http.StatusInternalServerError, errors.New("streaming unsupported"))
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	ch, cancel := p.Hub.Subscribe(id)
	defer cancel()
	send := func(e model.Event) {
		b, _ := json.Marshal(e)
		fmt.Fprintf(w, "id: %d\nevent: %s\ndata: %s\n\n", e.ID, e.Type, b)
		fl.Flush()
	}
	// Replay, then live. Events published during replay are buffered in the channel.
	for {
		f.Limit = 500
		evs, err := p.Orch.Store.QueryEvents(r.Context(), f)
		if err != nil || len(evs) == 0 {
			break
		}
		for _, e := range evs {
			send(*e)
			f.AfterID = e.ID
		}
	}
	after := f.AfterID
	keepalive := time.NewTicker(20 * time.Second)
	defer keepalive.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case e := <-ch:
			if e.ID > after {
				if f.RunID == "" || e.RunID == f.RunID {
					send(e)
				}
				after = e.ID
			}
		case <-keepalive.C:
			fmt.Fprint(w, ": keepalive\n\n")
			fl.Flush()
		}
	}
}

func (p *Platform) setPreview(w http.ResponseWriter, r *http.Request) {
	if _, ok := p.sandbox(w, r); !ok {
		return
	}
	var req struct {
		Port   int    `json:"port"`
		Access string `json:"access"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	sb, err := p.Orch.SetPreview(r.Context(), r.PathValue("id"), req.Port, req.Access)
	if err != nil {
		writeOrchErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, sb)
}

func (p *Platform) previewTicket(w http.ResponseWriter, r *http.Request) {
	sb, ok := p.sandbox(w, r)
	if !ok {
		return
	}
	var req struct {
		User string `json:"user"`
		Next string `json:"next"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if sb.Preview == nil {
		writeErr(w, http.StatusConflict, errors.New("sandbox has no preview"))
		return
	}
	if p.Ingress == nil {
		writeErr(w, http.StatusServiceUnavailable, errors.New("ingress disabled"))
		return
	}
	next := SafeNext(req.Next)
	t := p.Ingress.SignTicket(sb.Preview.Host, req.User, time.Minute)
	writeJSON(w, http.StatusOK, map[string]string{
		"ticket":   t,
		"redirect": fmt.Sprintf("https://%s/__sandbox/auth?ticket=%s&next=%s", sb.Preview.Host, url.QueryEscape(t), url.QueryEscape(next)),
	})
}

// usage answers GET /v1/usage: cost and consumption per tenant / slug / sandbox / run / day.
func (p *Platform) usage(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	q := &query{r: r}
	from, to := q.when("from"), q.when("to")
	if d := q.duration("since"); d > 0 {
		from = now.Add(-d)
	}
	groupBy := q.oneOf("group_by", "", usage.ByTenant, usage.BySlug, usage.BySandbox, usage.ByRun, usage.ByDay)
	if q.err != nil {
		writeErr(w, http.StatusBadRequest, q.err)
		return
	}
	tenant, ok := tenantScope(w, r, q.str("tenant"))
	if !ok {
		return
	}
	rep, err := usage.Build(r.Context(), p.Orch.Store, usage.Query{
		Tenant: tenant, Slug: q.str("slug"), SandboxID: q.str("sandbox"), RunID: q.str("run"),
		From: from, To: to, GroupBy: groupBy,
	}, p.Pricing, now)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if rep.Rows == nil {
		rep.Rows = []usage.Row{}
	}
	writeJSON(w, http.StatusOK, rep)
}

// trace answers GET /v1/trace: the event log across sandboxes, filtered by tenant / slug /
// sandbox / run / type. JSON page by default (X-Next-Cursor when full); stream=true follows live over SSE.
func (p *Platform) trace(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	q := &query{r: r}
	from, to := q.when("from"), q.when("to")
	if d := q.duration("since"); d > 0 {
		from = now.Add(-d)
	}
	after := q.int64("after", 0)
	if v := r.Header.Get("Last-Event-ID"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			writeErr(w, http.StatusBadRequest, errors.New("Last-Event-ID must be an integer"))
			return
		}
		after = n
	}
	limit := q.limit(500, 5000)
	stream := q.boolean("stream", false)
	if q.err != nil {
		writeErr(w, http.StatusBadRequest, q.err)
		return
	}
	tenant, ok := tenantScope(w, r, q.str("tenant"))
	if !ok {
		return
	}
	f := store.Filter{Tenant: tenant, Slug: q.str("slug"), SandboxID: q.str("sandbox"), RunID: q.str("run"),
		From: from, To: to, AfterID: after, Limit: limit + 1}
	// Agent output is the bulk of the log; a trace is about what happened, so it is opt-in.
	switch t := q.str("type"); t {
	case "":
		f.Types = []string{model.EventStatus, model.EventRunQueued, model.EventRunStart, model.EventRunDone,
			model.EventRunCancel, model.EventInput, model.EventEgressOK, model.EventEgressDen}
	case "all":
	default:
		f.Types = strings.Split(t, ",")
	}
	if !stream {
		evs, err := p.Orch.Store.QueryEvents(r.Context(), f)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		if evs == nil {
			evs = []*model.Event{}
		}
		if len(evs) > limit {
			evs = evs[:limit]
			w.Header().Set("X-Next-Cursor", strconv.FormatInt(evs[limit-1].ID, 10))
		}
		writeJSON(w, http.StatusOK, evs)
		return
	}
	fl, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, http.StatusInternalServerError, errors.New("streaming unsupported"))
		return
	}
	want := func(e *model.Event) bool {
		g := f
		g.Limit, g.To = 0, time.Time{}
		return matches(g, e)
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	ch, cancel := p.Hub.Subscribe(events.All)
	defer cancel()
	send := func(e model.Event) {
		b, _ := json.Marshal(e)
		fmt.Fprintf(w, "id: %d\nevent: %s\ndata: %s\n\n", e.ID, e.Type, b)
		fl.Flush()
	}
	for {
		g := f
		g.AfterID, g.Limit = after, 500
		evs, err := p.Orch.Store.QueryEvents(r.Context(), g)
		if err != nil || len(evs) == 0 {
			break
		}
		for _, e := range evs {
			send(*e)
			after = e.ID
		}
	}
	keepalive := time.NewTicker(20 * time.Second)
	defer keepalive.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case e := <-ch:
			if e.ID > after && want(&e) {
				send(e)
				after = e.ID
			}
		case <-keepalive.C:
			fmt.Fprint(w, ": keepalive\n\n")
			fl.Flush()
		}
	}
}

// matches applies a store.Filter to one live event (same semantics as the store query).
func matches(f store.Filter, e *model.Event) bool {
	if f.Tenant != "" && e.Tenant != f.Tenant || f.Slug != "" && e.Slug != f.Slug ||
		f.SandboxID != "" && e.SandboxID != f.SandboxID || f.RunID != "" && e.RunID != f.RunID {
		return false
	}
	if !f.From.IsZero() && e.At.Before(f.From) {
		return false
	}
	if len(f.Types) == 0 {
		return true
	}
	for _, t := range f.Types {
		if t == e.Type {
			return true
		}
	}
	return false
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// ErrorBody is the JSON every error response carries. `error` stays for older clients;
// `code` is the stable machine-readable class, `request_id` matches the server log line.
type ErrorBody struct {
	Error     string `json:"error"`
	Code      string `json:"code"`
	RequestID string `json:"request_id,omitempty"`
}

// Stable error codes (see openapi.yaml → Error).
const (
	CodeBadRequest   = "bad_request"
	CodeUnauthorized = "unauthorized"
	CodeForbidden    = "forbidden"
	CodeNotFound     = "not_found"
	CodeConflict     = "conflict"
	CodeTooLarge     = "too_large"
	CodeQuota        = "quota_exceeded"
	CodeUpstream     = "upstream_failed"
	CodeInternal     = "internal"
	CodeUnavailable  = "unavailable"
)

func codeFor(status int) string {
	switch status {
	case http.StatusBadRequest:
		return CodeBadRequest
	case http.StatusUnauthorized:
		return CodeUnauthorized
	case http.StatusForbidden:
		return CodeForbidden
	case http.StatusNotFound:
		return CodeNotFound
	case http.StatusConflict:
		return CodeConflict
	case http.StatusRequestEntityTooLarge:
		return CodeTooLarge
	case http.StatusTooManyRequests:
		return CodeQuota
	case http.StatusBadGateway:
		return CodeUpstream
	case http.StatusServiceUnavailable:
		return CodeUnavailable
	}
	return CodeInternal
}

func writeErr(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, ErrorBody{Error: err.Error(), Code: codeFor(code), RequestID: w.Header().Get("X-Request-Id")})
}

func writeOrchErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeErr(w, http.StatusNotFound, err)
	case errors.Is(err, orchestrator.ErrBadRequest):
		writeErr(w, http.StatusBadRequest, err)
	case errors.Is(err, orchestrator.ErrForbidden):
		writeErr(w, http.StatusForbidden, err)
	case errors.Is(err, orchestrator.ErrConflict), errors.Is(err, store.ErrConflict):
		writeErr(w, http.StatusConflict, err)
	case errors.Is(err, orchestrator.ErrQuota):
		writeErr(w, http.StatusTooManyRequests, err)
	case errors.Is(err, orchestrator.ErrRuntime):
		writeErr(w, http.StatusBadGateway, err)
	default:
		writeErr(w, http.StatusInternalServerError, err)
	}
}

// query parses parameters strictly: a malformed value is a 400, never a silent default.
type query struct {
	r   *http.Request
	err error
}

func (q *query) str(name string) string { return q.r.URL.Query().Get(name) }

func (q *query) has(name string) bool { return q.r.URL.Query().Has(name) }

func (q *query) fail(name string, err error) {
	if q.err == nil {
		q.err = fmt.Errorf("%s: %w", name, err)
	}
}

func (q *query) int64(name string, def int64) int64 {
	v := q.str(name)
	if v == "" {
		return def
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < 0 {
		q.fail(name, errors.New("must be a non-negative integer"))
		return def
	}
	return n
}

// limit returns ?limit bounded to (0, max], or def when absent.
func (q *query) limit(def, max int) int {
	n := int(q.int64("limit", int64(def)))
	if n <= 0 || n > max {
		q.fail("limit", fmt.Errorf("must be between 1 and %d", max))
		return def
	}
	return n
}

func (q *query) boolean(name string, def bool) bool {
	v := q.str(name)
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		q.fail(name, errors.New("must be true or false"))
		return def
	}
	return b
}

func (q *query) duration(name string) time.Duration {
	v := q.str(name)
	if v == "" {
		return 0
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		q.fail(name, errors.New("must be a positive duration such as 24h"))
		return 0
	}
	return d
}

func (q *query) when(name string) time.Time {
	v := q.str(name)
	if v == "" {
		return time.Time{}
	}
	if t, err := time.Parse(time.RFC3339, v); err == nil {
		return t
	}
	t, err := time.Parse("2006-01-02", v)
	if err != nil {
		q.fail(name, errors.New("must be RFC 3339 or YYYY-MM-DD"))
	}
	return t
}

func (q *query) cursor(name string) store.Cursor {
	c, err := store.ParseCursor(q.str(name))
	if err != nil {
		q.fail(name, err)
	}
	return c
}

func (q *query) oneOf(name, def string, allowed ...string) string {
	v := q.str(name)
	if v == "" {
		return def
	}
	for _, a := range allowed {
		if v == a {
			return v
		}
	}
	q.fail(name, fmt.Errorf("must be one of %s", strings.Join(allowed, ", ")))
	return def
}

type statusWriter struct {
	http.ResponseWriter
	code int
}

func (s *statusWriter) WriteHeader(c int) { s.code = c; s.ResponseWriter.WriteHeader(c) }
func (s *statusWriter) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func newRequestID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// logRequests assigns every request an id (or keeps the client's X-Request-Id), echoes it in
// the response and logs the outcome under it.
func logRequests(log *slog.Logger, next http.Handler) http.Handler {
	if log == nil {
		log = slog.Default()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rid := r.Header.Get("X-Request-Id")
		if rid == "" || len(rid) > 64 {
			rid = newRequestID()
		}
		w.Header().Set("X-Request-Id", rid)
		sw := &statusWriter{ResponseWriter: w, code: 200}
		start := time.Now()
		next.ServeHTTP(sw, r)
		log.Info("http", "rid", rid, "method", r.Method, "path", r.URL.Path, "code", sw.code, "took_ms", time.Since(start).Milliseconds())
	})
}

func swaggerUI(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(`<!doctype html><html><head><title>agent-sandbox API</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/5.17.14/swagger-ui.min.css"></head>
<body><div id="ui"></div>
<script src="https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/5.17.14/swagger-ui-bundle.min.js"></script>
<script>SwaggerUIBundle({url:'/openapi.yaml',dom_id:'#ui'})</script></body></html>`))
}

// shutdownServer is a small helper for main.
func ShutdownServer(ctx context.Context, srv *http.Server) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
}
