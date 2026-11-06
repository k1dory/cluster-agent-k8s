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
	"maps"
	"mime/multipart"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"agent-sandbox/api"
	"agent-sandbox/internal/apikeys"
	"agent-sandbox/internal/apply"
	"agent-sandbox/internal/bindings"
	"agent-sandbox/internal/catalog"
	"agent-sandbox/internal/ciauth"
	"agent-sandbox/internal/citrust"
	"agent-sandbox/internal/connections"
	"agent-sandbox/internal/credentials"
	"agent-sandbox/internal/events"
	"agent-sandbox/internal/gitrepo"
	"agent-sandbox/internal/gitsync"
	"agent-sandbox/internal/ingress"
	"agent-sandbox/internal/model"
	"agent-sandbox/internal/orchestrator"
	"agent-sandbox/internal/plan"
	"agent-sandbox/internal/policy"
	"agent-sandbox/internal/store"
	"agent-sandbox/internal/tenants"
	"agent-sandbox/internal/usage"
)

// Platform is the client-facing API.
type Platform struct {
	Orch     *orchestrator.Orchestrator
	Hub      *events.Hub
	Policies *policy.Set
	Ingress  *ingress.Handler
	Pricing  usage.Pricing
	Catalog  *catalog.Service // AgentDefinitions / EnvironmentProfiles; nil disables /v1/agents and /v1/environments
	// Connections, Bindings and TenantSettings are the other versioned resources (step 2.2);
	// each nil disables its routes.
	Connections    *connections.Service
	Bindings       *bindings.Service
	TenantSettings *tenants.Service
	Planner        *plan.Deps        // POST /v1/plan; nil disables
	Applier        *apply.Controller // POST /v1/apply, /v1/applies; nil disables
	GitRepos       *gitrepo.Service  // /v1/gitrepos; nil disables
	CITrusts       *citrust.Service  // /v1/citrusts; nil disables
	CIAuth         *ciauth.Service   // POST /v1/auth/ci; nil disables
	GitSync        *gitsync.Service  // /v1/gitrepos/{name}/check|sync|status; nil disables
	Token          string            // admin token: every tenant, every sandbox
	Tenants        map[string]string // tenant-scoped tokens: token → tenant
	// Keys authenticates tenant API keys issued through the API (sbk_…); nil disables them.
	Keys *apikeys.Service
	// Credentials are the secrets tenants bring through the API (BYOK); nil disables the routes.
	Credentials *credentials.Service
	// OAuth are the sign-ins sandboxd keeps fresh (subscriptions through the device flow); nil
	// disables their routes.
	OAuth *credentials.OAuth
	// Verifier checks bearer tokens that are not static ones (OIDC JWTs). nil disables.
	Verifier TokenVerifier
	// TTLFromToken caps the lifetime of sandboxes created with a short-lived token (and so
	// their agent certificates) at the token's expiry.
	TTLFromToken bool
	// AuthLimit bounds, per source address, POST /v1/auth/ci and failed bearer authentication
	// (see RateLimit); the zero value is on with the defaults.
	AuthLimit RateLimit
	limitOnce sync.Once
	limiter   *limiter

	Build   string // control-plane version reported by GET /v1/version
	Replica string // this replica's name (the pod), reported by GET /v1/version
	Log     *slog.Logger
}

// SetServices installs the configuration services (see internal/app).
func (p *Platform) SetServices(cat *catalog.Service, conns *connections.Service, bind *bindings.Service, tset *tenants.Service, planner *plan.Deps, applier *apply.Controller) {
	p.Catalog, p.Connections, p.Bindings, p.TenantSettings, p.Planner, p.Applier = cat, conns, bind, tset, planner, applier
}

// SetGit installs the Git repository services (see internal/app).
func (p *Platform) SetGit(repos *gitrepo.Service, sync *gitsync.Service) {
	p.GitRepos, p.GitSync = repos, sync
}

// SetCITrusts installs the CI trust catalogue (see internal/app); the exchange itself
// (CIAuth) is wired where the key service is.
func (p *Platform) SetCITrusts(trusts *citrust.Service) {
	p.CITrusts = trusts
}

// Principal is who is calling: the admin (every tenant) or one tenant. Expires is set for
// credentials with a lifetime of their own (OIDC tokens); zero for static tokens.
type Principal struct {
	Tenant  string     `json:"tenant"`
	Admin   bool       `json:"admin"`
	Subject string     `json:"subject,omitempty"`
	Expires *time.Time `json:"expires,omitempty"`
}

// expiresBefore is the cap an expiring credential puts on what it creates (zero: none).
func (pr Principal) expiresBefore() time.Time {
	if pr.Expires == nil {
		return time.Time{}
	}
	return *pr.Expires
}

func (pr Principal) admin() bool { return pr.Admin }

// TokenVerifier resolves a bearer token that is not one of the configured static tokens.
// An error that wraps ErrVerifierUnavailable says nothing about the token.
type TokenVerifier interface {
	Verify(ctx context.Context, token string) (Principal, error)
}

// ErrVerifierUnavailable marks a verification that could not be made: the identity provider
// (its discovery document, its keys) did not answer. The token is not judged, so the attempt
// it reserved is given back and the answer is 503, not 401: an outage of the provider must not
// spend an address's budget and lock out the valid tokens sent from there.
var ErrVerifierUnavailable = errors.New("token verification unavailable")

type principalKey struct{}

func principalOf(r *http.Request) Principal {
	pr, _ := r.Context().Value(principalKey{}).(Principal)
	return pr
}

// routeMux is a ServeMux that remembers its patterns, so a test can hold the routes against
// openapi.yaml.
type routeMux struct {
	*http.ServeMux
	patterns []string
}

func newRouteMux() *routeMux { return &routeMux{ServeMux: http.NewServeMux()} }

func (m *routeMux) HandleFunc(pattern string, h func(http.ResponseWriter, *http.Request)) {
	m.patterns = append(m.patterns, pattern)
	m.ServeMux.HandleFunc(pattern, h)
}

func (m *routeMux) Handle(pattern string, h http.Handler) {
	m.patterns = append(m.patterns, pattern)
	m.ServeMux.Handle(pattern, h)
}

// healthz is liveness, on both listeners.
func healthz(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok\n")) }

// Routes builds the platform mux.
func (p *Platform) Routes() http.Handler {
	return logRequests(p.Log, jsonMuxErrors(p.routes().ServeMux))
}

func (p *Platform) routes() *routeMux {
	mux := newRouteMux()
	mux.HandleFunc("GET /healthz", healthz)
	// Readiness: the store answers. A replica that lost its database stops taking traffic
	// (the others, on the same database, keep it); liveness stays /healthz, so it is not
	// restarted for an outage that is not its own.
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		if err := p.Orch.Store.Ping(ctx); err != nil {
			http.Error(w, "store: "+err.Error(), http.StatusServiceUnavailable)
			return
		}
		w.Write([]byte("ready\n"))
	})
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
	mux.HandleFunc("POST /v1/sandboxes/{id}/runs/{run}/close", p.auth(p.closeRun))
	p.chatRoutes(mux)
	mux.HandleFunc("GET /v1/sandboxes/{id}/events", p.auth(p.events))
	mux.HandleFunc("PUT /v1/sandboxes/{id}/preview", p.auth(p.setPreview))
	mux.HandleFunc("POST /v1/sandboxes/{id}/preview/ticket", p.auth(p.previewTicket))
	mux.HandleFunc("GET /v1/policies", p.auth(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, p.Policies.Slugs())
	}))
	mux.HandleFunc("GET /v1/usage", p.auth(p.usage))
	mux.HandleFunc("GET /v1/trace", p.auth(p.trace))
	p.configRoutes(mux)
	mux.HandleFunc("POST /v1/rollouts", p.auth(p.rollout))
	mux.HandleFunc("GET /v1/version", p.auth(p.version))
	p.keyRoutes(mux)
	p.credentialRoutes(mux)
	p.oauthRoutes(mux)
	p.ciAuthRoutes(mux)
	mux.HandleFunc("GET /v1/whoami", p.auth(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, principalOf(r))
	}))
	return mux
}

// rollout answers POST /v1/rollouts: move agents to another version (see orchestrator.RolloutRequest).
func (p *Platform) rollout(w http.ResponseWriter, r *http.Request) {
	var req orchestrator.RolloutRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeBodyErr(w, err)
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
	if p.Policies != nil && cfg.EnvVersion != nil {
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
		"replica":  p.Replica,
		"leader":   p.Orch.Leading(), // the replica running the reconciler
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
		if p.Token == "" && len(p.Tenants) == 0 && p.Verifier == nil && p.Keys == nil {
			writeErr(w, http.StatusServiceUnavailable, errors.New("no API tokens and no OIDC configured"))
			return
		}
		got := []byte(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		// Attempts are counted per source address. Each presented token reserves one before it
		// is checked, so concurrent guesses cannot all pass while the first are still being
		// verified; a token that authenticates (or a check that failed inside) gives it back.
		// Once the bucket is empty every token from there is refused unchecked (a check would
		// still tell a guess that is right). Requests without a token are not counted.
		lim, src := p.authLimiter(), "auth|"+sourceOf(r)
		reserved := false
		if lim != nil && len(got) > 0 {
			if d := lim.take(src); d > 0 {
				writeRateLimited(w, d)
				return
			}
			reserved = true
		}
		refund := func() {
			if reserved {
				lim.refund(src)
			}
		}
		var pr *Principal
		if p.Token != "" && subtle.ConstantTimeCompare(got, []byte(p.Token)) == 1 {
			pr = &Principal{Admin: true, Subject: "admin-token"}
		}
		for tok, tenant := range p.Tenants { // no early exit: timing stays independent of the match position
			if subtle.ConstantTimeCompare(got, []byte(tok)) == 1 && pr == nil {
				pr = &Principal{Tenant: tenant, Subject: "tenant-token"}
			}
		}
		if pr == nil && p.Keys != nil && apikeys.IsKey(string(got)) {
			k, err := p.Keys.Authenticate(r.Context(), string(got))
			if err != nil {
				if errors.Is(err, apikeys.ErrBadKey) {
					writeErr(w, http.StatusUnauthorized, errors.New("bad token"))
				} else {
					refund()
					writeErr(w, http.StatusInternalServerError, fmt.Errorf("api key: %w", err))
				}
				return
			}
			pr = &Principal{Tenant: k.Tenant, Subject: "key:" + k.ID, Expires: k.ExpiresAt}
		}
		if pr == nil && p.Verifier != nil && strings.Count(string(got), ".") == 2 {
			v, err := p.Verifier.Verify(r.Context(), string(got))
			if errors.Is(err, ErrVerifierUnavailable) {
				refund()
				writeErr(w, http.StatusServiceUnavailable, fmt.Errorf("token: %w", err))
				return
			}
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
		refund()
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

// scopeTenant is the one tenant-scope rule of the API: the admin works in the tenant it names
// (empty: the shared scope, or every tenant for a filter); a tenant principal works in its own,
// and naming another tenant is 403. With required, naming none is 400.
func scopeTenant(w http.ResponseWriter, r *http.Request, requested string, required bool) (string, bool) {
	if required && requested == "" {
		writeErr(w, http.StatusBadRequest, errors.New("tenant is required"))
		return "", false
	}
	pr := principalOf(r)
	if pr.admin() {
		return requested, true
	}
	if requested != "" && requested != pr.Tenant {
		writeErr(w, http.StatusForbidden, errOtherTenant(pr))
		return "", false
	}
	return pr.Tenant, true
}

// errOtherTenant is the refusal of a tenant principal that names another tenant.
func errOtherTenant(pr Principal) error { return errors.New("token is scoped to tenant " + pr.Tenant) }

// idempotent replays the stored response when the client repeats a request with the same
// Idempotency-Key (per tenant and route, 24h). Only 2xx responses are stored.
func (p *Platform) idempotent(next http.HandlerFunc) http.HandlerFunc { return p.keyed(false, next) }

// idempotentUpload is idempotent for the one route that takes multipart (messages): its
// multipart bodies are parsed and hashed by content. The route removes the parsed form's
// temporary files (removeForm).
func (p *Platform) idempotentUpload(next http.HandlerFunc) http.HandlerFunc {
	return p.keyed(true, next)
}

func (p *Platform) keyed(uploads bool, next http.HandlerFunc) http.HandlerFunc {
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
		hash, legacy, err := requestHash(w, r, uploads)
		if err != nil {
			writeBodyErr(w, err)
			return
		}
		full := principalOf(r).Tenant + "|" + r.Method + " " + r.URL.Path + "|" + key
		// The reservation is the lock: concurrent repeats see it and wait, a repeat with another
		// body is refused, and a finished request is replayed from the stored response.
		res, reserved, err := p.Orch.Store.ReserveIdempotent(r.Context(), full, hash)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		if !reserved {
			switch {
			case res.BodyHash != hash && (legacy == "" || res.BodyHash != legacy):
				writeErr(w, http.StatusUnprocessableEntity, errors.New("Idempotency-Key was already used with a different request body"))
			case res.InProgress() && res.Legacy() && time.Since(res.CreatedAt) > store.IdempotencyStale:
				// Left unfinished by a replica of an earlier release: what it created has a random
				// name no new attempt can find, so the request is not run again under this key.
				writeErr(w, http.StatusConflict, errors.New("a request with this Idempotency-Key did not finish before an upgrade and is not run again: check whether it took effect, then retry with a new key"))
			case res.InProgress():
				w.Header().Set("Retry-After", "1")
				writeErr(w, http.StatusConflict, errors.New("a request with this Idempotency-Key is still in progress"))
			default:
				w.Header().Set("Idempotency-Replayed", "true")
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(res.Status)
				w.Write(res.Body)
			}
			return
		}
		// What the request creates is named from the reservation's seed (orchestrator.KeyedID),
		// so an attempt that takes over an abandoned reservation finds what that one created.
		ctx := orchestrator.WithKeyedIDs(context.WithValue(r.Context(), reservationKey{}, res), res.Seed)
		rec := &recorder{ResponseWriter: w, code: http.StatusOK}
		next(rec, r.WithContext(ctx))
		// The response is held until the key's result is stored, and stored on a context the
		// client cannot cancel: a client that hangs up after the resource exists must not leave
		// the key unfinished (its retry would wait IdempotencyStale and then run again). The
		// write is conditional on the attempt's token: a holder that was slow, not dead, cannot
		// overwrite or drop the reservation of a later attempt. A release keeps the seed, so
		// the retry of a request whose outcome is unknown (it may have created the resource and
		// then failed) finds what it created.
		fctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), idempotencyFinishTimeout)
		defer cancel()
		if rec.code >= 200 && rec.code < 300 {
			err = p.Orch.Store.PutIdempotent(fctx, &store.Idempotent{Key: full, BodyHash: hash, Status: rec.code, Body: rec.body.Bytes(), Token: res.Token})
		} else {
			err = p.Orch.Store.ReleaseIdempotent(fctx, full, res.Token)
		}
		if err != nil {
			// Sent anyway: it describes what this attempt did. Unrecorded, the reservation stays
			// until IdempotencyStale and a retry then takes it over and finds the keyed
			// resource; superseded already (ErrConflict), a later attempt answers for the key.
			log := p.Log
			if log == nil {
				log = slog.Default() // as logRequests: a Platform built without a logger
			}
			log.Error("finish idempotent request", "key", key, "generation", res.Generation, "err", err)
		}
		rec.flush()
	}
}

// requestHash fingerprints the body of an idempotent request. The routes it wraps take JSON
// (or, for messages, multipart) under the body policy's cap: the hash is over the whole body,
// never a prefix of it, so two requests that differ past some offset are never taken for the
// same one; over the cap is 413.
//
// JSON is hashed as sent. A multipart body is hashed by what it carries, not by its bytes: the
// boundary is random per request, so a client's retry of the same upload never has the same
// bytes. The form is parsed here only on the route that takes uploads (files beyond
// multipartMemory spill to temporary files, which that route removes) and its handler reads
// the parsed form. Every other route reads a multipart body as the JSON it is not, under the
// JSON cap, and its handler refuses it: nothing is parsed or spilled there.
func requestHash(w http.ResponseWriter, r *http.Request, uploads bool) (hash, legacy string, err error) {
	if !uploads || !isMultipart(r) {
		body, err := readBody(w, r, jsonBodyLimit)
		if err != nil {
			return "", "", err
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		sum := sha256.Sum256(body)
		return hex.EncodeToString(sum[:]), "", nil
	}
	// The raw bytes are hashed on the way through as well: records stored before the content
	// hash hold the SHA-256 of the raw body (unprefixed), and the very retry of such a request
	// has those same bytes. legacy matches them for as long as they live (24h).
	capBody(w, r, multipartBodyLimit)
	raw := sha256.New()
	body := r.Body
	r.Body = struct {
		io.Reader
		io.Closer
	}{io.TeeReader(body, raw), body}
	if err := r.ParseMultipartForm(multipartMemory); err != nil {
		return "", "", err
	}
	if _, err := io.Copy(io.Discard, r.Body); err != nil { // the epilogue after the last part
		return "", "", err
	}
	hash, err = multipartHash(r.MultipartForm)
	if err != nil {
		return "", "", err
	}
	return multipartHashVersion + hash, hex.EncodeToString(raw.Sum(nil)), nil
}

// multipartHashVersion prefixes a content hash, so it is never taken for a raw body's.
const multipartHashVersion = "multipart-v1:"

// multipartHash is sha256 over the form's parts in a canonical order: fields by name, each
// field's values (and files) in the order they were sent, every name, file name and content
// length-prefixed so no two different forms write the same stream.
func multipartHash(form *multipart.Form) (string, error) {
	h := sha256.New()
	put := func(s string) { fmt.Fprintf(h, "%d:%s", len(s), s) }
	h.Write([]byte("multipart/form-data\n"))
	for _, name := range slices.Sorted(maps.Keys(form.Value)) {
		put("value")
		put(name)
		fmt.Fprintf(h, "%d\n", len(form.Value[name]))
		for _, v := range form.Value[name] {
			put(v)
		}
	}
	for _, name := range slices.Sorted(maps.Keys(form.File)) {
		put("file")
		put(name)
		fmt.Fprintf(h, "%d\n", len(form.File[name]))
		for _, fh := range form.File[name] {
			put(fh.Filename)
			f, err := fh.Open()
			if err != nil {
				return "", err
			}
			fmt.Fprintf(h, "%d:", fh.Size)
			_, err = io.Copy(h, f)
			f.Close()
			if err != nil {
				return "", err
			}
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// recorder holds a keyed request's response (status and body; headers go to the real writer's
// map, sent with the status) until the idempotency middleware has stored it, then flush sends it.
type recorder struct {
	http.ResponseWriter
	code        int
	wroteHeader bool
	body        bytes.Buffer
}

func (rc *recorder) WriteHeader(c int) {
	if !rc.wroteHeader {
		rc.code, rc.wroteHeader = c, true
	}
}
func (rc *recorder) Unwrap() http.ResponseWriter { return rc.ResponseWriter }
func (rc *recorder) Write(b []byte) (int, error) {
	rc.WriteHeader(http.StatusOK)
	return rc.body.Write(b)
}

func (rc *recorder) flush() {
	rc.ResponseWriter.WriteHeader(rc.code)
	if rc.body.Len() > 0 {
		rc.ResponseWriter.Write(rc.body.Bytes())
	}
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
	tenant, ok := scopeTenant(w, r, q.str("tenant"), false)
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
	if err := decodeJSON(w, r, &req); err != nil {
		writeBodyErr(w, err)
		return
	}
	pr := principalOf(r)
	if !pr.admin() {
		tenant, ok := scopeTenant(w, r, req.Tenant, false)
		if !ok {
			return
		}
		req.Tenant = tenant
	}
	req.Admin = pr.admin()
	if p.TTLFromToken {
		req.ExpiresBefore = pr.expiresBefore()
	}
	if req.AgentRef != "" {
		if err := p.resolveAgentRef(r, &req); err != nil {
			writeCatalogErr(w, err)
			return
		}
	} else if !pr.admin() && p.TenantSettings != nil && p.TenantSettings.Restricted(req.Tenant) {
		// The bare-slug path runs the server's default environment; a tenant confined to listed
		// environments (tenant settings) must create through an agent that names one of them.
		writeErr(w, http.StatusForbidden, errors.New("tenant "+req.Tenant+" is confined to its allowed environments: create with agent_ref"))
		return
	}
	// A keyed retry that took over an abandoned attempt answers with what that one created.
	if sb, ok := p.keyedSandbox(r, false); ok {
		writeJSON(w, http.StatusCreated, sb)
		return
	}
	sb, err := p.Orch.Create(r.Context(), req)
	if err != nil && sb == nil {
		if sb, ok := p.keyedSandbox(r, true); ok {
			writeJSON(w, http.StatusCreated, sb)
			return
		}
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
	if err := decodeJSON(w, r, &req); err != nil {
		writeBodyErr(w, err)
		return
	}
	if p.TTLFromToken {
		req.ExpiresBefore = principalOf(r).expiresBefore()
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
	if err := decodeJSON(w, r, &req); err != nil {
		writeBodyErr(w, err)
		return
	}
	if run, ok := p.keyedRun(r, r.PathValue("id"), false); ok {
		writeJSON(w, http.StatusAccepted, run)
		return
	}
	run, err := p.Orch.CreateRun(r.Context(), r.PathValue("id"), req.Task)
	if err != nil {
		if run, ok := p.keyedRun(r, r.PathValue("id"), true); ok {
			writeJSON(w, http.StatusAccepted, run)
			return
		}
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
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusInternalServerError, err) // the store failed: not a missing run
		return nil, false
	}
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
	if err := decodeJSON(w, r, &req); err != nil {
		writeBodyErr(w, err)
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
	if err := decodeJSON(w, r, &req); err != nil {
		writeBodyErr(w, err)
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
	if err := decodeJSON(w, r, &req); err != nil {
		writeBodyErr(w, err)
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
	t := p.Ingress.SignTicket(sb, req.User, time.Minute)
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
	tenant, ok := scopeTenant(w, r, q.str("tenant"), false)
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
	tenant, ok := scopeTenant(w, r, q.str("tenant"), false)
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
// `code` is the stable machine-readable class, `request_id` matches the server log line. A
// few errors travel with the record they are about (the sync of a repository, the plan of a
// refused apply, the rollback that could not run, the apply a conflict is with).
type ErrorBody struct {
	Error     string `json:"error"`
	Code      string `json:"code"`
	RequestID string `json:"request_id,omitempty"`
	Sync      any    `json:"sync,omitempty"`
	Plan      any    `json:"plan,omitempty"`
	Rollback  any    `json:"rollback,omitempty"`
	Apply     any    `json:"apply,omitempty"`
}

// Stable error codes (see openapi.yaml → Error). Most follow from the status (codeFor); the
// rest name a refusal more precisely than its status does.
const (
	CodeBadRequest   = "bad_request"
	CodeUnauthorized = "unauthorized"
	CodeForbidden    = "forbidden"
	CodeNotFound     = "not_found"
	CodeConflict     = "conflict"
	CodeTooLarge     = "too_large"
	CodeQuota        = "quota_exceeded"
	CodeUpstream     = "upstream_failed"
	CodeTimeout      = "timeout" // 504: the cluster or the pod did not answer in time
	CodeInternal     = "internal"
	CodeUnavailable  = "unavailable"
	CodeInvalid      = "invalid" // 422: the request was understood and refused by validation

	CodeInvalidPlan       = "invalid_plan"         // 422: a bundle does not validate; the plan is attached
	CodeNothingToRollBack = "nothing_to_roll_back" // 422: the rollback would change nothing
	CodeUnreachable       = "unreachable"          // 502: a Git repository could not be read
	CodeCredential        = "credential"           // 422: the credential a spec names is not available
	CodeStopped           = "stopped"              // 409: an apply of a sync did not finish
	CodeRateLimited       = "rate_limited"         // 429: too many attempts from this address
	CodePreviewTaken      = "preview_host_taken"   // 409: another sandbox holds the preview host
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
	case http.StatusGatewayTimeout:
		return CodeTimeout
	case http.StatusUnprocessableEntity:
		return CodeInvalid
	case http.StatusServiceUnavailable:
		return CodeUnavailable
	}
	return CodeInternal
}

// writeErr is the error response of every handler: the envelope, the code its status implies.
func writeErr(w http.ResponseWriter, status int, err error) {
	writeErrWith(w, status, ErrorBody{}, err)
}

// writeErrWith writes the envelope from base: its code (empty: the status's) and the record
// the error travels with. A 500 never carries the error text, nor a record (whose own error
// fields would carry it just the same): what failed inside (the store, the cluster) is logged
// under the request id, and the client gets the id to quote.
func writeErrWith(w http.ResponseWriter, status int, base ErrorBody, err error) {
	if base.Code == "" {
		base.Code = codeFor(status)
	}
	base.RequestID = w.Header().Get("X-Request-Id")
	base.Error = err.Error()
	if status == http.StatusInternalServerError {
		noteInternal(w, err)
		base.Error = "internal error"
		base.Sync, base.Plan, base.Rollback, base.Apply = nil, nil, nil, nil
		if base.RequestID != "" {
			base.Error += " (request " + base.RequestID + ")"
		}
	}
	writeJSON(w, status, base)
}

// noteInternal hands the detail of a 500 to the request log line (logRequests), or logs it on
// its own when the writer is not under logRequests.
func noteInternal(w http.ResponseWriter, err error) {
	for cur := w; cur != nil; {
		if sw, ok := cur.(*statusWriter); ok && sw.log {
			sw.err = err
			return
		}
		u, ok := cur.(interface{ Unwrap() http.ResponseWriter })
		if !ok {
			break
		}
		cur = u.Unwrap()
	}
	slog.Default().Error("internal error", "rid", w.Header().Get("X-Request-Id"), "err", err)
}

func writeOrchErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeErr(w, http.StatusNotFound, err)
	case errors.Is(err, orchestrator.ErrBadRequest):
		writeErr(w, http.StatusBadRequest, err)
	case errors.Is(err, orchestrator.ErrForbidden):
		writeErr(w, http.StatusForbidden, err)
	case errors.Is(err, store.ErrDuplicate):
		// Not a lost race (retrying does not help): another sandbox holds the value.
		writeErrWith(w, http.StatusConflict, ErrorBody{Code: CodePreviewTaken}, err)
	case errors.Is(err, orchestrator.ErrConflict), errors.Is(err, store.ErrConflict):
		writeErr(w, http.StatusConflict, err)
	case errors.Is(err, orchestrator.ErrQuota):
		writeErr(w, http.StatusTooManyRequests, err)
	case errors.Is(err, orchestrator.ErrRuntime):
		writeErr(w, http.StatusBadGateway, err)
	case errors.Is(err, orchestrator.ErrTimeout):
		writeErr(w, http.StatusGatewayTimeout, err)
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
	log  bool  // the request log line's writer (logRequests)
	err  error // what failed inside, for that line (writeErr on a 500)
}

func (s *statusWriter) Unwrap() http.ResponseWriter { return s.ResponseWriter }

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
		sw := &statusWriter{ResponseWriter: w, code: 200, log: true}
		start := time.Now()
		next.ServeHTTP(sw, r)
		if sw.err != nil {
			log.Error("http", "rid", rid, "method", r.Method, "path", r.URL.Path, "code", sw.code, "took_ms", time.Since(start).Milliseconds(), "err", sw.err)
			return
		}
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

// idempotencyFinishTimeout bounds storing a keyed request's result (detached from the client).
const idempotencyFinishTimeout = 10 * time.Second

// reservationKey carries a keyed request's reservation (store.Idempotent) to its handler.
type reservationKey struct{}

// keyedResult reports whether the handler should look for what an earlier attempt of the same
// keyed request created: always after the handler's own attempt failed (the store refuses a
// second resource of the keyed id: a holder that was slow, not dead, made it first; or this
// attempt made it and then failed), and before it only when an earlier attempt ran under the
// seed (generation > 1): the first attempt of a key has a fresh seed and nothing can carry its
// id yet.
func keyedResult(r *http.Request, failed bool) (seed string, ok bool) {
	res, _ := r.Context().Value(reservationKey{}).(*store.Idempotent)
	if res == nil || res.Seed == "" || !failed && res.Generation <= 1 {
		return "", false
	}
	return res.Seed, true
}

// keyedSandbox is the sandbox an earlier attempt of this keyed create made, if any.
func (p *Platform) keyedSandbox(r *http.Request, failed bool) (*model.Sandbox, bool) {
	seed, ok := keyedResult(r, failed)
	if !ok {
		return nil, false
	}
	ctx, cancel := recoveryContext(r)
	defer cancel()
	sb, err := p.Orch.Store.GetSandbox(ctx, orchestrator.KeyedID(seed, "sb"))
	return sb, err == nil
}

// keyedRun is the run an earlier attempt of this keyed request queued in the sandbox, if any.
func (p *Platform) keyedRun(r *http.Request, sandboxID string, failed bool) (*model.Run, bool) {
	seed, ok := keyedResult(r, failed)
	if !ok {
		return nil, false
	}
	ctx, cancel := recoveryContext(r)
	defer cancel()
	run, err := p.Orch.Store.GetRun(ctx, orchestrator.KeyedID(seed, "run"))
	if err != nil || run.SandboxID != sandboxID {
		return nil, false
	}
	// The attempt that queued it may have died before waking the sandbox for it.
	p.Orch.WakeForKeyedRun(ctx, run)
	return run, true
}

// recoveryContext is where a keyed request looks for what an earlier attempt created: detached
// from the client (a hang-up after the creation must not turn a found resource into an error
// and a released key) and bounded.
func recoveryContext(r *http.Request) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(r.Context()), idempotencyFinishTimeout)
}
