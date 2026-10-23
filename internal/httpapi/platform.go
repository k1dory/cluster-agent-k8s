// Package httpapi exposes sandboxd over HTTP: the platform API for clients and the
// gateway-facing API (authz, bootstrap, agent endpoints).
package httpapi

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
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
)

// Platform is the client-facing API.
type Platform struct {
	Orch     *orchestrator.Orchestrator
	Hub      *events.Hub
	Policies *policy.Set
	Ingress  *ingress.Handler
	Token    string
	Log      *slog.Logger
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
	mux.HandleFunc("POST /v1/sandboxes", p.auth(p.create))
	mux.HandleFunc("GET /v1/sandboxes/{id}", p.auth(p.get))
	mux.HandleFunc("DELETE /v1/sandboxes/{id}", p.auth(p.delete))
	mux.HandleFunc("POST /v1/sandboxes/{id}/sleep", p.auth(p.sleep))
	mux.HandleFunc("POST /v1/sandboxes/{id}/wake", p.auth(p.wake))
	mux.HandleFunc("POST /v1/sandboxes/{id}/touch", p.auth(p.touch))
	mux.HandleFunc("GET /v1/sandboxes/{id}/runs", p.auth(p.listRuns))
	mux.HandleFunc("POST /v1/sandboxes/{id}/runs", p.auth(p.createRun))
	mux.HandleFunc("GET /v1/sandboxes/{id}/runs/{run}", p.auth(p.getRun))
	mux.HandleFunc("POST /v1/sandboxes/{id}/runs/{run}/cancel", p.auth(p.cancelRun))
	mux.HandleFunc("POST /v1/sandboxes/{id}/runs/{run}/input", p.auth(p.input))
	mux.HandleFunc("GET /v1/sandboxes/{id}/events", p.auth(p.events))
	mux.HandleFunc("PUT /v1/sandboxes/{id}/preview", p.auth(p.setPreview))
	mux.HandleFunc("POST /v1/sandboxes/{id}/preview/ticket", p.auth(p.previewTicket))
	mux.HandleFunc("GET /v1/policies", p.auth(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, p.Policies.Slugs())
	}))
	return logRequests(p.Log, mux)
}

func (p *Platform) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if p.Token == "" {
			writeErr(w, http.StatusServiceUnavailable, errors.New("API token not configured"))
			return
		}
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if subtle.ConstantTimeCompare([]byte(got), []byte(p.Token)) != 1 {
			writeErr(w, http.StatusUnauthorized, errors.New("bad token"))
			return
		}
		next(w, r)
	}
}

func (p *Platform) list(w http.ResponseWriter, r *http.Request) {
	sbs, err := p.Orch.List(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if sbs == nil {
		sbs = []*model.Sandbox{}
	}
	writeJSON(w, http.StatusOK, sbs)
}

func (p *Platform) create(w http.ResponseWriter, r *http.Request) {
	var req orchestrator.CreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	sb, err := p.Orch.Create(r.Context(), req)
	if err != nil {
		writeOrchErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, sb)
}

func (p *Platform) get(w http.ResponseWriter, r *http.Request) {
	sb, err := p.Orch.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		writeOrchErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, sb)
}

func (p *Platform) delete(w http.ResponseWriter, r *http.Request) {
	if err := p.Orch.Delete(r.Context(), r.PathValue("id")); err != nil {
		writeOrchErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (p *Platform) sleep(w http.ResponseWriter, r *http.Request) {
	force, _ := strconv.ParseBool(r.URL.Query().Get("force"))
	sb, err := p.Orch.Sleep(r.Context(), r.PathValue("id"), force)
	if err != nil {
		writeOrchErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, sb)
}

func (p *Platform) wake(w http.ResponseWriter, r *http.Request) {
	sb, err := p.Orch.Wake(r.Context(), r.PathValue("id"))
	if err != nil {
		writeOrchErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, sb)
}

func (p *Platform) touch(w http.ResponseWriter, r *http.Request) {
	if _, err := p.Orch.Get(r.Context(), r.PathValue("id")); err != nil {
		writeOrchErr(w, err)
		return
	}
	p.Orch.Touch(r.Context(), r.PathValue("id"))
	w.WriteHeader(http.StatusNoContent)
}

func (p *Platform) listRuns(w http.ResponseWriter, r *http.Request) {
	runs, err := p.Orch.Store.ListRuns(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if runs == nil {
		runs = []*model.Run{}
	}
	writeJSON(w, http.StatusOK, runs)
}

func (p *Platform) createRun(w http.ResponseWriter, r *http.Request) {
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

func (p *Platform) getRun(w http.ResponseWriter, r *http.Request) {
	run, err := p.Orch.Store.GetRun(r.Context(), r.PathValue("run"))
	if err != nil || run.SandboxID != r.PathValue("id") {
		writeErr(w, http.StatusNotFound, store.ErrNotFound)
		return
	}
	writeJSON(w, http.StatusOK, run)
}

func (p *Platform) cancelRun(w http.ResponseWriter, r *http.Request) {
	run, err := p.Orch.CancelRun(r.Context(), r.PathValue("id"), r.PathValue("run"))
	if err != nil {
		writeOrchErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, run)
}

func (p *Platform) input(w http.ResponseWriter, r *http.Request) {
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
func (p *Platform) events(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, err := p.Orch.Get(r.Context(), id); err != nil {
		writeOrchErr(w, err)
		return
	}
	after, _ := strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
	if v := r.Header.Get("Last-Event-ID"); v != "" {
		after, _ = strconv.ParseInt(v, 10, 64)
	}
	runFilter := r.URL.Query().Get("run")
	want := func(e model.Event) bool { return runFilter == "" || e.RunID == runFilter }
	if stream, _ := strconv.ParseBool(r.URL.Query().Get("stream")); r.URL.Query().Has("stream") && !stream {
		// Plain JSON page of the log, for clients that do not speak SSE.
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		if limit <= 0 || limit > 5000 {
			limit = 1000
		}
		evs, err := p.Orch.Store.ListEvents(r.Context(), id, after, limit)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		out := []*model.Event{}
		for _, e := range evs {
			if want(*e) {
				out = append(out, e)
			}
		}
		writeJSON(w, http.StatusOK, out)
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
		evs, err := p.Orch.Store.ListEvents(r.Context(), id, after, 500)
		if err != nil || len(evs) == 0 {
			break
		}
		for _, e := range evs {
			if want(*e) {
				send(*e)
			}
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
			if e.ID > after {
				if want(e) {
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
	var req struct {
		User string `json:"user"`
		Next string `json:"next"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	sb, err := p.Orch.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		writeOrchErr(w, err)
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
	t := p.Ingress.SignTicket(sb.Preview.Host, req.User, time.Minute)
	next := req.Next
	if next == "" {
		next = "/"
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"ticket":   t,
		"redirect": fmt.Sprintf("https://%s/__sandbox/auth?ticket=%s&next=%s", sb.Preview.Host, t, next),
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, map[string]string{"error": err.Error()})
}

func writeOrchErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeErr(w, http.StatusNotFound, err)
	case errors.Is(err, orchestrator.ErrBadRequest):
		writeErr(w, http.StatusBadRequest, err)
	case errors.Is(err, orchestrator.ErrConflict):
		writeErr(w, http.StatusConflict, err)
	default:
		writeErr(w, http.StatusInternalServerError, err)
	}
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

func logRequests(log *slog.Logger, next http.Handler) http.Handler {
	if log == nil {
		log = slog.Default()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sw := &statusWriter{ResponseWriter: w, code: 200}
		start := time.Now()
		next.ServeHTTP(sw, r)
		log.Info("http", "method", r.Method, "path", r.URL.Path, "code", sw.code, "took_ms", time.Since(start).Milliseconds())
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
