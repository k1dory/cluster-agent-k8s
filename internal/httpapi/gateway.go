package httpapi

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"agent-sandbox/internal/authz"
	"agent-sandbox/internal/identity"
	"agent-sandbox/internal/model"
	"agent-sandbox/internal/orchestrator"
	"agent-sandbox/internal/registrar"
	"agent-sandbox/internal/store"
)

// Gateway is the listener only Caddy talks to: forward_auth, bootstrap and the agent API.
// Bind it to localhost or the gateway-only interface; never expose it to the sandbox VLAN directly.
type Gateway struct {
	Orch      *orchestrator.Orchestrator
	Registrar *registrar.Registrar
	Authz     *authz.Handler
	// MCP handles requests Caddy routes through the MCP proxy (policy hosts with an mcp rule).
	MCP http.Handler
	Log *slog.Logger
}

// Routes builds the gateway mux.
func (g *Gateway) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok\n")) })
	mux.Handle("GET /authz", g.Authz)
	mux.Handle("POST /authz", g.Authz)
	mux.HandleFunc("POST /bootstrap", g.bootstrap)
	mux.HandleFunc("GET /crl.pem", g.crl)
	mux.HandleFunc("GET /agent/runs/next", g.agent(g.nextRun))
	mux.HandleFunc("POST /agent/runs/{run}/events", g.agent(g.appendOutput))
	mux.HandleFunc("GET /agent/runs/{run}/input", g.agent(g.pollInput))
	mux.HandleFunc("POST /agent/runs/{run}/finish", g.agent(g.finish))
	if g.MCP != nil {
		mux.Handle("/", g.MCP) // everything else is an MCP host proxied by Caddy (see gateway template)
	}
	return logRequests(g.Log, mux)
}

func (g *Gateway) bootstrap(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	var req registrar.BootstrapRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	res, err := g.Registrar.Bootstrap(r.Context(), token, req)
	if errors.Is(err, registrar.ErrUnauthorized) {
		writeErr(w, http.StatusUnauthorized, err)
		return
	}
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (g *Gateway) crl(w http.ResponseWriter, r *http.Request) {
	b, err := g.Registrar.CRL(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Write(b)
}

type agentHandler func(w http.ResponseWriter, r *http.Request, id *identity.Identity)

// agent authenticates the call by the certificate Caddy forwarded and checks it is still live.
func (g *Gateway) agent(next agentHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := identity.FromRequest(r)
		if err != nil {
			writeErr(w, http.StatusForbidden, err)
			return
		}
		if _, err := g.Registrar.Check(r.Context(), id); err != nil {
			writeErr(w, http.StatusForbidden, err)
			return
		}
		if id.SandboxID == "" {
			writeErr(w, http.StatusForbidden, errors.New("certificate has no sandbox SAN"))
			return
		}
		next(w, r, id)
	}
}

func waitParam(r *http.Request) time.Duration {
	d, err := time.ParseDuration(r.URL.Query().Get("wait"))
	if err != nil || d <= 0 || d > 2*time.Minute {
		return 30 * time.Second
	}
	return d
}

func (g *Gateway) nextRun(w http.ResponseWriter, r *http.Request, id *identity.Identity) {
	run, err := g.Orch.NextRun(r.Context(), id.SandboxID, waitParam(r))
	if errors.Is(err, store.ErrNotFound) || errors.Is(err, r.Context().Err()) && err != nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, run)
}

func (g *Gateway) ownRun(r *http.Request, id *identity.Identity) (*model.Run, error) {
	run, err := g.Orch.Store.GetRun(r.Context(), r.PathValue("run"))
	if err != nil {
		return nil, err
	}
	if run.SandboxID != id.SandboxID {
		return nil, store.ErrNotFound
	}
	return run, nil
}

func (g *Gateway) appendOutput(w http.ResponseWriter, r *http.Request, id *identity.Identity) {
	run, err := g.ownRun(r, id)
	if err != nil {
		writeOrchErr(w, err)
		return
	}
	// Limits: MaxBodyBytes per request, MaxLineBytes per line. Exceeding either is a 413 and
	// nothing after the offending point is stored; lines before it are, and are acknowledged.
	//
	// With X-Batch-Id the server remembers how many lines of that batch it stored, so a retry
	// of the same batch (after a lost response or a 5xx) skips them instead of duplicating
	// output and usage. Progress is recorded before every response, success or error.
	batchKey := ""
	skip := 0
	if bid := r.Header.Get("X-Batch-Id"); bid != "" && len(bid) <= 100 {
		batchKey = "batch|" + run.ID + "|" + bid
		if rec, err := g.Orch.Store.GetIdempotent(r.Context(), batchKey); err == nil {
			skip = rec.Status
		}
	}
	n := 0
	remember := func() {
		if batchKey != "" {
			_ = g.Orch.Store.PutIdempotent(r.Context(), &store.Idempotent{Key: batchKey, Status: n, Body: []byte{}})
		}
	}
	sc := bufio.NewScanner(http.MaxBytesReader(w, r.Body, MaxBodyBytes))
	sc.Buffer(make([]byte, 0, 64<<10), MaxLineBytes)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		if n < skip {
			n++
			continue
		}
		if err := g.Orch.Output(r.Context(), id.SandboxID, run.ID, line); err != nil {
			remember()
			writeErr(w, http.StatusInternalServerError, fmt.Errorf("stored %d lines, then: %w", n, err))
			return
		}
		n++
	}
	remember()
	if err := sc.Err(); err != nil {
		var mbe *http.MaxBytesError
		switch {
		case errors.As(err, &mbe):
			writeErr(w, http.StatusRequestEntityTooLarge, fmt.Errorf("body exceeds %d bytes (stored %d lines)", MaxBodyBytes, n))
		case errors.Is(err, bufio.ErrTooLong):
			writeErr(w, http.StatusRequestEntityTooLarge, fmt.Errorf("line exceeds %d bytes (stored %d lines)", MaxLineBytes, n))
		default:
			writeErr(w, http.StatusBadRequest, fmt.Errorf("read body (stored %d lines): %w", n, err))
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"accepted": n, "skipped": skip})
}

// Output stream limits for POST /agent/runs/{run}/events.
const (
	MaxBodyBytes = 4 << 20
	MaxLineBytes = 1 << 20
)

func (g *Gateway) pollInput(w http.ResponseWriter, r *http.Request, id *identity.Identity) {
	run, err := g.ownRun(r, id)
	if err != nil {
		writeOrchErr(w, err)
		return
	}
	after, err := strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
	if r.URL.Query().Get("after") != "" && err != nil {
		writeErr(w, http.StatusBadRequest, errors.New("after must be an integer event id"))
		return
	}
	deadline := time.Now().Add(waitParam(r))
	for {
		// Filter by type in the store, so a run that writes a lot of output cannot push a
		// message or a cancel beyond the page the poll reads.
		// Type and run scope are both applied in the store, before LIMIT: events of other runs
		// in this sandbox cannot fill the page and hide ours.
		out, err := g.Orch.Store.QueryEvents(r.Context(), store.Filter{SandboxID: id.SandboxID, AfterID: after,
			Types: []string{model.EventInput, model.EventRunCancel}, RunScope: run.ID, Limit: 200})
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		if out == nil {
			out = []*model.Event{}
		}
		if len(out) > 0 || time.Now().After(deadline) {
			writeJSON(w, http.StatusOK, out)
			return
		}
		select {
		case <-r.Context().Done():
			return
		case <-time.After(500 * time.Millisecond):
		}
	}
}

func (g *Gateway) finish(w http.ResponseWriter, r *http.Request, id *identity.Identity) {
	run, err := g.ownRun(r, id)
	if err != nil {
		writeOrchErr(w, err)
		return
	}
	var req struct {
		ExitCode int          `json:"exit_code"`
		Usage    *model.Usage `json:"usage,omitempty"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if err := g.Orch.FinishRun(r.Context(), id.SandboxID, run.ID, req.ExitCode, req.Usage); err != nil {
		writeOrchErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
