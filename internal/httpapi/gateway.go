package httpapi

import (
	"bufio"
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
	return logRequests(g.Log, g.routes().ServeMux)
}

func (g *Gateway) routes() *routeMux {
	mux := newRouteMux()
	mux.HandleFunc("GET /healthz", healthz)
	mux.Handle("GET /authz", g.Authz)
	mux.Handle("POST /authz", g.Authz)
	mux.HandleFunc("POST /bootstrap", g.bootstrap)
	mux.HandleFunc("GET /crl.pem", g.crl)
	mux.HandleFunc("GET /agent/runs/next", g.agent(g.nextRun))
	mux.HandleFunc("POST /agent/runs/{run}/events", g.agent(g.appendOutput))
	mux.HandleFunc("GET /agent/runs/{run}/input", g.agent(g.pollInput))
	mux.HandleFunc("POST /agent/runs/{run}/finish", g.agent(g.finish))
	mux.HandleFunc("GET /agent/fs/requests", g.agent(g.fsRequests))
	mux.HandleFunc("POST /agent/fs/results", g.agent(g.fsResult))
	mux.HandleFunc("POST /agent/blobs", g.agent(g.putBlob))
	mux.HandleFunc("GET /agent/blobs/{name...}", g.agent(g.getBlob))
	if g.MCP != nil {
		mux.Handle("/", g.MCP) // everything else is an MCP host proxied by Caddy (see gateway template)
	}
	return mux
}

func (g *Gateway) bootstrap(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	var req registrar.BootstrapRequest
	if err := decodeStrict(w, r, &req, smallBodyLimit); err != nil {
		writeBodyErr(w, err)
		return
	}
	res, err := g.Registrar.Bootstrap(r.Context(), token, req)
	switch {
	case errors.Is(err, registrar.ErrUnauthorized):
		writeErr(w, http.StatusUnauthorized, err)
		return
	case errors.Is(err, registrar.ErrUnavailable):
		// The platform's side (the store, a lost race with the pod's own retry): agent-init
		// retries a 503, and exits on a 400.
		writeErr(w, http.StatusServiceUnavailable, err)
		return
	case err != nil:
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
	run, err := g.Orch.NextRunFor(r.Context(), id.SandboxID, runOwner(id), waitParam(r))
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

// runOwner is what a claim is handed to: the pod's instance ("" when the certificate has none).
func runOwner(id *identity.Identity) string {
	if id.Instance <= 0 {
		return ""
	}
	return strconv.Itoa(id.Instance)
}

// runCall reads the run a call is about and the attempt it names (X-Run-Attempt, 0 when the
// runner does not send it), refuses an attempt the run was handed out past (409), and
// confirms the claim: the runner's first call about a run says it got it, so it is not handed
// out again. false: the response is written.
func (g *Gateway) runCall(w http.ResponseWriter, r *http.Request, id *identity.Identity) (*model.Run, int, bool) {
	run, err := g.ownRun(r, id)
	if err != nil {
		writeOrchErr(w, err)
		return nil, 0, false
	}
	attempt := 0
	if h := r.Header.Get("X-Run-Attempt"); h != "" {
		if attempt, err = strconv.Atoi(h); err != nil || attempt < 1 {
			writeErr(w, http.StatusBadRequest, errors.New("X-Run-Attempt must be a positive integer"))
			return nil, 0, false
		}
	}
	if err := g.Orch.AckClaim(r.Context(), run, runOwner(id), attempt); err != nil {
		writeOrchErr(w, err)
		return nil, 0, false
	}
	return run, attempt, true
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
	run, attempt, ok := g.runCall(w, r, id)
	if !ok {
		return
	}
	// Limits: MaxBodyBytes per request, MaxLineBytes per line. Exceeding either is a 413 and
	// nothing after the offending point is stored; lines before it are, and are acknowledged.
	// A body that breaks off otherwise stores nothing: the runner sends it again whole.
	//
	// The lines, the usage and session they carry and, with X-Batch-Id, the batch's progress
	// are stored in one write, or nothing is. A 5xx does not say which (the commit may have
	// happened and its acknowledgement been lost), so the runner retries under the same
	// X-Batch-Id: a retry (after a lost response, on any replica, even at once) stores only what
	// is not stored yet; the same id with another body, or with more lines than a body that was
	// stored whole, is a 422.
	batchID := ""
	if bid := r.Header.Get("X-Batch-Id"); bid != "" && len(bid) <= 100 {
		batchID = bid
	}
	var lines []string
	sc := bufio.NewScanner(maxBytes(w, r.Body, MaxBodyBytes))
	sc.Buffer(make([]byte, 0, 64<<10), MaxLineBytes)
	for sc.Scan() {
		if line := sc.Text(); line != "" {
			lines = append(lines, line)
		}
	}
	tooLarge := ""
	if err := sc.Err(); err != nil {
		var mbe *http.MaxBytesError
		switch {
		case errors.As(err, &mbe):
			tooLarge = fmt.Sprintf("body exceeds %d bytes", MaxBodyBytes)
		case errors.Is(err, bufio.ErrTooLong):
			tooLarge = fmt.Sprintf("line exceeds %d bytes", MaxLineBytes)
		default:
			writeErr(w, http.StatusBadRequest, fmt.Errorf("read body (stored 0 lines): %w", err))
			return
		}
	}
	res, err := g.Orch.OutputBatch(r.Context(), id.SandboxID, run.ID, batchID, attempt, lines, tooLarge != "")
	switch {
	case errors.Is(err, store.ErrBatchMismatch):
		writeErr(w, http.StatusUnprocessableEntity, err)
		return
	case errors.Is(err, store.ErrNotFound), errors.Is(err, store.ErrConflict):
		writeOrchErr(w, err) // refused before anything was written
		return
	case err != nil:
		// Not "nothing was stored": the commit may have happened with its acknowledgement lost.
		// The detail goes to the request log; the runner is told what makes the retry safe.
		noteInternal(w, err)
		writeErr(w, http.StatusServiceUnavailable, errors.New("the batch may or may not have been stored: send it again with the same X-Batch-Id"))
		return
	}
	if tooLarge != "" {
		writeErr(w, http.StatusRequestEntityTooLarge, fmt.Errorf("%s (stored %d lines)", tooLarge, len(lines)))
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"accepted": len(lines), "skipped": res.Skipped})
}

// Output stream limits for POST /agent/runs/{run}/events.
const (
	MaxBodyBytes = 4 << 20
	MaxLineBytes = 1 << 20
)

func (g *Gateway) pollInput(w http.ResponseWriter, r *http.Request, id *identity.Identity) {
	run, _, ok := g.runCall(w, r, id)
	if !ok {
		return
	}
	// The runner acts on run.cancel, not on the status: a cancelled run without one (written by
	// a replica of an older release that failed between the two) gets it now.
	if err := g.Orch.EnsureCancelDelivered(r.Context(), run); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
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
			Types: []string{model.EventInput, model.EventReply, model.EventRunCancel, model.EventRunClose}, RunScope: run.ID, Limit: 200})
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
	run, attempt, ok := g.runCall(w, r, id)
	if !ok {
		return
	}
	var req struct {
		ExitCode int          `json:"exit_code"`
		Usage    *model.Usage `json:"usage,omitempty"`
	}
	// A body that does not decode is refused, never read as exit 0 without usage: that would
	// record a failed run as a success. The runner retries finish until it is acknowledged.
	if err := decodeStrict(w, r, &req, smallBodyLimit); err != nil {
		writeBodyErr(w, err)
		return
	}
	if err := g.Orch.FinishRunAttempt(r.Context(), id.SandboxID, run.ID, attempt, req.ExitCode, req.Usage); err != nil {
		writeOrchErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// fsRequests long-polls for file operations the control plane asked this pod to perform
// (fs.request events without an answer yet).
func (g *Gateway) fsRequests(w http.ResponseWriter, r *http.Request, id *identity.Identity) {
	after, err := strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
	if r.URL.Query().Get("after") != "" && err != nil {
		writeErr(w, http.StatusBadRequest, errors.New("after must be an integer event id"))
		return
	}
	deadline := time.Now().Add(waitParam(r))
	for {
		out, err := g.Orch.PendingFS(r.Context(), id.SandboxID, after)
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

// fsResult records the pod's answer to a file request.
func (g *Gateway) fsResult(w http.ResponseWriter, r *http.Request, id *identity.Identity) {
	var res model.FSResult
	if err := decodeStrict(w, r, &res, MaxBodyBytes); err != nil {
		writeBodyErr(w, err)
		return
	}
	if res.Blob != "" && !orchestrator.OwnsFSBlob(id.SandboxID, res.Blob) {
		writeErr(w, http.StatusForbidden, errors.New("blob belongs to another sandbox"))
		return
	}
	if err := g.Orch.AnswerFS(r.Context(), id.SandboxID, res); err != nil {
		writeOrchErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// putBlob stores file content the pod read, under a name confined to its sandbox.
func (g *Gateway) putBlob(w http.ResponseWriter, r *http.Request, id *identity.Identity) {
	data, err := io.ReadAll(maxBytes(w, r.Body, orchestrator.MaxFileBytes))
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeErr(w, http.StatusRequestEntityTooLarge, fmt.Errorf("file exceeds %d bytes", orchestrator.MaxFileBytes))
			return
		}
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	name := orchestrator.FSBlobName(id.SandboxID)
	if err := g.Orch.Store.PutBlob(r.Context(), name, data); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"name": name, "size": len(data)})
}

// getBlob hands the pod content the control plane wants written into its workspace.
func (g *Gateway) getBlob(w http.ResponseWriter, r *http.Request, id *identity.Identity) {
	name := r.PathValue("name")
	if !orchestrator.OwnsFSBlob(id.SandboxID, name) {
		writeErr(w, http.StatusNotFound, store.ErrNotFound)
		return
	}
	data, err := g.Orch.Store.GetBlob(r.Context(), name)
	if err != nil {
		writeOrchErr(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.Write(data)
}
