package httpapi

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"agent-sandbox/internal/harness"
	"agent-sandbox/internal/model"
	"agent-sandbox/internal/orchestrator"
	"agent-sandbox/internal/store"
	"github.com/k1dory/acpx"
)

// chatRoutes mounts the conversation and workspace endpoints of a sandbox.
//
//	POST /v1/sandboxes/{id}/messages          send the next message (JSON or multipart with files)
//	GET  /v1/sandboxes/{id}/messages          the conversation after ?after (one page)
//	GET  /v1/sandboxes/{id}/messages/stream   the conversation as SSE: replay, then live
//	POST /v1/sandboxes/{id}/messages/close    end the open conversation (the run finishes)
//	POST /v1/sandboxes/{id}/requests/{rid}    answer what the agent asks (a permission, a question)
//	GET  /v1/sandboxes/{id}/files?path=&depth= list the workspace
//	GET  /v1/sandboxes/{id}/files/content?path= read a file
//	PUT  /v1/sandboxes/{id}/files/content?path= write a file (the body)
func (p *Platform) chatRoutes(mux *routeMux) {
	mux.HandleFunc("POST /v1/sandboxes/{id}/messages", p.auth(removeForm(p.idempotentUpload(p.sendMessage))))
	mux.HandleFunc("GET /v1/sandboxes/{id}/messages", p.auth(p.listMessages))
	mux.HandleFunc("GET /v1/sandboxes/{id}/messages/stream", p.auth(p.streamMessages))
	mux.HandleFunc("POST /v1/sandboxes/{id}/messages/close", p.auth(p.closeConversation))
	mux.HandleFunc("POST /v1/sandboxes/{id}/requests/{request_id}", p.auth(p.idempotent(p.replyRequest)))
	mux.HandleFunc("GET /v1/sandboxes/{id}/files", p.auth(p.listFiles))
	mux.HandleFunc("GET /v1/sandboxes/{id}/files/content", p.auth(p.readFile))
	mux.HandleFunc("PUT /v1/sandboxes/{id}/files/content", p.auth(p.writeFile))
}

// MessageRequest is the JSON body of POST /messages.
type MessageRequest struct {
	Text string `json:"text"`
	// Attachments names workspace files already uploaded (PUT /files/content) that the message
	// refers to; they are listed after the text so the agent knows where to look.
	Attachments []string `json:"attachments,omitempty"`
}

// MessageResponse says which run carries the message and how it got there.
type MessageResponse struct {
	Run      *model.Run `json:"run"`
	Delivery string     `json:"delivery"` // input | resumed | new
	Files    []string   `json:"files,omitempty"`
}

var uploadNameRe = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// sendMessage: JSON {text, attachments} or multipart/form-data with a text field and file
// parts (each written to uploads/<name> in the workspace before the message is sent).
func (p *Platform) sendMessage(w http.ResponseWriter, r *http.Request) {
	if _, ok := p.sandbox(w, r); !ok {
		return
	}
	id := r.PathValue("id")
	var req MessageRequest
	var uploaded []string
	if isMultipart(r) {
		// Capped as a whole (every file at its cap, see body.go), so what ParseMultipartForm
		// spills to disk is bounded too; a form the idempotency middleware already parsed is
		// not parsed again.
		capBody(w, r, multipartBodyLimit)
		if err := r.ParseMultipartForm(multipartMemory); err != nil {
			writeBodyErr(w, err)
			return
		}
		// The parser stops at the closing boundary; what follows (the epilogue) counts against
		// the cap too, and is read to its end before anything is written or sent.
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			writeBodyErr(w, err)
			return
		}
		req.Text = r.FormValue("text")
		files := r.MultipartForm.File["file"]
		if len(files) > MaxUploadFiles {
			writeErr(w, http.StatusRequestEntityTooLarge, fmt.Errorf("at most %d files per message", MaxUploadFiles))
			return
		}
		for _, fh := range files {
			name := uploadNameRe.ReplaceAllString(path.Base(fh.Filename), "_")
			if name == "" || name == "." || name == ".." {
				writeErr(w, http.StatusBadRequest, fmt.Errorf("attachment %q has no usable name", fh.Filename))
				return
			}
			f, err := fh.Open()
			if err != nil {
				writeErr(w, http.StatusBadRequest, err)
				return
			}
			data, err := io.ReadAll(io.LimitReader(f, orchestrator.MaxFileBytes+1))
			f.Close()
			if err != nil || len(data) > orchestrator.MaxFileBytes {
				writeErr(w, http.StatusRequestEntityTooLarge, fmt.Errorf("attachment %s exceeds %d bytes", name, orchestrator.MaxFileBytes))
				return
			}
			target := "uploads/" + name
			if _, err := p.writeWorkspaceFile(r, id, target, data); err != nil {
				writeOrchErr(w, err)
				return
			}
			uploaded = append(uploaded, target)
		}
		req.Attachments = append(req.Attachments, uploaded...)
	} else {
		if err := decodeJSON(w, r, &req); err != nil {
			writeBodyErr(w, err)
			return
		}
	}
	text := strings.TrimSpace(req.Text)
	if len(req.Attachments) > 0 {
		var paths []string
		for _, a := range req.Attachments {
			cp, err := orchestrator.CleanFSPath(a)
			if err != nil || cp == "." || !harness.AttachmentPath("/workspace/"+cp) {
				writeErr(w, http.StatusBadRequest, fmt.Errorf("attachment path %q", a))
				return
			}
			paths = append(paths, "/workspace/"+cp)
		}
		// Listed after the text (every harness reads it); an ACP agent gets them as resource links.
		text = harness.WithAttachments(text, paths)
	}
	run, delivery, err := p.Orch.Say(r.Context(), id, text)
	if err != nil {
		writeOrchErr(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, MessageResponse{Run: run, Delivery: delivery, Files: uploaded})
}

func (p *Platform) listMessages(w http.ResponseWriter, r *http.Request) {
	if _, ok := p.sandbox(w, r); !ok {
		return
	}
	q := &query{r: r}
	after, limit, raw := q.int64("after", 0), q.limit(500, 5000), q.boolean("raw", false)
	if q.err != nil {
		writeErr(w, http.StatusBadRequest, q.err)
		return
	}
	msgs, next, err := p.Orch.Messages(r.Context(), r.PathValue("id"), after, limit, raw)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	w.Header().Set("X-Next-Cursor", strconv.FormatInt(next, 10))
	writeJSON(w, http.StatusOK, msgs)
}

// streamMessages replays the conversation after ?after (or Last-Event-ID), then follows it.
func (p *Platform) streamMessages(w http.ResponseWriter, r *http.Request) {
	if _, ok := p.sandbox(w, r); !ok {
		return
	}
	id := r.PathValue("id")
	q := &query{r: r}
	after, raw := q.int64("after", 0), q.boolean("raw", false)
	if v := r.Header.Get("Last-Event-ID"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			writeErr(w, http.StatusBadRequest, errors.New("Last-Event-ID must be an integer"))
			return
		}
		after = n
	}
	if q.err != nil {
		writeErr(w, http.StatusBadRequest, q.err)
		return
	}
	streamSSE(w, r, hubWake(p.Hub, id, model.EventRunQueued, model.EventInput, model.EventRunOutput, model.EventRunDone), 15*time.Second, after, func(ctx context.Context, after int64) ([]sseItem, int64, error) {
		msgs, next, err := p.Orch.Messages(ctx, id, after, ssePageSize, raw)
		items := make([]sseItem, 0, len(msgs))
		for _, m := range msgs {
			items = append(items, sseItem{ID: m.ID, Event: m.Role, Data: m})
		}
		return items, next, err
	})
}

// closeConversation ends the run in progress gracefully (its harness input is closed).
func (p *Platform) closeConversation(w http.ResponseWriter, r *http.Request) {
	if _, ok := p.sandbox(w, r); !ok {
		return
	}
	id := r.PathValue("id")
	run, err := p.Orch.Store.RunningRun(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusConflict, errors.New("no conversation is open"))
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	closed, err := p.Orch.CloseRun(r.Context(), id, run.ID)
	if err != nil {
		writeOrchErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, closed) // the run as it is now, not as it was before the close
}

func (p *Platform) closeRun(w http.ResponseWriter, r *http.Request) {
	if _, ok := p.ownRun(w, r); !ok {
		return
	}
	run, err := p.Orch.CloseRun(r.Context(), r.PathValue("id"), r.PathValue("run"))
	if err != nil {
		writeOrchErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, run)
}

// fsTimeout is how long a file operation waits for the pod (longer when it has to wake).
func fsTimeout(sb *model.Sandbox) time.Duration {
	if sb.Status == model.StatusRunning {
		return 60 * time.Second
	}
	return 3 * time.Minute
}

func (p *Platform) listFiles(w http.ResponseWriter, r *http.Request) {
	sb, ok := p.sandbox(w, r)
	if !ok {
		return
	}
	q := &query{r: r}
	depth, wake := int(q.int64("depth", 1)), q.boolean("wake", true)
	if q.err != nil {
		writeErr(w, http.StatusBadRequest, q.err)
		return
	}
	if depth < 1 || depth > 8 {
		writeErr(w, http.StatusBadRequest, errors.New("depth must be 1..8"))
		return
	}
	res, err := p.Orch.FS(r.Context(), sb.ID, model.FSRequest{Op: model.FSList, Path: r.URL.Query().Get("path"), Depth: depth}, wake, fsTimeout(sb))
	if err != nil {
		writeOrchErr(w, err)
		return
	}
	if !res.OK {
		writeErr(w, fsStatus(res.Error), errors.New(res.Error))
		return
	}
	if res.Entries == nil {
		res.Entries = []model.FSEntry{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": res.Entries, "truncated": res.Truncated})
}

func (p *Platform) readFile(w http.ResponseWriter, r *http.Request) {
	sb, ok := p.sandbox(w, r)
	if !ok {
		return
	}
	q := &query{r: r}
	wake := q.boolean("wake", true)
	res, err := p.Orch.FS(r.Context(), sb.ID, model.FSRequest{Op: model.FSRead, Path: r.URL.Query().Get("path")}, wake, fsTimeout(sb))
	if err != nil {
		writeOrchErr(w, err)
		return
	}
	if !res.OK {
		writeErr(w, fsStatus(res.Error), errors.New(res.Error))
		return
	}
	data, err := p.Orch.Store.GetBlob(r.Context(), res.Blob)
	if err != nil {
		writeErr(w, http.StatusBadGateway, fmt.Errorf("file content was not delivered: %w", err))
		return
	}
	_ = p.Orch.Store.DeleteBlob(r.Context(), res.Blob)
	ct := res.ContentType
	if ct == "" {
		ct = http.DetectContentType(data)
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.Header().Set("X-File-Size", strconv.FormatInt(res.Size, 10))
	w.Write(data)
}

func (p *Platform) writeFile(w http.ResponseWriter, r *http.Request) {
	sb, ok := p.sandbox(w, r)
	if !ok {
		return
	}
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
	res, err := p.writeWorkspaceFile(r, sb.ID, r.URL.Query().Get("path"), data)
	if err != nil {
		writeOrchErr(w, err)
		return
	}
	if !res.OK {
		writeErr(w, fsStatus(res.Error), errors.New(res.Error))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"path": res.Request, "size": res.Size})
}

// writeWorkspaceFile stores data as a blob and asks the pod to write it at p.
func (p *Platform) writeWorkspaceFile(r *http.Request, sandboxID, target string, data []byte) (*model.FSResult, error) {
	cp, err := orchestrator.CleanFSPath(target)
	if err != nil || cp == "." {
		return nil, fmt.Errorf("%w: path is required", orchestrator.ErrBadRequest)
	}
	sb, err := p.Orch.Get(r.Context(), sandboxID)
	if err != nil {
		return nil, err
	}
	blob := orchestrator.FSBlobName(sandboxID)
	if err := p.Orch.Store.PutBlob(r.Context(), blob, data); err != nil {
		return nil, err
	}
	defer p.Orch.Store.DeleteBlob(r.Context(), blob) //nolint:errcheck
	wake := (&query{r: r}).boolean("wake", true)
	res, err := p.Orch.FS(r.Context(), sandboxID, model.FSRequest{Op: model.FSWrite, Path: cp, Blob: blob}, wake, fsTimeout(sb))
	if err != nil {
		return nil, err
	}
	if res.OK {
		res.Request = cp
	}
	if !res.OK {
		return res, fmt.Errorf("%w: %s", orchestrator.ErrRuntime, res.Error)
	}
	return res, nil
}

// fsStatus maps the pod's error text to a status: a missing path is 404, the rest 502.
func fsStatus(msg string) int {
	switch {
	case strings.Contains(msg, "no such file"), strings.Contains(msg, "not found"):
		return http.StatusNotFound
	case strings.Contains(msg, "too large"), strings.Contains(msg, "exceeds"):
		return http.StatusRequestEntityTooLarge
	case strings.Contains(msg, "is a directory"), strings.Contains(msg, "not a directory"):
		return http.StatusBadRequest
	}
	return http.StatusBadGateway
}

// ReplyResponse names the run the reply went to.
type ReplyResponse struct {
	RunID     string `json:"run_id"`
	RequestID string `json:"request_id"`
}

// replyRequest: JSON {run_id, option_id} for a permission, {run_id, action, content} for a
// question; run_id is the request turn's (the run that asked). The runner answers the agent and
// writes the resolution (role resolved in the conversation).
func (p *Platform) replyRequest(w http.ResponseWriter, r *http.Request) {
	if _, ok := p.sandbox(w, r); !ok {
		return
	}
	var body struct {
		acpx.Reply
		RunID string `json:"run_id"`
	}
	if err := decodeJSON(w, r, &body); err != nil {
		writeBodyErr(w, err)
		return
	}
	reply := body.Reply
	reply.RequestID = r.PathValue("request_id")
	run, err := p.Orch.Reply(r.Context(), r.PathValue("id"), body.RunID, reply)
	if err != nil {
		writeOrchErr(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, ReplyResponse{RunID: run.ID, RequestID: reply.RequestID})
}
