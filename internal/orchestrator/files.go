package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"strings"
	"time"

	"agent-sandbox/internal/model"
	"agent-sandbox/internal/store"
)

// File transfer limits and the blob namespace used for them.
const (
	MaxFileBytes = 16 << 20
	fsBlobPrefix = "fs/"
	fsBlobTTL    = time.Hour
)

// FSBlobName is the blob a file transfer of sandbox id travels in; the agent API confines a
// pod to its own sandbox's names.
func FSBlobName(sandboxID string) string { return fsBlobPrefix + sandboxID + "/" + newID("blob") }

// OwnsFSBlob reports whether name is a transfer blob of sandbox id.
func OwnsFSBlob(sandboxID, name string) bool {
	return strings.HasPrefix(name, fsBlobPrefix+sandboxID+"/")
}

// CleanFSPath normalises a workspace path: relative to /workspace, no escape above it.
func CleanFSPath(p string) (string, error) {
	p = strings.TrimSpace(p)
	p = strings.TrimPrefix(p, "/workspace")
	p = strings.TrimPrefix(p, "/")
	if p == "" {
		return ".", nil
	}
	c := path.Clean("/" + p)
	if c == "/" {
		return ".", nil
	}
	return strings.TrimPrefix(c, "/"), nil
}

// FS asks the sandbox's pod to perform one file operation and waits for its answer. A
// sleeping sandbox is woken first when wake is set (otherwise ErrConflict). The pod answers
// through an fs.result event, so the request works whichever replica the pod talks to.
func (o *Orchestrator) FS(ctx context.Context, sandboxID string, req model.FSRequest, wake bool, timeout time.Duration) (*model.FSResult, error) {
	if o.Hub == nil {
		return nil, errors.New("file operations need the event hub")
	}
	p, err := CleanFSPath(req.Path)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadRequest, err)
	}
	req.Path = p
	switch req.Op {
	case model.FSList, model.FSRead, model.FSWrite:
	default:
		return nil, fmt.Errorf("%w: unknown file operation %q", ErrBadRequest, req.Op)
	}
	sb, err := o.Store.GetSandbox(ctx, sandboxID)
	if err != nil {
		return nil, err
	}
	switch sb.Status {
	case model.StatusDeleting, model.StatusStopping:
		return nil, fmt.Errorf("%w: sandbox is %s", ErrConflict, sb.Status)
	case model.StatusSleeping, model.StatusError:
		if !wake {
			return nil, fmt.Errorf("%w: sandbox is %s (wake it first)", ErrConflict, sb.Status)
		}
		if _, err := o.Wake(ctx, sandboxID); err != nil {
			return nil, err
		}
	}
	req.ID = newID("fs")
	ch, cancel := o.Hub.Subscribe(sandboxID)
	defer cancel()
	b, _ := json.Marshal(req)
	if err := o.emit(ctx, model.Event{SandboxID: sandboxID, Type: model.EventFSRequest, Data: string(b)}); err != nil {
		return nil, err
	}
	if timeout <= 0 {
		timeout = time.Minute
	}
	deadline := time.After(timeout)
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-deadline:
			return nil, fmt.Errorf("%w: no answer to %s %s", ErrTimeout, req.Op, req.Path)
		case e := <-ch:
			if e.Type != model.EventFSResult {
				continue
			}
			var res model.FSResult
			if json.Unmarshal([]byte(e.Data), &res) != nil || res.Request != req.ID {
				continue
			}
			return &res, nil
		}
	}
}

// PendingFS lists the file requests of a sandbox after event id after that have no answer
// yet (runner side). Requests older than ten minutes are not worth answering: the caller
// stopped waiting long ago.
func (o *Orchestrator) PendingFS(ctx context.Context, sandboxID string, after int64) ([]*model.Event, error) {
	since := time.Now().Add(-10 * time.Minute)
	reqs, err := o.Store.QueryEvents(ctx, store.Filter{SandboxID: sandboxID, AfterID: after, Types: []string{model.EventFSRequest}, From: since, Limit: 100})
	if err != nil {
		return nil, err
	}
	if len(reqs) == 0 {
		return nil, nil
	}
	done, err := o.Store.QueryEvents(ctx, store.Filter{SandboxID: sandboxID, AfterID: reqs[0].ID, Types: []string{model.EventFSResult}, From: since, Limit: 500})
	if err != nil {
		return nil, err
	}
	answered := map[string]bool{}
	for _, e := range done {
		var res model.FSResult
		if json.Unmarshal([]byte(e.Data), &res) == nil {
			answered[res.Request] = true
		}
	}
	var out []*model.Event
	for _, e := range reqs {
		var req model.FSRequest
		if json.Unmarshal([]byte(e.Data), &req) == nil && !answered[req.ID] {
			out = append(out, e)
		}
	}
	return out, nil
}

// AnswerFS records the pod's answer to a file request.
func (o *Orchestrator) AnswerFS(ctx context.Context, sandboxID string, res model.FSResult) error {
	if res.Request == "" {
		return fmt.Errorf("%w: request id is required", ErrBadRequest)
	}
	b, _ := json.Marshal(res)
	return o.emit(ctx, model.Event{SandboxID: sandboxID, Type: model.EventFSResult, Data: string(b)})
}

// purgeFSBlobs drops transfer blobs nobody collected (the reconciler calls it on the leader).
func (o *Orchestrator) purgeFSBlobs(ctx context.Context) {
	if n, err := o.Store.DeleteBlobsBefore(ctx, fsBlobPrefix, time.Now().Add(-fsBlobTTL)); err != nil {
		o.Log.Warn("purge file blobs", "err", err)
	} else if n > 0 {
		o.Log.Info("purged uncollected file blobs", "count", n)
	}
}
