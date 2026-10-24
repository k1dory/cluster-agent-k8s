package orchestrator

import (
	"context"
	"fmt"
	"strings"

	"agent-sandbox/internal/harness"
	"agent-sandbox/internal/model"
	"agent-sandbox/internal/store"
)

// Delivery says how a message reached the agent.
const (
	DeliveredInput   = "input"   // handed to the run in progress (or queued for the run about to start)
	DeliveredResumed = "resumed" // a new run that continues the last conversation (harness resume)
	DeliveredNew     = "new"     // a new run: no conversation to continue
)

// Say sends the next message of the sandbox's conversation. A run in progress (or queued)
// receives it as input; otherwise a new run continues the last finished run's harness session
// (the message is its prompt), or starts a fresh conversation when none exists. The run that
// carries the message is returned with how it was delivered.
func (o *Orchestrator) Say(ctx context.Context, sandboxID, text string) (*model.Run, string, error) {
	if strings.TrimSpace(text) == "" {
		return nil, "", fmt.Errorf("%w: text is required", ErrBadRequest)
	}
	sb, err := o.Store.GetSandbox(ctx, sandboxID)
	if err != nil {
		return nil, "", err
	}
	if sb.Status == model.StatusDeleting {
		return nil, "", fmt.Errorf("%w: sandbox is being deleted", ErrConflict)
	}
	runs, err := o.Store.ListRuns(ctx, sandboxID)
	if err != nil {
		return nil, "", err
	}
	var active, last *model.Run
	for _, r := range runs {
		switch r.Status {
		case model.RunRunning:
			active = r
		case model.RunQueued:
			if active == nil {
				active = r
			}
		default:
			// The conversation to continue is the latest settled run whose harness session is
			// known (a run without one, e.g. cancelled before the harness spoke, has nothing to resume).
			if r.Session != "" && (last == nil || r.CreatedAt.After(last.CreatedAt)) {
				last = r
			}
		}
	}
	if active != nil {
		if err := o.Input(ctx, sandboxID, active.ID, text); err != nil {
			return nil, "", err
		}
		return active, DeliveredInput, nil
	}
	if last != nil {
		r, err := o.queueRun(ctx, sandboxID, &model.Run{Task: text, ResumeOf: last.ID, Session: last.Session, Mode: model.RunMessage})
		if err != nil {
			return nil, "", err
		}
		return r, DeliveredResumed, nil
	}
	r, err := o.CreateRun(ctx, sandboxID, text)
	if err != nil {
		return nil, "", err
	}
	return r, DeliveredNew, nil
}

// CloseRun asks the runner to close the harness's input: an open conversation ends, the run
// finishes when the harness exits. A queued run is cancelled instead (nothing to close).
func (o *Orchestrator) CloseRun(ctx context.Context, sandboxID, runID string) (*model.Run, error) {
	r, err := o.Store.GetRun(ctx, runID)
	if err != nil || r.SandboxID != sandboxID {
		return nil, store.ErrNotFound
	}
	switch r.Status {
	case model.RunQueued:
		return o.CancelRun(ctx, sandboxID, runID)
	case model.RunRunning:
		return r, o.emit(ctx, model.Event{SandboxID: sandboxID, RunID: runID, Type: model.EventRunClose})
	}
	return r, nil
}

// Messages renders the conversation after event id after: up to limit events are scanned
// (next is the id to continue from). raw also includes harness output lines that are not
// turns, as role log.
func (o *Orchestrator) Messages(ctx context.Context, sandboxID string, after int64, limit int, raw bool) (msgs []model.Message, next int64, err error) {
	if limit <= 0 {
		limit = 500
	}
	evs, err := o.Store.QueryEvents(ctx, store.Filter{SandboxID: sandboxID, AfterID: after, Limit: limit,
		Types: []string{model.EventRunQueued, model.EventInput, model.EventRunOutput, model.EventRunDone}})
	if err != nil {
		return nil, after, err
	}
	runs := map[string]*model.Run{}
	next = after
	for _, e := range evs {
		next = e.ID
		if m, ok := o.message(ctx, *e, runs, raw); ok {
			msgs = append(msgs, m)
		}
	}
	if msgs == nil {
		msgs = []model.Message{}
	}
	return msgs, next, nil
}

// ToMessage converts one event of the stream into a conversation turn, if it is one.
func (o *Orchestrator) ToMessage(ctx context.Context, e model.Event, raw bool) (model.Message, bool) {
	return o.message(ctx, e, map[string]*model.Run{}, raw)
}

func (o *Orchestrator) message(ctx context.Context, e model.Event, runs map[string]*model.Run, raw bool) (model.Message, bool) {
	m := model.Message{ID: e.ID, RunID: e.RunID, At: e.At}
	switch e.Type {
	case model.EventRunQueued:
		r, ok := runs[e.RunID]
		if !ok {
			r, _ = o.Store.GetRun(ctx, e.RunID)
			runs[e.RunID] = r
		}
		if r == nil {
			return m, false
		}
		if r.Mode == model.RunResume {
			m.Role, m.Text = model.RoleSystem, "resumed after a rollout (continues run "+r.ResumeOf+")"
			return m, true
		}
		m.Role, m.Text = model.RoleUser, r.Task
		return m, true
	case model.EventInput:
		m.Role, m.Text = model.RoleUser, e.Data
		return m, true
	case model.EventRunOutput:
		role, text := harness.ParseMessage(e.Data)
		if role == "" {
			if !raw {
				return m, false
			}
			role, text = model.RoleLog, e.Data
		}
		m.Role, m.Text = role, text
		return m, true
	case model.EventRunDone:
		m.Role, m.Text = model.RoleSystem, "run "+e.Data
		return m, true
	}
	return m, false
}
