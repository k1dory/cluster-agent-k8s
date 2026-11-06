package store

import (
	"context"

	"agent-sandbox/internal/model"
)

// StatusCounter counts sandboxes by status and the unfinished runs (queued, running) by
// status, for the state gauges. Finished runs are not counted: the table grows with history,
// and what finished is a rate (a counter over the run events), not a level.
type StatusCounter interface {
	CountByStatus(ctx context.Context) (sandboxes, runs map[string]int, err error)
}

// SandboxStatuses and ActiveRunStatuses are the statuses the counts always carry (zeros too).
var (
	SandboxStatuses = []model.SandboxStatus{model.StatusCreating, model.StatusRunning, model.StatusSleeping,
		model.StatusWaking, model.StatusStopping, model.StatusDeleting, model.StatusError}
	ActiveRunStatuses = []model.RunStatus{model.RunQueued, model.RunRunning}
)

func zeroCounts() (sandboxes, runs map[string]int) {
	sandboxes, runs = map[string]int{}, map[string]int{}
	for _, s := range SandboxStatuses {
		sandboxes[string(s)] = 0
	}
	for _, s := range ActiveRunStatuses {
		runs[string(s)] = 0
	}
	return sandboxes, runs
}

func (m *Memory) CountByStatus(ctx context.Context) (sandboxes, runs map[string]int, err error) {
	sandboxes, runs = zeroCounts()
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, sb := range m.sandboxes {
		sandboxes[string(sb.Status)]++
	}
	for _, r := range m.runs {
		if _, active := runs[string(r.Status)]; active {
			runs[string(r.Status)]++
		}
	}
	return sandboxes, runs, nil
}
