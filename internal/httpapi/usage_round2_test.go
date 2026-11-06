package httpapi

import (
	"context"
	"errors"
	"testing"

	"agent-sandbox/internal/model"
	"agent-sandbox/internal/store"
)

// eventsDown fails every read of the event log.
type eventsDown struct{ store.Store }

func (eventsDown) QueryEvents(context.Context, store.Filter) ([]*model.Event, error) {
	return nil, errors.New("connection reset")
}

// A usage report whose pod history could not be read used to answer 200 with zero compute;
// it answers 500 now.
func TestUsageReportsAFailedHistoryReadRound2(t *testing.T) {
	s := newStack(t)
	s.orch.Store = eventsDown{s.orch.Store}
	resp, body := call(t, "GET", s.platform.URL+"/v1/usage?tenant=alice", "t0k", nil, nil)
	if resp.StatusCode != 500 {
		t.Fatalf("usage over a failing log: %d %s", resp.StatusCode, body)
	}
}
