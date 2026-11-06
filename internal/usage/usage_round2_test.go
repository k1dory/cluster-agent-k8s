package usage

import (
	"context"
	"errors"
	"testing"
	"time"

	"agent-sandbox/internal/model"
	"agent-sandbox/internal/store"
)

// failingEvents fails every read of the event log, the way a lost database connection does
// mid-report.
type failingEvents struct{ store.Store }

func (failingEvents) QueryEvents(context.Context, store.Filter) ([]*model.Event, error) {
	return nil, errors.New("connection reset")
}

// A failed read of the status history used to make podSeconds return nil: the report came
// back successful with zero compute. It is an error of the report now.
func TestReportFailsWhenPodHistoryCannotBeReadRound2(t *testing.T) {
	ctx := context.Background()
	mem := store.NewMemory()
	t0 := time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC)
	_ = mem.AppendEvent(ctx, &model.Event{SandboxID: "sb", Tenant: "acme", Slug: "dev", Type: model.EventStatus, Data: "waking", At: t0})
	now := t0.Add(time.Hour)
	rep, err := Build(ctx, failingEvents{mem}, Query{From: t0, To: now, GroupBy: ByTenant}, Pricing{PodHourUSD: 1}, now)
	if err == nil {
		t.Fatalf("a report without its pod history succeeded: %+v", rep)
	}
}

// With group_by=day an interval over midnight used to be attributed whole to the day it
// started; each day gets its own part now.
func TestDailyPodTimeSplitsAtMidnightRound2(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	start := time.Date(2026, 10, 20, 23, 50, 0, 0, time.UTC)
	ev := func(data string, at time.Time) {
		if err := st.AppendEvent(ctx, &model.Event{SandboxID: "sb", Tenant: "acme", Slug: "dev", Type: model.EventStatus, Data: data, At: at}); err != nil {
			t.Fatal(err)
		}
	}
	ev("waking", start)
	ev("sleeping", start.Add(20*time.Minute))
	// And a longer one, 22:00 on the 22nd to 02:00 on the 23rd.
	ev("waking", start.Add(46*time.Hour+10*time.Minute))
	ev("stopping", start.Add(50*time.Hour+10*time.Minute))
	from, to := start.Add(-time.Hour), start.Add(60*time.Hour)
	rep, err := Build(ctx, st, Query{From: from, To: to, GroupBy: ByDay}, Pricing{}, to)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]float64{}
	for _, r := range rep.Rows {
		got[r.Key] = r.PodSeconds
	}
	want := map[string]float64{"2026-10-20": 600, "2026-10-21": 600, "2026-10-22": 7200, "2026-10-23": 7200}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: %v pod seconds, want %v (rows %v)", k, got[k], v, got)
		}
	}
	if rep.Total.PodSeconds != 600+600+7200+7200 {
		t.Errorf("total %v", rep.Total.PodSeconds)
	}
}
