package usage

import (
	"context"
	"fmt"
	"testing"
	"time"

	"agent-sandbox/internal/model"
	"agent-sandbox/internal/store"
)

// smallCapStore caps a QueryRuns without a limit the way Postgres does (at MaxRunsPerQuery),
// only lower, so a test can cross the cap.
type smallCapStore struct {
	store.Store
	limit int
}

func (s smallCapStore) QueryRuns(ctx context.Context, f store.Filter) ([]*model.Run, error) {
	if f.Limit <= 0 || f.Limit > s.limit {
		f.Limit = s.limit
	}
	return s.Store.QueryRuns(ctx, f)
}

// The report read runs in one query with no limit, which the store caps: past the cap a 30-day
// report silently under-counted runs and model cost. It pages now, including across runs that
// share a creation time.
func TestReportCountsRunsPastTheStoreCap(t *testing.T) {
	ctx := context.Background()
	mem := store.NewMemory()
	t0 := time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC)
	const n = 2*runPage + 7
	for i := range n {
		at := t0.Add(time.Duration(i/3) * time.Second) // three runs per instant
		if err := mem.CreateRun(ctx, &model.Run{ID: fmt.Sprintf("r%05d", i), SandboxID: "sb", Tenant: "acme", Slug: "dev",
			Status: model.RunDone, CreatedAt: at, Usage: model.Usage{CostUSD: 1}}); err != nil {
			t.Fatal(err)
		}
	}
	st := smallCapStore{Store: mem, limit: runPage + 1}
	now := t0.Add(24 * time.Hour)
	rep, err := Build(ctx, st, Query{From: t0, To: now, GroupBy: ByTenant}, Pricing{}, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Rows) != 1 || rep.Rows[0].Runs != n || rep.Rows[0].ModelUSD != n {
		t.Fatalf("report over %d runs: %+v", n, rep.Rows)
	}
}
