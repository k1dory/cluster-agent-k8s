package orchestrator

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
	"go.opentelemetry.io/otel/codes"

	"agent-sandbox/internal/events"
	"agent-sandbox/internal/model"
	"agent-sandbox/internal/store"
	"agent-sandbox/internal/telemetry"
	"agent-sandbox/internal/telemetry/telemetrytest"
)

// The public operations are spans carrying the sandbox and run ids, children of the caller's
// span; a failure is the span's status; an empty long poll is not a failure.
func TestOperationsAreSpansWithTheirIDs(t *testing.T) {
	sr := telemetrytest.Record(t)
	o := New(store.NewMemory(), NewFakeRuntime(), nil, events.New(), Config{PreviewDomain: "preview.test", IdleCheckEvery: 10 * time.Millisecond}, nil)
	ctx, parent := telemetry.Tracer().Start(context.Background(), "request")
	sb, err := o.Create(ctx, CreateRequest{Name: "traced", Slug: "backend-dev", Owner: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	sb = waitStatus(t, o, sb.ID, model.StatusRunning)
	run, err := o.CreateRun(ctx, sb.ID, "task")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := o.NextRun(ctx, sb.ID, time.Second); err != nil {
		t.Fatal(err)
	}
	if _, err := o.OutputBatch(ctx, sb.ID, run.ID, "b1", 0, []string{"line"}, false); err != nil {
		t.Fatal(err)
	}
	if err := o.FinishRun(ctx, sb.ID, run.ID, 0, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := o.NextRun(ctx, sb.ID, 10*time.Millisecond); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("empty poll: %v", err)
	}
	if _, err := o.Wake(ctx, "sb_missing"); err == nil {
		t.Fatal("waking a missing sandbox succeeded")
	}
	parent.End()

	byName := func(name string) []string {
		var ids []string
		for _, s := range telemetrytest.Named(sr, name) {
			if s.SpanContext().TraceID() != parent.SpanContext().TraceID() {
				t.Fatalf("%s is not in the caller's trace", name)
			}
			ids = append(ids, telemetrytest.Attr(s, "sandbox_id")+"/"+telemetrytest.Attr(s, "run_id"))
		}
		return ids
	}
	if got := byName("orchestrator.Create"); len(got) != 1 || got[0] != sb.ID+"/" {
		t.Fatalf("Create spans: %v", got)
	}
	for _, name := range []string{"orchestrator.Output", "orchestrator.Finish"} {
		if got := byName(name); len(got) != 1 || got[0] != sb.ID+"/"+run.ID {
			t.Fatalf("%s spans: %v", name, got)
		}
	}
	next := telemetrytest.Named(sr, "orchestrator.NextRun")
	if len(next) != 2 || telemetrytest.Attr(next[0], "run_id") != run.ID || next[1].Status().Code == codes.Error {
		t.Fatalf("NextRun spans: claimed one with run_id, an empty poll without an error: %v", next)
	}
	wake := telemetrytest.Named(sr, "orchestrator.Wake")
	if len(wake) != 1 || wake[0].Status().Code != codes.Error {
		t.Fatalf("a failed Wake is not an error span: %v", wake)
	}
}

// A reconciler pass is timed, and one that cannot list the sandboxes is counted.
func TestReconcileIsTimedAndItsFailuresCounted(t *testing.T) {
	samples := func() uint64 {
		var m dto.Metric
		_ = telemetry.ReconcileDuration.Write(&m)
		return m.GetHistogram().GetSampleCount()
	}
	st := &failingList{Store: store.NewMemory()}
	o := New(st, NewFakeRuntime(), nil, events.New(), Config{PreviewDomain: "preview.test"}, nil)
	before, errsBefore := samples(), testutil.ToFloat64(telemetry.ReconcileErrors)
	o.Reconcile(t.Context())
	st.fail = true
	o.Reconcile(t.Context())
	if samples()-before != 2 || testutil.ToFloat64(telemetry.ReconcileErrors)-errsBefore != 1 {
		t.Fatalf("passes timed %d (want 2), failures counted %v (want 1)", samples()-before, testutil.ToFloat64(telemetry.ReconcileErrors)-errsBefore)
	}
}

type failingList struct {
	store.Store
	fail bool
}

func (s *failingList) ListSandboxes(ctx context.Context) ([]*model.Sandbox, error) {
	if s.fail {
		return nil, errors.New("db down")
	}
	return s.Store.ListSandboxes(ctx)
}
