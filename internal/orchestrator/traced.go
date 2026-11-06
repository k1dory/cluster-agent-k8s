package orchestrator

import (
	"context"
	"errors"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"agent-sandbox/internal/model"
	"agent-sandbox/internal/store"
	"agent-sandbox/internal/telemetry"
)

// The public operations below open a span each and run the operation as it was (the
// unexported function of the same name): sandbox_id and run_id ride on the span, so the trace
// of a request, of the agent's calls about a run, or of a reconciler pass shows which ones
// it touched. Nothing here changes what an operation does or returns.

func (o *Orchestrator) span(ctx context.Context, name string, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	return telemetry.Tracer().Start(ctx, "orchestrator."+name, trace.WithAttributes(attrs...))
}

func sandboxAttr(id string) attribute.KeyValue { return attribute.String("sandbox_id", id) }
func runAttr(id string) attribute.KeyValue     { return attribute.String("run_id", id) }

// Create registers a sandbox, provisions its volume and starts the first pod (see create).
func (o *Orchestrator) Create(ctx context.Context, req CreateRequest) (*model.Sandbox, error) {
	ctx, span := o.span(ctx, "Create", attribute.String("slug", req.Slug))
	sb, err := o.create(ctx, req)
	if sb != nil {
		span.SetAttributes(sandboxAttr(sb.ID))
	}
	return sb, telemetry.End(span, err)
}

// Wake starts a pod for a sleeping sandbox (see wake).
func (o *Orchestrator) Wake(ctx context.Context, id string) (*model.Sandbox, error) {
	ctx, span := o.span(ctx, "Wake", sandboxAttr(id))
	sb, err := o.wake(ctx, id)
	return sb, telemetry.End(span, err)
}

// Sleep deletes the pod and keeps the volume (see sleep).
func (o *Orchestrator) Sleep(ctx context.Context, id string, force bool) (*model.Sandbox, error) {
	ctx, span := o.span(ctx, "Sleep", sandboxAttr(id), attribute.Bool("force", force))
	sb, err := o.sleep(ctx, id, force)
	return sb, telemetry.End(span, err)
}

// Delete stops the pod, removes the volume and then the record (see deleteSandbox).
func (o *Orchestrator) Delete(ctx context.Context, id string) error {
	ctx, span := o.span(ctx, "Delete", sandboxAttr(id))
	return telemetry.End(span, o.deleteSandbox(ctx, id))
}

// NextRunFor long-polls for a queued run and hands it to owner (see nextRunFor). No run within
// the wait is an answer, not a failure of the span.
func (o *Orchestrator) NextRunFor(ctx context.Context, sandboxID, owner string, wait time.Duration) (*model.Run, error) {
	ctx, span := o.span(ctx, "NextRun", sandboxAttr(sandboxID))
	r, err := o.nextRunFor(ctx, sandboxID, owner, wait)
	if r != nil {
		span.SetAttributes(runAttr(r.ID), attribute.Int("attempt", r.Attempt))
	}
	if errors.Is(err, store.ErrNotFound) || err != nil && errors.Is(err, ctx.Err()) {
		span.End()
		return r, err
	}
	return r, telemetry.End(span, err)
}

// OutputBatch appends agent output to the event stream (see outputBatch).
func (o *Orchestrator) OutputBatch(ctx context.Context, sandboxID, runID, batchID string, attempt int, lines []string, partial bool) (*store.OutputResult, error) {
	ctx, span := o.span(ctx, "Output", sandboxAttr(sandboxID), runAttr(runID), attribute.Int("lines", len(lines)))
	res, err := o.outputBatch(ctx, sandboxID, runID, batchID, attempt, lines, partial)
	return res, telemetry.End(span, err)
}

// FinishRunAttempt records the result of a run (see finishRunAttempt).
func (o *Orchestrator) FinishRunAttempt(ctx context.Context, sandboxID, runID string, attempt, exitCode int, usage *model.Usage) error {
	ctx, span := o.span(ctx, "Finish", sandboxAttr(sandboxID), runAttr(runID), attribute.Int("exit_code", exitCode))
	return telemetry.End(span, o.finishRunAttempt(ctx, sandboxID, runID, attempt, exitCode, usage))
}

// Reconcile is one pass of the background work (see reconcile), timed and traced: the
// pass's span is the parent of every store and Kubernetes call it makes. Exported for tests.
func (o *Orchestrator) Reconcile(ctx context.Context) {
	ctx, span := o.span(ctx, "Reconcile")
	start := time.Now()
	o.reconcile(ctx)
	telemetry.ReconcileDuration.Observe(time.Since(start).Seconds())
	span.End()
}

// StateSource reads the state gauges (telemetry.NewStateCollector) from the store, when the
// store can count (both of ours can); nil otherwise.
func (o *Orchestrator) StateSource() telemetry.StateSource {
	sc, ok := o.Store.(store.StatusCounter)
	if !ok {
		return nil
	}
	return func(ctx context.Context) (telemetry.StateCounts, error) {
		sbs, runs, err := sc.CountByStatus(ctx)
		return telemetry.StateCounts{Sandboxes: sbs, Runs: runs}, err
	}
}
