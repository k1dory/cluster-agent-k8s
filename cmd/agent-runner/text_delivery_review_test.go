package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"agent-sandbox/internal/events"
	"agent-sandbox/internal/harness"
	"agent-sandbox/internal/model"
	"agent-sandbox/internal/orchestrator"
	"agent-sandbox/internal/store"
)

type reviewMessageInput struct{ bytes.Buffer }

func (*reviewMessageInput) Close() error { return nil }

// An accepted follow-up must reach the running harness or become a queued run.
// Keeping it only in the event history is not delivery. All state and HTTP are local fixtures.
func TestReviewAcceptedMidRunMessageIsDeliveredOrQueued(t *testing.T) {
	for _, mode := range []string{harness.InputText, harness.InputStreamJSON} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			st := store.NewMemory()
			o := orchestrator.New(st, orchestrator.NewFakeRuntime(), nil, events.New(), orchestrator.Config{}, nil)
			sb := &model.Sandbox{ID: "sb_delivery", Tenant: "fixture", Slug: "fixture", Status: model.StatusRunning,
				Launch: &model.Launch{HarnessInput: mode}}
			if err := st.CreateSandbox(ctx, sb); err != nil {
				t.Fatal(err)
			}
			run := &model.Run{ID: "run_delivery", SandboxID: sb.ID, Tenant: sb.Tenant, Slug: sb.Slug,
				Status: model.RunRunning, Task: "first task", Session: "fixture-session", CreatedAt: time.Now()}
			if err := st.CreateRun(ctx, run); err != nil {
				t.Fatal(err)
			}
			const followup = "also add the fixture tests"
			_, how, err := o.Say(ctx, sb.ID, followup)
			if mode == harness.InputText && errors.Is(err, orchestrator.ErrConflict) {
				return // An explicit rejection is preferable to reporting an undelivered input.
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := o.CloseRun(ctx, sb.ID, run.ID); err != nil {
				t.Fatal(err)
			}
			pending, err := st.QueryEvents(ctx, store.Filter{SandboxID: sb.ID, RunID: run.ID,
				Types: []string{model.EventInput, model.EventRunClose}})
			if err != nil {
				t.Fatal(err)
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(pending)
			}))
			defer server.Close()
			input := &reviewMessageInput{}
			forwardInput(ctx, &client{base: server.URL, http: server.Client()}, run.ID, input, cancel, newChat(mode, time.Minute))
			if err := o.FinishRun(ctx, sb.ID, run.ID, 0, nil); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(input.String(), followup) {
				return
			}
			runs, err := st.ListRuns(ctx, sb.ID)
			if err != nil {
				t.Fatal(err)
			}
			for _, next := range runs {
				if next.ID != run.ID && next.Status == model.RunQueued && strings.Contains(next.Task, followup) {
					return
				}
			}
			t.Fatalf("Say reported %q, but the runner consumed no follow-up and finishing the run queued none", how)
		})
	}
}
