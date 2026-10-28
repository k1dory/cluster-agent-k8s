package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"agent-sandbox/internal/events"
	"agent-sandbox/internal/harness"
	"agent-sandbox/internal/model"
	"agent-sandbox/internal/store"
)

// streamJSON switches a sandbox's harness to stream-json input, the mode that takes messages
// during a run.
func streamJSON(t *testing.T, st store.Store, id string) {
	t.Helper()
	sb, err := st.GetSandbox(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if sb.Launch == nil {
		sb.Launch = &model.Launch{}
	}
	sb.Launch.HarnessInput = harness.InputStreamJSON
	if err := st.UpdateSandbox(context.Background(), sb); err != nil {
		t.Fatal(err)
	}
}

// A text-mode harness reads only its task: a message for a queued run joins its task, a message
// during a run becomes the next run, which resumes the session the running one reports. The
// runner never sees an input event it would have to drop, and the input endpoint refuses.
func TestSayToATextModeHarnessIsTheNextRun(t *testing.T) {
	ctx := context.Background()
	o := New(store.NewMemory(), NewFakeRuntime(), nil, events.New(), Config{}, nil)
	o.leading.Store(true)
	sb, err := o.Create(ctx, CreateRequest{Name: "t", Slug: "backend-dev", Owner: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	waitStatus(t, o, sb.ID, model.StatusRunning)
	r1, how, err := o.Say(ctx, sb.ID, "add tests")
	if err != nil || how != DeliveredNew {
		t.Fatalf("first message: %v %s", err, how)
	}
	// Still queued: the message joins the task the harness will read.
	r, how, err := o.Say(ctx, sb.ID, "use pytest")
	if err != nil || how != DeliveredInput || r.ID != r1.ID || r.Task != "add tests\n\nuse pytest" {
		t.Fatalf("queued: %v %s %+v", err, how, r)
	}
	got, err := o.NextRun(ctx, sb.ID, time.Second)
	if err != nil || got.ID != r1.ID || got.Task != "add tests\n\nuse pytest" {
		t.Fatalf("claimed: %v %+v", err, got)
	}
	if err := o.Input(ctx, sb.ID, r1.ID, "hi"); !errors.Is(err, ErrConflict) {
		t.Fatalf("input to a text-mode run: %v", err)
	}
	// Running: two messages become the next run and the one after it, in order.
	r2, how, err := o.Say(ctx, sb.ID, "also cover the edge cases")
	if err != nil || how != DeliveredResumed || r2.ID == r1.ID || r2.Status != model.RunQueued || r2.ResumeOf != r1.ID || r2.Mode != model.RunMessage {
		t.Fatalf("during the run: %v %s %+v", err, how, r2)
	}
	r3, how, err := o.Say(ctx, sb.ID, "and the docs")
	if err != nil || how != DeliveredInput || r3.ID != r2.ID || r3.Task != "also cover the edge cases\n\nand the docs" {
		t.Fatalf("second message during the run: %v %s %+v", err, how, r3)
	}
	evs, _ := o.Store.QueryEvents(ctx, store.Filter{SandboxID: sb.ID, Types: []string{model.EventInput}})
	if len(evs) != 0 {
		t.Fatalf("no input event for a text-mode harness: %+v", evs)
	}
	if err := o.Output(ctx, sb.ID, r1.ID, `{"type":"system","subtype":"init","session_id":"sess-t"}`); err != nil {
		t.Fatal(err)
	}
	if err := o.FinishRun(ctx, sb.ID, r1.ID, 0, nil); err != nil {
		t.Fatal(err)
	}
	next, err := o.NextRun(ctx, sb.ID, time.Second)
	if err != nil || next.ID != r2.ID || next.Session != "sess-t" || next.Task != "also cover the edge cases\n\nand the docs" {
		t.Fatalf("next run resumes the session: %v %+v", err, next)
	}
	if stored, _ := o.Store.GetRun(ctx, r2.ID); stored.Session != "sess-t" {
		t.Fatalf("resolved session not stored: %+v", stored)
	}
}

func TestSayContinuesTheConversation(t *testing.T) {
	ctx := context.Background()
	o := New(store.NewMemory(), NewFakeRuntime(), nil, events.New(), Config{PreviewDomain: "preview.test"}, nil)
	o.leading.Store(true)
	sb, err := o.Create(ctx, CreateRequest{Name: "c", Slug: "backend-dev", Owner: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	waitStatus(t, o, sb.ID, model.StatusRunning)
	streamJSON(t, o.Store, sb.ID)
	// First message: a fresh conversation.
	r1, how, err := o.Say(ctx, sb.ID, "add tests")
	if err != nil || how != DeliveredNew || r1.Mode != model.RunTask || r1.Task != "add tests" {
		t.Fatalf("first message: %v %s %+v", err, how, r1)
	}
	// A second message while the run is queued or running is input to it (stream-json).
	if _, err := o.NextRun(ctx, sb.ID, time.Second); err != nil {
		t.Fatal(err)
	}
	r2, how, err := o.Say(ctx, sb.ID, "use pytest")
	if err != nil || how != DeliveredInput || r2.ID != r1.ID {
		t.Fatalf("input: %v %s %+v", err, how, r2)
	}
	// The harness reports its session and answers; the run ends.
	for _, line := range []string{
		`{"type":"system","subtype":"init","session_id":"sess-1"}`,
		`{"type":"assistant","message":{"content":[{"type":"tool_use","name":"Write"}]},"session_id":"sess-1"}`,
		`{"type":"assistant","message":{"content":[{"type":"text","text":"Tests added with pytest."}]},"session_id":"sess-1"}`,
		`{"type":"result","subtype":"success","num_turns":2,"session_id":"sess-1","usage":{"input_tokens":1,"output_tokens":1}}`,
	} {
		if err := o.Output(ctx, sb.ID, r1.ID, line); err != nil {
			t.Fatal(err)
		}
	}
	if err := o.FinishRun(ctx, sb.ID, r1.ID, 0, nil); err != nil {
		t.Fatal(err)
	}
	// The next message continues the session in a new run, with the message as the prompt.
	r3, how, err := o.Say(ctx, sb.ID, "also cover the edge cases")
	if err != nil || how != DeliveredResumed || r3.Mode != model.RunMessage || r3.ResumeOf != r1.ID || r3.Session != "sess-1" || r3.Task != "also cover the edge cases" {
		t.Fatalf("resumed: %v %s %+v", err, how, r3)
	}
	// The conversation view: user turns, assistant text, tool calls, run boundaries; raw adds the rest.
	msgs, next, err := o.Messages(ctx, sb.ID, 0, 0, false)
	if err != nil || next == 0 {
		t.Fatal(err)
	}
	var got []string
	for _, m := range msgs {
		got = append(got, m.Role+":"+m.Text)
	}
	want := []string{"user:add tests", "user:use pytest", "tool:Write", "assistant:Tests added with pytest.", "system:run done", "user:also cover the edge cases"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("conversation:\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	rawMsgs, _, _ := o.Messages(ctx, sb.ID, 0, 0, true)
	if len(rawMsgs) != len(msgs)+2 {
		t.Fatalf("raw view: %d messages, want %d", len(rawMsgs), len(msgs)+2)
	}
	// Paging continues from next.
	more, next2, _ := o.Messages(ctx, sb.ID, next, 0, false)
	if len(more) != 0 || next2 != next {
		t.Fatalf("paging: %+v %d", more, next2)
	}
	// Close: a queued run is cancelled; a running one gets run.close.
	if r, err := o.CloseRun(ctx, sb.ID, r3.ID); err != nil || r.Status != model.RunCancelled {
		t.Fatalf("close queued: %v %+v", err, r)
	}
	r4, _, _ := o.Say(ctx, sb.ID, "one more")
	if r4.Mode != model.RunMessage || r4.Session != "sess-1" || r4.ResumeOf != r3.ID {
		t.Fatalf("the conversation continues through the latest run of the session: %+v", r4)
	}
	if _, err := o.NextRun(ctx, sb.ID, time.Second); err != nil {
		t.Fatal(err)
	}
	if _, err := o.CloseRun(ctx, sb.ID, r4.ID); err != nil {
		t.Fatal(err)
	}
	evs, _ := o.Store.QueryEvents(ctx, store.Filter{SandboxID: sb.ID, RunID: r4.ID, Types: []string{model.EventRunClose}})
	if len(evs) != 1 {
		t.Fatal("close must reach the runner as run.close")
	}
}

func TestFSRoundTrip(t *testing.T) {
	ctx := context.Background()
	hub := events.New()
	o := New(store.NewMemory(), NewFakeRuntime(), nil, hub, Config{PreviewDomain: "preview.test"}, nil)
	o.leading.Store(true)
	sb, err := o.Create(ctx, CreateRequest{Name: "f", Slug: "backend-dev", Owner: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	waitStatus(t, o, sb.ID, model.StatusRunning)
	for _, bad := range []string{"../etc/passwd", "/workspace/../x"} {
		if p, _ := CleanFSPath(bad); strings.Contains(p, "..") {
			t.Fatalf("%s cleaned to %s", bad, p)
		}
	}
	if p, _ := CleanFSPath("/workspace/repo/src/"); p != "repo/src" {
		t.Fatalf("clean: %s", p)
	}
	// A simulated runner answers the pending request.
	go func() {
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			pending, _ := o.PendingFS(ctx, sb.ID, 0)
			for _, e := range pending {
				var req model.FSRequest
				_ = json.Unmarshal([]byte(e.Data), &req)
				_ = o.AnswerFS(ctx, sb.ID, model.FSResult{Request: req.ID, OK: true, Entries: []model.FSEntry{{Path: req.Path + "/main.go", Type: "file", Size: 12}}})
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()
	res, err := o.FS(ctx, sb.ID, model.FSRequest{Op: model.FSList, Path: "repo"}, true, 3*time.Second)
	if err != nil || !res.OK || len(res.Entries) != 1 || res.Entries[0].Path != "repo/main.go" {
		t.Fatalf("list: %v %+v", err, res)
	}
	if pending, _ := o.PendingFS(ctx, sb.ID, 0); len(pending) != 0 {
		t.Fatalf("answered requests are not pending: %+v", pending)
	}
	// Nobody answers: a timeout, not a hang; an unknown op is refused before anything is sent.
	if _, err := o.FS(ctx, sb.ID, model.FSRequest{Op: model.FSRead, Path: "x"}, true, 100*time.Millisecond); !errors.Is(err, ErrTimeout) {
		t.Fatalf("timeout: %v", err)
	}
	if _, err := o.FS(ctx, sb.ID, model.FSRequest{Op: "rm", Path: "x"}, true, time.Second); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("unknown op: %v", err)
	}
	// Blob names are confined per sandbox; uncollected blobs are purged by the reconciler.
	name := FSBlobName(sb.ID)
	if !OwnsFSBlob(sb.ID, name) || OwnsFSBlob("other", name) {
		t.Fatal("blob ownership")
	}
	_ = o.Store.PutBlob(ctx, name, []byte("x"))
	if n, _ := o.Store.DeleteBlobsBefore(ctx, "fs/", time.Now().Add(time.Second)); n != 1 {
		t.Fatalf("purge: %d", n)
	}
	// A sleeping sandbox is woken for a file operation unless wake=false.
	if _, err := o.Sleep(ctx, sb.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := o.FS(ctx, sb.ID, model.FSRequest{Op: model.FSList, Path: ""}, false, time.Second); !errors.Is(err, ErrConflict) {
		t.Fatalf("sleeping without wake: %v", err)
	}
	go func() {
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			if cur, _ := o.Get(ctx, sb.ID); cur.Status == model.StatusRunning {
				// Like the runner: every pending request is answered, stale ones included.
				pending, _ := o.PendingFS(ctx, sb.ID, 0)
				done := false
				for _, e := range pending {
					var req model.FSRequest
					_ = json.Unmarshal([]byte(e.Data), &req)
					_ = o.AnswerFS(ctx, sb.ID, model.FSResult{Request: req.ID, OK: true})
					done = done || req.Op == model.FSList
				}
				if done {
					return
				}
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()
	if res, err := o.FS(ctx, sb.ID, model.FSRequest{Op: model.FSList, Path: ""}, true, 3*time.Second); err != nil || !res.OK {
		t.Fatalf("wake and list: %v %+v", err, res)
	}
}
