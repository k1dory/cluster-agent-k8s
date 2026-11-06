package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	acp "github.com/coder/acp-go-sdk"
	"github.com/k1dory/acpx"

	"agent-sandbox/internal/harness"
)

// permissionRequest is a permission the agent asks for (allow or reject).
func permissionRequest() acp.RequestPermissionRequest {
	title := "Edit a.txt"
	return acp.RequestPermissionRequest{SessionId: "s", ToolCall: acp.ToolCallUpdate{ToolCallId: "call_1", Title: &title},
		Options: []acp.PermissionOption{
			{OptionId: "yes", Name: "Allow", Kind: acp.PermissionOptionKindAllowOnce},
			{OptionId: "no", Name: "Reject", Kind: acp.PermissionOptionKindRejectOnce},
		}}
}

// With permissions ask, a request the agent makes while the control plane stalls and the spool
// is full still reaches the person once the control plane is back (it has a reserve of its own),
// and their answer reaches the agent.
func TestRequestSurvivesAFullSpool(t *testing.T) {
	smallSpool(t, 2_000, 1_000, 500, 10)
	release := make(chan struct{})
	var releaseOnce sync.Once
	open := func() { releaseOnce.Do(func() { close(release) }) }
	var st batchStore
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		st.store(r)
	}))
	defer srv.Close()
	defer open()
	s := newOutputSpool(t.Context(), &client{base: srv.URL, http: srv.Client()}, "run_ask")
	cl := &acpClient{emit: s.emit, permissions: harness.PermissionsAsk, pending: acpx.NewPending(), askTimeout: time.Minute}
	s.emit("first")
	time.Sleep(spoolBatchDelay + 200*time.Millisecond) // the sender holds it, stalled
	for range 200 {
		s.emit(strings.Repeat("x", 100)) // the spool is full
	}
	type result struct {
		resp acp.RequestPermissionResponse
	}
	answered := make(chan result, 1)
	go func() {
		resp, _ := cl.RequestPermission(t.Context(), permissionRequest())
		answered <- result{resp}
	}()
	var reqID string
	for i := 0; reqID == "" && i < 200; i++ {
		if w := cl.pending.Waiting(); len(w) == 1 {
			reqID = w[0]
		}
		time.Sleep(10 * time.Millisecond)
	}
	if reqID == "" {
		t.Fatal("the agent's request is not waiting")
	}
	open() // the control plane is back; the person answers
	reply, _ := json.Marshal(acpx.Reply{RequestID: reqID, OptionID: "yes"})
	cl.reply(string(reply))
	select {
	case r := <-answered:
		if r.resp.Outcome.Selected == nil || r.resp.Outcome.Selected.OptionId != "yes" {
			t.Fatalf("the agent got %+v", r.resp.Outcome)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the answer did not reach the agent")
	}
	s.close(5 * time.Second)
	got := strings.Join(st.lines, "\n")
	if !strings.Contains(got, `"request":{"request_id":"`+reqID) || !strings.Contains(got, `"type":"acp.request_resolved"`) {
		t.Fatalf("the person never saw the request %s; delivered %d lines, last:\n%s", reqID, len(st.lines), st.lines[len(st.lines)-1])
	}
}

// A request that cannot be kept even in the requests' reserve is refused at once, not waited on
// for the ask timeout.
func TestUndeliverableRequestIsRefusedAtOnce(t *testing.T) {
	smallSpool(t, 2_000, 1_000, 0, 0)
	old := spoolRequestBytes
	spoolRequestBytes = 0
	defer func() { spoolRequestBytes = old }()
	stall := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-stall:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(stall)
	s := newOutputSpool(t.Context(), &client{base: srv.URL, http: srv.Client()}, "run_ask_full")
	defer s.stop()
	cl := &acpClient{emit: s.emit, emitRequest: s.emitKept, permissions: harness.PermissionsAsk, pending: acpx.NewPending(), askTimeout: time.Hour}
	for range 200 {
		s.emit(strings.Repeat("x", 100))
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	resp, err := cl.RequestPermission(ctx, permissionRequest())
	if err != nil || resp.Outcome.Cancelled == nil || ctx.Err() != nil {
		t.Fatalf("outcome %+v, err %v, waited %v", resp.Outcome, err, ctx.Err())
	}
	if w := cl.pending.Waiting(); len(w) != 0 {
		t.Fatalf("the request is still open: %v", w)
	}
}
