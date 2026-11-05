package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"agent-sandbox/internal/apikeys"
	"agent-sandbox/internal/model"
	"agent-sandbox/internal/store"
)

// One tenant-scope rule: another tenant is 403 with one text on every route that takes a
// tenant (query or path), and a required tenant that is empty is 400.
func TestReviewOneTenantScopeRule(t *testing.T) {
	s, _, _ := gitStack(t)
	s.p.Keys = &apikeys.Service{Store: s.orch.Store}
	api := s.platform.URL
	paths := []string{"/v1/sandboxes?tenant=bob", "/v1/usage?tenant=bob", "/v1/trace?tenant=bob", "/v1/agents?tenant=bob",
		"/v1/credentials?tenant=bob", "/v1/gitrepos/x/status?tenant=bob", "/v1/applies?tenant=bob", "/v1/drift?tenant=bob",
		"/v1/tenants/bob/keys", "/v1/tenants/bob/settings"}
	for _, path := range paths {
		resp, body := call(t, "GET", api+path, "alice-tok", nil, nil)
		wantErr(t, path, resp, body, 403, CodeForbidden)
		if e := errorOf(t, resp, body); e.Error != "token is scoped to tenant alice" {
			t.Fatalf("%s: %q", path, e.Error)
		}
	}
	resp, body := call(t, "POST", api+"/v1/sandboxes", "alice-tok", map[string]any{"name": "x", "slug": "backend-dev", "owner": "alice", "tenant": "bob"}, nil)
	wantErr(t, "create in another tenant", resp, body, 403, CodeForbidden)

	for _, admin := range []bool{true, false} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/", nil)
		req = req.WithContext(context.WithValue(req.Context(), principalKey{}, Principal{Admin: admin, Tenant: "alice"}))
		if _, ok := scopeTenant(rec, req, "", true); ok || rec.Code != 400 {
			t.Fatalf("admin=%v, required and empty: ok=%v %d", admin, ok, rec.Code)
		}
	}
}

// The apply routes answer 503 alike when the platform has no apply controller.
func TestReviewApplyRoutesWithoutAnApplier(t *testing.T) {
	s := newStack(t)
	api := s.platform.URL
	for _, rt := range [][2]string{{"GET", "/v1/drift"}, {"POST", "/v1/rollback"}, {"POST", "/v1/apply"}, {"GET", "/v1/applies"},
		{"GET", "/v1/applies/a1"}, {"POST", "/v1/applies/a1/resume"}} {
		resp, body := call(t, rt[0], api+rt[1], "t0k", `{}`, nil)
		wantErr(t, rt[0]+" "+rt[1], resp, body, 503, CodeUnavailable)
	}
}

// staleRunning answers RunningRun with the run as it was when the conversation was opened.
type staleRunning struct {
	store.Store
	run *model.Run
}

func (s staleRunning) RunningRun(context.Context, string) (*model.Run, error) {
	cp := *s.run
	return &cp, nil
}

// closeConversation answers with the run as CloseRun left it, not the copy read before.
func TestReviewCloseConversationReturnsTheRunAfterTheClose(t *testing.T) {
	s := newStack(t)
	api, gw := s.platform.URL, s.gateway.URL
	sb, hdr := agentOf(t, s, "close")
	resp, body := call(t, "POST", api+"/v1/sandboxes/"+sb.ID+"/messages", "alice-tok", MessageRequest{Text: "hello"}, nil)
	if resp.StatusCode != 202 {
		t.Fatalf("message: %d %s", resp.StatusCode, body)
	}
	_, body = call(t, "GET", gw+"/agent/runs/next?wait=2s", "", nil, hdr)
	var running model.Run
	_ = json.Unmarshal(body, &running)
	if running.Status != model.RunRunning {
		t.Fatalf("next: %s", body)
	}
	if resp, body := call(t, "POST", gw+"/agent/runs/"+running.ID+"/finish", "", `{"exit_code":0}`, hdr); resp.StatusCode != 204 {
		t.Fatalf("finish: %d %s", resp.StatusCode, body)
	}
	s.orch.Store = staleRunning{Store: s.orch.Store, run: &running}
	resp, body = call(t, "POST", api+"/v1/sandboxes/"+sb.ID+"/messages/close", "alice-tok", nil, nil)
	var got model.Run
	_ = json.Unmarshal(body, &got)
	if resp.StatusCode != 200 || got.ID != running.ID || got.Status != model.RunDone {
		t.Fatalf("close: %d %s", resp.StatusCode, body)
	}
}

type brokenBody struct{}

func (brokenBody) Read([]byte) (int, error) { return 0, errors.New("connection reset by peer") }

// A sync or webhook body that breaks off (a client gone) is 400, not "too large".
func TestReviewGitBodyReadErrorsAreNotTooLarge(t *testing.T) {
	s, _, _ := gitStack(t)
	for _, h := range []struct {
		name string
		fn   http.HandlerFunc
	}{{"sync", s.p.gitSyncRepo}, {"hook", s.p.gitHook}} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/", brokenBody{})
		req = req.WithContext(context.WithValue(req.Context(), principalKey{}, Principal{Admin: true}))
		h.fn(rec, req)
		if rec.Code != 400 || !strings.Contains(rec.Body.String(), `"code":"bad_request"`) {
			t.Fatalf("%s: %d %s", h.name, rec.Code, rec.Body)
		}
	}
	resp, body := call(t, "POST", s.platform.URL+"/v1/gitrepos/x/sync", "t0k", `{"commit":"`+strings.Repeat("a", syncBodyLimit)+`"}`, nil)
	wantErr(t, "sync over the cap", resp, body, 413, CodeTooLarge)
}
