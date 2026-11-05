package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"agent-sandbox/api"
	"agent-sandbox/internal/apikeys"
	"agent-sandbox/internal/apply"
	"agent-sandbox/internal/model"
	"agent-sandbox/internal/orchestrator"
	"agent-sandbox/internal/store"

	"gopkg.in/yaml.v3"
)

// Every code the server can write is a member of the Error enum in openapi.yaml, and the
// enum lists nothing the server never writes.
func TestReviewErrorCodesAreTheSpecEnum(t *testing.T) {
	var spec struct {
		Components struct {
			Schemas map[string]struct {
				Properties map[string]struct {
					Enum []string `yaml:"enum"`
				} `yaml:"properties"`
			} `yaml:"schemas"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(api.OpenAPI, &spec); err != nil {
		t.Fatal(err)
	}
	enum := spec.Components.Schemas["Error"].Properties["code"].Enum
	codes := []string{CodeBadRequest, CodeUnauthorized, CodeForbidden, CodeNotFound, CodeConflict, CodeTooLarge,
		CodeQuota, CodeUpstream, CodeTimeout, CodeInternal, CodeUnavailable, CodeInvalid,
		CodeInvalidPlan, CodeNothingToRollBack, CodeUnreachable, CodeCredential, CodeStopped, CodeRateLimited}
	for status := 400; status < 600; status++ {
		codes = append(codes, codeFor(status))
	}
	for _, c := range codes {
		if !slices.Contains(enum, c) {
			t.Errorf("code %q is not in the Error enum of openapi.yaml", c)
		}
	}
	for _, c := range enum {
		if !slices.Contains(codes, c) {
			t.Errorf("the Error enum lists %q, which the server never writes", c)
		}
	}
	for _, c := range spec.Components.Schemas["GitSyncError"].Properties["code"].Enum {
		if !slices.Contains(enum, c) {
			t.Errorf("GitSyncError code %q is not in the Error enum", c)
		}
	}
}

// A timeout is 504 `timeout`, not `internal`; the ad-hoc bodies of apply, rollback and git
// sync are the envelope (with request_id) plus their record.
func TestReviewErrorEnvelopeEverywhere(t *testing.T) {
	rec := func() *httptest.ResponseRecorder {
		r := httptest.NewRecorder()
		r.Header().Set("X-Request-Id", "rid-1")
		return r
	}
	check := func(what string, r *httptest.ResponseRecorder, status int, code, field string) {
		t.Helper()
		var m map[string]any
		if err := json.Unmarshal(r.Body.Bytes(), &m); err != nil || r.Code != status || m["code"] != code || m["request_id"] != "rid-1" || m["error"] == "" {
			t.Fatalf("%s: %d %s", what, r.Code, r.Body)
		}
		if _, ok := m[field]; field != "" && !ok {
			t.Fatalf("%s: no %q in %s", what, field, r.Body)
		}
	}
	r := rec()
	writeOrchErr(r, fmt.Errorf("%w: the pod did not answer", orchestrator.ErrTimeout))
	check("timeout", r, 504, CodeTimeout, "")
	r = rec()
	writeApply(r, nil, &apply.InvalidPlan{})
	check("apply invalid plan", r, 422, CodeInvalidPlan, "plan")
	r = rec()
	writeApply(r, &model.Apply{ID: "a1"}, apply.ErrKeyReused)
	check("apply conflict", r, 409, CodeConflict, "apply")
	r = rec()
	writeGitSync(r, &model.GitSync{}, errors.New("something else"))
	check("git sync, unknown failure", r, 500, CodeInternal, "sync")
	if strings.Contains(r.Body.String(), "something else") {
		t.Fatalf("a 500 carries the inner error: %s", r.Body)
	}
}

// failingStore fails the reads of runs and keys the way a lost database does.
type failingStore struct {
	store.Store
}

var errDB = errors.New("pq: connection reset by peer at 10.0.0.7:5432")

func (failingStore) GetRun(context.Context, string) (*model.Run, error)       { return nil, errDB }
func (failingStore) GetAPIKey(context.Context, string) (*model.APIKey, error) { return nil, errDB }

// A store that fails is 500, not "not found"; the body says only "internal error" and the
// request id, and the detail is in the log line of that id.
func TestReviewStoreFailuresAre500AndLogged(t *testing.T) {
	s := newStack(t)
	resp, body := call(t, "POST", s.platform.URL+"/v1/sandboxes", "t0k", map[string]any{"name": "db", "slug": "backend-dev", "owner": "alice"}, nil)
	if resp.StatusCode != 201 {
		t.Fatalf("create: %d %s", resp.StatusCode, body)
	}
	var sb model.Sandbox
	_ = json.Unmarshal(body, &sb)
	var logs bytes.Buffer
	broken := failingStore{s.orch.Store}
	s.orch.Store = broken
	s.p.Keys = &apikeys.Service{Store: broken}
	s.p.Log = slog.New(slog.NewJSONHandler(&logs, nil))
	srv := httptest.NewServer(s.p.Routes())
	defer srv.Close()

	for _, path := range []string{"/v1/sandboxes/" + sb.ID + "/runs/r1", "/v1/tenants/alice/keys/k1"} {
		logs.Reset()
		resp, body := call(t, "GET", srv.URL+path, "t0k", nil, map[string]string{"X-Request-Id": "rid-" + path[len(path)-2:]})
		wantErr(t, path, resp, body, 500, CodeInternal)
		if strings.Contains(string(body), "10.0.0.7") || !strings.Contains(string(body), "rid-") {
			t.Fatalf("%s: the body leaks the detail or lacks the id: %s", path, body)
		}
		if !strings.Contains(logs.String(), "10.0.0.7") || !strings.Contains(logs.String(), `"rid":"rid-`) {
			t.Fatalf("%s: the detail is not logged under the request id: %s", path, logs.String())
		}
	}
}

// writeErr must find the request's log line through the writers the middleware put on top.
func TestReviewInternalErrorReachesTheLogThroughTheRecorder(t *testing.T) {
	var logs bytes.Buffer
	h := logRequests(slog.New(slog.NewJSONHandler(&logs, nil)), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeErr(&recorder{ResponseWriter: w, code: 200}, http.StatusInternalServerError, errors.New("inner detail"))
	}))
	r := httptest.NewRecorder()
	h.ServeHTTP(r, httptest.NewRequest("GET", "/x", nil))
	if r.Code != 500 || strings.Contains(r.Body.String(), "inner detail") || !strings.Contains(logs.String(), "inner detail") {
		t.Fatalf("%d %s / log %s", r.Code, r.Body, logs.String())
	}
}
