package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"agent-sandbox/internal/ca"
	"agent-sandbox/internal/model"
	"agent-sandbox/internal/registrar"
	"agent-sandbox/internal/store"
)

type unreachableStore struct {
	store.Store
	down bool
}

func (u *unreachableStore) Ping(ctx context.Context) error {
	if u.down {
		return errors.New("dial tcp: connection refused")
	}
	return u.Store.Ping(ctx)
}

// /readyz follows the store: a replica whose database does not answer is not ready (and takes
// no traffic), while /healthz stays 200 so it is not restarted for an outage not its own.
// /v1/version names the replica that answered and whether it leads.
func TestReadinessFollowsTheStoreAndVersionNamesTheReplica(t *testing.T) {
	s := newStack(t)
	api := s.platform.URL
	st := &unreachableStore{Store: s.orch.Store}
	s.orch.Store = st
	s.p.Replica = "sandboxd-0"
	if resp, body := call(t, "GET", api+"/readyz", "", nil, nil); resp.StatusCode != 200 || string(body) != "ready\n" {
		t.Fatalf("ready: %d %s", resp.StatusCode, body)
	}
	st.down = true
	if resp, body := call(t, "GET", api+"/readyz", "", nil, nil); resp.StatusCode != http.StatusServiceUnavailable || string(body) == "" {
		t.Fatalf("store down: %d %s", resp.StatusCode, body)
	}
	if resp, _ := call(t, "GET", api+"/healthz", "", nil, nil); resp.StatusCode != 200 {
		t.Fatalf("liveness during a store outage: %d", resp.StatusCode)
	}
	st.down = false
	resp, body := call(t, "GET", api+"/v1/version", "t0k", nil, nil)
	var v struct {
		Replica string `json:"replica"`
		Leader  *bool  `json:"leader"`
	}
	if err := json.Unmarshal(body, &v); resp.StatusCode != 200 || err != nil || v.Replica != "sandboxd-0" || v.Leader == nil {
		t.Fatalf("version: %d %s %v", resp.StatusCode, body, err)
	}
}

type bootstrapStoreDown struct {
	store.Store
}

func (bootstrapStoreDown) GetSandbox(context.Context, string) (*model.Sandbox, error) {
	return nil, errors.New("dial tcp: connection refused")
}

// A bootstrap the platform could not complete on its own side (the store did not answer) is a
// 503, which agent-init retries; a 400 would make the init container exit on an outage that
// is not the pod's.
func TestBootstrapStoreOutageIsRetryable(t *testing.T) {
	s := newStack(t)
	s.tokens["pod-token"] = registrar.PodInfo{Name: "agent-x", SandboxID: "sb_missing_store", Slug: "backend-dev", Tenant: "alice"}
	s.reg.Store = bootstrapStoreDown{Store: s.reg.Store}
	_, csr, _ := ca.NewCSR("backend-dev")
	resp, body := call(t, "POST", s.gateway.URL+"/bootstrap", "pod-token", registrar.BootstrapRequest{CSR: string(csr)}, nil)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("bootstrap during a store outage: %d %s, want 503", resp.StatusCode, body)
	}
}
