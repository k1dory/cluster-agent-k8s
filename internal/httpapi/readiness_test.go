package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

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
