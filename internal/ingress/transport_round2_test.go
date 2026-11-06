package ingress

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"agent-sandbox/internal/model"
	"agent-sandbox/internal/store"
)

const lifecycleHost = "shop-alice.pv.test"

// lifecycleGet sends one preview request for lifecycleHost with the cookie (if any).
func lifecycleGet(h *Handler, path, cookie string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "https://"+lifecycleHost+path, nil)
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: cookieName, Value: cookie})
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// lifecycleBackend is the application in the sandbox; conns counts the connections it accepted.
func lifecycleBackend(t *testing.T) (ip string, port int, conns *atomic.Int32) {
	t.Helper()
	conns = &atomic.Int32{}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("app")) }))
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			conns.Add(1)
		}
	}
	srv.Start()
	t.Cleanup(srv.Close)
	host, p, _ := net.SplitHostPort(srv.Listener.Addr().String())
	port, _ = strconv.Atoi(p)
	return host, port, conns
}

// Every proxied request built its own http.Transport: no connection was ever reused and each
// request left an idle connection behind. One transport per Handler now serves them all.
func TestRound2PreviewReusesBackendConnections(t *testing.T) {
	ip, port, conns := lifecycleBackend(t)
	st := store.NewMemory()
	h := &Handler{Store: st}
	t.Cleanup(h.Close)
	now := time.Now()
	sb := &model.Sandbox{ID: "sb_conn", Name: "shop", Slug: "dev", Tenant: "acme", Owner: "alice", Status: model.StatusRunning, IP: ip,
		CreatedAt: now, LastActivity: now, Preview: &model.Preview{Port: port, Access: model.AccessLink, Host: lifecycleHost}}
	if err := st.CreateSandbox(context.Background(), sb); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if rec := lifecycleGet(h, "/", ""); rec.Code != http.StatusOK || rec.Body.String() != "app" {
			t.Fatalf("request %d: %d %q", i, rec.Code, rec.Body.String())
		}
	}
	if n := conns.Load(); n != 1 {
		t.Fatalf("three sequential requests opened %d connections to the sandbox, want 1", n)
	}
	if h.proxyTransport() != h.proxyTransport() {
		t.Fatal("the handler hands out more than one transport")
	}
}
