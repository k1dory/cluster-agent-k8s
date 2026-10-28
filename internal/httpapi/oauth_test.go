package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"agent-sandbox/internal/credentials"
	"agent-sandbox/internal/model"
)

// The sign-in routes: a tenant starts a device sign-in and gets the verification URL and the
// code, sees its own sign-ins only, a bad provider or name is 422, a provider refusing is 502,
// a name a plain credential holds is refused, removal is 204; without credentials.key the
// routes are 503. No response ever carries the device code.
func TestOAuthCredentialRoutes(t *testing.T) {
	s := newStack(t)
	api := s.platform.URL
	if resp, _ := call(t, "GET", api+"/v1/oauth-credentials", "alice-tok", nil, nil); resp.StatusCode != 503 {
		t.Fatalf("disabled: %d", resp.StatusCode)
	}
	down := false
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if down {
			w.WriteHeader(500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"device_auth_id":"SECRET-DEVICE-ID","user_code":"ABCD-1234","interval":"5"}`))
	}))
	defer idp.Close()
	creds, err := credentials.New(s.orch.Store, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	s.p.Credentials = creds
	s.p.OAuth = credentials.NewOAuth(creds, s.orch.Store, map[string]credentials.OAuthProvider{"chatgpt": {
		DeviceStyle: credentials.DeviceStyleOpenAI, ClientID: "c", DeviceURL: idp.URL + "/usercode", PollURL: idp.URL + "/token",
		VerificationURL: "https://auth.example.com/codex/device", TokenURL: idp.URL + "/oauth/token", RedirectURL: idp.URL + "/cb"}}, "test")

	resp, body := call(t, "POST", api+"/v1/oauth-credentials/chatgpt/login", "alice-tok", map[string]any{"provider": "chatgpt"}, nil)
	var c model.OAuthCredential
	_ = json.Unmarshal(body, &c)
	if resp.StatusCode != 201 || c.Tenant != "alice" || c.Status != model.OAuthPending || c.UserCode != "ABCD-1234" || c.VerificationURL != "https://auth.example.com/codex/device" {
		t.Fatalf("start: %d %s", resp.StatusCode, body)
	}
	if strings.Contains(string(body), "SECRET-DEVICE-ID") {
		t.Fatalf("the device code leaked: %s", body)
	}
	if resp, body := call(t, "POST", api+"/v1/oauth-credentials/chatgpt/login", "alice-tok", map[string]any{"provider": "chatgpt"}, nil); resp.StatusCode != 200 || !strings.Contains(string(body), `"generation":2`) {
		t.Fatalf("restart: %d %s", resp.StatusCode, body)
	}
	if resp, body := call(t, "GET", api+"/v1/oauth-credentials", "alice-tok", nil, nil); resp.StatusCode != 200 || !strings.Contains(string(body), `"chatgpt"`) || strings.Contains(string(body), "SECRET") {
		t.Fatalf("list: %d %s", resp.StatusCode, body)
	}
	if resp, _ := call(t, "GET", api+"/v1/oauth-credentials/chatgpt", "bob-tok", nil, nil); resp.StatusCode != 404 {
		t.Fatalf("bob reading alice's sign-in: %d", resp.StatusCode)
	}
	if resp, _ := call(t, "GET", api+"/v1/oauth-credentials?tenant=alice", "bob-tok", nil, nil); resp.StatusCode != 403 {
		t.Fatalf("bob listing alice's scope: %d", resp.StatusCode)
	}
	for _, bad := range []struct {
		name string
		body any
		code int
	}{
		{"x", map[string]any{"provider": "nope"}, 422},
		{"a.b", map[string]any{"provider": "chatgpt"}, 422},
		{"x", `{"provider":"chatgpt","extra":1}`, 400},
	} {
		if resp, body := call(t, "POST", api+"/v1/oauth-credentials/"+bad.name+"/login", "alice-tok", bad.body, nil); resp.StatusCode != bad.code {
			t.Fatalf("%s %v: %d %s, want %d", bad.name, bad.body, resp.StatusCode, body, bad.code)
		}
	}
	// One name, one kind, in both directions.
	if resp, _ := call(t, "PUT", api+"/v1/credentials/chatgpt", "alice-tok", map[string]any{"value": "v"}, nil); resp.StatusCode != 422 {
		t.Fatalf("a plain credential over a sign-in: %d", resp.StatusCode)
	}
	if resp, _ := call(t, "PUT", api+"/v1/credentials/plain", "alice-tok", map[string]any{"value": "v"}, nil); resp.StatusCode != 201 {
		t.Fatalf("plain: %d", resp.StatusCode)
	}
	if resp, _ := call(t, "POST", api+"/v1/oauth-credentials/plain/login", "alice-tok", map[string]any{"provider": "chatgpt"}, nil); resp.StatusCode != 422 {
		t.Fatalf("a sign-in over a plain credential: %d", resp.StatusCode)
	}
	down = true
	if resp, _ := call(t, "POST", api+"/v1/oauth-credentials/other/login", "alice-tok", map[string]any{"provider": "chatgpt"}, nil); resp.StatusCode != 502 {
		t.Fatalf("provider down: %d", resp.StatusCode)
	}
	if resp, _ := call(t, "DELETE", api+"/v1/oauth-credentials/chatgpt", "alice-tok", nil, nil); resp.StatusCode != 204 {
		t.Fatalf("delete: %d", resp.StatusCode)
	}
	if resp, _ := call(t, "DELETE", api+"/v1/oauth-credentials/chatgpt", "alice-tok", nil, nil); resp.StatusCode != 404 {
		t.Fatalf("delete twice: %d", resp.StatusCode)
	}
}
