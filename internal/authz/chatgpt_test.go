package authz

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"agent-sandbox/internal/credentials"
	"agent-sandbox/internal/policy"
	"agent-sandbox/internal/secrets"
	"agent-sandbox/internal/store"
)

// Codex on a ChatGPT subscription, as the shipped example policy sets it up: once the tenant's
// device sign-in is approved, the decision for the ChatGPT backend carries the access token
// sandboxd minted as the bearer and the account id from the ID token as ChatGPT-Account-ID;
// before approval the request is refused at the gateway with the reason, nothing injected.
func TestChatGPTSignInIsInjected(t *testing.T) {
	ctx := context.Background()
	enc := func(claims map[string]any) string {
		b, _ := json.Marshal(claims)
		return "e30." + base64.RawURLEncoding.EncodeToString(b) + ".sig"
	}
	access := enc(map[string]any{"exp": time.Now().Add(time.Hour).Unix()})
	approved := false
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/usercode":
			_, _ = w.Write([]byte(`{"device_auth_id":"d","user_code":"ABCD","interval":"1"}`))
		case "/poll":
			if !approved {
				w.WriteHeader(403)
				return
			}
			_, _ = w.Write([]byte(`{"authorization_code":"c","code_verifier":"v"}`))
		case "/token":
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": access, "refresh_token": "r",
				"id_token": enc(map[string]any{"https://api.openai.com/auth": map[string]any{"chatgpt_account_id": "acct-7"}})})
		}
	}))
	defer idp.Close()
	st := store.NewMemory()
	creds, err := credentials.New(st, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	o := credentials.NewOAuth(creds, st, map[string]credentials.OAuthProvider{"chatgpt": {DeviceStyle: credentials.DeviceStyleOpenAI,
		ClientID: "c", DeviceURL: idp.URL + "/usercode", PollURL: idp.URL + "/poll", TokenURL: idp.URL + "/token", RedirectURL: idp.URL + "/cb",
		AccountClaim: []string{"https://api.openai.com/auth", "chatgpt_account_id"}}}, "replica")
	clock := time.Now()
	o.Now = func() time.Time { return clock }
	if _, _, err := o.Start(ctx, "acme", "chatgpt", "chatgpt", "alice"); err != nil {
		t.Fatal(err)
	}
	pols, err := policy.Load("../../examples/policies")
	if err != nil {
		t.Fatal(err)
	}
	h := &Handler{Policies: pols, Secrets: secrets.Chain{credentials.Resolver{Service: creds, OAuth: o}}}
	san := "spiffe://sandbox/agent/llm-subscriptions/1,spiffe://sandbox/tenant/acme,spiffe://sandbox/sandbox/sb1"

	w := httptest.NewRecorder()
	h.ServeHTTP(w, req(san, "chatgpt.com", "POST", "/backend-api/codex/responses"))
	if w.Code != 502 || w.Header().Get("Authorization") != "" || w.Header().Get("Chatgpt-Account-Id") != "" {
		t.Fatalf("before approval: %d %v", w.Code, w.Header())
	}
	approved = true
	clock = clock.Add(2 * time.Second)
	o.Tick(ctx)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req(san, "chatgpt.com", "POST", "/backend-api/codex/responses"))
	if w.Code != 200 || w.Header().Get("Authorization") != "Bearer "+access || w.Header().Get("Chatgpt-Account-Id") != "acct-7" {
		t.Fatalf("after approval: %d Authorization=%q ChatGPT-Account-ID=%q", w.Code, w.Header().Get("Authorization"), w.Header().Get("Chatgpt-Account-Id"))
	}
}
