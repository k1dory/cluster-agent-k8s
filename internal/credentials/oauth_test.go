package credentials

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"agent-sandbox/internal/model"
	"agent-sandbox/internal/secrets"
	"agent-sandbox/internal/store"
)

// jwt builds an unsigned token with the given claims (the service reads, never verifies).
func jwt(claims map[string]any) string {
	b, _ := json.Marshal(claims)
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"none"}`)) + "." + enc(b) + ".sig"
}

// fakeIdP is an authorization server speaking both device-flow dialects: OpenAI's (JSON user
// code, a poll endpoint answering 403 until approval, then a code and verifier to exchange)
// and RFC 8628's (authorization_pending, slow_down, then the tokens). Refresh tokens rotate
// and are single-use, as ChatGPT's are.
type fakeIdP struct {
	t   *testing.T
	srv *httptest.Server
	now func() time.Time

	mu        sync.Mutex
	approved  bool
	rfcPolls  int
	refresh   string          // the refresh token currently valid
	spent     map[string]bool // refresh tokens already used
	revoked   bool
	refreshes int
	gen       int
	slowDowns int
	// exchangeDown answers the code exchange 503; codesIssued counts the approved polls that
	// handed the authorization code out (the real endpoint does that once).
	exchangeDown bool
	codesIssued  int
}

func newFakeIdP(t *testing.T, now func() time.Time) *fakeIdP {
	f := &fakeIdP{t: t, now: now, spent: map[string]bool{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

// tokens issues a new pair: an access token living an hour (exp in its claims, no expires_in,
// as ChatGPT's) and an ID token carrying the account claim.
func (f *fakeIdP) tokens(w http.ResponseWriter) {
	f.gen++
	f.refresh = fmt.Sprintf("rt-%d", f.gen)
	exp := f.now().Add(time.Hour).Unix()
	writeJSON(w, 200, map[string]any{
		"access_token":  jwt(map[string]any{"exp": exp, "n": f.gen}),
		"refresh_token": f.refresh,
		"id_token":      jwt(map[string]any{"https://api.openai.com/auth": map[string]any{"chatgpt_account_id": "acct-42"}}),
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func (f *fakeIdP) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	body := map[string]string{}
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		_ = json.NewDecoder(r.Body).Decode(&body)
	} else {
		_ = r.ParseForm()
		for k := range r.PostForm {
			body[k] = r.PostForm.Get(k)
		}
	}
	if body["client_id"] != "" && body["client_id"] != "test-client" {
		writeJSON(w, 401, map[string]any{"error": "invalid_client"})
		return
	}
	switch r.URL.Path {
	case "/api/accounts/deviceauth/usercode":
		writeJSON(w, 200, map[string]any{"device_auth_id": "dev-1", "user_code": "ABCD-1234", "interval": "5"})
	case "/api/accounts/deviceauth/token":
		if body["device_auth_id"] != "dev-1" || body["user_code"] != "ABCD-1234" {
			writeJSON(w, 400, map[string]any{"error": "bad device"})
			return
		}
		if !f.approved {
			w.WriteHeader(http.StatusForbidden) // codex-rs: 403/404 while the user has not approved
			return
		}
		f.codesIssued++
		writeJSON(w, 200, map[string]any{"authorization_code": "code-1", "code_challenge": "c", "code_verifier": "ver-1"})
	case "/oauth/token":
		switch body["grant_type"] {
		case "authorization_code":
			if f.exchangeDown {
				writeJSON(w, 503, map[string]any{"error": "temporarily_unavailable"})
				return
			}
			if body["code"] != "code-1" || body["code_verifier"] != "ver-1" || body["redirect_uri"] != f.srv.URL+"/deviceauth/callback" {
				writeJSON(w, 400, map[string]any{"error": "invalid_grant"})
				return
			}
			f.tokens(w)
		case "refresh_token":
			f.refreshes++
			switch {
			case f.revoked:
				writeJSON(w, 401, map[string]any{"error": map[string]any{"code": "refresh_token_invalidated", "message": "revoked"}})
			case f.spent[body["refresh_token"]]:
				writeJSON(w, 400, map[string]any{"error": map[string]any{"code": "refresh_token_reused"}})
			case body["refresh_token"] != f.refresh:
				writeJSON(w, 400, map[string]any{"error": "invalid_grant"})
			default:
				f.spent[body["refresh_token"]] = true
				f.tokens(w)
			}
		case "urn:ietf:params:oauth:grant-type:device_code":
			f.rfcPolls++
			switch {
			case body["device_code"] != "rfc-dev":
				writeJSON(w, 400, map[string]any{"error": "invalid_grant"})
			case f.rfcPolls == 1:
				writeJSON(w, 400, map[string]any{"error": "authorization_pending"})
			case f.rfcPolls == 2:
				f.slowDowns++
				writeJSON(w, 400, map[string]any{"error": "slow_down"})
			case !f.approved:
				writeJSON(w, 400, map[string]any{"error": "access_denied"})
			default:
				f.tokens(w)
			}
		default:
			writeJSON(w, 400, map[string]any{"error": "unsupported_grant_type"})
		}
	case "/rfc/device":
		writeJSON(w, 200, map[string]any{"device_code": "rfc-dev", "user_code": "WXYZ", "verification_uri": f.srv.URL + "/activate", "expires_in": 600, "interval": 2})
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeIdP) providers() map[string]OAuthProvider {
	u := f.srv.URL
	return map[string]OAuthProvider{
		"chatgpt": {DeviceStyle: DeviceStyleOpenAI, ClientID: "test-client", DeviceURL: u + "/api/accounts/deviceauth/usercode",
			PollURL: u + "/api/accounts/deviceauth/token", VerificationURL: u + "/codex/device", TokenURL: u + "/oauth/token",
			RedirectURL: u + "/deviceauth/callback", RefreshJSON: true, AccountClaim: []string{"https://api.openai.com/auth", "chatgpt_account_id"}},
		"rfc": {DeviceStyle: DeviceStyleRFC8628, ClientID: "test-client", DeviceURL: u + "/rfc/device", TokenURL: u + "/oauth/token"},
	}
}

// clock is a settable time shared by the service and the fake provider.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func newOAuth(t *testing.T, st *store.Memory, idp *fakeIdP, clk *clock, owner string) *OAuth {
	t.Helper()
	svc, err := New(st, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	o := NewOAuth(svc, st, idp.providers(), owner)
	o.Now = clk.now
	return o
}

func resolver(o *OAuth) secrets.Provider { return Resolver{Service: o.Service, OAuth: o} }

// The ChatGPT device sign-in end to end: the API's start returns the verification URL and the
// code, polls stay pending until the user approves, the code is exchanged, and from then on
// `secret:NAME` is the access token and `secret:NAME.account_id` the account id.
func TestDeviceSignInOpenAIDialect(t *testing.T) {
	ctx := context.Background()
	clk := &clock{t: time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)}
	idp := newFakeIdP(t, clk.now)
	st := store.NewMemory()
	o := newOAuth(t, st, idp, clk, "replica-a")

	c, created, err := o.Start(ctx, "acme", "chatgpt", "chatgpt", "alice")
	if err != nil || !created {
		t.Fatalf("start: %v %v", created, err)
	}
	if c.Status != model.OAuthPending || c.UserCode != "ABCD-1234" || c.VerificationURL != idp.srv.URL+"/codex/device" || c.LoginExpiresAt == nil {
		t.Fatalf("pending sign-in: %+v", c)
	}
	if _, err := resolver(o).Get(ctx, "acme", "chatgpt"); err == nil || !strings.Contains(err.Error(), "not approved yet") {
		t.Fatalf("a pending sign-in must not resolve: %v", err)
	}
	// Not due before the interval; then a poll that stays pending reschedules by the interval.
	o.Tick(ctx)
	clk.add(5 * time.Second)
	o.Tick(ctx)
	c, _ = o.Get(ctx, "acme", "chatgpt")
	if c.Status != model.OAuthPending || !c.NextAt.Equal(clk.now().Add(5*time.Second)) {
		t.Fatalf("after an unapproved poll: %+v", c)
	}
	idp.mu.Lock()
	idp.approved = true
	idp.mu.Unlock()
	clk.add(5 * time.Second)
	o.Tick(ctx)
	c, _ = o.Get(ctx, "acme", "chatgpt")
	if c.Status != model.OAuthActive || c.AccountID != "acct-42" || c.UserCode != "" || c.ExpiresAt == nil || !c.ExpiresAt.Equal(clk.now().Add(time.Hour)) {
		t.Fatalf("approved sign-in: %+v", c)
	}
	if want := c.ExpiresAt.Add(-5 * time.Minute); !c.NextAt.Equal(want) {
		t.Fatalf("next refresh %v, want 5 minutes before expiry %v", c.NextAt, want)
	}
	tok, err := resolver(o).Get(ctx, "acme", "chatgpt")
	if err != nil || !strings.Contains(tok, ".") {
		t.Fatalf("access token: %q %v", tok, err)
	}
	if acct, err := resolver(o).Get(ctx, "acme", "chatgpt"+AccountSuffix); err != nil || acct != "acct-42" {
		t.Fatalf("account id: %q %v", acct, err)
	}
	// Another tenant has no such sign-in.
	if _, err := resolver(o).Get(ctx, "other", "chatgpt"); !errors.Is(err, secrets.ErrNotFound) {
		t.Fatalf("other tenant: %v", err)
	}
	// Metadata never carries a token.
	b, _ := json.Marshal(c)
	if strings.Contains(string(b), tok) || strings.Contains(string(b), "rt-1") {
		t.Fatalf("metadata leaks a token: %s", b)
	}
}

// An outage of the token endpoint during the code exchange refuses nothing: the sign-in stays
// pending with the approved code kept (sealed), and once the provider is back the next tick
// exchanges that code (without asking the poll endpoint, which hands it out once) and the
// sign-in is active.
func TestDeviceSignInCodeExchangeOutageIsRetried(t *testing.T) {
	ctx := context.Background()
	clk := &clock{t: time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)}
	idp := newFakeIdP(t, clk.now)
	st := store.NewMemory()
	o := newOAuth(t, st, idp, clk, "replica-a")
	if _, _, err := o.Start(ctx, "acme", "chatgpt", "chatgpt", "alice"); err != nil {
		t.Fatal(err)
	}
	idp.mu.Lock()
	idp.approved, idp.exchangeDown = true, true
	idp.mu.Unlock()
	clk.add(5 * time.Second)
	o.Tick(ctx)
	c, _ := o.Get(ctx, "acme", "chatgpt")
	if c.Status != model.OAuthPending || !strings.Contains(c.Error, "503") {
		t.Fatalf("an exchange outage ended the sign-in: %+v", c)
	}
	idp.mu.Lock()
	idp.exchangeDown = false
	idp.mu.Unlock()
	clk.add(5 * time.Second)
	o.Tick(ctx)
	c, _ = o.Get(ctx, "acme", "chatgpt")
	if c.Status != model.OAuthActive || c.AccountID != "acct-42" {
		t.Fatalf("after the provider is back: %+v", c)
	}
	idp.mu.Lock()
	issued := idp.codesIssued
	idp.mu.Unlock()
	if issued != 1 {
		t.Fatalf("the retry asked the poll endpoint again (%d codes issued); it must exchange the kept code", issued)
	}
}

// RFC 8628: authorization_pending keeps polling at the interval, slow_down adds five seconds
// for good, then the tokens; access_denied ends the sign-in.
func TestDeviceSignInRFC8628PendingAndSlowDown(t *testing.T) {
	ctx := context.Background()
	clk := &clock{t: time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)}
	idp := newFakeIdP(t, clk.now)
	o := newOAuth(t, store.NewMemory(), idp, clk, "replica-a")
	c, _, err := o.Start(ctx, "acme", "rfcsub", "rfc", "alice")
	if err != nil || c.VerificationURL != idp.srv.URL+"/activate" || c.UserCode != "WXYZ" {
		t.Fatalf("start: %v %+v", err, c)
	}
	clk.add(2 * time.Second)
	o.Tick(ctx) // authorization_pending
	c, _ = o.Get(ctx, "acme", "rfcsub")
	if c.Status != model.OAuthPending || !c.NextAt.Equal(clk.now().Add(2*time.Second)) {
		t.Fatalf("pending: %+v", c)
	}
	clk.add(2 * time.Second)
	o.Tick(ctx) // slow_down: 2s + 5s
	c, _ = o.Get(ctx, "acme", "rfcsub")
	if !c.NextAt.Equal(clk.now().Add(7 * time.Second)) {
		t.Fatalf("slow_down must add five seconds: next %v at %v", c.NextAt, clk.now())
	}
	clk.add(2 * time.Second)
	o.Tick(ctx)
	if idp.rfcPolls != 2 {
		t.Fatalf("polled before the slowed interval: %d polls", idp.rfcPolls)
	}
	idp.mu.Lock()
	idp.approved = true
	idp.mu.Unlock()
	clk.add(5 * time.Second)
	o.Tick(ctx)
	c, _ = o.Get(ctx, "acme", "rfcsub")
	if c.Status != model.OAuthActive {
		t.Fatalf("after approval: %+v", c)
	}
	// The interval stays slowed for the rest of a sign-in: a fresh one that is denied fails.
	if _, _, err := o.Start(ctx, "acme", "denied", "rfc", "alice"); err != nil {
		t.Fatal(err)
	}
	idp.mu.Lock()
	idp.rfcPolls, idp.approved = 2, false
	idp.mu.Unlock()
	clk.add(10 * time.Second)
	o.Tick(ctx)
	c, _ = o.Get(ctx, "acme", "denied")
	if c.Status != model.OAuthFailed || !strings.Contains(c.Error, "access_denied") {
		t.Fatalf("denied sign-in: %+v", c)
	}
}

// signedIn returns an active sign-in "chatgpt" for acme.
func signedIn(t *testing.T, o *OAuth, idp *fakeIdP, clk *clock) {
	t.Helper()
	ctx := context.Background()
	idp.mu.Lock()
	idp.approved = true
	idp.mu.Unlock()
	if _, _, err := o.Start(ctx, "acme", "chatgpt", "chatgpt", "alice"); err != nil {
		t.Fatal(err)
	}
	clk.add(5 * time.Second)
	o.Tick(ctx)
	if c, _ := o.Get(ctx, "acme", "chatgpt"); c.Status != model.OAuthActive {
		t.Fatalf("sign-in: %+v", c)
	}
}

// Before the access token expires it is refreshed; the provider's rotated refresh token is the
// one used next (the old one is spent), and the gateway gets the new access token.
func TestRefreshRotatesTheRefreshToken(t *testing.T) {
	ctx := context.Background()
	clk := &clock{t: time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)}
	idp := newFakeIdP(t, clk.now)
	o := newOAuth(t, store.NewMemory(), idp, clk, "replica-a")
	signedIn(t, o, idp, clk)
	first, _ := resolver(o).Get(ctx, "acme", "chatgpt")
	for i := 1; i <= 3; i++ {
		clk.add(56 * time.Minute) // past expiry minus five minutes
		o.Tick(ctx)
		tok, err := resolver(o).Get(ctx, "acme", "chatgpt")
		if err != nil || tok == first {
			t.Fatalf("refresh %d: the token did not change (%v)", i, err)
		}
		first = tok
	}
	if idp.refreshes != 3 || len(idp.spent) != 3 {
		t.Fatalf("refreshes %d, spent %d: every refresh must use the token the previous one returned", idp.refreshes, len(idp.spent))
	}
	c, _ := o.Get(ctx, "acme", "chatgpt")
	if c.Error != "" || c.RefreshedAt == nil || !c.RefreshedAt.Equal(clk.now()) {
		t.Fatalf("after refreshes: %+v", c)
	}
}

// A revoked grant ends the sign-in with a clear error, the tokens are dropped, and the gateway
// gets that error instead of a dead token.
func TestRevokedRefreshTokenFailsClearly(t *testing.T) {
	ctx := context.Background()
	clk := &clock{t: time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)}
	idp := newFakeIdP(t, clk.now)
	st := store.NewMemory()
	o := newOAuth(t, st, idp, clk, "replica-a")
	signedIn(t, o, idp, clk)
	idp.mu.Lock()
	idp.revoked = true
	idp.mu.Unlock()
	clk.add(56 * time.Minute)
	o.Tick(ctx)
	c, ct, _ := st.GetOAuthCredential(ctx, "acme", "chatgpt")
	if c.Status != model.OAuthFailed || !strings.Contains(c.Error, "sign in again") || !strings.Contains(c.Error, "refresh_token_invalidated") {
		t.Fatalf("revoked: %+v", c)
	}
	if sec, err := o.unseal(c, ct); err != nil || sec.RefreshToken != "" || sec.AccessToken != "" {
		t.Fatalf("a failed sign-in must drop its tokens: %+v %v", sec, err)
	}
	_, err := resolver(o).Get(ctx, "acme", "chatgpt")
	if err == nil || errors.Is(err, secrets.ErrNotFound) || !strings.Contains(err.Error(), "sign in again") {
		t.Fatalf("the gateway must get the reason: %v", err)
	}
	// Failed rows are not due any more: nothing keeps hammering the provider.
	n := idp.refreshes
	clk.add(time.Hour)
	o.Tick(ctx)
	if idp.refreshes != n {
		t.Fatal("a failed sign-in was refreshed again")
	}
	// A transient failure (the provider down) keeps the sign-in and retries.
	signedIn(t, o, idp, clk)
	idp.mu.Lock()
	idp.revoked = false
	idp.mu.Unlock()
	idp.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) })
	clk.add(56 * time.Minute)
	o.Tick(ctx)
	c, _ = o.Get(ctx, "acme", "chatgpt")
	if c.Status != model.OAuthActive || !strings.Contains(c.Error, "503") || !c.NextAt.Equal(clk.now().Add(30*time.Second)) {
		t.Fatalf("transient failure: %+v", c)
	}
}

// Two replicas refreshing the same sign-in at the same moment spend its refresh token once:
// the row lease lets one through, the other finds it taken. A spent single-use token would
// otherwise revoke the grant for both.
func TestOneRefreshAcrossReplicas(t *testing.T) {
	ctx := context.Background()
	clk := &clock{t: time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)}
	idp := newFakeIdP(t, clk.now)
	st := store.NewMemory()
	a := newOAuth(t, st, idp, clk, "replica-a")
	b := newOAuth(t, st, idp, clk, "replica-b")
	signedIn(t, a, idp, clk)
	clk.add(56 * time.Minute)
	var wg sync.WaitGroup
	for _, o := range []*OAuth{a, b, a, b} {
		wg.Add(1)
		go func(o *OAuth) { defer wg.Done(); o.Tick(ctx) }(o)
	}
	wg.Wait()
	c, _ := a.Get(ctx, "acme", "chatgpt")
	if idp.refreshes != 1 || c.Status != model.OAuthActive || c.Error != "" {
		t.Fatalf("refreshes %d, state %+v: exactly one replica may refresh", idp.refreshes, c)
	}
	// An expired token found by the gateway is refreshed on the spot, once, by whichever
	// replica asks first.
	clk.add(2 * time.Hour)
	toks := make(chan string, 4)
	for _, o := range []*OAuth{a, b, a, b} {
		wg.Add(1)
		go func(o *OAuth) {
			defer wg.Done()
			tok, err := resolver(o).Get(ctx, "acme", "chatgpt")
			if err != nil {
				t.Error(err)
			}
			toks <- tok
		}(o)
	}
	wg.Wait()
	close(toks)
	seen := map[string]bool{}
	for tok := range toks {
		seen[tok] = true
	}
	if idp.refreshes != 2 || len(seen) != 1 {
		t.Fatalf("on-demand refresh: %d refreshes, %d distinct tokens", idp.refreshes, len(seen))
	}
}

// A sign-in nobody approved in time fails; a new sign-in under the name replaces the old one,
// and a replica still holding the old one's lease cannot save over it.
func TestExpiredSignInAndReplacement(t *testing.T) {
	ctx := context.Background()
	clk := &clock{t: time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)}
	idp := newFakeIdP(t, clk.now)
	st := store.NewMemory()
	o := newOAuth(t, st, idp, clk, "replica-a")
	if _, _, err := o.Start(ctx, "acme", "chatgpt", "chatgpt", "alice"); err != nil {
		t.Fatal(err)
	}
	clk.add(16 * time.Minute)
	o.Tick(ctx)
	c, _ := o.Get(ctx, "acme", "chatgpt")
	if c.Status != model.OAuthFailed || !strings.Contains(c.Error, "not approved") {
		t.Fatalf("expired sign-in: %+v", c)
	}
	old, _, err := st.LeaseOAuthCredential(ctx, "acme", "chatgpt", c.Generation, "replica-b", clk.now(), clk.now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	c2, created, err := o.Start(ctx, "acme", "chatgpt", "chatgpt", "bob")
	if err != nil || created || c2.Generation != c.Generation+1 || c2.Status != model.OAuthPending {
		t.Fatalf("restart: %v %v %+v", err, created, c2)
	}
	old.Status = model.OAuthActive
	if err := st.SaveOAuthCredential(ctx, old, nil, "replica-b"); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("a save for the replaced sign-in must conflict: %v", err)
	}
}

// One name, one kind: a sign-in may not take a plain credential's name or the reverse, and
// names carry no '.' (NAME.account_id is derived). An unknown provider names the known ones.
func TestSignInNamesAndProviders(t *testing.T) {
	ctx := context.Background()
	clk := &clock{t: time.Now()}
	idp := newFakeIdP(t, clk.now)
	o := newOAuth(t, store.NewMemory(), idp, clk, "replica-a")
	if _, _, err := o.Put(ctx, "acme", "plain", "v", "alice"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := o.Start(ctx, "acme", "plain", "chatgpt", "alice"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a sign-in over a plain credential: %v", err)
	}
	if _, _, err := o.Start(ctx, "acme", "chat.gpt", "chatgpt", "alice"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a dotted name: %v", err)
	}
	if _, _, err := o.Start(ctx, "acme", "x", "nope", "alice"); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "chatgpt") {
		t.Fatalf("unknown provider: %v", err)
	}
	if _, _, err := o.Start(ctx, "acme", "sub", "chatgpt", "alice"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := o.Put(ctx, "acme", "sub", "v", "alice"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a plain credential over a sign-in: %v", err)
	}
	// A provider refusing the start is ErrProvider, nothing stored.
	idp.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(404) })
	if _, _, err := o.Start(ctx, "acme", "down", "chatgpt", "alice"); !errors.Is(err, ErrProvider) {
		t.Fatalf("provider refusal: %v", err)
	}
	if _, err := o.Get(ctx, "acme", "down"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a refused start stored something: %v", err)
	}
}

// The configured providers lay over the defaults field by field; a new one must be complete.
func TestMergeOAuthProviders(t *testing.T) {
	ps, err := MergeOAuthProviders(map[string]OAuthProvider{"chatgpt": {ClientID: "other"}})
	if err != nil || ps["chatgpt"].ClientID != "other" || ps["chatgpt"].TokenURL != "https://auth.openai.com/oauth/token" {
		t.Fatalf("override: %v %+v", err, ps["chatgpt"])
	}
	if _, err := MergeOAuthProviders(map[string]OAuthProvider{"mine": {ClientID: "x"}}); err == nil {
		t.Fatal("an incomplete new provider must be refused")
	}
	if _, err := MergeOAuthProviders(map[string]OAuthProvider{"mine": {DeviceStyle: DeviceStyleRFC8628, ClientID: "x", DeviceURL: "ftp://x", TokenURL: "https://t"}}); err == nil {
		t.Fatal("a non-http URL must be refused")
	}
}
