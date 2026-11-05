package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"agent-sandbox/internal/apikeys"
	"agent-sandbox/internal/ciauth"
)

// Failed bearer authentication is limited per source address: once the bucket is empty every
// token from there is 429 unchecked (valid ones too), requests without a token are not
// counted, and another address is not affected.
func TestReviewFailedAuthenticationIsRateLimited(t *testing.T) {
	s := newStack(t)
	s.p.AuthLimit = RateLimit{Burst: 3, Every: time.Hour}
	h := s.p.Routes()
	srv := httptest.NewServer(h)
	defer srv.Close()
	for i := 0; i < 3; i++ {
		resp, body := call(t, "GET", srv.URL+"/v1/whoami", "guess-"+strconv.Itoa(i), nil, nil)
		wantErr(t, "guess", resp, body, 401, CodeUnauthorized)
	}
	for _, tok := range []string{"guess-4", "t0k", "sbk_not_a_key"} {
		resp, body := call(t, "GET", srv.URL+"/v1/whoami", tok, nil, nil)
		wantErr(t, "after the burst, "+tok, resp, body, 429, CodeRateLimited)
		if ra, _ := strconv.Atoi(resp.Header.Get("Retry-After")); ra < 1 {
			t.Fatalf("Retry-After %q", resp.Header.Get("Retry-After"))
		}
	}
	resp, body := call(t, "GET", srv.URL+"/v1/whoami", "", nil, nil)
	wantErr(t, "no token", resp, body, 401, CodeUnauthorized)
	// Another address still gets in.
	req := httptest.NewRequest("GET", "/v1/whoami", nil)
	req.RemoteAddr = "192.0.2.9:4711"
	req.Header.Set("Authorization", "Bearer t0k")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("another address: %d %s", rec.Code, rec.Body)
	}
}

// Every POST /v1/auth/ci counts, refused or not; Off turns both limits off.
func TestReviewCIExchangeIsRateLimitedAndTheLimitCanBeOff(t *testing.T) {
	s := newStack(t)
	st := s.orch.Store
	s.p.Keys = &apikeys.Service{Store: st}
	s.p.CIAuth = &ciauth.Service{Trusts: st, Keys: s.p.Keys, Uses: st}
	s.p.AuthLimit = RateLimit{Burst: 2, Every: time.Hour}
	srv := httptest.NewServer(s.p.Routes())
	defer srv.Close()
	for i, want := range []int{401, 400, 429, 429} {
		body := `{"token":"x"}`
		if i == 1 {
			body = `{}`
		}
		resp, out := call(t, "POST", srv.URL+"/v1/auth/ci", "", body, nil)
		if resp.StatusCode != want {
			t.Fatalf("exchange %d: %d %s, want %d", i, resp.StatusCode, out, want)
		}
		if want == 429 {
			wantErr(t, "exchange", resp, out, 429, CodeRateLimited)
		}
	}

	off := newStack(t)
	off.p.AuthLimit = RateLimit{Off: true, Burst: 1, Every: time.Hour}
	srv2 := httptest.NewServer(off.p.Routes())
	defer srv2.Close()
	for i := 0; i < 10; i++ {
		if resp, body := call(t, "GET", srv2.URL+"/v1/whoami", "guess", nil, nil); resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("limit off, guess %d: %d %s", i, resp.StatusCode, body)
		}
	}
}

// The bucket refills at its rate and idle full buckets are dropped.
func TestReviewLimiterRefillsAndForgets(t *testing.T) {
	now := time.Unix(1000, 0)
	l := newLimiter(RateLimit{Burst: 2, Every: 10 * time.Second})
	l.now = func() time.Time { return now }
	if l.take("a") != 0 || l.take("a") != 0 {
		t.Fatal("the burst is two")
	}
	if d := l.take("a"); d != 10*time.Second {
		t.Fatalf("empty bucket waits one interval, got %v", d)
	}
	now = now.Add(5 * time.Second)
	if d := l.wait("a"); d != 5*time.Second {
		t.Fatalf("half refilled: %v", d)
	}
	now = now.Add(5 * time.Second)
	if l.take("a") != 0 {
		t.Fatal("refilled one")
	}
	now = now.Add(time.Hour)
	l.wait("b") // a sweep runs on access
	if _, ok := l.buckets.Load("a"); ok {
		t.Fatal("an idle full bucket is kept")
	}
}
