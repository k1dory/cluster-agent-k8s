package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
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

// blockingVerifier holds every verification until released and counts them.
type blockingVerifier struct {
	calls   atomic.Int32
	release chan struct{}
}

func (v *blockingVerifier) Verify(ctx context.Context, _ string) (Principal, error) {
	v.calls.Add(1)
	select {
	case <-v.release:
	case <-ctx.Done():
	}
	return Principal{}, errors.New("bad signature")
}

// Concurrent guesses from one address spend the budget before they are checked: with a
// burst of 3 and a verifier that is slow, only 3 of 10 reach it, the others are 429 at once.
// A token that authenticates gives its attempt back.
func TestReviewConcurrentGuessesCannotOutrunTheLimit(t *testing.T) {
	s := newStack(t)
	v := &blockingVerifier{release: make(chan struct{})}
	s.p.Verifier = v
	s.p.AuthLimit = RateLimit{Burst: 3, Every: time.Hour}
	srv := httptest.NewServer(s.p.Routes())
	defer srv.Close()
	var once sync.Once
	release := func() { once.Do(func() { close(v.release) }) }
	defer release() // before srv.Close, which waits for the handlers held in the verifier

	// Successes do not spend: many valid requests leave the whole burst for guesses.
	for i := 0; i < 10; i++ {
		if resp, body := call(t, "GET", srv.URL+"/v1/whoami", "t0k", nil, nil); resp.StatusCode != 200 {
			t.Fatalf("valid token %d: %d %s", i, resp.StatusCode, body)
		}
	}
	codes := make(chan int, 10)
	for i := 0; i < 10; i++ {
		go func() {
			resp, _ := call(t, "GET", srv.URL+"/v1/whoami", "a.b.c", nil, nil)
			codes <- resp.StatusCode
		}()
	}
	limited := 0
	timeout := time.After(10 * time.Second)
	for limited < 7 {
		select {
		case c := <-codes:
			if c != 429 {
				t.Fatalf("a guess was answered %d while the first three were still being checked", c)
			}
			limited++
		case <-timeout:
			t.Fatalf("only %d guesses refused; %d reached the verifier", limited, v.calls.Load())
		}
	}
	// Counted only once every guess is answered: a guess holding a reservation may not have
	// entered the verifier yet while the others were refused.
	release()
	for i := 0; i < 3; i++ {
		if c := <-codes; c != 401 {
			t.Fatalf("a checked guess: %d", c)
		}
	}
	if n := v.calls.Load(); n != 3 {
		t.Fatalf("%d guesses reached the verifier, want 3", n)
	}
}

// A take that found a bucket the sweep then evicts must not spend from the detached bucket:
// the next take would get a fresh full one and the address would exceed its burst.
func TestReviewSweepCannotDetachABucketATakeIsUsing(t *testing.T) {
	now := time.Unix(1000, 0)
	l := newLimiter(RateLimit{Burst: 1, Every: 10 * time.Second})
	l.now = func() time.Time { return now }
	l.wait("a") // the bucket exists, full, and is idle from here on
	now = now.Add(time.Hour)
	l.lastSweep.Store(now.UnixNano()) // no sweep before the lookup: it comes right after it
	var once sync.Once
	l.lookedUp = func() { // the sweep runs between the lookup and the take
		once.Do(func() {
			l.lastSweep.Store(0)
			l.sweep(now)
		})
	}
	if d := l.take("a"); d != 0 {
		t.Fatalf("first attempt: %v", d)
	}
	if d := l.take("a"); d == 0 {
		t.Fatal("a second attempt passed a burst of one: the first spent from an evicted bucket")
	}
}

// Time is read under the bucket's lock: a take that read the clock, paused, and locked after
// a later take must not refill backwards. Burst 2, 10s: A reads t=0 and pauses, B takes at
// t=1 (one left), A then takes the last one; reading t=0 after B's t=1 used to subtract a
// tenth of a token and refuse A.
func TestReviewTakeDoesNotRefillBackwards(t *testing.T) {
	t0 := time.Unix(1000, 0)
	var mu sync.Mutex
	now := t0
	l := newLimiter(RateLimit{Burst: 2, Every: 10 * time.Second})
	l.now = func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	l.wait("a") // the bucket exists, full, at t0
	var fired atomic.Bool
	l.lookedUp = func() { // A has looked the bucket up, not locked it yet: B runs at t=1
		if fired.Swap(true) {
			return
		}
		mu.Lock()
		now = t0.Add(time.Second)
		mu.Unlock()
		if d := l.take("a"); d != 0 {
			t.Errorf("B: %v", d)
		}
	}
	if d := l.take("a"); d != 0 {
		t.Fatalf("A was refused with %v: the bucket was refilled backwards", d)
	}
}
