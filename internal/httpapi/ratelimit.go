package httpapi

import (
	"errors"
	"math"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// RateLimit bounds attempts per source address with a token bucket: Burst attempts at once,
// then one more every Every. It applies to POST /v1/auth/ci (every call) and to failed bearer
// authentication (a token that is no admin token, tenant token, API key or valid JWT). The
// zero value is the default; Off turns it off.
//
// The source is the connection's address: behind a proxy that does not preserve it every
// client shares one bucket, so a proxy deployment either keeps the address (PROXY protocol,
// a direct listener) or turns the limit off and limits at the proxy.
type RateLimit struct {
	Off   bool
	Burst int           // default 30
	Every time.Duration // default 1s
}

func (c RateLimit) withDefaults() RateLimit {
	if c.Burst <= 0 {
		c.Burst = 30
	}
	if c.Every <= 0 {
		c.Every = time.Second
	}
	return c
}

// limiter keeps one bucket per key in memory (per replica: an attacker spread over replicas
// gets a bucket on each, which still bounds the rate). Idle buckets are dropped on access.
type limiter struct {
	cfg       RateLimit
	now       func() time.Time
	buckets   sync.Map // key → *bucket
	lastSweep atomic.Int64
}

type bucket struct {
	mu     sync.Mutex
	tokens float64
	at     time.Time
}

func newLimiter(cfg RateLimit) *limiter {
	return &limiter{cfg: cfg.withDefaults(), now: time.Now}
}

// refill brings b up to now; the caller holds b.mu.
func (l *limiter) refill(b *bucket, now time.Time) {
	b.tokens = math.Min(float64(l.cfg.Burst), b.tokens+float64(now.Sub(b.at))/float64(l.cfg.Every))
	b.at = now
}

func (l *limiter) bucket(key string, now time.Time) *bucket {
	l.sweep(now)
	v, _ := l.buckets.LoadOrStore(key, &bucket{tokens: float64(l.cfg.Burst), at: now})
	return v.(*bucket)
}

// wait is how long until key has an attempt left (0: it has one now); nothing is spent.
func (l *limiter) wait(key string) time.Duration {
	now := l.now()
	b := l.bucket(key, now)
	b.mu.Lock()
	defer b.mu.Unlock()
	l.refill(b, now)
	return l.until(b)
}

// take spends one attempt of key, or says how long until there is one.
func (l *limiter) take(key string) time.Duration {
	now := l.now()
	b := l.bucket(key, now)
	b.mu.Lock()
	defer b.mu.Unlock()
	l.refill(b, now)
	if d := l.until(b); d > 0 {
		return d
	}
	b.tokens--
	return 0
}

// refund gives back an attempt take spent (an authentication that succeeded).
func (l *limiter) refund(key string) {
	now := l.now()
	b := l.bucket(key, now)
	b.mu.Lock()
	defer b.mu.Unlock()
	l.refill(b, now)
	b.tokens = min(float64(l.cfg.Burst), b.tokens+1)
}

func (l *limiter) until(b *bucket) time.Duration {
	if b.tokens >= 1 {
		return 0
	}
	return time.Duration((1 - b.tokens) * float64(l.cfg.Every))
}

// sweep drops, at most once a minute, the buckets that have refilled completely: they are
// what a new bucket would be.
func (l *limiter) sweep(now time.Time) {
	last := l.lastSweep.Load()
	if now.UnixNano()-last < int64(time.Minute) || !l.lastSweep.CompareAndSwap(last, now.UnixNano()) {
		return
	}
	full := time.Duration(l.cfg.Burst) * l.cfg.Every
	l.buckets.Range(func(k, v any) bool {
		b := v.(*bucket)
		b.mu.Lock()
		if now.Sub(b.at) >= full {
			l.buckets.Delete(k)
		}
		b.mu.Unlock()
		return true
	})
}

// sourceOf is the address a request came from (the connection's, see RateLimit).
func sourceOf(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// authLimiter is the platform's limiter, built on first use; nil when the limit is off.
func (p *Platform) authLimiter() *limiter {
	if p.AuthLimit.Off {
		return nil
	}
	p.limitOnce.Do(func() { p.limiter = newLimiter(p.AuthLimit) })
	return p.limiter
}

// writeRateLimited is 429 with Retry-After (whole seconds, at least one).
func writeRateLimited(w http.ResponseWriter, d time.Duration) {
	w.Header().Set("Retry-After", strconv.Itoa(max(1, int(math.Ceil(d.Seconds())))))
	writeErrWith(w, http.StatusTooManyRequests, ErrorBody{Code: CodeRateLimited}, errors.New("too many attempts from this address: retry later"))
}
