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
	lookedUp  func() // tests: runs between a bucket's lookup and its use
}

type bucket struct {
	mu     sync.Mutex
	tokens float64
	at     time.Time
	gone   bool // evicted by sweep: whoever holds it looks the key up again
}

func newLimiter(cfg RateLimit) *limiter {
	return &limiter{cfg: cfg.withDefaults(), now: time.Now}
}

// refill brings b up to now; the caller holds b.mu.
func (l *limiter) refill(b *bucket, now time.Time) {
	b.tokens = math.Min(float64(l.cfg.Burst), b.tokens+float64(now.Sub(b.at))/float64(l.cfg.Every))
	b.at = now
}

// use runs fn on key's bucket, locked and refilled. A bucket the sweep evicted between the
// lookup and the lock is gone: spending from it would let the next request start from a
// fresh full bucket, so the lookup is repeated until it holds the bucket in the map.
func (l *limiter) use(key string, fn func(b *bucket)) {
	for {
		now := l.now()
		l.sweep(now)
		v, _ := l.buckets.LoadOrStore(key, &bucket{tokens: float64(l.cfg.Burst), at: now})
		if l.lookedUp != nil {
			l.lookedUp()
		}
		b := v.(*bucket)
		b.mu.Lock()
		if b.gone {
			b.mu.Unlock()
			continue
		}
		l.refill(b, now)
		fn(b)
		b.mu.Unlock()
		return
	}
}

// wait is how long until key has an attempt left (0: it has one now); nothing is spent.
func (l *limiter) wait(key string) (d time.Duration) {
	l.use(key, func(b *bucket) { d = l.until(b) })
	return d
}

// take spends one attempt of key, or says how long until there is one.
func (l *limiter) take(key string) (d time.Duration) {
	l.use(key, func(b *bucket) {
		if d = l.until(b); d == 0 {
			b.tokens--
		}
	})
	return d
}

// refund gives back an attempt take spent (an authentication that succeeded).
func (l *limiter) refund(key string) {
	l.use(key, func(b *bucket) { b.tokens = min(float64(l.cfg.Burst), b.tokens+1) })
}

func (l *limiter) until(b *bucket) time.Duration {
	if b.tokens >= 1 {
		return 0
	}
	return time.Duration((1 - b.tokens) * float64(l.cfg.Every))
}

// sweep drops, at most once a minute, the buckets that have refilled completely: they are
// what a new bucket would be. Each is marked gone under its own lock (see use).
func (l *limiter) sweep(now time.Time) {
	last := l.lastSweep.Load()
	if now.UnixNano()-last < int64(time.Minute) || !l.lastSweep.CompareAndSwap(last, now.UnixNano()) {
		return
	}
	full := time.Duration(l.cfg.Burst) * l.cfg.Every
	l.buckets.Range(func(k, v any) bool {
		b := v.(*bucket)
		b.mu.Lock()
		if !b.gone && now.Sub(b.at) >= full {
			b.gone = true // under b.mu: a take that already holds it sees this and looks again
			l.buckets.CompareAndDelete(k, b)
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
