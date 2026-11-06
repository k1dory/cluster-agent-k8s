package credentials

import (
	"context"
	"sync"
	"testing"
	"time"

	"agent-sandbox/internal/model"
	"agent-sandbox/internal/store"
)

// lostLock is the memory store whose tenant lock no longer excludes anyone, as a Postgres
// advisory lock does once its connection is gone, with writes slowed down as another
// replica's round trip is. A check that rested on that lock and a write after it could both
// pass for the two kinds at once.
type lostLock struct{ *store.Memory }

func (lostLock) WithTenantLock(ctx context.Context, _ string, fn func(ctx context.Context) error) error {
	return fn(ctx)
}

func (s lostLock) PutCredential(ctx context.Context, c *model.Credential, ct []byte) (bool, error) {
	time.Sleep(20 * time.Millisecond)
	return s.Memory.PutCredential(ctx, c, ct)
}

func (s lostLock) PutOAuthCredential(ctx context.Context, c *model.OAuthCredential, ct []byte) (bool, error) {
	time.Sleep(20 * time.Millisecond)
	return s.Memory.PutOAuthCredential(ctx, c, ct)
}

// The namespace used to hold only while the tenant lock did: the absence check and the write
// were separate store calls. They are one atomic store operation now, so a plain credential
// and a sign-in created at once under one name still leave exactly one row however the lock
// fared.
func TestOneNameOneKindWithoutTheLockRound2(t *testing.T) {
	ctx := context.Background()
	clk := &clock{t: time.Now()}
	idp := newFakeIdP(t, clk.now)
	st := lostLock{store.NewMemory()}
	for i := range 10 {
		name := "tok" + string(rune('a'+i))
		svc, err := New(st, make([]byte, 32))
		if err != nil {
			t.Fatal(err)
		}
		o := NewOAuth(svc, st, idp.providers(), "r1")
		var wg sync.WaitGroup
		var plainErr, oauthErr error
		wg.Add(2)
		go func() { defer wg.Done(); _, _, plainErr = svc.Put(ctx, "acme", name, "v", "alice") }()
		go func() { defer wg.Done(); _, _, oauthErr = o.Start(ctx, "acme", name, "chatgpt", "alice") }()
		wg.Wait()
		_, _, perr := st.GetCredential(ctx, "acme", name)
		_, _, oerr := st.GetOAuthCredential(ctx, "acme", name)
		if (perr == nil) == (oerr == nil) || (plainErr == nil) == (oauthErr == nil) {
			t.Fatalf("%s: plain %v (row %v), sign-in %v (row %v): want exactly one", name, plainErr, perr, oauthErr, oerr)
		}
	}
}
