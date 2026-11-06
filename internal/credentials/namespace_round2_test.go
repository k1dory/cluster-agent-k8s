package credentials

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"testing"
	"time"

	"agent-sandbox/internal/model"
	"agent-sandbox/internal/store"
)

// slowWrites widens the window between a writer's "the other kind is absent" check and its
// write, as a second replica's round trip to Postgres does.
type slowWrites struct{ *store.Memory }

func (s slowWrites) PutCredential(ctx context.Context, c *model.Credential, ct []byte) (bool, error) {
	time.Sleep(20 * time.Millisecond)
	return s.Memory.PutCredential(ctx, c, ct)
}

func (s slowWrites) PutOAuthCredential(ctx context.Context, c *model.OAuthCredential, ct []byte) (bool, error) {
	time.Sleep(20 * time.Millisecond)
	return s.Memory.PutOAuthCredential(ctx, c, ct)
}

// Two services over one store stand for two replicas. A plain credential and a sign-in
// created at once under one name used to both succeed (each checked the other's table, then
// wrote its own); exactly one may.
func TestPlainAndSignInCannotShareANameRound2(t *testing.T) {
	ctx := context.Background()
	clk := &clock{t: time.Now()}
	idp := newFakeIdP(t, clk.now)
	st := slowWrites{store.NewMemory()}
	replica := func(owner string) *OAuth {
		svc, err := New(st, make([]byte, 32))
		if err != nil {
			t.Fatal(err)
		}
		o := NewOAuth(svc, st, idp.providers(), owner)
		o.Now = clk.now
		return o
	}
	a, b := replica("replica-a"), replica("replica-b")
	for i := 0; i < 10; i++ {
		name := "both" + strconv.Itoa(i)
		var wg sync.WaitGroup
		var plainErr, oauthErr error
		start := make(chan struct{})
		wg.Add(2)
		go func() { defer wg.Done(); <-start; _, _, plainErr = a.Put(ctx, "acme", name, "v", "alice") }()
		go func() { defer wg.Done(); <-start; _, _, oauthErr = b.Start(ctx, "acme", name, "chatgpt", "alice") }()
		close(start)
		wg.Wait()
		if (plainErr == nil) == (oauthErr == nil) {
			t.Fatalf("%s: plain=%v oauth=%v, want exactly one to succeed", name, plainErr, oauthErr)
		}
		for _, err := range []error{plainErr, oauthErr} {
			if err != nil && !errors.Is(err, ErrInvalid) {
				t.Fatalf("%s: the loser failed with %v, want ErrInvalid", name, err)
			}
		}
		_, _, perr := st.GetCredential(ctx, "acme", name)
		_, _, oerr := st.GetOAuthCredential(ctx, "acme", name)
		if (perr == nil) == (oerr == nil) {
			t.Fatalf("%s: stored plain=%v oauth=%v, want one kind", name, perr, oerr)
		}
	}
}

// NAME.account_id resolves from the sign-in NAME, so a plain credential under it is the same
// clash; the old checks compared the bare name only, and the resolver then preferred plain.
func TestAccountSuffixBelongsToTheSignInRound2(t *testing.T) {
	ctx := context.Background()
	clk := &clock{t: time.Now()}
	idp := newFakeIdP(t, clk.now)
	o := newOAuth(t, store.NewMemory(), idp, clk, "replica-a")
	if _, _, err := o.Start(ctx, "acme", "sub", "chatgpt", "alice"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := o.Put(ctx, "acme", "sub"+AccountSuffix, "v", "alice"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a plain credential over a sign-in's account id: %v", err)
	}
	if _, _, err := o.Put(ctx, "acme", "other"+AccountSuffix, "v", "alice"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := o.Start(ctx, "acme", "other", "chatgpt", "alice"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a sign-in whose account id a plain credential holds: %v", err)
	}
	// Another scope's names are its own.
	if _, _, err := o.Put(ctx, "globex", "sub", "v", "alice"); err != nil {
		t.Fatal(err)
	}
}
