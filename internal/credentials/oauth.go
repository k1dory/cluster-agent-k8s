package credentials

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"agent-sandbox/internal/model"
	"agent-sandbox/internal/secrets"
	"agent-sandbox/internal/store"
)

// AccountSuffix derives a second reference from a sign-in: `secret:NAME.account_id` resolves to
// the account id the provider put in the ID token (ChatGPT's backend wants it as the
// ChatGPT-Account-ID header next to the bearer token).
const AccountSuffix = ".account_id"

// ErrProvider is a refusal or failure of the OAuth provider while starting a sign-in.
var ErrProvider = errors.New("oauth provider")

// OAuth keeps tenants' subscription sign-ins: a tenant starts a device sign-in through the API
// (the response carries the verification URL and the user code to type there), every replica
// polls and refreshes the due ones under a lease on the row (Run), and the gateway resolves
// `secret:NAME` to the current access token (Resolver). The refresh token never leaves
// sandboxd: it is encrypted under the server's credentials key, like a plain credential.
type OAuth struct {
	*Service
	Store     store.OAuthCredentials
	Providers map[string]OAuthProvider // MergeOAuthProviders(config)
	Owner     string                   // this replica: the lease owner
	HTTP      *http.Client             // nil = 20 second timeout
	// RefreshBefore: how long before its expiry an access token is replaced (default 5m).
	// Lease: how long one replica may hold a row while it talks to the provider (default 1m;
	// longer than the HTTP timeout, so a lease never lapses under a request still running).
	// Every: how often Run looks for due rows (default 5s).
	RefreshBefore time.Duration
	Lease         time.Duration
	Every         time.Duration
	Log           *slog.Logger
	Now           func() time.Time

	// The lease serializes replicas; within one replica the lease is the replica's own, so
	// concurrent requests of the same process are serialized per row here.
	mu    sync.Mutex
	locks map[string]*sync.Mutex
}

// lock serializes this process's work on one row.
func (o *OAuth) lock(tenant, name string) func() {
	o.mu.Lock()
	if o.locks == nil {
		o.locks = map[string]*sync.Mutex{}
	}
	l, ok := o.locks[tenant+"\x00"+name]
	if !ok {
		l = &sync.Mutex{}
		o.locks[tenant+"\x00"+name] = l
	}
	o.mu.Unlock()
	l.Lock()
	return l.Unlock
}

// NewOAuth wires the sign-ins next to the plain credentials of svc (one name, one kind: each
// refuses a name the other holds) with the providers sandboxd may use (MergeOAuthProviders).
// owner names this replica in the row leases.
func NewOAuth(svc *Service, st store.OAuthCredentials, providers map[string]OAuthProvider, owner string) *OAuth {
	svc.signIns = st
	return &OAuth{Service: svc, Store: st, Providers: providers, Owner: owner}
}

// oauthSecret is what a row keeps encrypted: the device code while pending, the tokens after.
type oauthSecret struct {
	DeviceCode string `json:"device_code,omitempty"`
	Interval   int64  `json:"interval,omitempty"` // seconds
	// An approved OpenAI login whose code exchange failed transiently (deviceStart).
	AuthorizationCode string `json:"authorization_code,omitempty"`
	CodeVerifier      string `json:"code_verifier,omitempty"`
	AccessToken       string `json:"access_token,omitempty"`
	RefreshToken      string `json:"refresh_token,omitempty"`
}

func (o *OAuth) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

func (o *OAuth) refreshBefore() time.Duration {
	if o.RefreshBefore > 0 {
		return o.RefreshBefore
	}
	return 5 * time.Minute
}

func (o *OAuth) lease() time.Duration {
	if o.Lease > 0 {
		return o.Lease
	}
	return time.Minute
}

func (o *OAuth) log() *slog.Logger {
	if o.Log != nil {
		return o.Log
	}
	return slog.Default()
}

func (o *OAuth) client(provider string) (*oauthClient, error) {
	p, ok := o.Providers[provider]
	if !ok {
		names := make([]string, 0, len(o.Providers))
		for n := range o.Providers {
			names = append(names, n)
		}
		sort.Strings(names)
		return nil, fmt.Errorf("%w: unknown provider %q (configured: %s)", ErrInvalid, provider, strings.Join(names, ", "))
	}
	h := o.HTTP
	if h == nil {
		h = &http.Client{Timeout: 20 * time.Second}
	}
	return &oauthClient{p: p, http: h, now: o.now}, nil
}

func (o *OAuth) seal(c *model.OAuthCredential, s *oauthSecret) []byte {
	b, _ := json.Marshal(s)
	return o.Service.seal(c.Tenant, "oauth\x00"+c.Name, b)
}

func (o *OAuth) unseal(c *model.OAuthCredential, ciphertext []byte) (*oauthSecret, error) {
	b, err := o.Service.unseal(c.Tenant, "oauth\x00"+c.Name, ciphertext)
	if err != nil {
		return nil, err
	}
	var s oauthSecret
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("oauth credential %s/%s: %w", c.Tenant, c.Name, err)
	}
	return &s, nil
}

// Start begins a device sign-in under name with provider: the provider is asked for a user
// code now (a refusal is ErrProvider), the row starts pending, and Run polls it. A sign-in
// already under the name, whatever its state, is replaced: its tokens stop resolving at once.
func (o *OAuth) Start(ctx context.Context, tenant, name, provider, by string) (*model.OAuthCredential, bool, error) {
	if !nameRe.MatchString(name) || strings.Contains(name, ".") {
		return nil, false, fmt.Errorf("%w: name must be 1-64 characters: letters, digits, '_' or '-' (a '.' would clash with %s)", ErrInvalid, AccountSuffix)
	}
	// One name, one kind: `secret:NAME` must not mean a plain credential to one reader and a
	// sign-in to another.
	if _, _, err := o.Service.Store.GetCredential(ctx, tenant, name); err == nil {
		return nil, false, fmt.Errorf("%w: %q is a plain credential in this scope; remove it first", ErrInvalid, name)
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, false, err
	}
	cl, err := o.client(provider)
	if err != nil {
		return nil, false, err
	}
	d, err := cl.start(ctx)
	if err != nil {
		return nil, false, fmt.Errorf("%w: %s: %v", ErrProvider, provider, err)
	}
	now := o.now()
	exp := d.ExpiresAt
	c := &model.OAuthCredential{Tenant: tenant, Name: name, Provider: provider, Status: model.OAuthPending,
		VerificationURL: d.VerificationURL, UserCode: d.UserCode, LoginExpiresAt: &exp, NextAt: now.Add(d.Interval), CreatedBy: by}
	created, err := o.Store.PutOAuthCredential(ctx, c, o.seal(c, &oauthSecret{DeviceCode: d.Code, Interval: int64(d.Interval / time.Second)}))
	if err != nil {
		return nil, false, err
	}
	return c, created, nil
}

// Get returns a sign-in's metadata.
func (o *OAuth) Get(ctx context.Context, tenant, name string) (*model.OAuthCredential, error) {
	c, _, err := o.Store.GetOAuthCredential(ctx, tenant, name)
	return c, err
}

// List returns a scope's sign-ins, by name.
func (o *OAuth) List(ctx context.Context, tenant string) ([]*model.OAuthCredential, error) {
	return o.Store.ListOAuthCredentials(ctx, tenant)
}

// Delete forgets a sign-in: the next request that needs it fails to resolve. The grant itself
// stays valid at the provider until the user revokes it there.
func (o *OAuth) Delete(ctx context.Context, tenant, name string) error {
	return o.Store.DeleteOAuthCredential(ctx, tenant, name)
}

// Run polls pending sign-ins and refreshes active ones when they are due, on every replica;
// the row lease makes one replica at a time act on a row. It returns when ctx ends.
func (o *OAuth) Run(ctx context.Context) {
	every := o.Every
	if every <= 0 {
		every = 5 * time.Second
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		o.Tick(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Tick acts once on every due row. Exported for tests.
func (o *OAuth) Tick(ctx context.Context) {
	due, err := o.Store.DueOAuthCredentials(ctx, o.now(), 100)
	if err != nil {
		o.log().Warn("oauth credentials", "err", err)
		return
	}
	for _, c := range due {
		if _, err := o.act(ctx, c.Tenant, c.Name, c.Generation); err != nil && !errors.Is(err, store.ErrConflict) && !errors.Is(err, store.ErrNotFound) {
			o.log().Warn("oauth credential", "tenant", c.Tenant, "name", c.Name, "err", err)
		}
	}
}

// act takes the row's lease and does what its state calls for: one poll of a pending sign-in,
// or a refresh of an active one. The result is saved under the lease; a save that finds the
// lease gone (ErrConflict) is dropped, never written over a newer state.
func (o *OAuth) act(ctx context.Context, tenant, name string, gen int) (*model.OAuthCredential, error) {
	defer o.lock(tenant, name)()
	now := o.now()
	c, ciphertext, err := o.Store.LeaseOAuthCredential(ctx, tenant, name, gen, o.Owner, now, now.Add(o.lease()))
	if err != nil {
		return nil, err
	}
	sec, err := o.unseal(c, ciphertext)
	if err != nil {
		return nil, err
	}
	// Whoever held the lease before may have done the work already (two replicas found the
	// same expired token): under the lease the row is what counts, and a row that is not due
	// is left as it is.
	if c.NextAt.After(now) && (c.Status != model.OAuthActive || c.ExpiresAt == nil || c.ExpiresAt.After(now.Add(skew))) {
		return c, o.Store.SaveOAuthCredential(ctx, c, ciphertext, o.Owner)
	}
	cl, err := o.client(c.Provider)
	if err != nil {
		// The provider left the configuration: nothing can poll or refresh this row any more.
		o.fail(c, sec, err.Error())
		return c, o.Store.SaveOAuthCredential(ctx, c, o.seal(c, sec), o.Owner)
	}
	// The provider gets less than the lease: a request still running when the lease lapses
	// could spend a refresh token another replica is about to spend too.
	pctx, cancel := context.WithTimeout(ctx, o.lease()*3/4)
	defer cancel()
	switch c.Status {
	case model.OAuthPending:
		o.poll(pctx, cl, c, sec)
	case model.OAuthActive:
		o.refresh(pctx, cl, c, sec)
	default:
		c.NextAt = now.Add(24 * time.Hour)
	}
	return c, o.Store.SaveOAuthCredential(ctx, c, o.seal(c, sec), o.Owner)
}

func (o *OAuth) fail(c *model.OAuthCredential, sec *oauthSecret, reason string) {
	c.Status, c.Error = model.OAuthFailed, reason
	c.VerificationURL, c.UserCode = "", ""
	*sec = oauthSecret{} // nothing worth keeping: a dead refresh token is only a liability
}

func (o *OAuth) poll(ctx context.Context, cl *oauthClient, c *model.OAuthCredential, sec *oauthSecret) {
	now := o.now()
	interval := time.Duration(sec.Interval) * time.Second
	if interval <= 0 {
		interval = 5 * time.Second
	}
	if c.LoginExpiresAt != nil && !now.Before(*c.LoginExpiresAt) {
		o.fail(c, sec, "the sign-in was not approved before it expired: start it again")
		return
	}
	d := &deviceStart{Code: sec.DeviceCode, UserCode: c.UserCode, AuthorizationCode: sec.AuthorizationCode, CodeVerifier: sec.CodeVerifier}
	t, err := cl.poll(ctx, d)
	// Kept (sealed with the row) while an exchange waits for the provider; cleared once it went
	// through or the login failed.
	sec.AuthorizationCode, sec.CodeVerifier = d.AuthorizationCode, d.CodeVerifier
	var oe *OAuthError
	switch {
	case errors.Is(err, errPending):
		c.NextAt = now.Add(interval)
	case errors.Is(err, errSlowDown):
		// RFC 8628 3.5: every slow_down adds five seconds to the interval, for good.
		sec.Interval += 5
		c.NextAt = now.Add(interval + 5*time.Second)
	case errors.As(err, &oe) && oe.Permanent:
		o.fail(c, sec, "sign-in refused: "+oe.Error())
	case err != nil:
		// A provider outage or a network error: the sign-in stays pending, the user may still
		// approve it, the next poll comes at the interval.
		c.Error, c.NextAt = err.Error(), now.Add(interval)
	default:
		o.activate(c, sec, t, now)
	}
}

func (o *OAuth) refresh(ctx context.Context, cl *oauthClient, c *model.OAuthCredential, sec *oauthSecret) {
	now := o.now()
	t, err := cl.refresh(ctx, sec.RefreshToken)
	var oe *OAuthError
	switch {
	case errors.As(err, &oe) && oe.Permanent:
		o.fail(c, sec, "refresh refused, sign in again: "+oe.Error())
	case err != nil:
		// Transient: the current access token is still used until it expires; try again soon.
		c.Error, c.NextAt = err.Error(), now.Add(30*time.Second)
	default:
		if t.RefreshToken == "" {
			t.RefreshToken = sec.RefreshToken // the provider did not rotate it
		}
		o.activate(c, sec, t, now)
	}
}

// activate stores fresh tokens and schedules the next refresh RefreshBefore ahead of the
// expiry (half way, for a token that lives shorter than that).
func (o *OAuth) activate(c *model.OAuthCredential, sec *oauthSecret, t *oauthTokens, now time.Time) {
	exp := expiry(t, now, time.Hour)
	if id := accountID(o.Providers[c.Provider].AccountClaim, t.IDToken, t.AccessToken); id != "" {
		c.AccountID = id
	}
	*sec = oauthSecret{AccessToken: t.AccessToken, RefreshToken: t.RefreshToken}
	c.Status, c.Error, c.VerificationURL, c.UserCode, c.LoginExpiresAt = model.OAuthActive, "", "", "", nil
	c.ExpiresAt, c.RefreshedAt = &exp, &now
	next := exp.Add(-o.refreshBefore())
	if !next.After(now) {
		next = now.Add(exp.Sub(now) / 2)
	}
	c.NextAt = next
}

// skew: an access token this close to its expiry is not handed out; the caller refreshes it
// first (a request in flight should not die at the upstream mid-way).
const skew = 30 * time.Second

// resolve is the gateway's side: NAME is the current access token, NAME.account_id the account
// id. An expired token is refreshed on the spot (under the lease, like Run would); when another
// replica holds the lease, its result is waited for briefly.
func (o *OAuth) resolve(ctx context.Context, tenant, name string) (string, error) {
	base, wantAccount := strings.CutSuffix(name, AccountSuffix)
	c, ciphertext, err := o.Store.GetOAuthCredential(ctx, tenant, base)
	if errors.Is(err, store.ErrNotFound) {
		return "", secrets.ErrNotFound
	}
	if err != nil {
		return "", err
	}
	for attempt := 0; ; attempt++ {
		switch c.Status {
		case model.OAuthPending:
			return "", fmt.Errorf("oauth credential %s: the sign-in is not approved yet (%s, code %s)", base, c.VerificationURL, c.UserCode)
		case model.OAuthFailed:
			return "", fmt.Errorf("oauth credential %s: %s", base, c.Error)
		}
		if wantAccount {
			if c.AccountID == "" {
				return "", fmt.Errorf("oauth credential %s: the provider named no account id", base)
			}
			return c.AccountID, nil
		}
		if c.ExpiresAt != nil && c.ExpiresAt.After(o.now().Add(skew)) {
			sec, err := o.unseal(c, ciphertext)
			if err != nil {
				return "", err
			}
			return sec.AccessToken, nil
		}
		if attempt == 10 {
			return "", fmt.Errorf("oauth credential %s: the access token expired and no refresh succeeded (%s)", base, c.Error)
		}
		if attempt == 0 {
			// Conflict: another replica holds the lease and is refreshing it; NotFound: a new
			// sign-in replaced the row. Either way the row is read again below.
			if _, err := o.act(ctx, tenant, base, c.Generation); err != nil && !errors.Is(err, store.ErrConflict) && !errors.Is(err, store.ErrNotFound) {
				return "", err
			}
		} else {
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-time.After(300 * time.Millisecond):
			}
		}
		if c, ciphertext, err = o.Store.GetOAuthCredential(ctx, tenant, base); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return "", secrets.ErrNotFound
			}
			return "", err
		}
	}
}
