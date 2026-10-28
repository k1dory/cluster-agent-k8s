package credentials

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// OAuthProvider is an OAuth authorization server a tenant signs in to with the device
// authorization flow, so that sandboxd holds a refresh token and mints the access tokens the
// gateway injects. Every endpoint is configuration (sandboxd.yaml, credentials.oauth.providers);
// the built-in defaults (DefaultOAuthProviders) only fill what a provider entry leaves empty.
//
// Two dialects of the device flow exist in the wild and both are spoken here:
//   - RFC 8628 (DeviceStyle "rfc8628"): a form POST of client_id (and scope) returns
//     device_code, user_code, verification_uri, expires_in and interval; polling the token
//     endpoint with grant_type=urn:ietf:params:oauth:grant-type:device_code returns the tokens,
//     or the errors authorization_pending, slow_down, access_denied, expired_token.
//   - OpenAI's (DeviceStyle "openai", what `codex login --device-auth` speaks): a JSON POST of
//     client_id returns device_auth_id, user_code and interval; polling a separate endpoint
//     with device_auth_id and user_code answers 403/404 while the user has not approved, then
//     an authorization code and its PKCE verifier, which the token endpoint exchanges for the
//     tokens (redirect_uri: RedirectURL).
//
// Refresh is the standard refresh_token grant, as a form or (RefreshJSON, OpenAI's) a JSON
// body. A provider may rotate the refresh token on every refresh; the caller stores whatever
// comes back.
type OAuthProvider struct {
	DeviceStyle     string        `yaml:"device_style" json:"device_style"` // "openai" or "rfc8628"
	ClientID        string        `yaml:"client_id" json:"client_id"`
	Scope           string        `yaml:"scope" json:"scope,omitempty"`                   // rfc8628: requested scope
	DeviceURL       string        `yaml:"device_url" json:"device_url"`                   // where a login starts
	PollURL         string        `yaml:"poll_url" json:"poll_url,omitempty"`             // openai: where it is polled; rfc8628: TokenURL
	VerificationURL string        `yaml:"verification_url" json:"verification_url"`       // shown to the user when the server names none
	TokenURL        string        `yaml:"token_url" json:"token_url"`                     // code exchange and refresh
	RedirectURL     string        `yaml:"redirect_url" json:"redirect_url,omitempty"`     // openai: the code exchange's redirect_uri
	RefreshJSON     bool          `yaml:"refresh_json" json:"refresh_json,omitempty"`     // refresh with a JSON body instead of a form
	AccountClaim    []string      `yaml:"account_claim" json:"account_claim,omitempty"`   // path to the account id in the ID (or access) token's claims
	DeviceTimeout   time.Duration `yaml:"device_timeout" json:"device_timeout,omitempty"` // a login not approved by then fails (default 15m)
}

// Device flow dialects.
const (
	DeviceStyleOpenAI  = "openai"
	DeviceStyleRFC8628 = "rfc8628"
)

// DefaultOAuthProviders are the providers sandboxd knows without configuration. "chatgpt" is a
// ChatGPT sign-in as Codex CLI performs it (openai/codex, codex-rs/login: device_code_auth.rs,
// server.rs, auth/manager.rs): issuer https://auth.openai.com, Codex's public client id, the
// account id under the "https://api.openai.com/auth" claim. The access token it yields is what
// the ChatGPT backend (https://chatgpt.com/backend-api/codex) takes as a bearer, next to the
// ChatGPT-Account-ID header.
func DefaultOAuthProviders() map[string]OAuthProvider {
	const issuer = "https://auth.openai.com"
	return map[string]OAuthProvider{
		"chatgpt": {
			DeviceStyle:     DeviceStyleOpenAI,
			ClientID:        "app_EMoamEEZ73f0CkXaXp7hrann",
			DeviceURL:       issuer + "/api/accounts/deviceauth/usercode",
			PollURL:         issuer + "/api/accounts/deviceauth/token",
			VerificationURL: issuer + "/codex/device",
			TokenURL:        issuer + "/oauth/token",
			RedirectURL:     issuer + "/deviceauth/callback",
			RefreshJSON:     true,
			AccountClaim:    []string{"https://api.openai.com/auth", "chatgpt_account_id"},
			DeviceTimeout:   15 * time.Minute,
		},
	}
}

// MergeOAuthProviders lays configured providers over the defaults: a configured field wins, an
// empty one keeps the default of the same name; a name the defaults do not know must be
// complete.
func MergeOAuthProviders(configured map[string]OAuthProvider) (map[string]OAuthProvider, error) {
	out := DefaultOAuthProviders()
	for name, c := range configured {
		p := out[name]
		set := func(dst *string, v string) {
			if v != "" {
				*dst = v
			}
		}
		set(&p.DeviceStyle, c.DeviceStyle)
		set(&p.ClientID, c.ClientID)
		set(&p.Scope, c.Scope)
		set(&p.DeviceURL, c.DeviceURL)
		set(&p.PollURL, c.PollURL)
		set(&p.VerificationURL, c.VerificationURL)
		set(&p.TokenURL, c.TokenURL)
		set(&p.RedirectURL, c.RedirectURL)
		if c.RefreshJSON {
			p.RefreshJSON = true
		}
		if len(c.AccountClaim) > 0 {
			p.AccountClaim = c.AccountClaim
		}
		if c.DeviceTimeout > 0 {
			p.DeviceTimeout = c.DeviceTimeout
		}
		out[name] = p
	}
	for name, p := range out {
		if err := p.check(); err != nil {
			return nil, fmt.Errorf("credentials.oauth.providers.%s: %w", name, err)
		}
	}
	return out, nil
}

func (p OAuthProvider) check() error {
	switch p.DeviceStyle {
	case DeviceStyleOpenAI:
		if p.PollURL == "" || p.RedirectURL == "" {
			return errors.New("device_style openai needs poll_url and redirect_url")
		}
	case DeviceStyleRFC8628:
	default:
		return fmt.Errorf("device_style must be %s or %s", DeviceStyleOpenAI, DeviceStyleRFC8628)
	}
	if p.ClientID == "" || p.DeviceURL == "" || p.TokenURL == "" {
		return errors.New("client_id, device_url and token_url are required")
	}
	for _, u := range []string{p.DeviceURL, p.PollURL, p.TokenURL} {
		if u == "" {
			continue
		}
		if pu, err := url.Parse(u); err != nil || (pu.Scheme != "https" && pu.Scheme != "http") || pu.Host == "" {
			return fmt.Errorf("%q is not an http(s) URL", u)
		}
	}
	return nil
}

// deviceStart is what a started login keeps (encrypted) to poll with.
type deviceStart struct {
	Code            string // rfc8628 device_code; openai device_auth_id
	UserCode        string
	VerificationURL string
	Interval        time.Duration
	ExpiresAt       time.Time
	// OpenAI's approved login: the authorization code and its PKCE verifier, kept when their
	// exchange failed for a reason that may pass (an outage). The poll that follows exchanges
	// them again instead of asking the poll endpoint, which hands the code out once.
	AuthorizationCode string
	CodeVerifier      string
}

// oauthTokens is a token endpoint's answer.
type oauthTokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	ExpiresIn    int64  `json:"expires_in"`
}

// Poll outcomes that are not tokens.
var (
	errPending  = errors.New("authorization pending")
	errSlowDown = errors.New("slow down")
)

// OAuthError is a refusal from the provider: Permanent means the grant is gone (a revoked,
// expired or reused refresh token, a denied or expired login) and retrying cannot help; the
// tenant has to sign in again.
type OAuthError struct {
	Status    int
	Code      string
	Message   string
	Permanent bool
}

func (e *OAuthError) Error() string {
	s := fmt.Sprintf("provider answered %d", e.Status)
	if e.Code != "" {
		s += " " + e.Code
	}
	if e.Message != "" {
		s += ": " + e.Message
	}
	return s
}

// oauthClient talks to one provider.
type oauthClient struct {
	p    OAuthProvider
	http *http.Client
	now  func() time.Time
}

const maxOAuthBody = 1 << 20

// post sends a form or a JSON body and decodes a 2xx JSON answer into out; any other status is
// returned as an *OAuthError carrying the provider's error code.
func (c *oauthClient) post(ctx context.Context, endpoint string, asJSON bool, params map[string]string, out any) error {
	var body io.Reader
	ctype := "application/x-www-form-urlencoded"
	if asJSON {
		b, _ := json.Marshal(params)
		body, ctype = bytes.NewReader(b), "application/json"
	} else {
		form := url.Values{}
		for k, v := range params {
			form.Set(k, v)
		}
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxOAuthBody))
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		return refusal(resp.StatusCode, raw)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("provider answered %d with a body that is not JSON", resp.StatusCode)
	}
	return nil
}

// refusal reads the error code out of a provider's error body, in the shapes seen: RFC 6749's
// {"error": "invalid_grant", "error_description": ...} and OpenAI's {"error": {"code": ...,
// "message": ...}}. The body is never echoed whole: a provider may reflect what it was sent.
func refusal(status int, raw []byte) *OAuthError {
	e := &OAuthError{Status: status}
	var flat struct {
		Error       json.RawMessage `json:"error"`
		Description string          `json:"error_description"`
		Code        string          `json:"code"`
	}
	if json.Unmarshal(raw, &flat) == nil {
		var s string
		var nested struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		}
		switch {
		case json.Unmarshal(flat.Error, &s) == nil:
			e.Code, e.Message = s, flat.Description
		case json.Unmarshal(flat.Error, &nested) == nil:
			e.Code, e.Message = nested.Code, nested.Message
		default:
			e.Code = flat.Code
		}
	}
	if len(e.Message) > 200 {
		e.Message = e.Message[:200]
	}
	return e
}

// start begins a device login.
func (c *oauthClient) start(ctx context.Context) (*deviceStart, error) {
	timeout := c.p.DeviceTimeout
	if timeout <= 0 {
		timeout = 15 * time.Minute
	}
	if c.p.DeviceStyle == DeviceStyleOpenAI {
		var r struct {
			DeviceAuthID string          `json:"device_auth_id"`
			UserCode     string          `json:"user_code"`
			UserCodeAlt  string          `json:"usercode"`
			Interval     json.RawMessage `json:"interval"`
		}
		if err := c.post(ctx, c.p.DeviceURL, true, map[string]string{"client_id": c.p.ClientID}, &r); err != nil {
			return nil, err
		}
		if r.UserCode == "" {
			r.UserCode = r.UserCodeAlt
		}
		if r.DeviceAuthID == "" || r.UserCode == "" {
			return nil, errors.New("device login: the provider returned no device_auth_id or user_code")
		}
		return &deviceStart{Code: r.DeviceAuthID, UserCode: r.UserCode, VerificationURL: c.p.VerificationURL,
			Interval: seconds(r.Interval, 5), ExpiresAt: c.now().Add(timeout)}, nil
	}
	params := map[string]string{"client_id": c.p.ClientID}
	if c.p.Scope != "" {
		params["scope"] = c.p.Scope
	}
	var r struct {
		DeviceCode       string          `json:"device_code"`
		UserCode         string          `json:"user_code"`
		VerificationURI  string          `json:"verification_uri"`
		VerificationURL  string          `json:"verification_url"` // Google spells it so
		VerificationFull string          `json:"verification_uri_complete"`
		ExpiresIn        int64           `json:"expires_in"`
		Interval         json.RawMessage `json:"interval"`
	}
	if err := c.post(ctx, c.p.DeviceURL, false, params, &r); err != nil {
		return nil, err
	}
	if r.DeviceCode == "" || r.UserCode == "" {
		return nil, errors.New("device login: the provider returned no device_code or user_code")
	}
	d := &deviceStart{Code: r.DeviceCode, UserCode: r.UserCode, Interval: seconds(r.Interval, 5), ExpiresAt: c.now().Add(timeout)}
	for _, u := range []string{r.VerificationURI, r.VerificationURL, c.p.VerificationURL} {
		if u != "" {
			d.VerificationURL = u
			break
		}
	}
	if r.ExpiresIn > 0 {
		if at := c.now().Add(time.Duration(r.ExpiresIn) * time.Second); at.Before(d.ExpiresAt) {
			d.ExpiresAt = at
		}
	}
	return d, nil
}

// poll asks once whether the user approved the login: the tokens, errPending, errSlowDown, or
// an error (an *OAuthError with Permanent set when the login is over).
func (c *oauthClient) poll(ctx context.Context, d *deviceStart) (*oauthTokens, error) {
	if c.p.DeviceStyle == DeviceStyleOpenAI {
		var oe *OAuthError
		if d.AuthorizationCode == "" {
			var code struct {
				AuthorizationCode string `json:"authorization_code"`
				CodeVerifier      string `json:"code_verifier"`
			}
			err := c.post(ctx, c.p.PollURL, true, map[string]string{"device_auth_id": d.Code, "user_code": d.UserCode}, &code)
			if errors.As(err, &oe) && (oe.Status == http.StatusForbidden || oe.Status == http.StatusNotFound) {
				return nil, errPending // not approved yet (codex-rs: device_code_auth.rs poll_for_token)
			}
			if err != nil {
				return nil, err
			}
			if code.AuthorizationCode == "" || code.CodeVerifier == "" {
				return nil, errors.New("device login: approved, but the provider returned no authorization code")
			}
			d.AuthorizationCode, d.CodeVerifier = code.AuthorizationCode, code.CodeVerifier
		}
		var t oauthTokens
		err := c.post(ctx, c.p.TokenURL, false, map[string]string{
			"grant_type": "authorization_code", "client_id": c.p.ClientID, "code": d.AuthorizationCode,
			"redirect_uri": c.p.RedirectURL, "code_verifier": d.CodeVerifier,
		}, &t)
		// The code is single-use and the provider refused it (a 4xx: invalid_grant, an expired
		// code): this login is over. An outage (5xx, 408, 429) or a network error refused
		// nothing: the code stays in d and the next poll exchanges it again.
		if errors.As(err, &oe) && !transientStatus(oe.Status) {
			oe.Permanent = true
		}
		if err != nil {
			return nil, err
		}
		d.AuthorizationCode, d.CodeVerifier = "", ""
		return &t, checkTokens(&t)
	}
	var t oauthTokens
	err := c.post(ctx, c.p.TokenURL, false, map[string]string{
		"grant_type": "urn:ietf:params:oauth:grant-type:device_code", "device_code": d.Code, "client_id": c.p.ClientID,
	}, &t)
	var oe *OAuthError
	if errors.As(err, &oe) {
		switch oe.Code {
		case "authorization_pending":
			return nil, errPending
		case "slow_down":
			return nil, errSlowDown
		case "access_denied", "expired_token", "invalid_grant":
			oe.Permanent = true
		}
		return nil, oe
	}
	if err != nil {
		return nil, err
	}
	return &t, checkTokens(&t)
}

// transientStatus: a provider answer that refuses nothing, so the same request may succeed later.
func transientStatus(status int) bool {
	return status >= 500 || status == http.StatusRequestTimeout || status == http.StatusTooManyRequests
}

// refresh trades the refresh token for new tokens. A refusal that means the grant is gone
// (401, invalid_grant, OpenAI's refresh_token_expired / _reused / _invalidated) is Permanent;
// anything else (5xx, a network error) is worth retrying later.
func (c *oauthClient) refresh(ctx context.Context, refreshToken string) (*oauthTokens, error) {
	var t oauthTokens
	err := c.post(ctx, c.p.TokenURL, c.p.RefreshJSON, map[string]string{
		"grant_type": "refresh_token", "client_id": c.p.ClientID, "refresh_token": refreshToken,
	}, &t)
	var oe *OAuthError
	if errors.As(err, &oe) {
		switch strings.ToLower(oe.Code) {
		case "invalid_grant", "refresh_token_expired", "refresh_token_reused", "refresh_token_invalidated", "invalid_client", "unauthorized_client":
			oe.Permanent = true
		}
		if oe.Status == http.StatusUnauthorized {
			oe.Permanent = true
		}
		return nil, oe
	}
	if err != nil {
		return nil, err
	}
	if t.AccessToken == "" {
		return nil, errors.New("refresh: the provider returned no access token")
	}
	return &t, nil
}

func checkTokens(t *oauthTokens) error {
	if t.AccessToken == "" || t.RefreshToken == "" {
		return errors.New("device login: the provider returned no access or refresh token")
	}
	return nil
}

// expiry is when an access token stops working: the token response's expires_in, else the
// JWT's exp claim, else fallback from now.
func expiry(t *oauthTokens, now time.Time, fallback time.Duration) time.Time {
	if t.ExpiresIn > 0 {
		return now.Add(time.Duration(t.ExpiresIn) * time.Second)
	}
	if claims := jwtClaims(t.AccessToken); claims != nil {
		if exp, ok := claims["exp"].(float64); ok && exp > 0 {
			return time.Unix(int64(exp), 0)
		}
	}
	return now.Add(fallback)
}

// accountID reads the account id at path from the ID token's claims, else the access token's.
// The tokens are not verified here: they came straight from the provider's token endpoint over
// TLS, and the id only becomes a header the same provider checks.
func accountID(path []string, tokens ...string) string {
	if len(path) == 0 {
		return ""
	}
	for _, tok := range tokens {
		var v any = jwtClaims(tok)
		for _, k := range path {
			m, ok := v.(map[string]any)
			if !ok {
				v = nil
				break
			}
			v = m[k]
		}
		if s, ok := v.(string); ok && s != "" {
			return s
		}
	}
	return ""
}

// jwtClaims decodes a JWT's payload without verifying it; nil when tok is not a JWT.
func jwtClaims(tok string) map[string]any {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return nil
	}
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return nil
	}
	var m map[string]any
	if json.Unmarshal(b, &m) != nil {
		return nil
	}
	return m
}

// seconds reads an interval given as a number or a string of one (OpenAI sends "5").
func seconds(raw json.RawMessage, def int) time.Duration {
	s := strings.Trim(strings.TrimSpace(string(raw)), `"`)
	if n, err := strconv.Atoi(s); err == nil && n > 0 {
		return time.Duration(n) * time.Second
	}
	return time.Duration(def) * time.Second
}
