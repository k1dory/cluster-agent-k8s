// Package ingress is the preview proxy: <name>-<owner>.<domain> → sandbox IP:port.
//
// Access levels: link (anyone with the URL), sso / members (needs a cookie issued from an
// HMAC ticket that your auth service mints after checking the user; that service's
// URL is AuthURL). A sleeping sandbox gets woken (if wake_on_preview) and a 503 page.
package ingress

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	"agent-sandbox/internal/model"
	"agent-sandbox/internal/store"
)

// Waker wakes sleeping sandboxes.
type Waker interface {
	Wake(ctx context.Context, id string) (*model.Sandbox, error)
	Touch(ctx context.Context, id string)
}

// Handler serves preview traffic.
type Handler struct {
	Store          store.Store
	Waker          Waker
	AuthURL        string // where to send unauthenticated users; "" disables sso/members
	TicketKey      []byte // HMAC key shared with your auth service
	CookieTTL      time.Duration
	HitsAsActivity bool
	Log            *slog.Logger
}

const cookieName = "__Host-sandbox_pv"
const callbackPath = "/__sandbox/auth"

type ticket struct {
	Host string `json:"host"`
	User string `json:"user"`
	Exp  int64  `json:"exp"`
}

// askPath is Caddy's on_demand_tls ask hook: 200 only for hosts that have a preview, so
// strangers cannot burn the ACME rate limit by inventing names.
const askPath = "/__sandbox/ask"

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == askPath {
		if _, err := h.Store.SandboxByPreviewHost(r.Context(), strings.ToLower(r.URL.Query().Get("domain"))); err != nil {
			http.Error(w, "unknown", http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		return
	}
	host := strings.ToLower(r.Host)
	if hh, _, err := net.SplitHostPort(host); err == nil {
		host = hh
	}
	sb, err := h.Store.SandboxByPreviewHost(r.Context(), host)
	if err != nil {
		http.Error(w, "no such preview", http.StatusNotFound)
		return
	}
	if r.URL.Path == callbackPath {
		h.callback(w, r, sb)
		return
	}
	if sb.Preview.Access != model.AccessLink {
		if !h.authorized(r, sb) {
			if h.AuthURL == "" {
				http.Error(w, "preview requires sign-in but no auth URL is configured", http.StatusForbidden)
				return
			}
			u, _ := url.Parse(h.AuthURL)
			q := u.Query()
			q.Set("host", host)
			q.Set("next", r.URL.RequestURI())
			u.RawQuery = q.Encode()
			http.Redirect(w, r, u.String(), http.StatusFound)
			return
		}
	}
	if sb.Status != model.StatusRunning || sb.IP == "" {
		if sb.Status == model.StatusSleeping && sb.WakeOnPreview && h.Waker != nil {
			go func() { _, _ = h.Waker.Wake(context.Background(), sb.ID) }()
		}
		w.Header().Set("Retry-After", "5")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprintf(w, `<!doctype html><meta http-equiv="refresh" content="5"><title>Waking up</title>
<body style="font-family:system-ui;margin:4rem auto;max-width:32rem"><h1>Sandbox is %s</h1>
<p>The application will be back in a few seconds. This page refreshes itself.</p></body>`, sb.Status)
		return
	}
	if h.HitsAsActivity && h.Waker != nil {
		h.Waker.Touch(r.Context(), sb.ID)
	}
	target := &url.URL{Scheme: "http", Host: net.JoinHostPort(sb.IP, strconv.Itoa(sb.Preview.Port))}
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			// Dev servers (vite, next) reject unknown Host names but accept the IP.
			pr.Out.Host = target.Host
			pr.SetXForwarded()
		},
		Transport: &http.Transport{
			DialContext:           (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
			ResponseHeaderTimeout: 60 * time.Second,
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			http.Error(w, "application in sandbox is not answering on port "+strconv.Itoa(sb.Preview.Port), http.StatusBadGateway)
		},
	}
	rp.ServeHTTP(w, r)
}

func (h *Handler) authorized(r *http.Request, sb *model.Sandbox) bool {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return false
	}
	t, err := h.verify(c.Value)
	if err != nil {
		return false
	}
	return t.Host == sb.Preview.Host
}

// callback receives ?ticket=<signed> from the auth service and sets the cookie.
func (h *Handler) callback(w http.ResponseWriter, r *http.Request, sb *model.Sandbox) {
	t, err := h.verify(r.URL.Query().Get("ticket"))
	if err != nil || t.Host != sb.Preview.Host {
		http.Error(w, "bad ticket", http.StatusForbidden)
		return
	}
	ttl := h.CookieTTL
	if ttl == 0 {
		ttl = time.Hour
	}
	cookie := h.Sign(ticket{Host: t.Host, User: t.User, Exp: time.Now().Add(ttl).Unix()})
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: cookie, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: int(ttl.Seconds())})
	next := r.URL.Query().Get("next")
	if next == "" || !strings.HasPrefix(next, "/") {
		next = "/"
	}
	http.Redirect(w, r, next, http.StatusFound)
}

// Sign produces host.user.exp.sig (base64url parts). The API mints these with a short exp.
func (h *Handler) Sign(t ticket) string {
	body, _ := json.Marshal(t)
	b := base64.RawURLEncoding.EncodeToString(body)
	mac := hmac.New(sha256.New, h.TicketKey)
	mac.Write([]byte(b))
	return b + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// SignTicket is the exported helper used by the platform API to mint a ticket for a user.
func (h *Handler) SignTicket(host, user string, ttl time.Duration) string {
	return h.Sign(ticket{Host: host, User: user, Exp: time.Now().Add(ttl).Unix()})
}

func (h *Handler) verify(s string) (*ticket, error) {
	if len(h.TicketKey) == 0 {
		return nil, errors.New("no ticket key")
	}
	parts := strings.Split(s, ".")
	if len(parts) != 2 {
		return nil, errors.New("malformed")
	}
	mac := hmac.New(sha256.New, h.TicketKey)
	mac.Write([]byte(parts[0]))
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || !hmac.Equal(sig, mac.Sum(nil)) {
		return nil, errors.New("bad signature")
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}
	var t ticket
	if err := json.Unmarshal(body, &t); err != nil {
		return nil, err
	}
	if time.Now().Unix() > t.Exp {
		return nil, errors.New("expired")
	}
	return &t, nil
}
