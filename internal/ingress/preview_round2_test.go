package ingress

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	"agent-sandbox/internal/model"
	"agent-sandbox/internal/store"
)

func lifecyclePreviewSandbox(t *testing.T, st store.Store, id string, gen int64, ip string, port int) *model.Sandbox {
	t.Helper()
	now := time.Now()
	sb := &model.Sandbox{ID: id, Name: "shop", Slug: "dev", Tenant: "acme", Owner: "alice", Status: model.StatusRunning, IP: ip,
		CreatedAt: now, LastActivity: now, PreviewGen: gen, Preview: &model.Preview{Port: port, Access: model.AccessMembers, Host: lifecycleHost}}
	if err := st.CreateSandbox(context.Background(), sb); err != nil {
		t.Fatal(err)
	}
	return sb
}

// signIn goes through the callback with a ticket and returns the cookie it sets ("" if refused).
func lifecycleSignIn(t *testing.T, h *Handler, tk string) string {
	t.Helper()
	rec := lifecycleGet(h, callbackPath+"?ticket="+url.QueryEscape(tk), "")
	if rec.Code != http.StatusFound {
		return ""
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == cookieName {
			return c.Value
		}
	}
	t.Fatal("callback answered 302 without the cookie")
	return ""
}

// The preview ticket and cookie carried only host, user and expiry, and authorization compared
// the host: <name>-<owner> is reused when a sandbox is deleted and created again, so whoever
// had signed in to the old one kept access to the new one. The ticket now names the sandbox,
// its tenant and the access generation; a ticket or cookie of an earlier one is refused.
func TestRound2PreviewCookieDoesNotOutliveItsSandbox(t *testing.T) {
	ip, port, _ := lifecycleBackend(t)
	st := store.NewMemory()
	h := &Handler{Store: st, TicketKey: []byte("k"), AuthURL: "https://auth.test/login"}
	t.Cleanup(h.Close)
	a := lifecyclePreviewSandbox(t, st, "sb_a", 0, ip, port)
	tkA := h.SignTicket(a, "bob", time.Minute)
	cookieA := lifecycleSignIn(t, h, tkA)
	if cookieA == "" {
		t.Fatal("ticket for the sandbox refused")
	}
	if rec := lifecycleGet(h, "/", cookieA); rec.Code != http.StatusOK {
		t.Fatalf("signed-in request to the sandbox: %d", rec.Code)
	}
	// Deleted and created again under the same name and owner: same preview host.
	if err := st.DeleteSandbox(context.Background(), a.ID); err != nil {
		t.Fatal(err)
	}
	lifecyclePreviewSandbox(t, st, "sb_a2", 0, ip, port)
	if rec := lifecycleGet(h, "/", cookieA); rec.Code != http.StatusFound {
		t.Fatalf("cookie of the deleted sandbox on its successor: %d, want a redirect to sign in", rec.Code)
	}
	if lifecycleSignIn(t, h, tkA) != "" {
		t.Fatal("ticket of the deleted sandbox accepted by its successor's callback")
	}
}

// Closing the preview or changing its access level bumps the generation: sign-ins from before
// are refused, new ones work.
func TestRound2PreviewCookieOfARevokedGenerationIsRefused(t *testing.T) {
	ip, port, _ := lifecycleBackend(t)
	st := store.NewMemory()
	h := &Handler{Store: st, TicketKey: []byte("k"), AuthURL: "https://auth.test/login"}
	t.Cleanup(h.Close)
	sb := lifecyclePreviewSandbox(t, st, "sb_gen", 0, ip, port)
	old := lifecycleSignIn(t, h, h.SignTicket(sb, "bob", time.Minute))
	if old == "" {
		t.Fatal("ticket refused")
	}
	cur, _ := st.GetSandbox(context.Background(), sb.ID)
	cur.PreviewGen++
	if err := st.UpdateSandbox(context.Background(), cur); err != nil {
		t.Fatal(err)
	}
	if rec := lifecycleGet(h, "/", old); rec.Code != http.StatusFound {
		t.Fatalf("cookie of a revoked generation: %d, want a redirect to sign in", rec.Code)
	}
	fresh := lifecycleSignIn(t, h, h.SignTicket(cur, "bob", time.Minute))
	if fresh == "" {
		t.Fatal("ticket of the current generation refused")
	}
	if rec := lifecycleGet(h, "/", fresh); rec.Code != http.StatusOK {
		t.Fatalf("cookie of the current generation: %d", rec.Code)
	}
}
