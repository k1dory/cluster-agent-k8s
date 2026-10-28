package credentials

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type reviewOAuthTransport func(*http.Request) (*http.Response, error)

func (f reviewOAuthTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

// A complete 503 response from the code exchange is an outage, not a denied grant.
// The HTTP transport is replaced; neither provider URL is contacted.
func TestReviewOAuthCodeExchangeOutageRemainsRetryable(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusServiceUnavailable} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			calls := 0
			client := &oauthClient{
				p: OAuthProvider{DeviceStyle: DeviceStyleOpenAI, ClientID: "fixture-client",
					PollURL: "https://provider.example.com/poll", TokenURL: "https://provider.example.com/token",
					RedirectURL: "https://provider.example.com/callback"},
				now: time.Now,
				http: &http.Client{Transport: reviewOAuthTransport(func(r *http.Request) (*http.Response, error) {
					calls++
					code, body := http.StatusOK, `{"authorization_code":"fixture-code","code_verifier":"fixture-verifier"}`
					if r.URL.Path == "/token" {
						code = status
						if status == http.StatusBadRequest {
							body = `{"error":"invalid_grant"}`
						} else {
							body = `{"error":"temporarily_unavailable"}`
						}
					}
					return &http.Response{StatusCode: code, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
				})},
			}
			_, err := client.poll(context.Background(), &deviceStart{Code: "fixture-device", UserCode: "FIXTURE"})
			var refusal *OAuthError
			if calls != 2 || !errors.As(err, &refusal) {
				t.Fatalf("expected an exchange refusal after two fixture requests, got calls=%d err=%v", calls, err)
			}
			wantPermanent := status == http.StatusBadRequest
			if refusal.Permanent != wantPermanent {
				t.Fatalf("code exchange HTTP %d: permanent=%v, want %v", status, refusal.Permanent, wantPermanent)
			}
		})
	}
}
