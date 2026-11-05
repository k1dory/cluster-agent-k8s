package main

import (
	"bufio"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// Through the bridge a harness that speaks plain HTTP on loopback reaches the gateway with the
// pod's client certificate: SNI and Host are the target host, path, query, headers and body
// pass unchanged, and a streamed answer arrives as it is written.
func TestGatewayBridgePresentsTheClientCertificate(t *testing.T) {
	var mu sync.Mutex
	var seen struct{ cn, sni, host, path, query, apiKey, body string }
	release := make(chan struct{})
	gw := newTestGateway(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		seen.cn, seen.sni, seen.host = r.TLS.PeerCertificates[0].Subject.CommonName, r.TLS.ServerName, r.Host
		seen.path, seen.query, seen.apiKey, seen.body = r.URL.EscapedPath(), r.URL.RawQuery, r.Header.Get("x-api-key"), string(b)
		mu.Unlock()
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: first\n\n")
		w.(http.Flusher).Flush()
		<-release
		_, _ = io.WriteString(w, "data: second\n\n")
	}), "api.example.test")
	gw.route(t)
	h, err := newGatewayBridge(gw.certDir)
	if err != nil {
		t.Fatal(err)
	}
	bridge := httptest.NewServer(h)
	defer bridge.Close()

	req, _ := http.NewRequest(http.MethodPost, bridge.URL+"/https/api.example.test/v1/messages%2Fx?beta=true", strings.NewReader(`{"stream":true}`))
	req.Header.Set("x-api-key", "placeholder")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d: %s", resp.StatusCode, b)
	}
	// The first event arrives while the gateway still holds the second: the answer streams.
	first := make(chan string, 1)
	r := bufio.NewReader(resp.Body)
	go func() { l, _ := r.ReadString('\n'); first <- l }()
	select {
	case l := <-first:
		if l != "data: first\n" {
			t.Fatalf("first line %q", l)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the streamed answer was buffered by the bridge")
	}
	close(release)
	rest, _ := io.ReadAll(r)
	if !strings.Contains(string(rest), "data: second") {
		t.Fatalf("rest %q", rest)
	}
	mu.Lock()
	defer mu.Unlock()
	if seen.cn != "sandbox-test/1" || seen.sni != "api.example.test" || seen.host != "api.example.test" {
		t.Fatalf("identity at the gateway: cert %q, SNI %q, Host %q", seen.cn, seen.sni, seen.host)
	}
	if seen.path != "/v1/messages%2Fx" || seen.query != "beta=true" || seen.apiKey != "placeholder" || seen.body != `{"stream":true}` {
		t.Fatalf("request at the gateway: %+v", seen)
	}
}

// Anything but /https/<host>/… is refused at the bridge; a gateway that rejects the client
// (here: a certificate it does not trust) is a 502, not a hang.
func TestGatewayBridgeRefusesWhatItCannotForward(t *testing.T) {
	gw := newTestGateway(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}), "api.example.test")
	gw.route(t)
	h, err := newGatewayBridge(gw.certDir)
	if err != nil {
		t.Fatal(err)
	}
	bridge := httptest.NewServer(h)
	defer bridge.Close()
	for _, p := range []string{"/", "/http/api.example.test/", "/https//x", "/https/user@api.example.test/", "/https/:443/"} {
		resp, err := http.Get(bridge.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", p, resp.StatusCode)
		}
	}
	other := newTestGateway(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}), "api.example.test")
	h2, err := newGatewayBridge(other.certDir) // another CA's client certificate and trust
	if err != nil {
		t.Fatal(err)
	}
	bridge2 := httptest.NewServer(h2)
	defer bridge2.Close()
	resp, err := http.Get(bridge2.URL + "/https/api.example.test/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("untrusted gateway: %d, want 502", resp.StatusCode)
	}
}

func TestGatewayBridgeURL(t *testing.T) {
	for in, want := range map[string]string{
		"https://argus-mcp.asb.internal/":      "http://127.0.0.1:4480/https/argus-mcp.asb.internal/",
		"https://mcp.example.com:8443/mcp?x=1": "http://127.0.0.1:4480/https/mcp.example.com:8443/mcp?x=1",
		"https://api.anthropic.com":            "http://127.0.0.1:4480/https/api.anthropic.com",
		"http://plain.example.com/":            "http://plain.example.com/",
		"https://user:pass@mcp.example.com/":   "https://user:pass@mcp.example.com/",
		"not a url":                            "not a url",
	} {
		if got := gatewayBridgeURL(in); got != want {
			t.Errorf("%q → %q, want %q", in, got, want)
		}
	}
}
