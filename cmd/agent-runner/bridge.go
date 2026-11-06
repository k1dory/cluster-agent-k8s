package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// gatewayBridgeAddr is where the runner serves the gateway bridge, on the pod's loopback. A
// fixed address, so a profile can name it in a harness's configuration (a provider's base URL).
const gatewayBridgeAddr = "127.0.0.1:4480"

// The gateway terminates every connection that leaves the pod and requires the pod's client
// certificate (mTLS). Claude Code, git and curl present it from the settings agent-init writes;
// many harnesses cannot (OpenCode on Bun, Hermes on Python's httpx, Codex on Rust: none reads a
// client certificate from the environment). The bridge closes that gap for any of them: plain
// HTTP on loopback, http://127.0.0.1:4480/https/<host>/<path>, forwarded as
// https://<host>/<path> through the gateway with the pod's certificate. Headers and bodies pass
// unchanged (the gateway still swaps placeholder credentials and enforces the policy),
// responses stream (SSE), WebSocket upgrades are carried. It adds no reach the pod lacks: the
// certificate is the pod's own, the network lock still admits only the gateway.

// gatewayBridgeURL is target (an https URL) as seen through the bridge; anything else unchanged.
func gatewayBridgeURL(target string) string {
	u, err := url.Parse(target)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return target
	}
	return "http://" + gatewayBridgeAddr + "/https/" + u.Host + u.EscapedPath() + query(u)
}

func query(u *url.URL) string {
	if u.RawQuery == "" {
		return ""
	}
	return "?" + u.RawQuery
}

// splitBridgePath takes /https/<host>/<rest> (escaped) apart; ok is false for anything else.
func splitBridgePath(escaped string) (host, rest string, ok bool) {
	p, found := strings.CutPrefix(escaped, "/https/")
	if !found {
		return "", "", false
	}
	host, rest, _ = strings.Cut(p, "/")
	if host == "" || strings.ContainsAny(host, "@/?#%") {
		return "", "", false
	}
	if h, port, err := net.SplitHostPort(host); err == nil {
		if h == "" || port == "" {
			return "", "", false
		}
	}
	return host, "/" + rest, true
}

// certDir is where agent-init wrote the pod's identity ($CERT_DIR, /certs).
func certDir() string {
	if d := os.Getenv("CERT_DIR"); d != "" {
		return d
	}
	return "/certs"
}

// loadIdentity reads the pod's client certificate and the gateway's trust from certDir: the
// gateway CA agent-init wrote, else the system pool. A CA file with no certificate in it, or no
// system pool, is an error: a client that trusts nothing fails later and less clearly.
func loadIdentity(certDir string) (tls.Certificate, *x509.CertPool, error) {
	cert, err := tls.LoadX509KeyPair(filepath.Join(certDir, "tls.crt"), filepath.Join(certDir, "tls.key"))
	if err != nil {
		return cert, nil, fmt.Errorf("client cert: %w", err)
	}
	if gw, err := os.ReadFile(filepath.Join(certDir, "gateway-ca.crt")); err == nil && len(bytes.TrimSpace(gw)) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(gw) {
			return cert, nil, fmt.Errorf("trust: %s holds no certificate", filepath.Join(certDir, "gateway-ca.crt"))
		}
		return cert, pool, nil
	}
	pool, err := x509.SystemCertPool()
	if err != nil {
		return cert, nil, fmt.Errorf("trust: %w", err)
	}
	return cert, pool, nil
}

// newGatewayBridge is the bridge's handler: client certificate and trust from certDir (what
// agent-init wrote), connections to the gateway at GATEWAY_IP (port SANDBOX_GATEWAY_PORT, 443)
// whatever the host, with the host as SNI; without GATEWAY_IP the host itself is dialled.
func newGatewayBridge(certDir string) (http.Handler, error) {
	cert, pool, err := loadIdentity(certDir)
	if err != nil {
		return nil, err
	}
	gwIP, gwPort := os.Getenv("GATEWAY_IP"), os.Getenv("SANDBOX_GATEWAY_PORT")
	if gwPort == "" {
		gwPort = "443"
	}
	dialer := &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if gwIP != "" {
				addr = net.JoinHostPort(gwIP, gwPort)
			}
			return dialer.DialContext(ctx, network, addr)
		},
		// HTTP/1.1 to the gateway: WebSocket upgrades (Codex's responses stream) need it.
		TLSClientConfig:       &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: pool, MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 10 * time.Minute,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConnsPerHost:   8,
	}
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			host, rest, _ := splitBridgePath(pr.In.URL.EscapedPath())
			path, _ := url.PathUnescape(rest)
			pr.Out.URL = &url.URL{Scheme: "https", Host: host, Path: path, RawPath: rest, RawQuery: pr.In.URL.RawQuery}
			pr.Out.Host = host
		},
		Transport:     transport,
		FlushInterval: -1, // stream: SSE and chunked answers reach the harness as they come
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			http.Error(w, "agent-runner gateway bridge: "+err.Error(), http.StatusBadGateway)
		},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, _, ok := splitBridgePath(r.URL.EscapedPath()); !ok {
			http.Error(w, "agent-runner gateway bridge: use http://"+gatewayBridgeAddr+"/https/<host>/<path>", http.StatusBadRequest)
			return
		}
		proxy.ServeHTTP(w, r)
	}), nil
}

// serveGatewayBridge serves the bridge on gatewayBridgeAddr until ctx ends. A bridge that cannot
// start is reported and the runner goes on: the harnesses that present the certificate
// themselves do not need it.
func serveGatewayBridge(ctx context.Context, certDir string) {
	h, err := newGatewayBridge(certDir)
	if err == nil {
		srv := &http.Server{Addr: gatewayBridgeAddr, Handler: h, ReadHeaderTimeout: 30 * time.Second}
		go func() { <-ctx.Done(); _ = srv.Close() }()
		err = srv.ListenAndServe()
		if errors.Is(err, http.ErrServerClosed) {
			return
		}
	}
	fmt.Fprintln(os.Stderr, "agent-runner: gateway bridge unavailable:", err)
}
