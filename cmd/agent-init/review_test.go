package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"agent-sandbox/internal/ca"
	"agent-sandbox/internal/model"
	"agent-sandbox/internal/registrar"
	"agent-sandbox/internal/store"
)

type reviewTLSLog func([]byte) (int, error)

func (f reviewTLSLog) Write(p []byte) (int, error) { return f(p) }

func TestReviewBootstrapRecoversWhenGatewayRootAppears(t *testing.T) {
	// Run the real init loop in a child so a failed retry cannot hang the test suite.
	if os.Getenv("SANDBOX_REVIEW_INIT_CHILD") == "1" {
		if err := run(); err != nil {
			t.Fatal(err)
		}
		return
	}
	// Gateway trust is published asynchronously and the current pod mounts it as optional.
	// Once the file appears, a subsequent bootstrap attempt must pick it up.
	failedHandshake := make(chan struct{}, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(registrar.BootstrapResponse{Slug: "dev", Instance: 1})
	}))
	server.Config.ErrorLog = log.New(reviewTLSLog(func(p []byte) (int, error) {
		if strings.Contains(string(p), "TLS handshake error") {
			select {
			case failedHandshake <- struct{}{}:
			default:
			}
		}
		return len(p), nil
	}), "", 0)
	server.StartTLS()
	defer server.Close()
	dir := t.TempDir()
	rootPath := filepath.Join(dir, "late-root.crt")
	tokenPath := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenPath, []byte("review-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SANDBOX_REVIEW_INIT_CHILD", "1")
	t.Setenv("REGISTRAR_URL", server.URL)
	t.Setenv("GATEWAY_CA_FILE", rootPath)
	t.Setenv("BOOTSTRAP_TOKEN_FILE", tokenPath)
	t.Setenv("CERT_DIR", filepath.Join(dir, "identity"))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestReviewBootstrapRecoversWhenGatewayRootAppears$")
	// Collect output after Wait; no buffer is read while the child is writing.
	var output bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &output
	result := make(chan error, 1)
	go func() { result <- cmd.Run() }()
	select {
	case <-failedHandshake:
	case err := <-result:
		t.Fatalf("child stopped before exercising missing trust: %v", err)
	case <-ctx.Done():
		<-result
		t.Fatal("initial TLS attempt did not arrive")
	}
	root := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := os.WriteFile(rootPath, root, 0o600); err != nil {
		cancel()
		<-result
		t.Fatal(err)
	}
	if err := <-result; err != nil {
		t.Fatalf("gateway root appeared after the first TLS failure, but bootstrap never recovered within 5s: %v\n%s", err, output.String())
	}
}

func TestReviewBootstrapTrustsMountedRootAndWritesClientIdentity(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	if err := st.CreateSandbox(ctx, &model.Sandbox{ID: "sb-init-review", Slug: "dev", Tenant: "acme"}); err != nil {
		t.Fatal(err)
	}
	issuer, err := ca.Generate("review agent issuer", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	reg := &registrar.Registrar{CA: issuer, Store: st, TTL: time.Hour, Resolver: registrar.StaticResolver{
		"review-pod-token": {Name: "pod-review", SandboxID: "sb-init-review", Slug: "dev", Tenant: "acme"},
	}}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/bootstrap" || r.Header.Get("Authorization") != "Bearer review-pod-token" {
			http.Error(w, "bad bootstrap identity", http.StatusUnauthorized)
			return
		}
		var request registrar.BootstrapRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		result, err := reg.Bootstrap(r.Context(), "review-pod-token", request)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		_ = json.NewEncoder(w).Encode(result)
	}))
	defer server.Close()
	root := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	reg.SetGatewayCA(root)
	dir := t.TempDir()
	certDir := filepath.Join(dir, "identity")
	for name, content := range map[string][]byte{"root.crt": root, "token": []byte("review-pod-token\n")} {
		if err := os.WriteFile(filepath.Join(dir, name), content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("CERT_DIR", certDir)
	t.Setenv("SANDBOX_SLUG", "dev")
	t.Setenv("REGISTRAR_URL", server.URL)
	t.Setenv("BOOTSTRAP_TOKEN_FILE", filepath.Join(dir, "token"))
	t.Setenv("GATEWAY_CA_FILE", filepath.Join(dir, "root.crt"))
	if err := run(); err != nil {
		t.Fatal(err)
	}
	if _, err := tls.LoadX509KeyPair(filepath.Join(certDir, "tls.crt"), filepath.Join(certDir, "tls.key")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(certDir, "tls.key"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("private key mode=%o", info.Mode().Perm())
	}
	data, err := os.ReadFile(filepath.Join(certDir, "env.sh"))
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{
		"export CLAUDE_CODE_CLIENT_CERT=" + filepath.Join(certDir, "tls.crt"),
		"export CLAUDE_CODE_CLIENT_KEY=" + filepath.Join(certDir, "tls.key"),
		"export NODE_EXTRA_CA_CERTS=" + filepath.Join(certDir, "gateway-ca.crt"),
	} {
		if !strings.Contains(string(data), value) {
			t.Errorf("missing client setting %q", value)
		}
	}
}
