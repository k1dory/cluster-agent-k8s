package integration

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"agent-sandbox/internal/ca"
	"agent-sandbox/internal/gateway"
	"agent-sandbox/internal/policy"
)

// Caddy's bootstrap configuration (the one the container starts with, before sandboxd pushes
// anything) already provisions the "local" CA: a root and an intermediate of Caddy's own, kept
// in its storage. When the pushed configuration names the shared gateway root instead, Caddy
// loads that root from the files but goes on signing with the intermediate it finds in
// storage, issued under the root it generated for itself, and the pods, trusting the shared
// root, see "certificate signed by unknown authority" (the eighth acceptance run). The sites
// must therefore be signed by the shared root itself, not by whatever intermediate the storage
// holds: a pod trusting the root published by sandboxd verifies the chain.
func TestRealCaddySignsUnderTheSharedRoot(t *testing.T) {
	bin := caddyBin(t)
	ctx := context.Background()
	adminPort, httpsPort, httpPort, regPort := freePort(t), freePort(t), freePort(t), freePort(t)

	root, err := ca.Generate("agent-sandbox gateway root", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath, keyPath, err := root.WriteTo(dir, "gateway-root")
	if err != nil {
		t.Fatal(err)
	}
	agentCA, err := ca.Generate("test agent CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	proc := startCaddy(t, bin, adminPort) // provisions Caddy's own root and intermediate first
	cfg := gateway.Config{IP: "127.0.0.1", Bind: "127.0.0.1", HTTPSPort: httpsPort, HTTPPort: httpPort,
		CaddyAdmin: fmt.Sprintf("http://127.0.0.1:%d", adminPort), SandboxdAddr: "127.0.0.1:9",
		APIHost: "api.sandbox.internal", RegistrarHost: "registrar.sandbox.internal", RegistrarPort: regPort,
		RootCert: certPath, RootKey: keyPath, AccessLog: "stderr", StrictSNI: true}
	syncer := &gateway.Syncer{Cfg: cfg, Policies: policy.FromPolicies(&policy.Policy{Slug: "none"}), AgentCA: agentCA.PEM()}
	if err := syncer.SyncOnce(ctx, true); err != nil {
		t.Fatalf("push config: %v\n%s", err, proc.out.String())
	}

	// What sandboxd publishes to the pods: the shared root, as it is, never Caddy's answer.
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(root.PEM()) {
		t.Fatal("root is not a PEM certificate")
	}
	for _, site := range []struct {
		host string
		port int
	}{{"registrar.sandbox.internal", regPort}, {"api.sandbox.internal", httpsPort}} {
		var err error
		for deadline := time.Now().Add(30 * time.Second); ; {
			err = handshake(site.host, site.port, pool)
			if err == nil || time.Now().After(deadline) {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if err != nil {
			t.Errorf("%s is not trusted through the shared root: %v", site.host, err)
		}
	}
	if t.Failed() {
		t.Logf("caddy output:\n%s", proc.out.String())
	}
	if _, err := os.Stat(certPath); err != nil {
		t.Fatal(err)
	}
}

// handshake connects to the site with the given trust store and verifies the served chain
// against it, the way agent-init does with the published gateway root.
func handshake(host string, port int, pool *x509.CertPool) error {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 5*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	tc := tls.Client(conn, &tls.Config{ServerName: host, RootCAs: pool})
	defer tc.Close()
	if err := tc.Handshake(); err != nil {
		// A policy host wants a client certificate; the chain was verified before that.
		return err
	}
	return nil
}
