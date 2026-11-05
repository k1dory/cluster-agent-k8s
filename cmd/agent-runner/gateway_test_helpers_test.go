package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// testGateway is a stand-in for the sandbox gateway: TLS for the given names under a CA of its
// own, a client certificate from that CA required. certDir holds what agent-init would write
// for a pod (tls.crt, tls.key, gateway-ca.crt). The handler sees requests only after a client
// certificate was verified; r.TLS.PeerCertificates[0] is it.
type testGateway struct {
	certDir string
	srv     *httptest.Server
	port    string
}

func newTestGateway(t *testing.T, handler http.Handler, names ...string) *testGateway {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test gateway root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	issue := func(serial int64, cn string, usage x509.ExtKeyUsage, dns []string) ([]byte, *ecdsa.PrivateKey) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}, DNSNames: dns,
			IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		return der, key
	}
	pemCert := func(der []byte) []byte { return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}) }
	pemKey := func(k *ecdsa.PrivateKey) []byte {
		b, _ := x509.MarshalECPrivateKey(k)
		return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: b})
	}
	srvDER, srvKey := issue(2, "gateway", x509.ExtKeyUsageServerAuth, append(names, "localhost"))
	cliDER, cliKey := issue(3, "sandbox-test/1", x509.ExtKeyUsageClientAuth, nil)

	dir := t.TempDir()
	for name, data := range map[string][]byte{"tls.crt": pemCert(cliDER), "tls.key": pemKey(cliKey), "gateway-ca.crt": pemCert(caDER)} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	srvCert, err := tls.X509KeyPair(pemCert(srvDER), pemKey(srvKey))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{srvCert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	return &testGateway{certDir: dir, srv: srv, port: port}
}

// route points the bridge at this gateway for every host, as GATEWAY_IP does in a pod.
func (g *testGateway) route(t *testing.T) {
	t.Helper()
	t.Setenv("GATEWAY_IP", "127.0.0.1")
	t.Setenv("SANDBOX_GATEWAY_PORT", g.port)
}
