package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// bridgeClient is the test binary as an agent would be (ACP_BRIDGE_CLIENT=<url>): one request to
// the bridge, the answer's status and body on stdout.
func bridgeClient(u string) int {
	resp, err := http.Get(u)
	if err != nil {
		fmt.Println("error:", err)
		return 1
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	fmt.Printf("%d %s\n", resp.StatusCode, b)
	return 0
}

// The isolation the model-call tests use keeps what they need: an agent process, cut off from
// the network, still reaches the gateway bridge on the test's loopback, and through it a gateway
// that requires the pod's client certificate. On Linux that holds only because the whole test
// runs in one network namespace (runOfflineInNetns); isolating the agent alone breaks it.
func TestOfflineAgentReachesTheBridgeAndTheGateway(t *testing.T) {
	if runOfflineInNetns(t) {
		return
	}
	isolate := noNetwork(t)
	gw := newTestGateway(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hello %s", r.TLS.PeerCertificates[0].Subject.CommonName)
	}), "api.example.test")
	gw.route(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go serveGatewayBridge(ctx, gw.certDir)
	for i := 0; ; i++ {
		if c, err := net.DialTimeout("tcp", gatewayBridgeAddr, 200*time.Millisecond); err == nil {
			c.Close()
			break
		}
		if i == 50 {
			t.Fatal("the gateway bridge did not start")
		}
		time.Sleep(100 * time.Millisecond)
	}
	cmd := exec.Command(isolate[0], append(isolate[1:], os.Args[0])...)
	cmd.Env = append(os.Environ(), "ACP_BRIDGE_CLIENT="+gatewayBridgeURL("https://api.example.test/"))
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "200 hello sandbox-test/1") {
		t.Fatalf("an isolated agent did not get through the bridge to the gateway: %v\n%s", err, out)
	}
}

// loopbackSelftest is the test binary as an isolated agent (ACP_LOOPBACK_SELFTEST=1): a server of
// its own on loopback must answer (opencode acp needs one), the outside must not.
func loopbackSelftest() int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Println("loopback listen:", err)
		return 1
	}
	defer l.Close()
	go func() {
		if c, err := l.Accept(); err == nil {
			_, _ = c.Write([]byte("own"))
			c.Close()
		}
	}()
	c, err := net.DialTimeout("tcp", l.Addr().String(), 2*time.Second)
	if err != nil {
		fmt.Println("loopback dial:", err)
		return 1
	}
	b, _ := io.ReadAll(c)
	c.Close()
	if _, err := net.DialTimeout("tcp", "1.1.1.1:443", 3*time.Second); err == nil {
		fmt.Println("the outside was reachable")
		return 1
	}
	fmt.Printf("loopback %s, outside cut\n", b)
	return 0
}

// noNetwork's prefix leaves an agent its own loopback and nothing beyond it.
func TestNoNetworkKeepsOnlyLoopback(t *testing.T) {
	isolate := noNetwork(t)
	cmd := exec.Command(isolate[0], append(isolate[1:], os.Args[0])...)
	cmd.Env = append(os.Environ(), "ACP_LOOPBACK_SELFTEST=1")
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "loopback own, outside cut") {
		t.Fatalf("isolated process: %v\n%s", err, out)
	}
}
