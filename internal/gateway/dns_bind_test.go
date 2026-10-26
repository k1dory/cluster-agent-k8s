package gateway

import (
	"context"
	"net"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// A bind that fails (the port is taken) is tried again until it succeeds: the server answers
// once the address is free, and ListenAndServe never gave up in between.
func TestDNSBindIsRetriedUntilTheAddressIsFree(t *testing.T) {
	d := &DNS{IP: net.ParseIP("10.77.77.1"), Policies: testSet(), Extra: []string{"api.sandbox.internal"}, RetryEvery: 50 * time.Millisecond}
	blocker, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := blocker.LocalAddr().String()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- d.ListenAndServe(ctx, addr) }()
	time.Sleep(150 * time.Millisecond)
	select {
	case err := <-done:
		t.Fatalf("ListenAndServe gave up on a taken address: %v", err)
	default:
	}
	blocker.Close()
	cl := &dns.Client{Timeout: 200 * time.Millisecond}
	m := new(dns.Msg)
	m.SetQuestion("api.sandbox.internal.", dns.TypeA)
	deadline := time.Now().Add(5 * time.Second)
	for {
		if r, _, err := cl.Exchange(m, addr); err == nil && len(r.Answer) == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the server did not come up after the address was freed")
		}
		time.Sleep(50 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("after cancel: %v", err)
	}
}

// On Linux the address is bound with IP_FREEBIND: a gateway address this host does not hold
// (a VIP on another node) binds all the same, so a standby replica is ready the moment the
// address moves to it.
func TestDNSBindsAnAddressTheHostDoesNotHold(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("IP_FREEBIND is Linux-only")
	}
	d := &DNS{IP: net.ParseIP("10.77.77.1"), Policies: testSet(), RetryEvery: 50 * time.Millisecond}
	probe, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := probe.LocalAddr().(*net.UDPAddr).Port
	probe.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	udp, tcp, err := d.bind(ctx, net.JoinHostPort("192.0.2.1", strconv.Itoa(port))) // TEST-NET-1: never on a host
	if err != nil {
		t.Fatalf("freebind: %v", err)
	}
	udp.Close()
	tcp.Close()
}
