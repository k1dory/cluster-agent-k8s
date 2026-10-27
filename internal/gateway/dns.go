package gateway

import (
	"context"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// DNS is the pods' only resolver: allowlisted names → gateway IP, everything else NXDOMAIN.
// No upstream, so no query ever leaves the VLAN and no DNS tunnelling is possible.
type DNS struct {
	IP       net.IP
	Policies HostLister // the policy set, or the guard that adds the connections' hosts
	Extra    []string   // internal hosts (api, registrar)
	Log      *slog.Logger
	// RetryEvery is how often a bind that failed is tried again (0: 5s).
	RetryEvery time.Duration
}

// Allowed reports whether the gateway serves name (an internal host, a repository host or a
// connection's own host).
func (d *DNS) Allowed(name string) bool {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	for _, h := range d.Extra {
		if strings.EqualFold(h, name) {
			return true
		}
	}
	for _, h := range d.Policies.Hosts() {
		if h.Name == name {
			return true
		}
	}
	return false
}

// ServeDNS implements dns.Handler.
func (d *DNS) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	m.RecursionAvailable = false
	if len(r.Question) != 1 {
		m.Rcode = dns.RcodeRefused
		_ = w.WriteMsg(m)
		return
	}
	q := r.Question[0]
	if !d.Allowed(q.Name) {
		m.Rcode = dns.RcodeNameError
		if d.Log != nil {
			d.Log.Warn("dns", "verdict", "nxdomain", "name", q.Name, "type", dns.TypeToString[q.Qtype], "src", w.RemoteAddr().String())
		}
		_ = w.WriteMsg(m)
		return
	}
	switch q.Qtype {
	case dns.TypeA, dns.TypeANY:
		m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30}, A: d.IP.To4()})
	default:
		// AAAA, HTTPS, TXT...: NODATA. The name exists, only A records do.
	}
	_ = w.WriteMsg(m)
}

// ListenAndServe runs UDP and TCP servers on addr until ctx ends. The address is bound
// with IP_FREEBIND where the platform has it (Linux): a replica standing by for a gateway
// address it does not hold yet (a VIP on another node) binds all the same and serves the
// moment the address moves to its node. A bind that fails anyway is tried again every
// RetryEvery until ctx ends, logged each time: a standby never gives up on the address.
func (d *DNS) ListenAndServe(ctx context.Context, addr string) error {
	retry := d.RetryEvery
	if retry <= 0 {
		retry = 5 * time.Second
	}
	for {
		udp, tcp, err := d.bind(ctx, addr)
		if err == nil {
			return d.serve(ctx, udp, tcp)
		}
		if d.Log != nil {
			d.Log.Error("dns: bind failed, trying again", "addr", addr, "retry", retry, "err", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(retry):
		}
	}
}

// bind opens the UDP and TCP sockets, both or neither.
func (d *DNS) bind(ctx context.Context, addr string) (net.PacketConn, net.Listener, error) {
	lc := net.ListenConfig{Control: freebind}
	udp, err := lc.ListenPacket(ctx, "udp", addr)
	if err != nil {
		return nil, nil, err
	}
	tcp, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		_ = udp.Close()
		return nil, nil, err
	}
	return udp, tcp, nil
}

// serve answers on the open sockets until ctx ends or a server fails.
func (d *DNS) serve(ctx context.Context, udp net.PacketConn, tcp net.Listener) error {
	us := &dns.Server{PacketConn: udp, Handler: d}
	ts := &dns.Server{Listener: tcp, Handler: d}
	errCh := make(chan error, 2)
	go func() { errCh <- us.ActivateAndServe() }()
	go func() { errCh <- ts.ActivateAndServe() }()
	select {
	case <-ctx.Done():
		_ = us.Shutdown()
		_ = ts.Shutdown()
		return nil
	case err := <-errCh:
		_ = us.Shutdown()
		_ = ts.Shutdown()
		return err
	}
}
