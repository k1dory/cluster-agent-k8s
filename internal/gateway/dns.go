package gateway

import (
	"context"
	"log/slog"
	"net"
	"strings"

	"github.com/miekg/dns"

	"agent-sandbox/internal/policy"
)

// DNS is the pods' only resolver: allowlisted names → gateway IP, everything else NXDOMAIN.
// No upstream, so no query ever leaves the VLAN and no DNS tunnelling is possible.
type DNS struct {
	IP       net.IP
	Policies *policy.Set
	Extra    []string // internal hosts (api, registrar)
	Log      *slog.Logger
}

func (d *DNS) allowed(name string) bool {
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
	if !d.allowed(q.Name) {
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

// ListenAndServe runs UDP and TCP servers on addr until ctx ends.
func (d *DNS) ListenAndServe(ctx context.Context, addr string) error {
	udp := &dns.Server{Addr: addr, Net: "udp", Handler: d}
	tcp := &dns.Server{Addr: addr, Net: "tcp", Handler: d}
	errCh := make(chan error, 2)
	go func() { errCh <- udp.ListenAndServe() }()
	go func() { errCh <- tcp.ListenAndServe() }()
	select {
	case <-ctx.Done():
		_ = udp.Shutdown()
		_ = tcp.Shutdown()
		return nil
	case err := <-errCh:
		_ = udp.Shutdown()
		_ = tcp.Shutdown()
		return err
	}
}
