// Copyright 2015 Matthew Holt and The Caddy Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package caddytls

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/certmagic"
	"github.com/libdns/libdns"
	"github.com/miekg/dns"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(InternalDNS{})
}

// InternalDNS is a DNS provider that runs an embedded DNS server
// to serve ACME DNS-01 challenge TXT records directly. It is
// intended for use when the _acme-challenge subdomain is delegated
// to the Caddy server via an NS record in the parent zone.
type InternalDNS struct {
	// The address to listen on for DNS queries (TCP and UDP). Defaults to ":53".
	ListenAddr string `json:"listen_addr,omitempty"`

	// MNAME: FQDN of the primary nameserver placed in synthetic SOA records.
	// This should match the NS record.
	Mname string `json:"mname,omitempty"`

	// RNAME: responsible-mailbox FQDN placed in synthetic SOA records
	// (e.g. "hostmaster.example.com.").
	Rname string `json:"rname,omitempty"`

	tlsApp    *TLS
	records   map[string][]libdns.RR // key: FQDN (lowercase)
	udpServer *dns.Server
	tcpServer *dns.Server
	udpLn     net.PacketConn
	tcpLn     net.Listener
	logger    *zap.Logger
	mu        *sync.RWMutex
}

func (InternalDNS) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "dns.providers.internal",
		New: func() caddy.Module { return new(InternalDNS) },
	}
}

func (d *InternalDNS) Provision(ctx caddy.Context) error {
	d.logger = ctx.Logger()

	if d.ListenAddr == "" {
		d.ListenAddr = ":53"
	}

	d.mu = new(sync.RWMutex)
	d.records = make(map[string][]libdns.RR)

	if tlsIface, err := ctx.AppIfConfigured("tls"); err == nil {
		d.tlsApp = tlsIface.(*TLS)
	}

	udpAddr, err := net.ResolveUDPAddr("udp", d.ListenAddr)
	if err != nil {
		return fmt.Errorf("resolving UDP listen address: %w", err)
	}
	d.udpLn, err = net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("listening on UDP %s: %w", d.ListenAddr, err)
	}

	d.tcpLn, err = net.Listen("tcp", d.ListenAddr)
	if err != nil {
		d.udpLn.Close()
		return fmt.Errorf("listening on TCP %s: %w", d.ListenAddr, err)
	}

	var wg sync.WaitGroup
	wg.Add(2)

	d.udpServer = &dns.Server{
		PacketConn: d.udpLn,
		Handler:    dns.HandlerFunc(d.serveDNS),
		NotifyStartedFunc: func() {
			wg.Done()
		},
	}
	d.tcpServer = &dns.Server{
		Listener: d.tcpLn,
		Handler:  dns.HandlerFunc(d.serveDNS),
		NotifyStartedFunc: func() {
			wg.Done()
		},
	}

	go func() {
		if err := d.udpServer.ActivateAndServe(); err != nil {
			d.logger.Error("UDP DNS server error", zap.Error(err))
		}
	}()
	go func() {
		if err := d.tcpServer.ActivateAndServe(); err != nil {
			d.logger.Error("TCP DNS server error", zap.Error(err))
		}
	}()

	wg.Wait()

	return nil
}

func (d *InternalDNS) Cleanup() error {
	if d.udpServer != nil {
		if err := d.udpServer.Shutdown(); err != nil {
			d.logger.Error("shutting down UDP DNS server", zap.Error(err))
		}
	}
	if d.tcpServer != nil {
		if err := d.tcpServer.Shutdown(); err != nil {
			d.logger.Error("shutting down TCP DNS server", zap.Error(err))
		}
	}
	return nil
}

func (d *InternalDNS) serveDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false
	m.Authoritative = true

	// https://www.rfc-editor.org/rfc/rfc6891#section-6.1.1
	// If an OPT record is present in a received request, compliant
	// responders MUST include an OPT record in their respective responses.
	if opt := r.IsEdns0(); opt != nil {
		m.SetEdns0(opt.UDPSize(), opt.Do())
	}

	if len(r.Question) == 0 {
		m.Rcode = dns.RcodeFormatError
		if err := w.WriteMsg(m); err != nil {
			d.logger.Warn("failed to write DNS response", zap.Error(err))
		}
		return
	}

	q := r.Question[0]
	name := strings.ToLower(q.Name)

	// Derive the zone this name falls under from the TLS automate list.
	var matchedZone string
	if d.tlsApp != nil {
		for subject := range d.tlsApp.automateNames {
			s := strings.TrimPrefix(strings.ToLower(subject), "*.")
			zone := "_acme-challenge." + s + "."
			if name == zone || strings.HasSuffix(name, "."+zone) {
				matchedZone = zone
				break
			}
		}
	}

	if q.Qtype == dns.TypeSOA && matchedZone == name {
		m.Answer = append(m.Answer, d.syntheticSOA(matchedZone))
		if err := w.WriteMsg(m); err != nil {
			d.logger.Warn("failed to write DNS response", zap.Error(err))
		}
		return
	}

	d.mu.RLock()
	recs, ok := d.records[name]
	d.mu.RUnlock()

	if !ok {
		m.Rcode = dns.RcodeNameError
		if matchedZone != "" {
			m.Ns = append(m.Ns, d.syntheticSOA(matchedZone))
		}
		if err := w.WriteMsg(m); err != nil {
			d.logger.Warn("failed to write DNS response", zap.Error(err))
		}
		return
	}

	for _, rec := range recs {
		if dns.StringToType[rec.Type] != q.Qtype {
			continue
		}

		hdr := dns.RR_Header{
			Name:   name,
			Rrtype: q.Qtype,
			Class:  dns.ClassINET,
			Ttl:    uint32(rec.TTL.Seconds()),
		}

		switch rec.Type {
		case "A":
			m.Answer = append(m.Answer, &dns.A{Hdr: hdr, A: net.ParseIP(rec.Data)})
		case "AAAA":
			m.Answer = append(m.Answer, &dns.AAAA{Hdr: hdr, AAAA: net.ParseIP(rec.Data)})
		case "CNAME":
			m.Answer = append(m.Answer, &dns.CNAME{Hdr: hdr, Target: rec.Data})
		case "TXT":
			m.Answer = append(m.Answer, &dns.TXT{Hdr: hdr, Txt: []string{rec.Data}})
		case "SRV", "HTTPS":
			rr, err := dns.NewRR(fmt.Sprintf("%s %d IN %s %s", name, uint32(rec.TTL.Seconds()), rec.Type, rec.Data))
			if err != nil {
				d.logger.Warn("failed to parse record data for internal DNS response",
					zap.String("type", rec.Type),
					zap.String("name", name),
					zap.String("data", rec.Data),
					zap.Error(err))
				continue
			}
			m.Answer = append(m.Answer, rr)
		default:
			d.logger.Warn("unhandled record type in internal DNS server",
				zap.String("type", rec.Type),
				zap.String("name", name))
		}
	}

	if len(m.Answer) == 0 {
		m.Rcode = dns.RcodeNameError
		if matchedZone != "" {
			m.Ns = append(m.Ns, d.syntheticSOA(matchedZone))
		}
	}

	if err := w.WriteMsg(m); err != nil {
		d.logger.Warn("failed to write DNS response", zap.Error(err))
	}
}

func (d *InternalDNS) syntheticSOA(zone string) dns.RR {
	return &dns.SOA{
		Hdr: dns.RR_Header{
			Name:   zone,
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		Ns:     dns.Fqdn(d.Mname),
		Mbox:   dns.Fqdn(d.Rname),
		Serial: 1,
	}
}

func (d *InternalDNS) AppendRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	zone = normalizeZone(zone)
	results := make([]libdns.Record, 0, len(recs))

	for _, rec := range recs {
		rr := rec.RR()
		name := strings.ToLower(libdns.AbsoluteName(rr.Name, zone))

		d.records[name] = append(d.records[name], rr)
		results = append(results, rec)
	}

	return results, nil
}

func (d *InternalDNS) DeleteRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	zone = normalizeZone(zone)
	results := make([]libdns.Record, 0, len(recs))

	for _, rec := range recs {
		rr := rec.RR()
		name := strings.ToLower(libdns.AbsoluteName(rr.Name, zone))

		existing, ok := d.records[name]
		if !ok {
			continue
		}

		var kept []libdns.RR
		for _, e := range existing {
			match := e.Name == rr.Name &&
				(rr.Type == "" || e.Type == rr.Type) &&
				(rr.TTL == 0 || e.TTL == rr.TTL) &&
				(rr.Data == "" || e.Data == rr.Data)

			if match {
				results = append(results, rec)
			} else {
				kept = append(kept, e)
			}
		}

		if len(kept) == 0 {
			delete(d.records, name)
		} else {
			d.records[name] = kept
		}
	}

	return results, nil
}

func (d *InternalDNS) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	zone = normalizeZone(zone)

	var results []libdns.Record
	for name, rrs := range d.records {
		if !(name == zone || strings.HasSuffix(name, "."+zone)) {
			continue
		}
		for _, rr := range rrs {
			parsed, err := libdns.RR{
				Name: libdns.RelativeName(name, zone),
				Type: rr.Type,
				TTL:  rr.TTL,
				Data: rr.Data,
			}.Parse()
			if err != nil {
				return nil, err
			}
			results = append(results, parsed)
		}
	}

	return results, nil
}

func (d *InternalDNS) SetRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	zone = normalizeZone(zone)

	type key struct {
		name string
		typ  string
	}
	setKeys := make(map[key]struct{})
	for _, rec := range recs {
		rr := rec.RR()
		name := strings.ToLower(libdns.AbsoluteName(rr.Name, zone))
		setKeys[key{name: name, typ: rr.Type}] = struct{}{}
	}

	for k := range setKeys {
		existing, ok := d.records[k.name]
		if !ok {
			continue
		}
		var kept []libdns.RR
		for _, e := range existing {
			if e.Type == k.typ {
				continue
			}
			kept = append(kept, e)
		}
		if len(kept) == 0 {
			delete(d.records, k.name)
		} else {
			d.records[k.name] = kept
		}
	}

	for _, rec := range recs {
		rr := rec.RR()
		name := strings.ToLower(libdns.AbsoluteName(rr.Name, zone))
		d.records[name] = append(d.records[name], rr)
	}

	return recs, nil
}

func normalizeZone(zone string) string {
	zone = strings.ToLower(zone)
	if !strings.HasSuffix(zone, ".") {
		zone += "."
	}
	return zone
}

// Syntax:
//
//	dns internal [<listen_addr>] {
//	    mname <primary_nameserver_fqdn>
//	    rname <responsible_mailbox_fqdn>
//	}
func (d *InternalDNS) UnmarshalCaddyfile(disp *caddyfile.Dispenser) error {
	disp.Next() // consume provider name

	if disp.NextArg() {
		d.ListenAddr = disp.Val()
	}
	if disp.NextArg() {
		return disp.Errf("unexpected argument '%s'", disp.Val())
	}

	for disp.NextBlock(0) {
		switch disp.Val() {
		case "mname":
			if !disp.NextArg() {
				return disp.ArgErr()
			}
			d.Mname = disp.Val()
		case "rname":
			if !disp.NextArg() {
				return disp.ArgErr()
			}
			d.Rname = disp.Val()
		default:
			return disp.Errf("unrecognized subdirective '%s'", disp.Val())
		}
	}

	return nil
}

var (
	_ caddy.Module          = (*InternalDNS)(nil)
	_ caddy.Provisioner     = (*InternalDNS)(nil)
	_ caddy.CleanerUpper    = (*InternalDNS)(nil)
	_ caddyfile.Unmarshaler = (*InternalDNS)(nil)
	_ certmagic.DNSProvider = (*InternalDNS)(nil)
	_ libdns.RecordGetter   = (*InternalDNS)(nil)
	_ libdns.RecordSetter   = (*InternalDNS)(nil)
)
