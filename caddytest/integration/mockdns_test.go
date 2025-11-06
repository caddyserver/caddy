package integration

import (
	"context"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/libdns"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func init() {
	caddy.RegisterModule(MockDNSProvider{})
}

// MockDNSProvider is a mock DNS provider, for testing config with DNS modules.
type MockDNSProvider struct {
	Argument string `json:"argument,omitempty"` // optional argument useful for testing
}

// CaddyModule returns the Caddy module information.
func (MockDNSProvider) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "dns.providers.mock",
		New: func() caddy.Module { return new(MockDNSProvider) },
	}
}

// Provision sets up the module.
func (MockDNSProvider) Provision(ctx caddy.Context) error {
	return nil
}

// UnmarshalCaddyfile sets up the module from Caddyfile tokens.
func (p *MockDNSProvider) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume directive name

	if d.NextArg() {
		p.Argument = d.Val()
	}
	if d.NextArg() {
		return d.Errf("unexpected argument '%s'", d.Val())
	}
	return nil
}

// AppendRecords appends DNS records to the zone.
func (MockDNSProvider) AppendRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	return nil, nil
}

// DeleteRecords deletes DNS records from the zone.
func (MockDNSProvider) DeleteRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	return nil, nil
}

// GetRecords gets DNS records from the zone.
func (MockDNSProvider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	return nil, nil
}

// SetRecords sets DNS records in the zone.
func (MockDNSProvider) SetRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	return nil, nil
}

// Interface guard
var (
	_ caddyfile.Unmarshaler = (*MockDNSProvider)(nil)
	_ certmagic.DNSProvider = (*MockDNSProvider)(nil)
	_ caddy.Provisioner     = (*MockDNSProvider)(nil)
	_ caddy.Module          = (*MockDNSProvider)(nil)
)
