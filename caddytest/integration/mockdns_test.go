package integration

import (
	"context"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/certmagic"
	"github.com/libdns/libdns"
)

func init() {
	caddy.RegisterModule(MockDNSProvider{})
}

// MockDNSProvider is a mock DNS provider, for testing config with DNS modules.
type MockDNSProvider struct{}

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
func (MockDNSProvider) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
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
var _ caddyfile.Unmarshaler = (*MockDNSProvider)(nil)
var _ certmagic.DNSProvider = (*MockDNSProvider)(nil)
var _ caddy.Provisioner = (*MockDNSProvider)(nil)
var _ caddy.Module = (*MockDNSProvider)(nil)
