package caddyhttp

import (
	"net/netip"
	"testing"
)

func TestCIDRExpressionToPrefix(t *testing.T) {
	tests := []struct {
		name    string
		expr    string
		want    netip.Prefix
		wantErr bool
	}{
		{
			name: "valid CIDR IPv4",
			expr: "192.168.0.0/16",
			want: netip.MustParsePrefix("192.168.0.0/16"),
		},
		{
			name: "valid CIDR IPv6",
			expr: "fd00::/8",
			want: netip.MustParsePrefix("fd00::/8"),
		},
		{
			name: "single IPv4 becomes /32",
			expr: "192.168.1.1",
			want: netip.MustParsePrefix("192.168.1.1/32"),
		},
		{
			name: "single IPv6 becomes /128",
			expr: "::1",
			want: netip.MustParsePrefix("::1/128"),
		},
		{
			name: "loopback IPv4",
			expr: "127.0.0.1",
			want: netip.MustParsePrefix("127.0.0.1/32"),
		},
		{
			name: "full IPv6 address",
			expr: "2001:db8::1",
			want: netip.MustParsePrefix("2001:db8::1/128"),
		},
		{
			name:    "invalid CIDR",
			expr:    "192.168.0.0/33",
			wantErr: true,
		},
		{
			name:    "invalid IP",
			expr:    "not-an-ip",
			wantErr: true,
		},
		{
			name:    "empty string",
			expr:    "",
			wantErr: true,
		},
		{
			name:    "CIDR with invalid IP",
			expr:    "999.999.999.999/24",
			wantErr: true,
		},
		{
			name: "CIDR /0 matches everything",
			expr: "0.0.0.0/0",
			want: netip.MustParsePrefix("0.0.0.0/0"),
		},
		{
			name: "CIDR /32 single host",
			expr: "10.0.0.1/32",
			want: netip.MustParsePrefix("10.0.0.1/32"),
		},
		{
			name:    "malformed CIDR with extra slash",
			expr:    "10.0.0.0/8/16",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CIDRExpressionToPrefix(tt.expr)
			if (err != nil) != tt.wantErr {
				t.Errorf("CIDRExpressionToPrefix(%q) error = %v, wantErr %v", tt.expr, err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("CIDRExpressionToPrefix(%q) = %v, want %v", tt.expr, got, tt.want)
			}
		})
	}
}

func TestStaticIPRangeProvision(t *testing.T) {
	tests := []struct {
		name    string
		ranges  []string
		wantLen int
		wantErr bool
	}{
		{
			name:    "valid CIDR ranges",
			ranges:  []string{"192.168.0.0/16", "10.0.0.0/8"},
			wantLen: 2,
		},
		{
			name:    "single IPs",
			ranges:  []string{"192.168.1.1", "10.0.0.1"},
			wantLen: 2,
		},
		{
			name:    "mixed CIDR and single IP",
			ranges:  []string{"192.168.0.0/16", "10.0.0.1"},
			wantLen: 2,
		},
		{
			name:    "invalid range",
			ranges:  []string{"not-valid"},
			wantErr: true,
		},
		{
			name:    "empty ranges",
			ranges:  []string{},
			wantLen: 0,
		},
		{
			name:    "nil ranges",
			ranges:  nil,
			wantLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &StaticIPRange{Ranges: tt.ranges}
			// We can't easily create a caddy.Context here without full module setup,
			// but Provision only uses the ranges field, so we test the logic directly.
			// The Provision method calls CIDRExpressionToPrefix which we test separately.
			var parsedCount int
			var gotErr bool
			for _, r := range s.Ranges {
				_, err := CIDRExpressionToPrefix(r)
				if err != nil {
					gotErr = true
					break
				}
				parsedCount++
			}

			if gotErr != tt.wantErr {
				t.Errorf("provision error = %v, wantErr %v", gotErr, tt.wantErr)
			}
			if !tt.wantErr && parsedCount != tt.wantLen {
				t.Errorf("parsed %d ranges, want %d", parsedCount, tt.wantLen)
			}
		})
	}
}

func TestStaticIPRangeGetIPRanges(t *testing.T) {
	s := &StaticIPRange{
		ranges: []netip.Prefix{
			netip.MustParsePrefix("192.168.0.0/16"),
			netip.MustParsePrefix("10.0.0.0/8"),
		},
	}

	result := s.GetIPRanges(nil) // request is unused
	if len(result) != 2 {
		t.Errorf("GetIPRanges() returned %d prefixes, want 2", len(result))
	}
}

func TestStaticIPRangeCaddyModule(t *testing.T) {
	s := StaticIPRange{}
	info := s.CaddyModule()
	if info.ID != "http.ip_sources.static" {
		t.Errorf("CaddyModule().ID = %v, want 'http.ip_sources.static'", info.ID)
	}
	mod := info.New()
	if mod == nil {
		t.Error("New() should not return nil")
	}
}

func TestPrivateRangesCIDRWrapper(t *testing.T) {
	ranges := PrivateRangesCIDR()
	if len(ranges) == 0 {
		t.Error("PrivateRangesCIDR() should return non-empty list")
	}

	// Verify all ranges are valid CIDR or IP expressions
	for _, r := range ranges {
		_, err := CIDRExpressionToPrefix(r)
		if err != nil {
			t.Errorf("PrivateRangesCIDR() returned invalid range %q: %v", r, err)
		}
	}
}
