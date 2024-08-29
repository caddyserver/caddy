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
	"crypto/tls"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/internal"
)

func init() {
	caddy.RegisterModule(MatchServerName{})
	caddy.RegisterModule(MatchRemoteIP{})
	caddy.RegisterModule(MatchLocalIP{})
}

// MatchServerName matches based on SNI. Names in
// this list may use left-most-label wildcards,
// similar to wildcard certificates.
type MatchServerName []string

// CaddyModule returns the Caddy module information.
func (MatchServerName) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.handshake_match.sni",
		New: func() caddy.Module { return new(MatchServerName) },
	}
}

// Match matches hello based on SNI.
func (m MatchServerName) Match(hello *tls.ClientHelloInfo) bool {
	repl := caddy.NewReplacer()
	// caddytls.TestServerNameMatcher calls this function without any context
	if ctx := hello.Context(); ctx != nil {
		// In some situations the existing context may have no replacer
		if replAny := ctx.Value(caddy.ReplacerCtxKey); replAny != nil {
			repl = replAny.(*caddy.Replacer)
		}
	}

	for _, name := range m {
		rs := repl.ReplaceAll(name, "")
		if certmagic.MatchWildcard(hello.ServerName, rs) {
			return true
		}
	}
	return false
}

// UnmarshalCaddyfile sets up the MatchServerName from Caddyfile tokens. Syntax:
//
//	sni <domains...>
func (m *MatchServerName) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		wrapper := d.Val()

		// At least one same-line option must be provided
		if d.CountRemainingArgs() == 0 {
			return d.ArgErr()
		}

		*m = append(*m, d.RemainingArgs()...)

		// No blocks are supported
		if d.NextBlock(d.Nesting()) {
			return d.Errf("malformed TLS handshake matcher '%s': blocks are not supported", wrapper)
		}
	}

	return nil
}

// MatchRemoteIP matches based on the remote IP of the
// connection. Specific IPs or CIDR ranges can be specified.
//
// Note that IPs can sometimes be spoofed, so do not rely
// on this as a replacement for actual authentication.
type MatchRemoteIP struct {
	// The IPs or CIDR ranges to match.
	Ranges []string `json:"ranges,omitempty"`

	// The IPs or CIDR ranges to *NOT* match.
	NotRanges []string `json:"not_ranges,omitempty"`

	cidrs    []netip.Prefix
	notCidrs []netip.Prefix
	logger   *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (MatchRemoteIP) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.handshake_match.remote_ip",
		New: func() caddy.Module { return new(MatchRemoteIP) },
	}
}

// Provision parses m's IP ranges, either from IP or CIDR expressions.
func (m *MatchRemoteIP) Provision(ctx caddy.Context) error {
	repl := caddy.NewReplacer()
	m.logger = ctx.Logger()
	for _, str := range m.Ranges {
		rs := repl.ReplaceAll(str, "")
		cidrs, err := m.parseIPRange(rs)
		if err != nil {
			return err
		}
		m.cidrs = append(m.cidrs, cidrs...)
	}
	for _, str := range m.NotRanges {
		rs := repl.ReplaceAll(str, "")
		cidrs, err := m.parseIPRange(rs)
		if err != nil {
			return err
		}
		m.notCidrs = append(m.notCidrs, cidrs...)
	}
	return nil
}

// Match matches hello based on the connection's remote IP.
func (m MatchRemoteIP) Match(hello *tls.ClientHelloInfo) bool {
	remoteAddr := hello.Conn.RemoteAddr().String()
	ipStr, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		ipStr = remoteAddr // weird; maybe no port?
	}
	ipAddr, err := netip.ParseAddr(ipStr)
	if err != nil {
		m.logger.Error("invalid client IP address", zap.String("ip", ipStr))
		return false
	}
	return (len(m.cidrs) == 0 || m.matches(ipAddr, m.cidrs)) &&
		(len(m.notCidrs) == 0 || !m.matches(ipAddr, m.notCidrs))
}

func (MatchRemoteIP) parseIPRange(str string) ([]netip.Prefix, error) {
	var cidrs []netip.Prefix
	if strings.Contains(str, "/") {
		ipNet, err := netip.ParsePrefix(str)
		if err != nil {
			return nil, fmt.Errorf("parsing CIDR expression: %v", err)
		}
		cidrs = append(cidrs, ipNet)
	} else {
		ipAddr, err := netip.ParseAddr(str)
		if err != nil {
			return nil, fmt.Errorf("invalid IP address: '%s': %v", str, err)
		}
		ip := netip.PrefixFrom(ipAddr, ipAddr.BitLen())
		cidrs = append(cidrs, ip)
	}
	return cidrs, nil
}

func (MatchRemoteIP) matches(ip netip.Addr, ranges []netip.Prefix) bool {
	for _, ipRange := range ranges {
		if ipRange.Contains(ip) {
			return true
		}
	}
	return false
}

// UnmarshalCaddyfile sets up the MatchRemoteIP from Caddyfile tokens. Syntax:
//
//	remote_ip <ranges...>
//
// Note: IPs and CIDRs prefixed with ! symbol are treated as not_ranges
func (m *MatchRemoteIP) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		wrapper := d.Val()

		// At least one same-line option must be provided
		if d.CountRemainingArgs() == 0 {
			return d.ArgErr()
		}

		for d.NextArg() {
			val := d.Val()
			var exclamation bool
			if len(val) > 1 && val[0] == '!' {
				exclamation, val = true, val[1:]
			}
			ranges := []string{val}
			if val == "private_ranges" {
				ranges = internal.PrivateRangesCIDR()
			}
			if exclamation {
				m.NotRanges = append(m.NotRanges, ranges...)
			} else {
				m.Ranges = append(m.Ranges, ranges...)
			}
		}

		// No blocks are supported
		if d.NextBlock(d.Nesting()) {
			return d.Errf("malformed TLS handshake matcher '%s': blocks are not supported", wrapper)
		}
	}

	return nil
}

// MatchLocalIP matches based on the IP address of the interface
// receiving the connection. Specific IPs or CIDR ranges can be specified.
type MatchLocalIP struct {
	// The IPs or CIDR ranges to match.
	Ranges []string `json:"ranges,omitempty"`

	cidrs  []netip.Prefix
	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (MatchLocalIP) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.handshake_match.local_ip",
		New: func() caddy.Module { return new(MatchLocalIP) },
	}
}

// Provision parses m's IP ranges, either from IP or CIDR expressions.
func (m *MatchLocalIP) Provision(ctx caddy.Context) error {
	repl := caddy.NewReplacer()
	m.logger = ctx.Logger()
	for _, str := range m.Ranges {
		rs := repl.ReplaceAll(str, "")
		cidrs, err := m.parseIPRange(rs)
		if err != nil {
			return err
		}
		m.cidrs = append(m.cidrs, cidrs...)
	}
	return nil
}

// Match matches hello based on the connection's remote IP.
func (m MatchLocalIP) Match(hello *tls.ClientHelloInfo) bool {
	localAddr := hello.Conn.LocalAddr().String()
	ipStr, _, err := net.SplitHostPort(localAddr)
	if err != nil {
		ipStr = localAddr // weird; maybe no port?
	}
	ipAddr, err := netip.ParseAddr(ipStr)
	if err != nil {
		m.logger.Error("invalid local IP address", zap.String("ip", ipStr))
		return false
	}
	return (len(m.cidrs) == 0 || m.matches(ipAddr, m.cidrs))
}

func (MatchLocalIP) parseIPRange(str string) ([]netip.Prefix, error) {
	var cidrs []netip.Prefix
	if strings.Contains(str, "/") {
		ipNet, err := netip.ParsePrefix(str)
		if err != nil {
			return nil, fmt.Errorf("parsing CIDR expression: %v", err)
		}
		cidrs = append(cidrs, ipNet)
	} else {
		ipAddr, err := netip.ParseAddr(str)
		if err != nil {
			return nil, fmt.Errorf("invalid IP address: '%s': %v", str, err)
		}
		ip := netip.PrefixFrom(ipAddr, ipAddr.BitLen())
		cidrs = append(cidrs, ip)
	}
	return cidrs, nil
}

func (MatchLocalIP) matches(ip netip.Addr, ranges []netip.Prefix) bool {
	for _, ipRange := range ranges {
		if ipRange.Contains(ip) {
			return true
		}
	}
	return false
}

// UnmarshalCaddyfile sets up the MatchLocalIP from Caddyfile tokens. Syntax:
//
//	local_ip <ranges...>
func (m *MatchLocalIP) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		wrapper := d.Val()

		// At least one same-line option must be provided
		if d.CountRemainingArgs() == 0 {
			return d.ArgErr()
		}

		for d.NextArg() {
			val := d.Val()
			if val == "private_ranges" {
				m.Ranges = append(m.Ranges, internal.PrivateRangesCIDR()...)
				continue
			}
			m.Ranges = append(m.Ranges, val)
		}

		// No blocks are supported
		if d.NextBlock(d.Nesting()) {
			return d.Errf("malformed TLS handshake matcher '%s': blocks are not supported", wrapper)
		}
	}

	return nil
}

// Interface guards
var (
	_ ConnectionMatcher = (*MatchServerName)(nil)
	_ ConnectionMatcher = (*MatchRemoteIP)(nil)

	_ caddy.Provisioner = (*MatchLocalIP)(nil)
	_ ConnectionMatcher = (*MatchLocalIP)(nil)

	_ caddyfile.Unmarshaler = (*MatchLocalIP)(nil)
	_ caddyfile.Unmarshaler = (*MatchRemoteIP)(nil)
	_ caddyfile.Unmarshaler = (*MatchServerName)(nil)
)
