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
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(MatchServerName{})
	caddy.RegisterModule(MatchRemoteIP{})
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
	for _, name := range m {
		if certmagic.MatchWildcard(hello.ServerName, name) {
			return true
		}
	}
	return false
}

// MatchRemoteIP matches based on the remote IP of the
// connection. Specific IPs or CIDR ranges can be specified.
//
// Note that IPs can sometimes be spoofed, so do not rely
// on this as a replacement for actual authentication.
type MatchRemoteIP struct {
	// The IPs or CIDR ranges to match.
	Ranges []string `json:"ranges,omitempty"`

	cidrs  []*net.IPNet
	logger *zap.Logger
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
	m.logger = ctx.Logger(m)
	for _, str := range m.Ranges {
		if strings.Contains(str, "/") {
			_, ipNet, err := net.ParseCIDR(str)
			if err != nil {
				return fmt.Errorf("parsing CIDR expression: %v", err)
			}
			m.cidrs = append(m.cidrs, ipNet)
		} else {
			ip := net.ParseIP(str)
			if ip == nil {
				return fmt.Errorf("invalid IP address: %s", str)
			}
			mask := len(ip) * 8
			m.cidrs = append(m.cidrs, &net.IPNet{
				IP:   ip,
				Mask: net.CIDRMask(mask, mask),
			})
		}
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
	ip := net.ParseIP(ipStr)
	if ip == nil {
		m.logger.Error("invalid client IP addresss", zap.String("ip", ipStr))
		return false
	}
	for _, ipRange := range m.cidrs {
		if ipRange.Contains(ip) {
			return true
		}
	}
	return false
}

// Interface guards
var (
	_ ConnectionMatcher = (*MatchServerName)(nil)
	_ ConnectionMatcher = (*MatchRemoteIP)(nil)
)
