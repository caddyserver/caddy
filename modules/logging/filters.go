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

package logging

import (
	"net"
	"strconv"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"go.uber.org/zap/zapcore"
)

func init() {
	caddy.RegisterModule(DeleteFilter{})
	caddy.RegisterModule(ReplaceFilter{})
	caddy.RegisterModule(IPMaskFilter{})
}

// LogFieldFilter can filter (or manipulate)
// a field in a log entry.
type LogFieldFilter interface {
	Filter(zapcore.Field) zapcore.Field
}

// DeleteFilter is a Caddy log field filter that
// deletes the field.
type DeleteFilter struct{}

// CaddyModule returns the Caddy module information.
func (DeleteFilter) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.logging.encoders.filter.delete",
		New: func() caddy.Module { return new(DeleteFilter) },
	}
}

// UnmarshalCaddyfile sets up the module from Caddyfile tokens.
func (DeleteFilter) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	return nil
}

// Filter filters the input field.
func (DeleteFilter) Filter(in zapcore.Field) zapcore.Field {
	in.Type = zapcore.SkipType
	return in
}

// ReplaceFilter is a Caddy log field filter that
// replaces the field with the indicated string.
type ReplaceFilter struct {
	Value string `json:"value,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (ReplaceFilter) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.logging.encoders.filter.replace",
		New: func() caddy.Module { return new(ReplaceFilter) },
	}
}

// UnmarshalCaddyfile sets up the module from Caddyfile tokens.
func (f *ReplaceFilter) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if d.NextArg() {
			f.Value = d.Val()
		}
	}
	return nil
}

// Filter filters the input field with the replacement value.
func (f *ReplaceFilter) Filter(in zapcore.Field) zapcore.Field {
	in.Type = zapcore.StringType
	in.String = f.Value
	return in
}

// IPMaskFilter is a Caddy log field filter that
// masks IP addresses.
type IPMaskFilter struct {
	// The IPv4 mask, as an subnet size CIDR.
	IPv4MaskRaw int `json:"ipv4_cidr,omitempty"`

	// The IPv6 mask, as an subnet size CIDR.
	IPv6MaskRaw int `json:"ipv6_cidr,omitempty"`

	v4Mask net.IPMask
	v6Mask net.IPMask
}

// CaddyModule returns the Caddy module information.
func (IPMaskFilter) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.logging.encoders.filter.ip_mask",
		New: func() caddy.Module { return new(IPMaskFilter) },
	}
}

// UnmarshalCaddyfile sets up the module from Caddyfile tokens.
func (m *IPMaskFilter) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "ipv4":
				if !d.NextArg() {
					return d.ArgErr()
				}
				val, err := strconv.Atoi(d.Val())
				if err != nil {
					return d.Errf("error parsing %s: %v", d.Val(), err)
				}
				m.IPv4MaskRaw = val

			case "ipv6":
				if !d.NextArg() {
					return d.ArgErr()
				}
				val, err := strconv.Atoi(d.Val())
				if err != nil {
					return d.Errf("error parsing %s: %v", d.Val(), err)
				}
				m.IPv6MaskRaw = val

			default:
				return d.Errf("unrecognized subdirective %s", d.Val())
			}
		}
	}
	return nil
}

// Provision parses m's IP masks, from integers.
func (m *IPMaskFilter) Provision(ctx caddy.Context) error {
	parseRawToMask := func(rawField int, bitLen int) net.IPMask {
		if rawField == 0 {
			return nil
		}

		// we assume the int is a subnet size CIDR
		// e.g. "16" being equivalent to masking the last
		// two bytes of an ipv4 address, like "255.255.0.0"
		return net.CIDRMask(rawField, bitLen)
	}

	m.v4Mask = parseRawToMask(m.IPv4MaskRaw, 32)
	m.v6Mask = parseRawToMask(m.IPv6MaskRaw, 128)

	return nil
}

// Filter filters the input field.
func (m IPMaskFilter) Filter(in zapcore.Field) zapcore.Field {
	host, port, err := net.SplitHostPort(in.String)
	if err != nil {
		host = in.String // assume whole thing was IP address
	}
	ipAddr := net.ParseIP(host)
	if ipAddr == nil {
		return in
	}
	mask := m.v4Mask
	if ipAddr.To4() == nil {
		mask = m.v6Mask
	}
	masked := ipAddr.Mask(mask)
	if port == "" {
		in.String = masked.String()
	} else {
		in.String = net.JoinHostPort(masked.String(), port)
	}
	return in
}

// Interface guards
var (
	_ LogFieldFilter = (*DeleteFilter)(nil)
	_ LogFieldFilter = (*ReplaceFilter)(nil)
	_ LogFieldFilter = (*IPMaskFilter)(nil)

	_ caddyfile.Unmarshaler = (*DeleteFilter)(nil)
	_ caddyfile.Unmarshaler = (*ReplaceFilter)(nil)
	_ caddyfile.Unmarshaler = (*IPMaskFilter)(nil)

	_ caddy.Provisioner = (*IPMaskFilter)(nil)
)
