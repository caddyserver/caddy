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
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"unicode/utf8"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"go.uber.org/zap/zapcore"
)

func init() {
	caddy.RegisterModule(DeleteFilter{})
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

// IPMaskFilter is a Caddy log field filter that
// masks IP addresses.
type IPMaskFilter struct {
	// The IPv4 mask, as an subnet size CIDR, or a IP + CIDR string.
	IPv4MaskRaw json.RawMessage `json:"ipv4_cidr,omitempty"`

	// The IPv6 mask, as an subnet size CIDR, or a IP + CIDR string.
	IPv6MaskRaw json.RawMessage `json:"ipv6_cidr,omitempty"`

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
				if _, err := strconv.Atoi(d.Val()); err == nil {
					m.IPv4MaskRaw = json.RawMessage(d.Val())
				} else {
					m.IPv4MaskRaw = json.RawMessage(`"` + d.Val() + `"`)
				}

			case "ipv6":
				if !d.NextArg() {
					return d.ArgErr()
				}
				if _, err := strconv.Atoi(d.Val()); err == nil {
					m.IPv6MaskRaw = json.RawMessage(d.Val())
				} else {
					m.IPv6MaskRaw = json.RawMessage(`"` + d.Val() + `"`)
				}

			default:
				return d.Errf("unrecognized subdirective %s", d.Val())
			}
		}
	}
	return nil
}

// Provision parses m's IP masks, from either integers or strings.
func (m *IPMaskFilter) Provision(ctx caddy.Context) error {
	parseRawToMask := func(rawField json.RawMessage, bitLen int) (net.IPMask, error) {
		if rawField == nil {
			return nil, nil
		}

		// integers or strings are both expected to be valid utf8
		if !utf8.Valid(rawField) {
			return nil, fmt.Errorf("not valid UTF8")
		}

		// try to convert to an int if possible, else it's a string
		i, err := strconv.Atoi(string(rawField))
		if err == nil {
			// we assume the int is a subnet size CIDR
			// e.g. "16" being equivalent to masking the last
			// two bytes of an ipv4 address, like "255.255.0.0"
			return net.CIDRMask(i, bitLen), nil
		}

		// we try to parse the string as an IP CIDR,
		// i.e. something like "192.168.0.0/16", we just
		// care about the "16" as the mask and drop the rest
		var s string
		if err := json.Unmarshal(rawField, &s); err != nil {
			return nil, err
		}
		_, ipNet, err := net.ParseCIDR(s)
		if err != nil {
			return nil, err
		}
		return ipNet.Mask, nil
	}

	v4Mask, err := parseRawToMask(m.IPv4MaskRaw, 32)
	if err != nil {
		return fmt.Errorf("parsing ipv4_cidr failed: %v", err)
	}
	m.v4Mask = v4Mask

	v6Mask, err := parseRawToMask(m.IPv6MaskRaw, 128)
	if err != nil {
		return fmt.Errorf("parsing ipv6_cidr failed: %v", err)
	}
	m.v6Mask = v6Mask

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
	if ipAddr.To16() != nil {
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
	_ LogFieldFilter = (*IPMaskFilter)(nil)

	_ caddyfile.Unmarshaler = (*DeleteFilter)(nil)
	_ caddyfile.Unmarshaler = (*IPMaskFilter)(nil)
)
