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

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap/zapcore"
)

func init() {
	caddy.RegisterModule(DeleteFilter{})
	caddy.RegisterModule(IPMaskFilter{})
}

// LogFieldFilter can filter (or manipulate)
// a field in a log entry. If delete is true,
// out will be ignored and the field will be
// removed from the output.
type LogFieldFilter interface {
	Filter(zapcore.Field) zapcore.Field
}

// DeleteFilter is a Caddy log field filter that
// deletes the field.
type DeleteFilter struct{}

// CaddyModule returns the Caddy module information.
func (DeleteFilter) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		Name: "caddy.logging.encoders.filter.delete",
		New:  func() caddy.Module { return new(DeleteFilter) },
	}
}

// Filter filters the input field.
func (DeleteFilter) Filter(in zapcore.Field) zapcore.Field {
	in.Type = zapcore.SkipType
	return in
}

// IPMaskFilter is a Caddy log field filter that
// masks IP addresses.
type IPMaskFilter struct {
	IPv4CIDR int `json:"ipv4_cidr,omitempty"`
	IPv6CIDR int `json:"ipv6_cidr,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (IPMaskFilter) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		Name: "caddy.logging.encoders.filter.ip_mask",
		New:  func() caddy.Module { return new(IPMaskFilter) },
	}
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
	bitLen := 32
	cidrPrefix := m.IPv4CIDR
	if ipAddr.To16() != nil {
		bitLen = 128
		cidrPrefix = m.IPv6CIDR
	}
	mask := net.CIDRMask(cidrPrefix, bitLen)
	masked := ipAddr.Mask(mask)
	if port == "" {
		in.String = masked.String()
	} else {
		in.String = net.JoinHostPort(masked.String(), port)
	}
	return in
}
