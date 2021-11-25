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
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"go.uber.org/zap/zapcore"
)

func init() {
	caddy.RegisterModule(DeleteFilter{})
	caddy.RegisterModule(ReplaceFilter{})
	caddy.RegisterModule(IPMaskFilter{})
	caddy.RegisterModule(QueryFilter{})
	caddy.RegisterModule(CookieFilter{})
	caddy.RegisterModule(RegexpFilter{})
	caddy.RegisterModule(HashFilter{})
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

// hash returns the first 4 bytes of the SHA-256 hash of the given data as hexadecimal
func hash(s string) string {
	return fmt.Sprintf("%.4x", sha256.Sum256([]byte(s)))
}

// HashFilter is a Caddy log field filter that
// replaces the field with the initial 4 bytes of the SHA-256 hash of the content.
type HashFilter struct {
}

// CaddyModule returns the Caddy module information.
func (HashFilter) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.logging.encoders.filter.hash",
		New: func() caddy.Module { return new(HashFilter) },
	}
}

// UnmarshalCaddyfile sets up the module from Caddyfile tokens.
func (f *HashFilter) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	return nil
}

// Filter filters the input field with the replacement value.
func (f *HashFilter) Filter(in zapcore.Field) zapcore.Field {
	in.String = hash(in.String)
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

type filterAction string

const (
	// Replace value(s).
	replaceAction filterAction = "replace"

	// Hash value(s).
	hashAction filterAction = "hash"

	// Delete.
	deleteAction filterAction = "delete"
)

func (a filterAction) IsValid() error {
	switch a {
	case replaceAction, deleteAction, hashAction:
		return nil
	}

	return errors.New("invalid action type")
}

type queryFilterAction struct {
	// `replace` to replace the value(s) associated with the parameter(s), `hash` to replace them with the 4 initial bytes of the SHA-256 of their content or `delete` to remove them entirely.
	Type filterAction `json:"type"`

	// The name of the query parameter.
	Parameter string `json:"parameter"`

	// The value to use as replacement if the action is `replace`.
	Value string `json:"value,omitempty"`
}

// QueryFilter is a Caddy log field filter that filters
// query parameters from a URL.
//
// This filter updates the logged URL string to remove, replace or hash
// query parameters containing sensitive data. For instance, it can be
// used to redact any kind of secrets which were passed as query parameters,
// such as OAuth access tokens, session IDs, magic link tokens, etc.
type QueryFilter struct {
	// A list of actions to apply to the query parameters of the URL.
	Actions []queryFilterAction `json:"actions"`
}

// Validate checks that action types are correct.
func (f *QueryFilter) Validate() error {
	for _, a := range f.Actions {
		if err := a.Type.IsValid(); err != nil {
			return err
		}
	}

	return nil
}

// CaddyModule returns the Caddy module information.
func (QueryFilter) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.logging.encoders.filter.query",
		New: func() caddy.Module { return new(QueryFilter) },
	}
}

// UnmarshalCaddyfile sets up the module from Caddyfile tokens.
func (m *QueryFilter) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			qfa := queryFilterAction{}
			switch d.Val() {
			case "replace":
				if !d.NextArg() {
					return d.ArgErr()
				}

				qfa.Type = replaceAction
				qfa.Parameter = d.Val()

				if !d.NextArg() {
					return d.ArgErr()
				}
				qfa.Value = d.Val()

			case "hash":
				if !d.NextArg() {
					return d.ArgErr()
				}

				qfa.Type = hashAction
				qfa.Parameter = d.Val()

			case "delete":
				if !d.NextArg() {
					return d.ArgErr()
				}

				qfa.Type = deleteAction
				qfa.Parameter = d.Val()

			default:
				return d.Errf("unrecognized subdirective %s", d.Val())
			}

			m.Actions = append(m.Actions, qfa)
		}
	}
	return nil
}

// Filter filters the input field.
func (m QueryFilter) Filter(in zapcore.Field) zapcore.Field {
	u, err := url.Parse(in.String)
	if err != nil {
		return in
	}

	q := u.Query()
	for _, a := range m.Actions {
		switch a.Type {
		case replaceAction:
			for i := range q[a.Parameter] {
				q[a.Parameter][i] = a.Value
			}

		case hashAction:
			for i := range q[a.Parameter] {
				q[a.Parameter][i] = hash(a.Value)
			}

		case deleteAction:
			q.Del(a.Parameter)
		}
	}

	u.RawQuery = q.Encode()
	in.String = u.String()

	return in
}

type cookieFilterAction struct {
	// `replace` to replace the value of the cookie, `hash` to replace it with the 4 initial bytes of the SHA-156 of its content or `delete` to remove it entirely.
	Type filterAction `json:"type"`

	// The name of the cookie.
	Name string `json:"name"`

	// The value to use as replacement if the action is `replace`.
	Value string `json:"value,omitempty"`
}

// CookieFilter is a Caddy log field filter that filters
// cookies.
//
// This filter updates the logged HTTP header string
// to remove, replace or hash cookies containing sensitive data. For instance,
// it can be used to redact any kind of secrets, such as session IDs.
//
// If several actions are configured for the same cookie name, only the first
// will be applied.
type CookieFilter struct {
	// A list of actions to apply to the cookies.
	Actions []cookieFilterAction `json:"actions"`
}

// Validate checks that action types are correct.
func (f *CookieFilter) Validate() error {
	for _, a := range f.Actions {
		if err := a.Type.IsValid(); err != nil {
			return err
		}
	}

	return nil
}

// CaddyModule returns the Caddy module information.
func (CookieFilter) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.logging.encoders.filter.cookie",
		New: func() caddy.Module { return new(CookieFilter) },
	}
}

// UnmarshalCaddyfile sets up the module from Caddyfile tokens.
func (m *CookieFilter) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			cfa := cookieFilterAction{}
			switch d.Val() {
			case "replace":
				if !d.NextArg() {
					return d.ArgErr()
				}

				cfa.Type = replaceAction
				cfa.Name = d.Val()

				if !d.NextArg() {
					return d.ArgErr()
				}
				cfa.Value = d.Val()

			case "hash":
				if !d.NextArg() {
					return d.ArgErr()
				}

				cfa.Type = hashAction
				cfa.Name = d.Val()

			case "delete":
				if !d.NextArg() {
					return d.ArgErr()
				}

				cfa.Type = deleteAction
				cfa.Name = d.Val()

			default:
				return d.Errf("unrecognized subdirective %s", d.Val())
			}

			m.Actions = append(m.Actions, cfa)
		}
	}
	return nil
}

// Filter filters the input field.
func (m CookieFilter) Filter(in zapcore.Field) zapcore.Field {
	originRequest := http.Request{Header: http.Header{"Cookie": []string{in.String}}}
	cookies := originRequest.Cookies()
	transformedRequest := http.Request{Header: make(http.Header)}

OUTER:
	for _, c := range cookies {
		for _, a := range m.Actions {
			if c.Name != a.Name {
				continue
			}

			switch a.Type {
			case replaceAction:
				c.Value = a.Value
				transformedRequest.AddCookie(c)
				continue OUTER

			case hashAction:
				c.Value = hash(c.Value)
				transformedRequest.AddCookie(c)
				continue OUTER

			case deleteAction:
				continue OUTER
			}
		}

		transformedRequest.AddCookie(c)
	}

	in.String = transformedRequest.Header.Get("Cookie")

	return in
}

// RegexpFilter is a Caddy log field filter that
// replaces the field matching the provided regexp with the indicated string.
type RegexpFilter struct {
	// The regular expression pattern defining what to replace.
	RawRegexp string `json:"regexp,omitempty"`

	// The value to use as replacement
	Value string `json:"value,omitempty"`

	regexp *regexp.Regexp
}

// CaddyModule returns the Caddy module information.
func (RegexpFilter) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.logging.encoders.filter.regexp",
		New: func() caddy.Module { return new(RegexpFilter) },
	}
}

// UnmarshalCaddyfile sets up the module from Caddyfile tokens.
func (f *RegexpFilter) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if d.NextArg() {
			f.RawRegexp = d.Val()
		}
		if d.NextArg() {
			f.Value = d.Val()
		}
	}
	return nil
}

// Provision compiles m's regexp.
func (m *RegexpFilter) Provision(ctx caddy.Context) error {
	r, err := regexp.Compile(m.RawRegexp)
	if err != nil {
		return err
	}

	m.regexp = r

	return nil
}

// Filter filters the input field with the replacement value if it matches the regexp.
func (f *RegexpFilter) Filter(in zapcore.Field) zapcore.Field {
	in.String = f.regexp.ReplaceAllString(in.String, f.Value)

	return in
}

// Interface guards
var (
	_ LogFieldFilter = (*DeleteFilter)(nil)
	_ LogFieldFilter = (*ReplaceFilter)(nil)
	_ LogFieldFilter = (*IPMaskFilter)(nil)
	_ LogFieldFilter = (*QueryFilter)(nil)
	_ LogFieldFilter = (*CookieFilter)(nil)
	_ LogFieldFilter = (*RegexpFilter)(nil)

	_ caddyfile.Unmarshaler = (*DeleteFilter)(nil)
	_ caddyfile.Unmarshaler = (*ReplaceFilter)(nil)
	_ caddyfile.Unmarshaler = (*IPMaskFilter)(nil)
	_ caddyfile.Unmarshaler = (*QueryFilter)(nil)
	_ caddyfile.Unmarshaler = (*CookieFilter)(nil)
	_ caddyfile.Unmarshaler = (*RegexpFilter)(nil)

	_ caddy.Provisioner = (*IPMaskFilter)(nil)
	_ caddy.Provisioner = (*RegexpFilter)(nil)

	_ caddy.Validator = (*QueryFilter)(nil)
)
