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

package proxyprotocol

import (
	"fmt"
	"net"
	"time"

	"github.com/mastercactapus/proxyprotocol"

	"github.com/caddyserver/caddy/v2"
)

// ListenerWrapper provides PROXY protocol support to Caddy by implementing
// the caddy.ListenerWrapper interface. It must be loaded before the `tls` listener.
//
// Credit goes to https://github.com/mastercactapus/caddy2-proxyprotocol for having
// initially implemented this as a plugin.
type ListenerWrapper struct {
	// Timeout specifies an optional maximum time for
	// the PROXY header to be received.
	// If zero, timeout is disabled. Default is 5s.
	Timeout caddy.Duration `json:"timeout,omitempty"`

	// Allow is an optional list of CIDR ranges to
	// allow/require PROXY headers from.
	Allow []string `json:"allow,omitempty"`

	rules []proxyprotocol.Rule
}

// Provision sets up the listener wrapper.
func (pp *ListenerWrapper) Provision(ctx caddy.Context) error {
	rules := make([]proxyprotocol.Rule, 0, len(pp.Allow))
	for _, s := range pp.Allow {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			return fmt.Errorf("invalid subnet '%s': %w", s, err)
		}
		rules = append(rules, proxyprotocol.Rule{
			Timeout: time.Duration(pp.Timeout),
			Subnet:  n,
		})
	}

	pp.rules = rules

	return nil
}

// WrapListener adds PROXY protocol support to the listener.
func (pp *ListenerWrapper) WrapListener(l net.Listener) net.Listener {
	pl := proxyprotocol.NewListener(l, time.Duration(pp.Timeout))
	pl.SetFilter(pp.rules)
	return pl
}
