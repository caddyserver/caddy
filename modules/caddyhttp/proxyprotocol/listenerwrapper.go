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
	"net"
	"net/netip"
	"time"

	goproxy "github.com/pires/go-proxyproto"

	"github.com/caddyserver/caddy/v2"
)

// ListenerWrapper provides PROXY protocol support to Caddy by implementing
// the caddy.ListenerWrapper interface. If a connection is received via Unix
// socket, it's trusted. Otherwise, it's checked against the Allow/Deny lists,
// then it's handled by the FallbackPolicy.
//
// It must be loaded before the `tls` listener because the PROXY protocol
// encapsulates the TLS data.
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
	allow []netip.Prefix

	// Deny is an optional list of CIDR ranges to
	// deny PROXY headers from.
	Deny []string `json:"deny,omitempty"`
	deny []netip.Prefix

	// FallbackPolicy specifies the policy to use if the downstream
	// IP address is not in the Allow list nor is in the Deny list.
	//
	// NOTE: The generated docs which describe the value of this
	// field is wrong because of how this type unmarshals JSON in a
	// custom way. The field expects a string, not a number.
	//
	// Accepted values are: IGNORE, USE, REJECT, REQUIRE, SKIP
	//
	// - IGNORE: address from PROXY header, but accept connection
	//
	// - USE: address from PROXY header
	//
	// - REJECT: connection when PROXY header is sent
	//   Note: even though the first read on the connection returns an error if
	//   a PROXY header is present, subsequent reads do not. It is the task of
	//   the code using the connection to handle that case properly.
	//
	// - REQUIRE: connection to send PROXY header, reject if not present
	//   Note: even though the first read on the connection returns an error if
	//   a PROXY header is not present, subsequent reads do not. It is the task
	//   of the code using the connection to handle that case properly.
	//
	// - SKIP: accepts a connection without requiring the PROXY header.
	//   Note: an example usage can be found in the SkipProxyHeaderForCIDR
	//   function.
	//
	// Default: IGNORE
	//
	// Policy definitions are here: https://pkg.go.dev/github.com/pires/go-proxyproto@v0.7.0#Policy
	FallbackPolicy Policy `json:"fallback_policy,omitempty"`

	policy goproxy.ConnPolicyFunc
}

// Provision sets up the listener wrapper.
func (pp *ListenerWrapper) Provision(ctx caddy.Context) error {
	for _, cidr := range pp.Allow {
		ipnet, err := netip.ParsePrefix(cidr)
		if err != nil {
			return err
		}
		pp.allow = append(pp.allow, ipnet)
	}
	for _, cidr := range pp.Deny {
		ipnet, err := netip.ParsePrefix(cidr)
		if err != nil {
			return err
		}
		pp.deny = append(pp.deny, ipnet)
	}

	pp.policy = func(options goproxy.ConnPolicyOptions) (goproxy.Policy, error) {
		// trust unix sockets
		if network := options.Upstream.Network(); caddy.IsUnixNetwork(network) || caddy.IsFdNetwork(network) {
			return goproxy.USE, nil
		}
		ret := pp.FallbackPolicy
		host, _, err := net.SplitHostPort(options.Upstream.String())
		if err != nil {
			return goproxy.REJECT, err
		}

		ip, err := netip.ParseAddr(host)
		if err != nil {
			return goproxy.REJECT, err
		}
		for _, ipnet := range pp.deny {
			if ipnet.Contains(ip) {
				return goproxy.REJECT, nil
			}
		}
		for _, ipnet := range pp.allow {
			if ipnet.Contains(ip) {
				ret = PolicyUSE
				break
			}
		}
		return policyToGoProxyPolicy[ret], nil
	}
	return nil
}

// WrapListener adds PROXY protocol support to the listener.
func (pp *ListenerWrapper) WrapListener(l net.Listener) net.Listener {
	pl := &goproxy.Listener{
		Listener:          l,
		ReadHeaderTimeout: time.Duration(pp.Timeout),
	}
	pl.ConnPolicy = pp.policy
	return pl
}
