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

package reverseproxy

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/caddyserver/caddy/v2"
)

type parsedAddr struct {
	network, scheme, host, port string
	valid                       bool
}

func (p parsedAddr) dialAddr() string {
	if !p.valid {
		return ""
	}
	// for simplest possible config, we only need to include
	// the network portion if the user specified one
	if p.network != "" {
		return caddy.JoinNetworkAddress(p.network, p.host, p.port)
	}

	// if the host is a placeholder, then we don't want to join with an empty port,
	// because that would just append an extra ':' at the end of the address.
	if p.port == "" && strings.Contains(p.host, "{") {
		return p.host
	}
	return net.JoinHostPort(p.host, p.port)
}

func (p parsedAddr) rangedPort() bool {
	return strings.Contains(p.port, "-")
}

func (p parsedAddr) replaceablePort() bool {
	return strings.Contains(p.port, "{") && strings.Contains(p.port, "}")
}

func (p parsedAddr) isUnix() bool {
	return caddy.IsUnixNetwork(p.network)
}

// parseUpstreamDialAddress parses configuration inputs for
// the dial address, including support for a scheme in front
// as a shortcut for the port number, and a network type,
// for example 'unix' to dial a unix socket.
func parseUpstreamDialAddress(upstreamAddr string) (parsedAddr, error) {
	var network, scheme, host, port string

	if strings.Contains(upstreamAddr, "://") {
		// we get a parsing error if a placeholder is specified
		// so we return a more user-friendly error message instead
		// to explain what to do instead
		if strings.Contains(upstreamAddr, "{") {
			return parsedAddr{}, fmt.Errorf("due to parsing difficulties, placeholders are not allowed when an upstream address contains a scheme")
		}

		toURL, err := url.Parse(upstreamAddr)
		if err != nil {
			// if the error seems to be due to a port range,
			// try to replace the port range with a dummy
			// single port so that url.Parse() will succeed
			if strings.Contains(err.Error(), "invalid port") && strings.Contains(err.Error(), "-") {
				index := strings.LastIndex(upstreamAddr, ":")
				if index == -1 {
					return parsedAddr{}, fmt.Errorf("parsing upstream URL: %v", err)
				}
				portRange := upstreamAddr[index+1:]
				if strings.Count(portRange, "-") != 1 {
					return parsedAddr{}, fmt.Errorf("parsing upstream URL: parse \"%v\": port range invalid: %v", upstreamAddr, portRange)
				}
				toURL, err = url.Parse(strings.ReplaceAll(upstreamAddr, portRange, "0"))
				if err != nil {
					return parsedAddr{}, fmt.Errorf("parsing upstream URL: %v", err)
				}
				port = portRange
			} else {
				return parsedAddr{}, fmt.Errorf("parsing upstream URL: %v", err)
			}
		}
		if port == "" {
			port = toURL.Port()
		}

		// there is currently no way to perform a URL rewrite between choosing
		// a backend and proxying to it, so we cannot allow extra components
		// in backend URLs
		if toURL.Path != "" || toURL.RawQuery != "" || toURL.Fragment != "" {
			return parsedAddr{}, fmt.Errorf("for now, URLs for proxy upstreams only support scheme, host, and port components")
		}

		// ensure the port and scheme aren't in conflict
		if toURL.Scheme == "http" && port == "443" {
			return parsedAddr{}, fmt.Errorf("upstream address has conflicting scheme (http://) and port (:443, the HTTPS port)")
		}
		if toURL.Scheme == "https" && port == "80" {
			return parsedAddr{}, fmt.Errorf("upstream address has conflicting scheme (https://) and port (:80, the HTTP port)")
		}
		if toURL.Scheme == "h2c" && port == "443" {
			return parsedAddr{}, fmt.Errorf("upstream address has conflicting scheme (h2c://) and port (:443, the HTTPS port)")
		}

		// if port is missing, attempt to infer from scheme
		if port == "" {
			switch toURL.Scheme {
			case "", "http", "h2c":
				port = "80"
			case "https":
				port = "443"
			}
		}

		scheme, host = toURL.Scheme, toURL.Hostname()
	} else {
		var err error
		network, host, port, err = caddy.SplitNetworkAddress(upstreamAddr)
		if err != nil {
			host = upstreamAddr
		}
		// we can assume a port if only a hostname is specified, but use of a
		// placeholder without a port likely means a port will be filled in
		if port == "" && !strings.Contains(host, "{") && !caddy.IsUnixNetwork(network) && !caddy.IsFdNetwork(network) {
			port = "80"
		}
	}

	// special case network to support both unix and h2c at the same time
	if network == "unix+h2c" {
		network = "unix"
		scheme = "h2c"
	}
	return parsedAddr{network, scheme, host, port, true}, nil
}
