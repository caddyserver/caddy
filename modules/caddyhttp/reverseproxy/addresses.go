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

// parseUpstreamDialAddress parses configuration inputs for
// the dial address, including support for a scheme in front
// as a shortcut for the port number, and a network type,
// for example 'unix' to dial a unix socket.
//
// TODO: the logic in this function is kind of sensitive, we
// need to write tests before making any more changes to it
func parseUpstreamDialAddress(upstreamAddr string) (string, string, error) {
	var network, scheme, host, port string

	if strings.Contains(upstreamAddr, "://") {
		// we get a parsing error if a placeholder is specified
		// so we return a more user-friendly error message instead
		// to explain what to do instead
		if strings.Contains(upstreamAddr, "{") {
			return "", "", fmt.Errorf("due to parsing difficulties, placeholders are not allowed when an upstream address contains a scheme")
		}

		toURL, err := url.Parse(upstreamAddr)
		if err != nil {
			return "", "", fmt.Errorf("parsing upstream URL: %v", err)
		}

		// there is currently no way to perform a URL rewrite between choosing
		// a backend and proxying to it, so we cannot allow extra components
		// in backend URLs
		if toURL.Path != "" || toURL.RawQuery != "" || toURL.Fragment != "" {
			return "", "", fmt.Errorf("for now, URLs for proxy upstreams only support scheme, host, and port components")
		}

		// ensure the port and scheme aren't in conflict
		urlPort := toURL.Port()
		if toURL.Scheme == "http" && urlPort == "443" {
			return "", "", fmt.Errorf("upstream address has conflicting scheme (http://) and port (:443, the HTTPS port)")
		}
		if toURL.Scheme == "https" && urlPort == "80" {
			return "", "", fmt.Errorf("upstream address has conflicting scheme (https://) and port (:80, the HTTP port)")
		}
		if toURL.Scheme == "h2c" && urlPort == "443" {
			return "", "", fmt.Errorf("upstream address has conflicting scheme (h2c://) and port (:443, the HTTPS port)")
		}

		// if port is missing, attempt to infer from scheme
		if toURL.Port() == "" {
			var toPort string
			switch toURL.Scheme {
			case "", "http", "h2c":
				toPort = "80"
			case "https":
				toPort = "443"
			}
			toURL.Host = net.JoinHostPort(toURL.Hostname(), toPort)
		}

		scheme, host, port = toURL.Scheme, toURL.Hostname(), toURL.Port()
	} else {
		// extract network manually, since caddy.ParseNetworkAddress() will always add one
		if beforeSlash, afterSlash, slashFound := strings.Cut(upstreamAddr, "/"); slashFound {
			network = strings.ToLower(strings.TrimSpace(beforeSlash))
			upstreamAddr = afterSlash
		}
		var err error
		host, port, err = net.SplitHostPort(upstreamAddr)
		if err != nil {
			host = upstreamAddr
		}
		// we can assume a port if only a hostname is specified, but use of a
		// placeholder without a port likely means a port will be filled in
		if port == "" && !strings.Contains(host, "{") {
			port = "80"
		}
	}

	// special case network to support both unix and h2c at the same time
	if network == "unix+h2c" {
		network = "unix"
		scheme = "h2c"
	}

	// for simplest possible config, we only need to include
	// the network portion if the user specified one
	if network != "" {
		return caddy.JoinNetworkAddress(network, host, port), scheme, nil
	}

	// if the host is a placeholder, then we don't want to join with an empty port,
	// because that would just append an extra ':' at the end of the address.
	if port == "" && strings.Contains(host, "{") {
		return host, scheme, nil
	}

	return net.JoinHostPort(host, port), scheme, nil
}
