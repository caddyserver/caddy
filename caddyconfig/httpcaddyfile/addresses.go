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

package httpcaddyfile

import (
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/caddyserver/certmagic"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// mapAddressToProtocolToServerBlocks returns a map of listener address to list of server
// blocks that will be served on that address. To do this, each server block is
// expanded so that each one is considered individually, although keys of a
// server block that share the same address stay grouped together so the config
// isn't repeated unnecessarily. For example, this Caddyfile:
//
//	example.com {
//		bind 127.0.0.1
//	}
//	www.example.com, example.net/path, localhost:9999 {
//		bind 127.0.0.1 1.2.3.4
//	}
//
// has two server blocks to start with. But expressed in this Caddyfile are
// actually 4 listener addresses: 127.0.0.1:443, 1.2.3.4:443, 127.0.0.1:9999,
// and 127.0.0.1:9999. This is because the bind directive is applied to each
// key of its server block (specifying the host part), and each key may have
// a different port. And we definitely need to be sure that a site which is
// bound to be served on a specific interface is not served on others just
// because that is more convenient: it would be a potential security risk
// if the difference between interfaces means private vs. public.
//
// So what this function does for the example above is iterate each server
// block, and for each server block, iterate its keys. For the first, it
// finds one key (example.com) and determines its listener address
// (127.0.0.1:443 - because of 'bind' and automatic HTTPS). It then adds
// the listener address to the map value returned by this function, with
// the first server block as one of its associations.
//
// It then iterates each key on the second server block and associates them
// with one or more listener addresses. Indeed, each key in this block has
// two listener addresses because of the 'bind' directive. Once we know
// which addresses serve which keys, we can create a new server block for
// each address containing the contents of the server block and only those
// specific keys of the server block which use that address.
//
// It is possible and even likely that some keys in the returned map have
// the exact same list of server blocks (i.e. they are identical). This
// happens when multiple hosts are declared with a 'bind' directive and
// the resulting listener addresses are not shared by any other server
// block (or the other server blocks are exactly identical in their token
// contents). This happens with our example above because 1.2.3.4:443
// and 1.2.3.4:9999 are used exclusively with the second server block. This
// repetition may be undesirable, so call consolidateAddrMappings() to map
// multiple addresses to the same lists of server blocks (a many:many mapping).
// (Doing this is essentially a map-reduce technique.)
func (st *ServerType) mapAddressToProtocolToServerBlocks(originalServerBlocks []serverBlock,
	options map[string]any,
) (map[string]map[string][]serverBlock, error) {
	addrToProtocolToServerBlocks := map[string]map[string][]serverBlock{}

	type keyWithParsedKey struct {
		key       caddyfile.Token
		parsedKey Address
	}

	for i, sblock := range originalServerBlocks {
		// within a server block, we need to map all the listener addresses
		// implied by the server block to the keys of the server block which
		// will be served by them; this has the effect of treating each
		// key of a server block as its own, but without having to repeat its
		// contents in cases where multiple keys really can be served together
		addrToProtocolToKeyWithParsedKeys := map[string]map[string][]keyWithParsedKey{}
		for j, key := range sblock.block.Keys {
			parsedKey, err := ParseAddress(key.Text)
			if err != nil {
				return nil, fmt.Errorf("parsing key: %v", err)
			}
			parsedKey = parsedKey.Normalize()

			// a key can have multiple listener addresses if there are multiple
			// arguments to the 'bind' directive (although they will all have
			// the same port, since the port is defined by the key or is implicit
			// through automatic HTTPS)
			listeners, err := st.listenersForServerBlockAddress(sblock, parsedKey, options)
			if err != nil {
				return nil, fmt.Errorf("server block %d, key %d (%s): determining listener address: %v", i, j, key.Text, err)
			}

			// associate this key with its protocols and each listener address served with them
			kwpk := keyWithParsedKey{key, parsedKey}
			for addr, protocols := range listeners {
				protocolToKeyWithParsedKeys, ok := addrToProtocolToKeyWithParsedKeys[addr]
				if !ok {
					protocolToKeyWithParsedKeys = map[string][]keyWithParsedKey{}
					addrToProtocolToKeyWithParsedKeys[addr] = protocolToKeyWithParsedKeys
				}

				// an empty protocol indicates the default, a nil or empty value in the ListenProtocols array
				if len(protocols) == 0 {
					protocols[""] = struct{}{}
				}
				for prot := range protocols {
					protocolToKeyWithParsedKeys[prot] = append(
						protocolToKeyWithParsedKeys[prot],
						kwpk)
				}
			}
		}

		// make a slice of the map keys so we can iterate in sorted order
		addrs := make([]string, 0, len(addrToProtocolToKeyWithParsedKeys))
		for addr := range addrToProtocolToKeyWithParsedKeys {
			addrs = append(addrs, addr)
		}
		sort.Strings(addrs)

		// now that we know which addresses serve which keys of this
		// server block, we iterate that mapping and create a list of
		// new server blocks for each address where the keys of the
		// server block are only the ones which use the address; but
		// the contents (tokens) are of course the same
		for _, addr := range addrs {
			protocolToKeyWithParsedKeys := addrToProtocolToKeyWithParsedKeys[addr]

			prots := make([]string, 0, len(protocolToKeyWithParsedKeys))
			for prot := range protocolToKeyWithParsedKeys {
				prots = append(prots, prot)
			}
			sort.Strings(prots)

			protocolToServerBlocks, ok := addrToProtocolToServerBlocks[addr]
			if !ok {
				protocolToServerBlocks = map[string][]serverBlock{}
				addrToProtocolToServerBlocks[addr] = protocolToServerBlocks
			}

			for _, prot := range prots {
				keyWithParsedKeys := protocolToKeyWithParsedKeys[prot]

				keys := make([]caddyfile.Token, len(keyWithParsedKeys))
				parsedKeys := make([]Address, len(keyWithParsedKeys))

				for k, keyWithParsedKey := range keyWithParsedKeys {
					keys[k] = keyWithParsedKey.key
					parsedKeys[k] = keyWithParsedKey.parsedKey
				}

				protocolToServerBlocks[prot] = append(protocolToServerBlocks[prot], serverBlock{
					block: caddyfile.ServerBlock{
						Keys:     keys,
						Segments: sblock.block.Segments,
					},
					pile:       sblock.pile,
					parsedKeys: parsedKeys,
				})
			}
		}
	}

	return addrToProtocolToServerBlocks, nil
}

// consolidateAddrMappings eliminates repetition of identical server blocks in a mapping of
// single listener addresses to protocols to lists of server blocks. Since multiple addresses
// may serve multiple protocols to identical sites (server block contents), this function turns
// a 1:many mapping into a many:many mapping. Server block contents (tokens) must be
// exactly identical so that reflect.DeepEqual returns true in order for the addresses to be combined.
// Identical entries are deleted from the addrToServerBlocks map. Essentially, each pairing (each
// association from multiple addresses to multiple server blocks; i.e. each element of
// the returned slice) becomes a server definition in the output JSON.
func (st *ServerType) consolidateAddrMappings(addrToProtocolToServerBlocks map[string]map[string][]serverBlock) []sbAddrAssociation {
	sbaddrs := make([]sbAddrAssociation, 0, len(addrToProtocolToServerBlocks))

	addrs := make([]string, 0, len(addrToProtocolToServerBlocks))
	for addr := range addrToProtocolToServerBlocks {
		addrs = append(addrs, addr)
	}
	sort.Strings(addrs)

	for _, addr := range addrs {
		protocolToServerBlocks := addrToProtocolToServerBlocks[addr]

		prots := make([]string, 0, len(protocolToServerBlocks))
		for prot := range protocolToServerBlocks {
			prots = append(prots, prot)
		}
		sort.Strings(prots)

		for _, prot := range prots {
			serverBlocks := protocolToServerBlocks[prot]

			// now find other addresses that map to identical
			// server blocks and add them to our map of listener
			// addresses and protocols, while removing them from
			// the original map
			listeners := map[string]map[string]struct{}{}

			for otherAddr, otherProtocolToServerBlocks := range addrToProtocolToServerBlocks {
				for otherProt, otherServerBlocks := range otherProtocolToServerBlocks {
					if addr == otherAddr && prot == otherProt || reflect.DeepEqual(serverBlocks, otherServerBlocks) {
						listener, ok := listeners[otherAddr]
						if !ok {
							listener = map[string]struct{}{}
							listeners[otherAddr] = listener
						}
						listener[otherProt] = struct{}{}
						delete(otherProtocolToServerBlocks, otherProt)
					}
				}
			}

			addresses := make([]string, 0, len(listeners))
			for lnAddr := range listeners {
				addresses = append(addresses, lnAddr)
			}
			sort.Strings(addresses)

			addressesWithProtocols := make([]addressWithProtocols, 0, len(listeners))

			for _, lnAddr := range addresses {
				lnProts := listeners[lnAddr]
				prots := make([]string, 0, len(lnProts))
				for prot := range lnProts {
					prots = append(prots, prot)
				}
				sort.Strings(prots)

				addressesWithProtocols = append(addressesWithProtocols, addressWithProtocols{
					address:   lnAddr,
					protocols: prots,
				})
			}

			sbaddrs = append(sbaddrs, sbAddrAssociation{
				addressesWithProtocols: addressesWithProtocols,
				serverBlocks:           serverBlocks,
			})
		}
	}

	return sbaddrs
}

// listenersForServerBlockAddress essentially converts the Caddyfile site addresses to a map from
// Caddy listener addresses and the protocols to serve them with to the parsed address for each server block.
func (st *ServerType) listenersForServerBlockAddress(sblock serverBlock, addr Address,
	options map[string]any,
) (map[string]map[string]struct{}, error) {
	switch addr.Scheme {
	case "wss":
		return nil, fmt.Errorf("the scheme wss:// is only supported in browsers; use https:// instead")
	case "ws":
		return nil, fmt.Errorf("the scheme ws:// is only supported in browsers; use http:// instead")
	case "https", "http", "":
		// Do nothing or handle the valid schemes
	default:
		return nil, fmt.Errorf("unsupported URL scheme %s://", addr.Scheme)
	}

	// figure out the HTTP and HTTPS ports; either
	// use defaults, or override with user config
	httpPort, httpsPort := strconv.Itoa(caddyhttp.DefaultHTTPPort), strconv.Itoa(caddyhttp.DefaultHTTPSPort)
	if hport, ok := options["http_port"]; ok {
		httpPort = strconv.Itoa(hport.(int))
	}
	if hsport, ok := options["https_port"]; ok {
		httpsPort = strconv.Itoa(hsport.(int))
	}

	// default port is the HTTPS port
	lnPort := httpsPort
	if addr.Port != "" {
		// port explicitly defined
		lnPort = addr.Port
	} else if addr.Scheme == "http" {
		// port inferred from scheme
		lnPort = httpPort
	}

	// error if scheme and port combination violate convention
	if (addr.Scheme == "http" && lnPort == httpsPort) || (addr.Scheme == "https" && lnPort == httpPort) {
		return nil, fmt.Errorf("[%s] scheme and port violate convention", addr.String())
	}

	// the bind directive specifies hosts (and potentially network), and the protocols to serve them with, but is optional
	lnCfgVals := make([]addressesWithProtocols, 0, len(sblock.pile["bind"]))
	for _, cfgVal := range sblock.pile["bind"] {
		if val, ok := cfgVal.Value.(addressesWithProtocols); ok {
			lnCfgVals = append(lnCfgVals, val)
		}
	}
	if len(lnCfgVals) == 0 {
		if defaultBindValues, ok := options["default_bind"].([]ConfigValue); ok {
			for _, defaultBindValue := range defaultBindValues {
				lnCfgVals = append(lnCfgVals, defaultBindValue.Value.(addressesWithProtocols))
			}
		} else {
			lnCfgVals = []addressesWithProtocols{{
				addresses: []string{""},
				protocols: nil,
			}}
		}
	}

	// use a map to prevent duplication
	listeners := map[string]map[string]struct{}{}
	for _, lnCfgVal := range lnCfgVals {
		for _, lnAddr := range lnCfgVal.addresses {
			lnNetw, lnHost, _, err := caddy.SplitNetworkAddress(lnAddr)
			if err != nil {
				return nil, fmt.Errorf("splitting listener address: %v", err)
			}
			networkAddr, err := caddy.ParseNetworkAddress(caddy.JoinNetworkAddress(lnNetw, lnHost, lnPort))
			if err != nil {
				return nil, fmt.Errorf("parsing network address: %v", err)
			}
			if _, ok := listeners[addr.String()]; !ok {
				listeners[networkAddr.String()] = map[string]struct{}{}
			}
			for _, protocol := range lnCfgVal.protocols {
				listeners[networkAddr.String()][protocol] = struct{}{}
			}
		}
	}

	return listeners, nil
}

// addressesWithProtocols associates a list of listen addresses
// with a list of protocols to serve them with
type addressesWithProtocols struct {
	addresses []string
	protocols []string
}

// Address represents a site address. It contains
// the original input value, and the component
// parts of an address. The component parts may be
// updated to the correct values as setup proceeds,
// but the original value should never be changed.
//
// The Host field must be in a normalized form.
type Address struct {
	Original, Scheme, Host, Port, Path string
}

// ParseAddress parses an address string into a structured format with separate
// scheme, host, port, and path portions, as well as the original input string.
func ParseAddress(str string) (Address, error) {
	const maxLen = 4096
	if len(str) > maxLen {
		str = str[:maxLen]
	}
	remaining := strings.TrimSpace(str)
	a := Address{Original: remaining}

	// extract scheme
	splitScheme := strings.SplitN(remaining, "://", 2)
	switch len(splitScheme) {
	case 0:
		return a, nil
	case 1:
		remaining = splitScheme[0]
	case 2:
		a.Scheme = splitScheme[0]
		remaining = splitScheme[1]
	}

	// extract host and port
	hostSplit := strings.SplitN(remaining, "/", 2)
	if len(hostSplit) > 0 {
		host, port, err := net.SplitHostPort(hostSplit[0])
		if err != nil {
			host, port, err = net.SplitHostPort(hostSplit[0] + ":")
			if err != nil {
				host = hostSplit[0]
			}
		}
		a.Host = host
		a.Port = port
	}
	if len(hostSplit) == 2 {
		// all that remains is the path
		a.Path = "/" + hostSplit[1]
	}

	// make sure port is valid
	if a.Port != "" {
		if portNum, err := strconv.Atoi(a.Port); err != nil {
			return Address{}, fmt.Errorf("invalid port '%s': %v", a.Port, err)
		} else if portNum < 0 || portNum > 65535 {
			return Address{}, fmt.Errorf("port %d is out of range", portNum)
		}
	}

	return a, nil
}

// String returns a human-readable form of a. It will
// be a cleaned-up and filled-out URL string.
func (a Address) String() string {
	if a.Host == "" && a.Port == "" {
		return ""
	}
	scheme := a.Scheme
	if scheme == "" {
		if a.Port == strconv.Itoa(certmagic.HTTPSPort) {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}
	s := scheme
	if s != "" {
		s += "://"
	}
	if a.Port != "" &&
		((scheme == "https" && a.Port != strconv.Itoa(caddyhttp.DefaultHTTPSPort)) ||
			(scheme == "http" && a.Port != strconv.Itoa(caddyhttp.DefaultHTTPPort))) {
		s += net.JoinHostPort(a.Host, a.Port)
	} else {
		s += a.Host
	}
	if a.Path != "" {
		s += a.Path
	}
	return s
}

// Normalize returns a normalized version of a.
func (a Address) Normalize() Address {
	path := a.Path

	// ensure host is normalized if it's an IP address
	host := strings.TrimSpace(a.Host)
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.Is6() && !ip.Is4() && !ip.Is4In6() {
			host = ip.String()
		}
	}

	return Address{
		Original: a.Original,
		Scheme:   lowerExceptPlaceholders(a.Scheme),
		Host:     lowerExceptPlaceholders(host),
		Port:     a.Port,
		Path:     path,
	}
}

// lowerExceptPlaceholders lowercases s except within
// placeholders (substrings in non-escaped '{ }' spans).
// See https://github.com/caddyserver/caddy/issues/3264
func lowerExceptPlaceholders(s string) string {
	var sb strings.Builder
	var escaped, inPlaceholder bool
	for _, ch := range s {
		if ch == '\\' && !escaped {
			escaped = true
			sb.WriteRune(ch)
			continue
		}
		if ch == '{' && !escaped {
			inPlaceholder = true
		}
		if ch == '}' && inPlaceholder && !escaped {
			inPlaceholder = false
		}
		if inPlaceholder {
			sb.WriteRune(ch)
		} else {
			sb.WriteRune(unicode.ToLower(ch))
		}
		escaped = false
	}
	return sb.String()
}
