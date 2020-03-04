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
	"reflect"
	"strconv"
	"strings"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/mholt/certmagic"
)

// mapAddressToServerBlocks returns a map of listener address to list of server
// blocks that will be served on that address. To do this, each server block is
// expanded so that each one is considered individually, although keys of a
// server block that share the same address stay grouped together so the config
// isn't repeated unnecessarily. For example, this Caddyfile:
//
// 	example.com {
// 		bind 127.0.0.1
// 	}
// 	www.example.com, example.net/path, localhost:9999 {
// 		bind 127.0.0.1 1.2.3.4
// 	}
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
func (st *ServerType) mapAddressToServerBlocks(originalServerBlocks []serverBlock,
	options map[string]interface{}) (map[string][]serverBlock, error) {
	sbmap := make(map[string][]serverBlock)

	for i, sblock := range originalServerBlocks {
		// within a server block, we need to map all the listener addresses
		// implied by the server block to the keys of the server block which
		// will be served by them; this has the effect of treating each
		// key of a server block as its own, but without having to repeat its
		// contents in cases where multiple keys really can be served together
		addrToKeys := make(map[string][]string)
		for j, key := range sblock.block.Keys {
			// a key can have multiple listener addresses if there are multiple
			// arguments to the 'bind' directive (although they will all have
			// the same port, since the port is defined by the key or is implicit
			// through automatic HTTPS)
			addrs, err := st.listenerAddrsForServerBlockKey(sblock, key, options)
			if err != nil {
				return nil, fmt.Errorf("server block %d, key %d (%s): determining listener address: %v", i, j, key, err)
			}

			// associate this key with each listener address it is served on
			for _, addr := range addrs {
				addrToKeys[addr] = append(addrToKeys[addr], key)
			}
		}

		// now that we know which addresses serve which keys of this
		// server block, we iterate that mapping and create a list of
		// new server blocks for each address where the keys of the
		// server block are only the ones which use the address; but
		// the contents (tokens) are of course the same
		for addr, keys := range addrToKeys {
			sbmap[addr] = append(sbmap[addr], serverBlock{
				block: caddyfile.ServerBlock{
					Keys:     keys,
					Segments: sblock.block.Segments,
				},
				pile: sblock.pile,
			})
		}
	}

	return sbmap, nil
}

// consolidateAddrMappings eliminates repetition of identical server blocks in a mapping of
// single listener addresses to lists of server blocks. Since multiple addresses may serve
// identical sites (server block contents), this function turns a 1:many mapping into a
// many:many mapping. Server block contents (tokens) must be exactly identical so that
// reflect.DeepEqual returns true in order for the addresses to be combined. Identical
// entries are deleted from the addrToServerBlocks map. Essentially, each pairing (each
// association from multiple addresses to multiple server blocks; i.e. each element of
// the returned slice) becomes a server definition in the output JSON.
func (st *ServerType) consolidateAddrMappings(addrToServerBlocks map[string][]serverBlock) []sbAddrAssociation {
	var sbaddrs []sbAddrAssociation
	for addr, sblocks := range addrToServerBlocks {
		// we start with knowing that at least this address
		// maps to these server blocks
		a := sbAddrAssociation{
			addresses:    []string{addr},
			serverBlocks: sblocks,
		}

		// now find other addresses that map to identical
		// server blocks and add them to our list of
		// addresses, while removing them from the map
		for otherAddr, otherSblocks := range addrToServerBlocks {
			if addr == otherAddr {
				continue
			}
			if reflect.DeepEqual(sblocks, otherSblocks) {
				a.addresses = append(a.addresses, otherAddr)
				delete(addrToServerBlocks, otherAddr)
			}
		}

		sbaddrs = append(sbaddrs, a)
	}
	return sbaddrs
}

func (st *ServerType) listenerAddrsForServerBlockKey(sblock serverBlock, key string,
	options map[string]interface{}) ([]string, error) {
	addr, err := ParseAddress(key)
	if err != nil {
		return nil, fmt.Errorf("parsing key: %v", err)
	}
	addr = addr.Normalize()

	// figure out the HTTP and HTTPS ports; either
	// use defaults, or override with user config
	httpPort, httpsPort := strconv.Itoa(certmagic.HTTPPort), strconv.Itoa(certmagic.HTTPSPort)
	if hport, ok := options["http_port"]; ok {
		httpPort = strconv.Itoa(hport.(int))
	}
	if hsport, ok := options["https_port"]; ok {
		httpsPort = strconv.Itoa(hsport.(int))
	}

	lnPort := DefaultPort
	if addr.Port != "" {
		// port explicitly defined
		lnPort = addr.Port
	} else if addr.Scheme != "" {
		// port inferred from scheme
		if addr.Scheme == "http" {
			lnPort = httpPort
		} else if addr.Scheme == "https" {
			lnPort = httpsPort
		}
	} else if certmagic.HostQualifies(addr.Host) {
		// automatic HTTPS
		lnPort = httpsPort
	}

	// error if scheme and port combination violate convention
	if (addr.Scheme == "http" && lnPort == httpsPort) || (addr.Scheme == "https" && lnPort == httpPort) {
		return nil, fmt.Errorf("[%s] scheme and port violate convention", key)
	}

	// the bind directive specifies hosts, but is optional
	var lnHosts []string
	for _, cfgVal := range sblock.pile["bind"] {
		lnHosts = append(lnHosts, cfgVal.Value.([]string)...)
	}
	if len(lnHosts) == 0 {
		lnHosts = []string{""}
	}

	// use a map to prevent duplication
	listeners := make(map[string]struct{})
	for _, host := range lnHosts {
		listeners[net.JoinHostPort(host, lnPort)] = struct{}{}
	}

	// now turn map into list
	var listenersList []string
	for lnStr := range listeners {
		listenersList = append(listenersList, lnStr)
	}
	// sort.Strings(listenersList) // TODO: is sorting necessary?

	return listenersList, nil
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

// TODO: which of the methods on Address are even used?

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
	if !caseSensitivePath {
		path = strings.ToLower(path)
	}

	// ensure host is normalized if it's an IP address
	host := a.Host
	if ip := net.ParseIP(host); ip != nil {
		host = ip.String()
	}

	return Address{
		Original: a.Original,
		Scheme:   strings.ToLower(a.Scheme),
		Host:     strings.ToLower(host),
		Port:     a.Port,
		Path:     path,
	}
}

// Key returns a string form of a, much like String() does, but this
// method doesn't add anything default that wasn't in the original.
func (a Address) Key() string {
	res := ""
	if a.Scheme != "" {
		res += a.Scheme + "://"
	}
	if a.Host != "" {
		res += a.Host
	}
	// insert port only if the original has its own explicit port
	if a.Port != "" &&
		len(a.Original) >= len(res) &&
		strings.HasPrefix(a.Original[len(res):], ":"+a.Port) {
		res += ":" + a.Port
	}
	if a.Path != "" {
		res += a.Path
	}
	return res
}

const (
	// DefaultPort is the default port to use.
	DefaultPort = "2015"

	caseSensitivePath = false // TODO: Used?
)
