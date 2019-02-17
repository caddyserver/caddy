// Copyright 2015 Light Code Labs, LLC
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

package httpserver

import (
	"net"
	"strings"
)

// vhostTrie facilitates virtual hosting. It matches
// requests first by hostname (with support for
// wildcards as TLS certificates support them), then
// by longest matching path.
type vhostTrie struct {
	fallbackHosts []string
	edges         map[string]*vhostTrie
	site          *SiteConfig // site to match on this node; also known as a virtual host
	path          string      // the path portion of the key for the associated site
}

// newVHostTrie returns a new vhostTrie.
func newVHostTrie() *vhostTrie {
	// TODO: fallbackHosts doesn't discriminate between network interfaces;
	// i.e. if there is a host "0.0.0.0", it could match a request coming
	// in to "[::1]" (and vice-versa) even though the IP versions differ.
	// This might be OK, or maybe it's not desirable. The 'bind' directive
	// can be used to restrict what interface a listener binds to.
	return &vhostTrie{edges: make(map[string]*vhostTrie), fallbackHosts: []string{"0.0.0.0", "[::]", ""}}
}

// Insert adds stack to t keyed by key. The key should be
// a valid "host/path" combination (or just host).
func (t *vhostTrie) Insert(key string, site *SiteConfig) {
	host, path := t.splitHostPath(key)
	if _, ok := t.edges[host]; !ok {
		t.edges[host] = newVHostTrie()
	}
	t.edges[host].insertPath(path, path, site)
}

// insertPath expects t to be a host node (not a root node),
// and inserts site into the t according to remainingPath.
func (t *vhostTrie) insertPath(remainingPath, originalPath string, site *SiteConfig) {
	if remainingPath == "" {
		t.site = site
		t.path = originalPath
		return
	}
	ch := string(remainingPath[0])
	if _, ok := t.edges[ch]; !ok {
		t.edges[ch] = newVHostTrie()
	}
	t.edges[ch].insertPath(remainingPath[1:], originalPath, site)
}

// Match returns the virtual host (site) in v with
// the closest match to key. If there was a match,
// it returns the SiteConfig and the path portion of
// the key used to make the match. The matched path
// would be a prefix of the path portion of the
// key, if not the whole path portion of the key.
// If there is no match, nil and empty string will
// be returned.
//
// A typical key will be in the form "host" or "host/path".
func (t *vhostTrie) Match(key string) (*SiteConfig, string) {
	host, path := t.splitHostPath(key)
	// try the given host, then, if no match, try fallback hosts
	branch := t.matchHost(host)
	for _, h := range t.fallbackHosts {
		if branch != nil {
			break
		}
		branch = t.matchHost(h)
	}
	if branch == nil {
		return nil, ""
	}
	node := branch.matchPath(path)
	if node == nil {
		return nil, ""
	}
	return node.site, node.path
}

// matchHost returns the vhostTrie matching host. The matching
// algorithm is the same as used to match certificates to host
// with SNI during TLS handshakes. In other words, it supports,
// to some degree, the use of wildcard (*) characters.
func (t *vhostTrie) matchHost(host string) *vhostTrie {
	// try exact match
	if subtree, ok := t.edges[host]; ok {
		return subtree
	}

	// then try replacing labels in the host
	// with wildcards until we get a match
	labels := strings.Split(host, ".")
	for i := range labels {
		labels[i] = "*"
		candidate := strings.Join(labels, ".")
		if subtree, ok := t.edges[candidate]; ok {
			return subtree
		}
	}

	return nil
}

// matchPath traverses t until it finds the longest key matching
// remainingPath, and returns its node.
func (t *vhostTrie) matchPath(remainingPath string) *vhostTrie {
	var longestMatch *vhostTrie
	for len(remainingPath) > 0 {
		ch := string(remainingPath[0])
		next, ok := t.edges[ch]
		if !ok {
			break
		}
		if next.site != nil {
			longestMatch = next
		}
		t = next
		remainingPath = remainingPath[1:]
	}
	return longestMatch
}

// splitHostPath separates host from path in key.
func (t *vhostTrie) splitHostPath(key string) (host, path string) {
	parts := strings.SplitN(key, "/", 2)
	host, path = strings.ToLower(parts[0]), "/"
	if len(parts) > 1 {
		path += parts[1]
	}
	// strip out the port (if present) from the host, since
	// each port has its own socket, and each socket has its
	// own listener, and each listener has its own server
	// instance, and each server instance has its own vhosts.
	// removing the port is a simple way to standardize so
	// when requests come in, we can be sure to get a match.
	hostname, _, err := net.SplitHostPort(host)
	if err == nil {
		host = hostname
	}
	return
}

// String returns a list of all the entries in t; assumes that
// t is a root node.
func (t *vhostTrie) String() string {
	var s string
	for host, edge := range t.edges {
		s += edge.str(host)
	}
	return s
}

func (t *vhostTrie) str(prefix string) string {
	var s string
	for key, edge := range t.edges {
		if edge.site != nil {
			s += prefix + key + "\n"
		}
		s += edge.str(prefix + key)
	}
	return s
}
