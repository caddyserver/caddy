package httpserver

import (
	"net"
	"strings"
)

// vhostTrie facilitates virtual hosting. It can match
// request paths first by hostname (with support for
// wildcards as TLS certificates support them), then by
// longest matching path.
type vhostTrie struct {
	edges map[string]*vhostTrie
	stack Handler
}

// newVHostTrie returns a new vhostTrie.
func newVHostTrie() *vhostTrie {
	return &vhostTrie{edges: make(map[string]*vhostTrie)}
}

// Insert adds stack to t keyed by key. The key should be
// a valid host/path combination (or just host).
func (t *vhostTrie) Insert(key string, stack Handler) {
	host, path := t.splitHostPath(key)
	if _, ok := t.edges[host]; !ok {
		t.edges[host] = newVHostTrie()
	}
	t.edges[host].insertPath(path, stack)
}

// insertPath expects t to be a host node (not a root node),
// and inserts stack into the t according to remainingPath.
func (t *vhostTrie) insertPath(remainingPath string, stack Handler) {
	if remainingPath == "" {
		t.stack = stack
		return
	}
	ch := string(remainingPath[0])
	if _, ok := t.edges[ch]; !ok {
		t.edges[ch] = newVHostTrie()
	}
	t.edges[ch].insertPath(remainingPath[1:], stack)
}

// Match returns the middleware stack in v with
// the closest match to key.
func (t *vhostTrie) Match(key string) Handler {
	host, path := t.splitHostPath(key)
	// try the given host, then, if no match, try wildcard hosts
	branch := t.matchHost(host)
	if branch == nil {
		branch = t.matchHost("0.0.0.0")
	}
	if branch == nil {
		branch = t.matchHost("")
	}
	if branch == nil {
		return nil
	}
	node := branch.matchPath(path)
	if node == nil {
		return nil
	}
	return node.stack
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
		if next.stack != nil {
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
