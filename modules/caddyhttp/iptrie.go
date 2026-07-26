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

package caddyhttp

import (
	"net/netip"
)

// iptrieNode represents a node in the bitwise binary prefix trie.
type iptrieNode struct {
	children [2]*iptrieNode
	// isEnd is true if a CIDR prefix ends at this node depth.
	isEnd bool
	// zones holds zone identifiers associated with CIDRs ending at this node.
	// An empty string in zones means any zone (or no zone required) matches.
	zones []string
}

// ipTrie is an internal bitwise binary prefix trie for fast O(W) IP and CIDR prefix lookups.
type ipTrie struct {
	v4Root *iptrieNode
	v6Root *iptrieNode
	count  int
}

// newIPTrie constructs a new ipTrie from a list of netip.Prefix and corresponding zone strings.
func newIPTrie(cidrs []*netip.Prefix, zones []string) *ipTrie {
	t := &ipTrie{
		v4Root: &iptrieNode{},
		v6Root: &iptrieNode{},
		count:  len(cidrs),
	}

	for i, prefix := range cidrs {
		if prefix == nil {
			continue
		}
		zone := ""
		if i < len(zones) {
			zone = zones[i]
		}
		t.insert(*prefix, zone)
	}

	return t
}

// insert adds a prefix and associated zone string into the trie.
func (t *ipTrie) insert(prefix netip.Prefix, zone string) {
	addr := prefix.Addr()
	bits := prefix.Bits()

	var root *iptrieNode
	var bytes []byte

	if addr.Is4() {
		root = t.v4Root
		b4 := addr.As4()
		bytes = b4[:]
	} else if addr.Is6() {
		root = t.v6Root
		b16 := addr.As16()
		bytes = b16[:]
	} else {
		return
	}

	if bits < 0 {
		bits = len(bytes) * 8
	}
	if bits > len(bytes)*8 {
		bits = len(bytes) * 8
	}

	curr := root
	for bitIdx := 0; bitIdx < bits; bitIdx++ {
		byteIdx := bitIdx / 8
		bitOffset := 7 - (bitIdx % 8)
		bitVal := (bytes[byteIdx] >> bitOffset) & 1

		if curr.children[bitVal] == nil {
			curr.children[bitVal] = &iptrieNode{}
		}
		curr = curr.children[bitVal]
	}

	curr.isEnd = true
	// Check if zone already exists to avoid duplicate entries
	for _, z := range curr.zones {
		if z == zone {
			return
		}
	}
	curr.zones = append(curr.zones, zone)
}

// contains tests whether clientIP matches any CIDR prefix stored in the trie.
// It returns (matches, zoneFilterPassed) matching the exact return tuple contract of matchIPByCidrZones.
func (t *ipTrie) contains(clientIP netip.Addr, zoneID string) (bool, bool) {
	var curr *iptrieNode
	var bytes []byte
	var maxBits int

	if clientIP.Is4() {
		curr = t.v4Root
		b4 := clientIP.As4()
		bytes = b4[:]
		maxBits = 32
	} else if clientIP.Is6() {
		curr = t.v6Root
		b16 := clientIP.As16()
		bytes = b16[:]
		maxBits = 128
	} else {
		return false, true
	}

	foundZoneMismatch := false

	// Check root node first (in case 0.0.0.0/0 or ::/0 was inserted)
	if curr.isEnd {
		m, zm := checkZoneMatch(curr.zones, zoneID)
		if m {
			return true, false
		}
		if zm {
			foundZoneMismatch = true
		}
	}

	for bitIdx := 0; bitIdx < maxBits; bitIdx++ {
		byteIdx := bitIdx / 8
		bitOffset := 7 - (bitIdx % 8)
		bitVal := (bytes[byteIdx] >> bitOffset) & 1

		curr = curr.children[bitVal]
		if curr == nil {
			break
		}

		if curr.isEnd {
			m, zm := checkZoneMatch(curr.zones, zoneID)
			if m {
				return true, false
			}
			if zm {
				foundZoneMismatch = true
			}
		}
	}

	if foundZoneMismatch {
		return false, false
	}
	return false, true
}

func checkZoneMatch(nodeZones []string, requestZoneID string) (bool, bool) {
	hasMismatch := false
	for _, z := range nodeZones {
		if z == "" || z == requestZoneID {
			return true, false
		}
		hasMismatch = true
	}
	return false, hasMismatch
}
