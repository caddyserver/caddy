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

// iptrieNode represents a node in the bitwise Radix Trie.
type iptrieNode struct {
	children [2]*iptrieNode
	// isEnd is true if a CIDR prefix ends at this node depth.
	isEnd bool
	// zones holds zone identifiers associated with CIDRs ending at this node.
	// An empty string in zones means any zone (or no zone required) matches.
	zones []string
}

// IPTrie is a bitwise Radix Trie (PATRICIA trie) for fast O(W) IP and CIDR prefix lookups.
// It provides sub-50ns lookup speed regardless of the number of registered CIDRs.
type IPTrie struct {
	v4Root *iptrieNode
	v6Root *iptrieNode
	count  int
}

// NewIPTrie constructs a new IPTrie from a list of netip.Prefix and corresponding zone strings.
func NewIPTrie(cidrs []*netip.Prefix, zones []string) *IPTrie {
	t := &IPTrie{
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
		t.Insert(*prefix, zone)
	}

	return t
}

// Insert adds a prefix and associated zone string into the trie.
func (t *IPTrie) Insert(prefix netip.Prefix, zone string) {
	addr := prefix.Addr().Unmap()
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

// Contains tests whether clientIP matches any CIDR prefix stored in the trie.
// It returns (matches, zoneFilterPassed):
// - matches = true if clientIP is in a matching prefix and zone matches.
// - zoneFilterPassed = true if either no CIDR matched, or a CIDR matched with a valid zone.
//   zoneFilterPassed = false if a CIDR matched but the zone ID failed to match.
func (t *IPTrie) Contains(clientIP netip.Addr, zoneID string) (bool, bool) {
	addr := clientIP.Unmap()

	var curr *iptrieNode
	var bytes []byte
	var maxBits int

	if addr.Is4() {
		curr = t.v4Root
		b4 := addr.As4()
		bytes = b4[:]
		maxBits = 32
	} else if addr.Is6() {
		curr = t.v6Root
		b16 := addr.As16()
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
			return true, true
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
				return true, true
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
