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
	"fmt"
	"net/netip"
	"testing"
)

func TestIPTrie(t *testing.T) {
	tests := []struct {
		name          string
		cidrs         []string
		zones         []string
		queryIP       string
		queryZone     string
		wantMatch     bool
		wantZonePass  bool
	}{
		{
			name:         "IPv4 exact match",
			cidrs:        []string{"192.168.1.1/32"},
			zones:        []string{""},
			queryIP:      "192.168.1.1",
			wantMatch:    true,
			wantZonePass: true,
		},
		{
			name:         "IPv4 subnet match",
			cidrs:        []string{"10.0.0.0/16"},
			zones:        []string{""},
			queryIP:      "10.0.4.20",
			wantMatch:    true,
			wantZonePass: true,
		},
		{
			name:         "IPv4 no match",
			cidrs:        []string{"10.0.0.0/16"},
			zones:        []string{""},
			queryIP:      "10.1.0.1",
			wantMatch:    false,
			wantZonePass: true,
		},
		{
			name:         "IPv6 subnet match",
			cidrs:        []string{"2001:db8::/32"},
			zones:        []string{""},
			queryIP:      "2001:db8:1234:5678::1",
			wantMatch:    true,
			wantZonePass: true,
		},
		{
			name:         "IPv4-mapped IPv6 match",
			cidrs:        []string{"192.168.1.0/24"},
			zones:        []string{""},
			queryIP:      "::ffff:192.168.1.42",
			wantMatch:    true,
			wantZonePass: true,
		},
		{
			name:         "Zone ID match success",
			cidrs:        []string{"fe80::/10"},
			zones:        []string{"eth0"},
			queryIP:      "fe80::1",
			queryZone:    "eth0",
			wantMatch:    true,
			wantZonePass: true,
		},
		{
			name:         "Zone ID mismatch",
			cidrs:        []string{"fe80::/10"},
			zones:        []string{"eth0"},
			queryIP:      "fe80::1",
			queryZone:    "eth1",
			wantMatch:    false,
			wantZonePass: false,
		},
		{
			name:         "Catch-all 0.0.0.0/0",
			cidrs:        []string{"0.0.0.0/0"},
			zones:        []string{""},
			queryIP:      "1.2.3.4",
			wantMatch:    true,
			wantZonePass: true,
		},
		{
			name:         "Overlapping subnets broader allows",
			cidrs:        []string{"10.0.0.0/8", "10.1.0.0/16"},
			zones:        []string{"", "eth0"},
			queryIP:      "10.1.2.3",
			queryZone:    "eth1",
			wantMatch:    true, // 10.0.0.0/8 has no zone requirement, so it matches
			wantZonePass: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var prefixes []*netip.Prefix
			for _, c := range tt.cidrs {
				p := netip.MustParsePrefix(c)
				prefixes = append(prefixes, &p)
			}

			trie := NewIPTrie(prefixes, tt.zones)
			addr := netip.MustParseAddr(tt.queryIP)

			gotMatch, gotZonePass := trie.Contains(addr, tt.queryZone)

			if gotMatch != tt.wantMatch {
				t.Errorf("IPTrie.Contains() match = %v, want %v", gotMatch, tt.wantMatch)
			}
			if gotZonePass != tt.wantZonePass {
				t.Errorf("IPTrie.Contains() zonePass = %v, want %v", gotZonePass, tt.wantZonePass)
			}
		})
	}
}

// Micro-benchmarks comparing Linear Slice iteration vs Radix Trie lookup
func benchmarkIPLookups(b *testing.B, numCIDRs int) {
	cidrs := make([]*netip.Prefix, 0, numCIDRs)
	zones := make([]string, numCIDRs)

	for i := 0; i < numCIDRs; i++ {
		a := (i >> 16) & 0xFF
		bByte := (i >> 8) & 0xFF
		c := i & 0xFF
		cidrStr := fmt.Sprintf("10.%d.%d.%d/32", a, bByte, c)
		p := netip.MustParsePrefix(cidrStr)
		cidrs = append(cidrs, &p)
	}

	trie := NewIPTrie(cidrs, zones)
	targetIP := netip.MustParseAddr(fmt.Sprintf("10.%d.%d.%d", (numCIDRs-1)>>16, ((numCIDRs-1)>>8)&0xFF, (numCIDRs-1)&0xFF))

	b.Run(fmt.Sprintf("Linear_%d", numCIDRs), func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = matchIPByCidrZones(targetIP, "", cidrs, zones)
		}
	})

	b.Run(fmt.Sprintf("RadixTrie_%d", numCIDRs), func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = trie.Contains(targetIP, "")
		}
	})
}

func BenchmarkIPLookup_10(b *testing.B)    { benchmarkIPLookups(b, 10) }
func BenchmarkIPLookup_100(b *testing.B)   { benchmarkIPLookups(b, 100) }
func BenchmarkIPLookup_1000(b *testing.B)  { benchmarkIPLookups(b, 1000) }
func BenchmarkIPLookup_10000(b *testing.B) { benchmarkIPLookups(b, 10000) }
