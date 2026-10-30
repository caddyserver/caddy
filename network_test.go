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

package caddy

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNetworkAddress_String_Consistency(t *testing.T) {
	tests := []struct {
		name string
		addr NetworkAddress
	}{
		{
			name: "basic tcp",
			addr: NetworkAddress{Network: "tcp", Host: "localhost", StartPort: 8080, EndPort: 8080},
		},
		{
			name: "tcp with port range",
			addr: NetworkAddress{Network: "tcp", Host: "localhost", StartPort: 8080, EndPort: 8090},
		},
		{
			name: "unix socket",
			addr: NetworkAddress{Network: "unix", Host: "/tmp/socket"},
		},
		{
			name: "udp",
			addr: NetworkAddress{Network: "udp", Host: "0.0.0.0", StartPort: 53, EndPort: 53},
		},
		{
			name: "ipv6",
			addr: NetworkAddress{Network: "tcp", Host: "::1", StartPort: 80, EndPort: 80},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			str := test.addr.String()

			// Parse the string back
			parsed, err := ParseNetworkAddress(str)
			if err != nil {
				t.Fatalf("Failed to parse string representation: %v", err)
			}

			// Should be equivalent to original
			if parsed.Network != test.addr.Network {
				t.Errorf("Network mismatch: expected %s, got %s", test.addr.Network, parsed.Network)
			}
			if parsed.Host != test.addr.Host {
				t.Errorf("Host mismatch: expected %s, got %s", test.addr.Host, parsed.Host)
			}
			if parsed.StartPort != test.addr.StartPort {
				t.Errorf("StartPort mismatch: expected %d, got %d", test.addr.StartPort, parsed.StartPort)
			}
			if parsed.EndPort != test.addr.EndPort {
				t.Errorf("EndPort mismatch: expected %d, got %d", test.addr.EndPort, parsed.EndPort)
			}
		})
	}
}

func TestNetworkAddress_PortRangeSize_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		addr     NetworkAddress
		expected uint
	}{
		{
			name:     "single port",
			addr:     NetworkAddress{StartPort: 80, EndPort: 80},
			expected: 1,
		},
		{
			name:     "invalid range (end < start)",
			addr:     NetworkAddress{StartPort: 8080, EndPort: 8070},
			expected: 0,
		},
		{
			name:     "zero ports",
			addr:     NetworkAddress{StartPort: 0, EndPort: 0},
			expected: 1,
		},
		{
			name:     "maximum range",
			addr:     NetworkAddress{StartPort: 1, EndPort: 65535},
			expected: 65535,
		},
		{
			name:     "large range",
			addr:     NetworkAddress{StartPort: 8000, EndPort: 9000},
			expected: 1001,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			size := test.addr.PortRangeSize()
			if size != test.expected {
				t.Errorf("Expected %d, got %d", test.expected, size)
			}
		})
	}
}

func TestNetworkAddress_At_Validation(t *testing.T) {
	addr := NetworkAddress{
		Network:   "tcp",
		Host:      "localhost",
		StartPort: 8080,
		EndPort:   8090,
	}

	// Test valid offsets
	for offset := uint(0); offset <= 10; offset++ {
		result := addr.At(offset)
		expectedPort := 8080 + offset

		if result.StartPort != expectedPort || result.EndPort != expectedPort {
			t.Errorf("Offset %d: expected port %d, got %d-%d",
				offset, expectedPort, result.StartPort, result.EndPort)
		}

		if result.Network != addr.Network || result.Host != addr.Host {
			t.Errorf("Offset %d: network/host should be preserved", offset)
		}
	}
}

func TestNetworkAddress_Expand_LargeRange(t *testing.T) {
	addr := NetworkAddress{
		Network:   "tcp",
		Host:      "localhost",
		StartPort: 8000,
		EndPort:   8010,
	}

	expanded := addr.Expand()
	expectedSize := 11 // 8000 to 8010 inclusive

	if len(expanded) != expectedSize {
		t.Errorf("Expected %d addresses, got %d", expectedSize, len(expanded))
	}

	// Verify each address
	for i, expandedAddr := range expanded {
		expectedPort := uint(8000 + i)
		if expandedAddr.StartPort != expectedPort || expandedAddr.EndPort != expectedPort {
			t.Errorf("Address %d: expected port %d, got %d-%d",
				i, expectedPort, expandedAddr.StartPort, expandedAddr.EndPort)
		}
	}
}

func TestNetworkAddress_IsLoopback_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		addr     NetworkAddress
		expected bool
	}{
		{
			name:     "unix socket",
			addr:     NetworkAddress{Network: "unix", Host: "/tmp/socket"},
			expected: true, // Unix sockets are always considered loopback
		},
		{
			name:     "fd network",
			addr:     NetworkAddress{Network: "fd", Host: "3"},
			expected: true, // fd networks are always considered loopback
		},
		{
			name:     "localhost",
			addr:     NetworkAddress{Network: "tcp", Host: "localhost"},
			expected: true,
		},
		{
			name:     "127.0.0.1",
			addr:     NetworkAddress{Network: "tcp", Host: "127.0.0.1"},
			expected: true,
		},
		{
			name:     "::1",
			addr:     NetworkAddress{Network: "tcp", Host: "::1"},
			expected: true,
		},
		{
			name:     "127.0.0.2",
			addr:     NetworkAddress{Network: "tcp", Host: "127.0.0.2"},
			expected: true, // Part of 127.0.0.0/8 loopback range
		},
		{
			name:     "192.168.1.1",
			addr:     NetworkAddress{Network: "tcp", Host: "192.168.1.1"},
			expected: false, // Private but not loopback
		},
		{
			name:     "invalid ip",
			addr:     NetworkAddress{Network: "tcp", Host: "invalid-ip"},
			expected: false,
		},
		{
			name:     "empty host",
			addr:     NetworkAddress{Network: "tcp", Host: ""},
			expected: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := test.addr.isLoopback()
			if result != test.expected {
				t.Errorf("Expected %v, got %v", test.expected, result)
			}
		})
	}
}

func TestNetworkAddress_IsWildcard_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		addr     NetworkAddress
		expected bool
	}{
		{
			name:     "empty host",
			addr:     NetworkAddress{Network: "tcp", Host: ""},
			expected: true,
		},
		{
			name:     "ipv4 any",
			addr:     NetworkAddress{Network: "tcp", Host: "0.0.0.0"},
			expected: true,
		},
		{
			name:     "ipv6 any",
			addr:     NetworkAddress{Network: "tcp", Host: "::"},
			expected: true,
		},
		{
			name:     "localhost",
			addr:     NetworkAddress{Network: "tcp", Host: "localhost"},
			expected: false,
		},
		{
			name:     "specific ip",
			addr:     NetworkAddress{Network: "tcp", Host: "192.168.1.1"},
			expected: false,
		},
		{
			name:     "invalid ip",
			addr:     NetworkAddress{Network: "tcp", Host: "invalid"},
			expected: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := test.addr.isWildcardInterface()
			if result != test.expected {
				t.Errorf("Expected %v, got %v", test.expected, result)
			}
		})
	}
}

func TestSplitNetworkAddress_IPv6_EdgeCases(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		expectNetwork string
		expectHost    string
		expectPort    string
		expectErr     bool
	}{
		{
			name:       "ipv6 with port",
			input:      "[::1]:8080",
			expectHost: "::1",
			expectPort: "8080",
		},
		{
			name:       "ipv6 without port",
			input:      "[::1]",
			expectHost: "::1",
		},
		{
			name:       "ipv6 without brackets or port",
			input:      "::1",
			expectHost: "::1",
		},
		{
			name:       "ipv6 loopback",
			input:      "[::1]:443",
			expectHost: "::1",
			expectPort: "443",
		},
		{
			name:       "ipv6 any address",
			input:      "[::]:80",
			expectHost: "::",
			expectPort: "80",
		},
		{
			name:          "ipv6 with network prefix",
			input:         "tcp6/[::1]:8080",
			expectNetwork: "tcp6",
			expectHost:    "::1",
			expectPort:    "8080",
		},
		{
			name:       "malformed ipv6",
			input:      "[::1:8080", // Missing closing bracket
			expectHost: "::1:8080",
		},
		{
			name:       "ipv6 with zone",
			input:      "[fe80::1%eth0]:8080",
			expectHost: "fe80::1%eth0",
			expectPort: "8080",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			network, host, port, err := SplitNetworkAddress(test.input)

			if test.expectErr && err == nil {
				t.Error("Expected error but got none")
			}
			if !test.expectErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			if network != test.expectNetwork {
				t.Errorf("Network: expected '%s', got '%s'", test.expectNetwork, network)
			}
			if host != test.expectHost {
				t.Errorf("Host: expected '%s', got '%s'", test.expectHost, host)
			}
			if port != test.expectPort {
				t.Errorf("Port: expected '%s', got '%s'", test.expectPort, port)
			}
		})
	}
}

func TestParseNetworkAddress_PortRange_Validation(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		expectErr bool
		errMsg    string
	}{
		{
			name:      "valid range",
			input:     "localhost:8080-8090",
			expectErr: false,
		},
		{
			name:      "inverted range",
			input:     "localhost:8090-8080",
			expectErr: true,
			errMsg:    "end port must not be less than start port",
		},
		{
			name:      "too large range",
			input:     "localhost:0-65535",
			expectErr: true,
			errMsg:    "port range exceeds 65535 ports",
		},
		{
			name:      "invalid start port",
			input:     "localhost:abc-8080",
			expectErr: true,
		},
		{
			name:      "invalid end port",
			input:     "localhost:8080-xyz",
			expectErr: true,
		},
		{
			name:      "port too large",
			input:     "localhost:99999",
			expectErr: true,
		},
		{
			name:      "negative port",
			input:     "localhost:-80",
			expectErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := ParseNetworkAddress(test.input)

			if test.expectErr && err == nil {
				t.Error("Expected error but got none")
			}
			if !test.expectErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			if test.expectErr && test.errMsg != "" && err != nil {
				if !containsString(err.Error(), test.errMsg) {
					t.Errorf("Expected error containing '%s', got '%s'", test.errMsg, err.Error())
				}
			}
		})
	}
}

func TestNetworkAddress_Listen_ContextCancellation(t *testing.T) {
	addr := NetworkAddress{
		Network:   "tcp",
		Host:      "localhost",
		StartPort: 0, // Let OS assign port
		EndPort:   0,
	}

	// Create context that will be cancelled
	ctx, cancel := context.WithCancel(context.Background())

	// Start listening in a goroutine
	listenDone := make(chan error, 1)
	go func() {
		_, err := addr.Listen(ctx, 0, net.ListenConfig{})
		listenDone <- err
	}()

	// Cancel context immediately
	cancel()

	// Should get context cancellation error quickly
	select {
	case err := <-listenDone:
		if err == nil {
			t.Error("Expected error due to context cancellation")
		}
		// Accept any error related to context cancellation
		// (could be context.Canceled or DNS lookup error due to cancellation)
	case <-time.After(time.Second):
		t.Error("Listen operation did not respect context cancellation")
	}
}

func TestNetworkAddress_ListenAll_PartialFailure(t *testing.T) {
	// Create an address range where some ports might fail to bind
	addr := NetworkAddress{
		Network:   "tcp",
		Host:      "localhost",
		StartPort: 0, // OS-assigned port
		EndPort:   2, // Try to bind 3 ports starting from OS-assigned
	}

	// This test might be flaky depending on available ports,
	// but tests the error handling logic
	ctx := context.Background()

	listeners, err := addr.ListenAll(ctx, net.ListenConfig{})

	// Either all succeed or all fail (due to cleanup on partial failure)
	if err != nil {
		// If there's an error, no listeners should be returned
		if len(listeners) != 0 {
			t.Errorf("Expected no listeners on error, got %d", len(listeners))
		}
	} else {
		// If successful, should have listeners for all ports in range
		expectedCount := int(addr.PortRangeSize())
		if len(listeners) != expectedCount {
			t.Errorf("Expected %d listeners, got %d", expectedCount, len(listeners))
		}

		// Clean up listeners
		for _, ln := range listeners {
			if closer, ok := ln.(interface{ Close() error }); ok {
				closer.Close()
			}
		}
	}
}

func TestJoinNetworkAddress_SpecialCases(t *testing.T) {
	tests := []struct {
		name     string
		network  string
		host     string
		port     string
		expected string
	}{
		{
			name:     "empty everything",
			network:  "",
			host:     "",
			port:     "",
			expected: "",
		},
		{
			name:     "network only",
			network:  "tcp",
			host:     "",
			port:     "",
			expected: "tcp/",
		},
		{
			name:     "host only",
			network:  "",
			host:     "localhost",
			port:     "",
			expected: "localhost",
		},
		{
			name:     "port only",
			network:  "",
			host:     "",
			port:     "8080",
			expected: ":8080",
		},
		{
			name:     "unix socket with port (port ignored)",
			network:  "unix",
			host:     "/tmp/socket",
			port:     "8080",
			expected: "unix//tmp/socket",
		},
		{
			name:     "fd network with port (port ignored)",
			network:  "fd",
			host:     "3",
			port:     "8080",
			expected: "fd/3",
		},
		{
			name:     "ipv6 host with port",
			network:  "tcp",
			host:     "::1",
			port:     "8080",
			expected: "tcp/[::1]:8080",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := JoinNetworkAddress(test.network, test.host, test.port)
			if result != test.expected {
				t.Errorf("Expected '%s', got '%s'", test.expected, result)
			}
		})
	}
}

func TestIsUnixNetwork_IsFdNetwork(t *testing.T) {
	tests := []struct {
		network string
		isUnix  bool
		isFd    bool
	}{
		{"unix", true, false},
		{"unixgram", true, false},
		{"unixpacket", true, false},
		{"fd", false, true},
		{"fdgram", false, true},
		{"tcp", false, false},
		{"udp", false, false},
		{"", false, false},
		{"unix-like", true, false},
		{"fd-like", false, true},
	}

	for _, test := range tests {
		t.Run(test.network, func(t *testing.T) {
			if IsUnixNetwork(test.network) != test.isUnix {
				t.Errorf("IsUnixNetwork('%s'): expected %v, got %v",
					test.network, test.isUnix, IsUnixNetwork(test.network))
			}
			if IsFdNetwork(test.network) != test.isFd {
				t.Errorf("IsFdNetwork('%s'): expected %v, got %v",
					test.network, test.isFd, IsFdNetwork(test.network))
			}

			// Test NetworkAddress methods too
			addr := NetworkAddress{Network: test.network}
			if addr.IsUnixNetwork() != test.isUnix {
				t.Errorf("NetworkAddress.IsUnixNetwork(): expected %v, got %v",
					test.isUnix, addr.IsUnixNetwork())
			}
			if addr.IsFdNetwork() != test.isFd {
				t.Errorf("NetworkAddress.IsFdNetwork(): expected %v, got %v",
					test.isFd, addr.IsFdNetwork())
			}
		})
	}
}

func TestRegisterNetwork_Validation(t *testing.T) {
	// Save original state
	originalNetworkTypes := make(map[string]ListenerFunc)
	for k, v := range networkTypes {
		originalNetworkTypes[k] = v
	}
	defer func() {
		// Restore original state
		networkTypes = originalNetworkTypes
	}()

	mockListener := func(ctx context.Context, network, host, portRange string, portOffset uint, cfg net.ListenConfig) (any, error) {
		return nil, nil
	}

	// Test reserved network types that should panic
	reservedTypes := []string{
		"tcp", "tcp4", "tcp6",
		"udp", "udp4", "udp6",
		"unix", "unixpacket", "unixgram",
		"ip:1", "ip4:1", "ip6:1",
		"fd", "fdgram",
	}

	for _, networkType := range reservedTypes {
		t.Run("reserved_"+networkType, func(t *testing.T) {
			defer func() {
				if r := recover(); r == nil {
					t.Errorf("Expected panic for reserved network type: %s", networkType)
				}
			}()
			RegisterNetwork(networkType, mockListener)
		})
	}

	// Test valid registration
	t.Run("valid_registration", func(t *testing.T) {
		customNetwork := "custom-network"
		RegisterNetwork(customNetwork, mockListener)

		if _, exists := networkTypes[customNetwork]; !exists {
			t.Error("Custom network should be registered")
		}
	})

	// Test duplicate registration should panic
	t.Run("duplicate_registration", func(t *testing.T) {
		customNetwork := "another-custom"
		RegisterNetwork(customNetwork, mockListener)

		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic for duplicate registration")
			}
		}()
		RegisterNetwork(customNetwork, mockListener)
	})
}

func TestListenerUsage_EdgeCases(t *testing.T) {
	// Test ListenerUsage function with various inputs
	tests := []struct {
		name     string
		network  string
		addr     string
		expected int
	}{
		{
			name:     "non-existent listener",
			network:  "tcp",
			addr:     "localhost:9999",
			expected: 0,
		},
		{
			name:     "empty network and address",
			network:  "",
			addr:     "",
			expected: 0,
		},
		{
			name:     "unix socket",
			network:  "unix",
			addr:     "/tmp/non-existent.sock",
			expected: 0,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			usage := ListenerUsage(test.network, test.addr)
			if usage != test.expected {
				t.Errorf("Expected usage %d, got %d", test.expected, usage)
			}
		})
	}
}

func TestNetworkAddress_Port_Formatting(t *testing.T) {
	tests := []struct {
		name     string
		addr     NetworkAddress
		expected string
	}{
		{
			name:     "single port",
			addr:     NetworkAddress{StartPort: 80, EndPort: 80},
			expected: "80",
		},
		{
			name:     "port range",
			addr:     NetworkAddress{StartPort: 8080, EndPort: 8090},
			expected: "8080-8090",
		},
		{
			name:     "zero ports",
			addr:     NetworkAddress{StartPort: 0, EndPort: 0},
			expected: "0",
		},
		{
			name:     "large ports",
			addr:     NetworkAddress{StartPort: 65534, EndPort: 65535},
			expected: "65534-65535",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := test.addr.port()
			if result != test.expected {
				t.Errorf("Expected '%s', got '%s'", test.expected, result)
			}
		})
	}
}

func TestNetworkAddress_JoinHostPort_SpecialNetworks(t *testing.T) {
	tests := []struct {
		name     string
		addr     NetworkAddress
		offset   uint
		expected string
	}{
		{
			name: "unix socket ignores offset",
			addr: NetworkAddress{
				Network: "unix",
				Host:    "/tmp/socket",
			},
			offset:   100,
			expected: "/tmp/socket",
		},
		{
			name: "fd network ignores offset",
			addr: NetworkAddress{
				Network: "fd",
				Host:    "3",
			},
			offset:   50,
			expected: "3",
		},
		{
			name: "tcp with offset",
			addr: NetworkAddress{
				Network:   "tcp",
				Host:      "localhost",
				StartPort: 8000,
			},
			offset:   10,
			expected: "localhost:8010",
		},
		{
			name: "ipv6 with offset",
			addr: NetworkAddress{
				Network:   "tcp",
				Host:      "::1",
				StartPort: 8000,
			},
			offset:   5,
			expected: "[::1]:8005",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := test.addr.JoinHostPort(test.offset)
			if result != test.expected {
				t.Errorf("Expected '%s', got '%s'", test.expected, result)
			}
		})
	}
}

// Helper function for string containment check
func containsString(haystack, needle string) bool {
	return len(haystack) >= len(needle) &&
		(needle == "" || haystack == needle ||
			strings.Contains(haystack, needle))
}

func TestListenerKey_Generation(t *testing.T) {
	tests := []struct {
		network  string
		addr     string
		expected string
	}{
		{
			network:  "tcp",
			addr:     "localhost:8080",
			expected: "tcp/localhost:8080",
		},
		{
			network:  "unix",
			addr:     "/tmp/socket",
			expected: "unix//tmp/socket",
		},
		{
			network:  "",
			addr:     "localhost:8080",
			expected: "/localhost:8080",
		},
		{
			network:  "tcp",
			addr:     "",
			expected: "tcp/",
		},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("%s_%s", test.network, test.addr), func(t *testing.T) {
			result := listenerKey(test.network, test.addr)
			if result != test.expected {
				t.Errorf("Expected '%s', got '%s'", test.expected, result)
			}
		})
	}
}

func TestNetworkAddress_ConcurrentAccess(t *testing.T) {
	// Test that NetworkAddress methods are safe for concurrent read access
	addr := NetworkAddress{
		Network:   "tcp",
		Host:      "localhost",
		StartPort: 8080,
		EndPort:   8090,
	}

	const numGoroutines = 50
	var wg sync.WaitGroup

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			// Call various methods concurrently
			_ = addr.String()
			_ = addr.PortRangeSize()
			_ = addr.IsUnixNetwork()
			_ = addr.IsFdNetwork()
			_ = addr.isLoopback()
			_ = addr.isWildcardInterface()
			_ = addr.port()
			_ = addr.JoinHostPort(uint(id % 10))
			_ = addr.At(uint(id % 11))

			// Expand creates new slice, should be safe
			expanded := addr.Expand()
			if len(expanded) == 0 {
				t.Errorf("Goroutine %d: Expected non-empty expansion", id)
			}
		}(i)
	}

	wg.Wait()
}

func TestNetworkAddress_IPv6_Zone_Handling(t *testing.T) {
	// Test IPv6 addresses with zone identifiers
	input := "tcp/[fe80::1%eth0]:8080"

	addr, err := ParseNetworkAddress(input)
	if err != nil {
		t.Fatalf("Failed to parse IPv6 with zone: %v", err)
	}

	if addr.Network != "tcp" {
		t.Errorf("Expected network 'tcp', got '%s'", addr.Network)
	}
	if addr.Host != "fe80::1%eth0" {
		t.Errorf("Expected host 'fe80::1%%eth0', got '%s'", addr.Host)
	}
	if addr.StartPort != 8080 {
		t.Errorf("Expected port 8080, got %d", addr.StartPort)
	}

	// Test string representation round-trip
	str := addr.String()
	parsed, err := ParseNetworkAddress(str)
	if err != nil {
		t.Fatalf("Failed to parse string representation: %v", err)
	}

	if parsed.Host != addr.Host {
		t.Errorf("Round-trip failed: expected host '%s', got '%s'", addr.Host, parsed.Host)
	}
}

func BenchmarkParseNetworkAddress(b *testing.B) {
	inputs := []string{
		"localhost:8080",
		"tcp/localhost:8080-8090",
		"unix//tmp/socket",
		"[::1]:443",
		"udp/:53",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		input := inputs[i%len(inputs)]
		ParseNetworkAddress(input)
	}
}

func BenchmarkNetworkAddress_String(b *testing.B) {
	addr := NetworkAddress{
		Network:   "tcp",
		Host:      "localhost",
		StartPort: 8080,
		EndPort:   8090,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		addr.String()
	}
}

func BenchmarkNetworkAddress_Expand(b *testing.B) {
	addr := NetworkAddress{
		Network:   "tcp",
		Host:      "localhost",
		StartPort: 8000,
		EndPort:   8100, // 101 addresses
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		addr.Expand()
	}
}
