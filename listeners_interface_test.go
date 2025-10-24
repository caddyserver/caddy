// Copyright 2025 Matthew Holt and The Caddy Authors
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
	"os"
	"runtime"
	"strings"
	"testing"
)

func TestIsInterfaceName(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
		desc     string
	}{
		// Valid interface names
		{"eth0", true, "typical ethernet interface"},
		{"wlan0", true, "wireless interface"},
		{"tailscale0", true, "tailscale interface"},
		{"enp0s3", true, "predictable network interface name"},
		{"lo", true, "loopback interface"},
		{"docker0", true, "docker bridge interface"},
		{"br-901e40e4488d", true, "docker custom bridge interface"},
		{"enx9cbf0d00631a", true, "USB ethernet adapter interface"},
		{"veth1308dcd", true, "docker veth pair interface"},

		// Invalid interface names (IP addresses)
		{"192.168.1.1", false, "IPv4 address"},
		{"127.0.0.1", false, "localhost IPv4"},
		{"::1", false, "IPv6 localhost"},
		{"2001:db8::1", false, "IPv6 address"},
		{"fe80::", false, "IPv6 link-local address starting with letter"},
		{"example.com", false, "hostname with dots"},
		{"localhost", false, "hostname"},
		{"my-host.local", false, "hostname with dashes and dots"},
		{"3", false, "numeric file descriptor"},
		{"10", false, "another numeric file descriptor"},
		{"", false, "empty string"},
		{"eth/0", false, "interface with forward slash"},
		{"eth\\0", false, "interface with backslash"},
		{"eth\n0", false, "interface with newline"},
		{"eth\t0", false, "interface with tab"},
		{"eth\x00", false, "interface with null character"},

		// Invalid interface names (unregistered Caddy placeholders that won't be replaced)
		{"{upstream}", false, "Caddy upstream placeholder (not registered in global replacer)"},
		{"{http.request.host}", false, "Caddy HTTP placeholder (not registered in global replacer)"},
		{"{vars.interface}", false, "Caddy variable placeholder (not registered in global replacer)"},
	}

	for _, test := range tests {
		result := isInterfaceName(test.input)
		if result != test.expected {
			t.Errorf("isInterfaceName(%q) = %v, expected %v (%s)",
				test.input, result, test.expected, test.desc)
		}
	}
}

func TestIsInterfaceNameWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-specific test, skipping on non-Windows platform")
	}

	windowsTests := []struct {
		input    string
		expected bool
		desc     string
	}{
		// Typical Windows interface names
		{"Wi-Fi 2", true, "Windows Wi-Fi interface"},
		{"vEthernet (WSL (Hyper-V firewall))", true, "Windows WSL virtual interface"},
		{"Local Area Connection", true, "Windows LAN connection"},
		{"Loopback Pseudo-Interface 1", true, "Windows loopback (should be detected as interface name)"},
		{"Ethernet", true, "Windows Ethernet interface"},
		{"OpenVPN Connect DCO Adapter", true, "Windows VPN adapter"},

		// Should still reject invalid ones
		{"192.168.1.1", false, "IP address should still fail"},
		{"example.com", false, "hostname should still fail"},
		{"", false, "empty string should still fail"},
	}

	for _, test := range windowsTests {
		result := isInterfaceName(test.input)
		if result != test.expected {
			t.Errorf("isInterfaceName(%q) = %v, expected %v (%s)",
				test.input, result, test.expected, test.desc)
		}
	}
}

func TestIsInterfaceNameUnix(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix-specific test, skipping on Windows platform")
	}

	unixTests := []struct {
		input    string
		expected bool
		desc     string
	}{
		// Should pass on Unix systems
		{"eth0", true, "short ethernet interface"},
		{"wlan0", true, "short wireless interface"},
		{"br-901e40e4488d", true, "docker bridge (14 chars)"},
		{"enx9cbf0d00631a", true, "USB ethernet (15 chars)"},

		// Should fail on Unix systems - too long (would pass on Windows)
		{"verylonginterfacename", false, "too long for Unix (22 chars)"},
		{"Local Area Connection", false, "Windows-style name too long for Unix"},
	}

	for _, test := range unixTests {
		result := isInterfaceName(test.input)
		if result != test.expected {
			t.Errorf("isInterfaceName(%q) = %v, expected %v (%s)",
				test.input, result, test.expected, test.desc)
		}
	}
}

func TestIsInterfaceNameWithModes(t *testing.T) {
	// Test isInterfaceName with interface:port:mode patterns
	tests := []struct {
		input    string
		expected bool
		desc     string
	}{
		// Valid interface:port:mode patterns
		{"eth0:8080:ipv4", true, "ethernet interface with IPv4 mode"},
		{"wlan0:443:ipv6", true, "wireless interface with IPv6 mode"},
		{"docker0:9000:auto", true, "docker interface with auto mode"},
		{"enp0s3:8080:ipv4", true, "predictable interface with mode"},
		{"br-901e40e4488d:3000:ipv6", true, "docker bridge with IPv6 mode"},
		{"veth1308dcd:8080:auto", true, "veth pair with auto mode"},
		{"eth0:8080:all", true, "ethernet interface with all mode"},

		// Invalid - wrong modes
		{"eth0:8080:invalid", false, "interface with invalid mode"},
		{"docker0:9000:tcp", false, "interface with non-binding mode"},

		// Invalid - not interface names
		{"192.168.1.1:80:ipv4", false, "IP address with mode"},
		{"fe80:::8080:ipv6", false, "IPv6 address with mode"},
		{"example.com:443:ipv6", false, "hostname with mode"},
		{"localhost:8080:auto", false, "localhost with mode"},

		// Edge cases
		{"eth0:8080", false, "interface with port but no mode"},
		{"eth0", true, "plain interface name should still work"},
	}

	for _, test := range tests {
		result := isInterfaceName(test.input)
		if result != test.expected {
			t.Errorf("isInterfaceName(%q) = %v, expected %v (%s)",
				test.input, result, test.expected, test.desc)
		}
	}
}

func TestSelectIPByMode(t *testing.T) {
	// Test the IP selection logic with mock data
	testCases := []struct {
		mode            InterfaceBindingMode
		ipAddresses     []string
		expectedResults []string
		expectError     bool
		desc            string
	}{
		{
			InterfaceBindingAuto,
			[]string{"192.168.1.100", "fe80::1"},
			[]string{"192.168.1.100"}, // Should prefer IPv4
			false,
			"auto mode prefers IPv4",
		},
		{
			InterfaceBindingAuto,
			[]string{"fe80::1", "2001:db8::1"},
			[]string{"fe80::1"}, // Should fallback to IPv6
			false,
			"auto mode fallback to IPv6",
		},
		{
			InterfaceBindingFirstIPv4,
			[]string{"192.168.1.100", "10.0.0.1", "fe80::1"},
			[]string{"192.168.1.100"}, // Should use first IPv4
			false,
			"firstipv4 mode uses first IPv4",
		},
		{
			InterfaceBindingFirstIPv6,
			[]string{"192.168.1.100", "fe80::1", "2001:db8::1"},
			[]string{"fe80::1"}, // Should use first IPv6
			false,
			"firstipv6 mode uses first IPv6",
		},
		{
			InterfaceBindingIPv4,
			[]string{"192.168.1.100", "10.0.0.1", "fe80::1"},
			[]string{"192.168.1.100", "10.0.0.1"}, // Should return all IPv4
			false,
			"ipv4 mode returns all IPv4 addresses",
		},
		{
			InterfaceBindingIPv6,
			[]string{"192.168.1.100", "fe80::1", "2001:db8::1"},
			[]string{"fe80::1", "2001:db8::1"}, // Should return all IPv6
			false,
			"ipv6 mode returns all IPv6 addresses",
		},
		{
			InterfaceBindingAll,
			[]string{"192.168.1.100", "10.0.0.1", "fe80::1", "2001:db8::1"},
			[]string{"192.168.1.100", "10.0.0.1", "fe80::1", "2001:db8::1"}, // Should return all IPs (IPv4 first, then IPv6)
			false,
			"all mode returns all IP addresses",
		},
		{
			InterfaceBindingAll,
			[]string{"192.168.1.100", "fe80::1"},
			[]string{"192.168.1.100", "fe80::1"}, // Should return all IPs
			false,
			"all mode with mixed addresses",
		},
		{
			InterfaceBindingAll,
			[]string{"192.168.1.100"},
			[]string{"192.168.1.100"}, // Single IPv4
			false,
			"all mode with single IPv4",
		},
		{
			InterfaceBindingAll,
			[]string{"fe80::1"},
			[]string{"fe80::1"}, // Single IPv6
			false,
			"all mode with single IPv6",
		},
		{
			InterfaceBindingIPv4,
			[]string{"fe80::1"},
			nil, // Should error - no IPv4
			true,
			"ipv4 mode with no IPv4 addresses should error",
		},
		{
			InterfaceBindingIPv6,
			[]string{"192.168.1.100"},
			nil, // Should error - no IPv6
			true,
			"ipv6 mode with no IPv6 addresses should error",
		},
		{
			InterfaceBindingAuto,
			[]string{},
			nil, // Should error - no addresses
			true,
			"auto mode with no addresses should error",
		},
		{
			InterfaceBindingAll,
			[]string{},
			nil, // Should error - no addresses
			true,
			"all mode with no addresses should error",
		},
		{
			InterfaceBindingAuto,
			[]string{"invalid_ip", "also_invalid"},
			nil, // Should error - no valid IPs
			true,
			"auto mode with invalid IP addresses should error",
		},
	}

	for _, tc := range testCases {
		results, err := selectIPByMode(tc.ipAddresses, tc.mode)

		if tc.expectError {
			if err == nil {
				t.Errorf("selectIPByMode(%v, %s) should have failed (%s)",
					tc.ipAddresses, tc.mode, tc.desc)
			}
			continue
		}

		if err != nil {
			t.Errorf("selectIPByMode(%v, %s) failed unexpectedly: %v (%s)",
				tc.ipAddresses, tc.mode, err, tc.desc)
			continue
		}

		if len(results) != len(tc.expectedResults) {
			t.Errorf("selectIPByMode(%v, %s) returned %d results, expected %d (%s)",
				tc.ipAddresses, tc.mode, len(results), len(tc.expectedResults), tc.desc)
			continue
		}

		for i, result := range results {
			if result != tc.expectedResults[i] {
				t.Errorf("selectIPByMode(%v, %s) result[%d] = %s, expected %s (%s)",
					tc.ipAddresses, tc.mode, i, result, tc.expectedResults[i], tc.desc)
			}
		}
	}
}

func TestIsInterfaceNameWithPlaceholders(t *testing.T) {
	// Set up environment variables for testing
	os.Setenv("TEST_VALID_INTERFACE", "eth0")
	os.Setenv("TEST_INVALID_INTERFACE", "192.168.1.1")
	os.Setenv("INTERFACE_NUM", "1")
	os.Setenv("PREFIX", "wlan")
	defer func() {
		os.Unsetenv("TEST_VALID_INTERFACE")
		os.Unsetenv("TEST_INVALID_INTERFACE")
		os.Unsetenv("INTERFACE_NUM")
		os.Unsetenv("PREFIX")
	}()

	// Create temporary files for testing
	validTempFile, err := os.CreateTemp("", "valid_interface_*.txt")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(validTempFile.Name())
	validTempFile.WriteString("wlan0")
	validTempFile.Close()

	invalidTempFile, err := os.CreateTemp("", "invalid_interface_*.txt")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(invalidTempFile.Name())
	invalidTempFile.WriteString("example.com") // Invalid interface (hostname)
	invalidTempFile.Close()

	emptyTempFile, err := os.CreateTemp("", "empty_interface_*.txt")
	if err != nil {
		t.Fatalf("Failed to create empty temp file: %v", err)
	}
	defer os.Remove(emptyTempFile.Name())
	emptyTempFile.Close() // Keep it empty

	tests := []struct {
		input    string
		expected bool
		desc     string
	}{
		// Valid placeholders resolving to valid interfaces
		{"{env.TEST_VALID_INTERFACE}", true, "env placeholder resolving to valid interface"},
		{"{file." + validTempFile.Name() + "}", true, "file placeholder resolving to valid interface"},

		// Valid partial placeholders resolving to valid interfaces
		{"eth{env.INTERFACE_NUM}", true, "partial env placeholder resolving to eth1"},
		{"{env.PREFIX}0", true, "env placeholder with suffix resolving to wlan0"},
		{"docker{env.INTERFACE_NUM}", true, "prefix with env placeholder resolving to docker1"},

		// Valid placeholders resolving to invalid interfaces
		{"{env.TEST_INVALID_INTERFACE}", false, "env placeholder resolving to IP address"},
		{"{file." + invalidTempFile.Name() + "}", false, "file placeholder resolving to hostname"},

		// Unregistered placeholders (not in global replacer, won't be replaced)
		{"{http.request.host}", false, "HTTP placeholder (not in global replacer)"},
		{"{vars.interface}", false, "vars placeholder (not in global replacer)"},
		{"{upstream}", false, "upstream placeholder (not in global replacer)"},

		// Mixed with unregistered placeholders (partial replacement will fail)
		{"eth{env.INTERFACE_NUM}-{http.request.host}", false, "mixed env and HTTP (HTTP not replaced, contains {)"},
		{"{env.PREFIX}-{vars.suffix}", false, "mixed env and vars (vars not replaced, contains {)"},

		// Invalid placeholder resolution
		{"{env.NONEXISTENT}", false, "nonexistent environment variable"},
		{"{file." + emptyTempFile.Name() + "}", false, "empty file content"},

		// Invalid placeholder syntax
		{"{invalid}", false, "invalid placeholder without prefix"},
		{"{env.}", false, "empty env placeholder"},
	}

	for _, test := range tests {
		result := isInterfaceName(test.input)
		if result != test.expected {
			t.Errorf("isInterfaceName(%q) = %v, expected %v (%s)",
				test.input, result, test.expected, test.desc)
		}
	}
}

func TestNetworkAddressIsInterfaceNetwork(t *testing.T) {
	tests := []struct {
		na       NetworkAddress
		expected bool
		desc     string
	}{
		{
			NetworkAddress{Network: "tcp", Host: "eth0"},
			true,
			"TCP with interface name",
		},
		{
			NetworkAddress{Network: "udp", Host: "wlan0"},
			true,
			"UDP with interface name",
		},
		{
			NetworkAddress{Network: "tcp", Host: "192.168.1.1"},
			false,
			"TCP with IP address",
		},
		{
			NetworkAddress{Network: "unix", Host: "eth0"},
			false,
			"Unix socket with interface-like name",
		},
		{
			NetworkAddress{Network: "tcp", Host: "example.com"},
			false,
			"TCP with hostname",
		},
		// Test encoded interface names with binding modes
		{
			NetworkAddress{Network: "tcp", Host: "wlan0" + InterfaceDelimiter + "ipv4"},
			true,
			"TCP with encoded interface name and IPv4 mode",
		},
		{
			NetworkAddress{Network: "tcp", Host: "eth0" + InterfaceDelimiter + "ipv6"},
			true,
			"TCP with encoded interface name and IPv6 mode",
		},
		{
			NetworkAddress{Network: "udp", Host: "tailscale0" + InterfaceDelimiter + "ipv4"},
			true,
			"UDP with encoded interface name and mode",
		},
		{
			NetworkAddress{Network: "tcp", Host: "example.com" + InterfaceDelimiter + "ipv4"},
			false,
			"TCP with hostname that has mode encoding (should be false)",
		},
		{
			NetworkAddress{Network: "tcp", Host: "192.168.1.1" + InterfaceDelimiter + "auto"},
			false,
			"TCP with IP address that has mode encoding (should be false)",
		},
	}

	for _, test := range tests {
		result := test.na.IsInterfaceNetwork()
		if result != test.expected {
			t.Errorf("NetworkAddress{%s, %s}.IsInterfaceNetwork() = %v, expected %v (%s)",
				test.na.Network, test.na.Host, result, test.expected, test.desc)
		}
	}
}

func TestParseInterfaceAddress(t *testing.T) {
	tests := []struct {
		network      string
		host         string
		port         string
		expectedHost string
		expectErr    bool
		desc         string
	}{
		// Valid cases - different interfaces and networks
		{"tcp", "eth0", "80", "eth0" + InterfaceDelimiter + "auto", false, "valid interface with port"},
		{"udp", "wlan0", "8080", "wlan0" + InterfaceDelimiter + "auto", false, "valid interface with different port"},
		{"tcp", "eth0", "8000-8010", "eth0" + InterfaceDelimiter + "auto", false, "valid interface with port range"},
		{"tcp", "wlan0", "443-444", "wlan0" + InterfaceDelimiter + "auto", false, "valid interface with small port range"},
		{"tcp", "enp0s3", "9000-9100", "enp0s3" + InterfaceDelimiter + "auto", false, "valid interface with larger port range"},
		{"tcp", "enp0s3", "9000", "enp0s3" + InterfaceDelimiter + "auto", false, "predictable interface name"},
		{"tcp", "docker0", "3000", "docker0" + InterfaceDelimiter + "auto", false, "docker bridge interface"},

		// Valid cases - different binding modes
		{"tcp", "eth0", "443:ipv4", "eth0" + InterfaceDelimiter + "ipv4", false, "valid interface with IPv4 mode"},
		{"tcp", "wlan0", "8080:ipv6", "wlan0" + InterfaceDelimiter + "ipv6", false, "valid interface with IPv6 mode"},
		{"tcp", "enp0s3", "9000:auto", "enp0s3" + InterfaceDelimiter + "auto", false, "valid interface with explicit auto mode"},
		{"tcp", "eth0", "443:all", "eth0" + InterfaceDelimiter + "all", false, "valid interface with all mode"},
		{"tcp", "wlan0", "8080-8090:all", "wlan0" + InterfaceDelimiter + "all", false, "port range with all mode"},

		// Valid cases - port ranges with binding modes
		{"tcp", "eth0", "8080-8090:ipv4", "eth0" + InterfaceDelimiter + "ipv4", false, "port range with IPv4 mode"},
		{"tcp", "wlan0", "443-445:ipv6", "wlan0" + InterfaceDelimiter + "ipv6", false, "port range with IPv6 mode"},
		{"tcp", "docker0", "3000-3010:auto", "docker0" + InterfaceDelimiter + "auto", false, "port range with auto mode"},

		// Error cases - invalid hosts
		{"tcp", "192.168.1.1", "80", "", true, "IP address should fail"},
		{"tcp", "example.com", "80", "", true, "hostname should fail"},
		{"tcp", "localhost", "80", "", true, "localhost should fail"},
		{"tcp", "", "80", "", true, "empty interface should fail"},

		// Error cases - invalid ports
		{"tcp", "eth0", "", "", true, "missing port should fail"},
		{"tcp", "eth0", "invalid", "", true, "invalid port should fail"},
		{"tcp", "eth0", "70000", "", true, "port too high should fail"},
		{"tcp", "eth0", "8090-8080", "", true, "reversed port range should fail"},
		{"tcp", "eth0", "8080-invalid", "", true, "invalid end port in range should fail"},
		{"tcp", "eth0", "invalid-8090", "", true, "invalid start port in range should fail"},
		{"tcp", "eth0", "8080-", "", true, "missing end port in range should fail"},
		{"tcp", "eth0", "-8090", "", true, "missing start port in range should fail"},

		// Error cases - invalid binding modes
		{"tcp", "eth0", "443:invalid", "", true, "invalid mode should fail"},
		{"tcp", "eth0", "443:tcp", "", true, "non-binding mode should fail"},
		{"tcp", "eth0", "443:", "", true, "empty mode should fail"},
	}

	for _, test := range tests {
		na, err := parseInterfaceAddress(test.network, test.host, test.port)

		if test.expectErr {
			if err == nil {
				t.Errorf("parseInterfaceAddress(%s, %s, %s) should have failed (%s)",
					test.network, test.host, test.port, test.desc)
			}
			continue
		}

		if err != nil {
			t.Errorf("parseInterfaceAddress(%s, %s, %s) failed: %v (%s)",
				test.network, test.host, test.port, err, test.desc)
			continue
		}

		if na.Network != test.network {
			t.Errorf("parseInterfaceAddress(%s, %s, %s) network = %s, expected %s",
				test.network, test.host, test.port, na.Network, test.network)
		}

		if na.Host != test.expectedHost {
			t.Errorf("parseInterfaceAddress(%s, %s, %s) host = %s, expected %s",
				test.network, test.host, test.port, na.Host, test.expectedHost)
		}

		// For valid cases, also verify the mode encoding/decoding
		parts := strings.SplitN(na.Host, InterfaceDelimiter, 2)
		if len(parts) != 2 {
			t.Errorf("parseInterfaceAddress(%s, %s, %s) should encode mode in Host field",
				test.network, test.host, test.port)
		} else {
			// Verify interface name is preserved
			if parts[0] != test.host {
				t.Errorf("parseInterfaceAddress(%s, %s, %s) interface = %s, expected %s",
					test.network, test.host, test.port, parts[0], test.host)
			}
			// Verify mode is valid
			mode := InterfaceBindingMode(parts[1])
			if mode != InterfaceBindingAuto && mode != InterfaceBindingFirstIPv4 && mode != InterfaceBindingFirstIPv6 &&
				mode != InterfaceBindingIPv4 && mode != InterfaceBindingIPv6 && mode != InterfaceBindingAll {
				t.Errorf("parseInterfaceAddress(%s, %s, %s) invalid mode: %s",
					test.network, test.host, test.port, mode)
			}
		}
	}
}

func TestTryParseInterfaceWithModeInHost(t *testing.T) {
	tests := []struct {
		host                 string
		expectedInterface    string
		expectedPortWithMode string
		expectedSuccess      bool
		desc                 string
	}{
		// Valid cases
		{"eth0:8080:ipv4", "eth0", "8080:ipv4", true, "Ethernet interface with IPv4 mode"},
		{"wlan0:443:ipv6", "wlan0", "443:ipv6", true, "Wireless interface with IPv6 mode"},
		{"enp0s3:9000:auto", "enp0s3", "9000:auto", true, "Predictable network interface with auto mode"},
		{"tailscale0:8090:ipv4", "tailscale0", "8090:ipv4", true, "Tailscale interface with IPv4 mode"},
		{"docker0:3000:ipv6", "docker0", "3000:ipv6", true, "Docker bridge interface with IPv6 mode"},
		{"wlan0:443:all", "wlan0", "443:all", true, "Wireless interface with all mode"},

		// Invalid cases - not enough parts
		{"eth0", "", "", false, "Interface name only"},
		{"eth0:8080", "", "", false, "Interface with port but no mode"},

		// Invalid cases - invalid mode
		{"eth0:8080:invalid", "", "", false, "Invalid binding mode"},
		{"enp0s3:8080:tcp", "", "", false, "Non-binding mode"},

		// Invalid cases - invalid interface name
		{"192.168.1.1:80:ipv4", "", "", false, "IP address instead of interface"},
		{"example.com:443:ipv6", "", "", false, "Hostname instead of interface"},
		{"localhost:8080:auto", "", "", false, "Localhost hostname"},

		// Edge cases
		{"", "", "", false, "Empty string"},
		{"br-1234567890ab:8080:ipv4", "br-1234567890ab", "8080:ipv4", true, "Docker custom bridge interface"},
	}

	for _, test := range tests {
		result, success := tryParseInterfaceWithModeInHost(test.host)

		if success != test.expectedSuccess {
			t.Errorf("tryParseInterfaceWithModeInHost(%q) success = %v, expected %v (%s)",
				test.host, success, test.expectedSuccess, test.desc)
			continue
		}

		if !test.expectedSuccess {
			continue // Skip checking values for cases that should fail
		}

		if result.interfaceName != test.expectedInterface {
			t.Errorf("tryParseInterfaceWithModeInHost(%q) interfaceName = %q, expected %q (%s)",
				test.host, result.interfaceName, test.expectedInterface, test.desc)
		}

		if result.portWithMode != test.expectedPortWithMode {
			t.Errorf("tryParseInterfaceWithModeInHost(%q) portWithMode = %q, expected %q (%s)",
				test.host, result.portWithMode, test.expectedPortWithMode, test.desc)
		}
	}
}

func TestParseNetworkAddressWithInterface(t *testing.T) {
	tests := []struct {
		addr      string
		expectErr bool
		desc      string
	}{
		{"eth0:80", false, "interface with port"},
		{"tcp/wlan0:8080", false, "explicit TCP with interface"},
		{"udp/eth0:53", false, "explicit UDP with interface"},
		{"eth0", true, "interface without port should fail in default parsing"},
		{"192.168.1.1:80", false, "regular IP address should still work"},
	}

	for _, test := range tests {
		na, err := ParseNetworkAddress(test.addr)

		if test.expectErr {
			if err == nil {
				t.Errorf("ParseNetworkAddress(%s) should have failed (%s)", test.addr, test.desc)
			}
			continue
		}

		if err != nil {
			t.Errorf("ParseNetworkAddress(%s) failed: %v (%s)", test.addr, err, test.desc)
			continue
		}

		// For interface addresses, verify they are detected correctly
		if isInterfaceName(na.Host) {
			if !na.IsInterfaceNetwork() {
				t.Errorf("ParseNetworkAddress(%s) should detect interface network (%s)", test.addr, test.desc)
			}
		}
	}

	// Test interface without port with explicit default port (should work)
	na, err := ParseNetworkAddressWithDefaults("eth0", "tcp", 8080)
	if err != nil {
		t.Errorf("ParseNetworkAddressWithDefaults(eth0, tcp, 8080) should succeed: %v", err)
	} else {
		if na.StartPort != 8080 || na.EndPort != 8080 {
			t.Errorf("ParseNetworkAddressWithDefaults(eth0, tcp, 8080) should set port to 8080, got %d-%d", na.StartPort, na.EndPort)
		}
		if !na.IsInterfaceNetwork() {
			t.Error("ParseNetworkAddressWithDefaults(eth0, tcp, 8080) should detect interface network")
		}
	}
}
