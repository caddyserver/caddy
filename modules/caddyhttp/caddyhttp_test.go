package caddyhttp

import (
	"os"
	"reflect"
	"testing"
)

func TestSplitListenerAddr(t *testing.T) {
	for i, tc := range []struct {
		input         string
		expectNetwork string
		expectHost    string
		expectPort    string
		expectErr     bool
	}{
		{
			input:     "",
			expectErr: true,
		},
		{
			input:     "foo",
			expectErr: true,
		},
		{
			input:      "foo:1234",
			expectHost: "foo",
			expectPort: "1234",
		},
		{
			input:      "foo:1234-5678",
			expectHost: "foo",
			expectPort: "1234-5678",
		},
		{
			input:         "udp/foo:1234",
			expectNetwork: "udp",
			expectHost:    "foo",
			expectPort:    "1234",
		},
		{
			input:         "tcp6/foo:1234-5678",
			expectNetwork: "tcp6",
			expectHost:    "foo",
			expectPort:    "1234-5678",
		},
		{
			input:         "udp/",
			expectNetwork: "udp",
			expectErr:     true,
		},
	} {
		actualNetwork, actualHost, actualPort, err := splitListenAddr(tc.input)
		if tc.expectErr && err == nil {
			t.Errorf("Test %d: Expected error but got: %v", i, err)
		}
		if !tc.expectErr && err != nil {
			t.Errorf("Test %d: Expected no error but got: %v", i, err)
		}
		if actualNetwork != tc.expectNetwork {
			t.Errorf("Test %d: Expected network '%s' but got '%s'", i, tc.expectNetwork, actualNetwork)
		}
		if actualHost != tc.expectHost {
			t.Errorf("Test %d: Expected host '%s' but got '%s'", i, tc.expectHost, actualHost)
		}
		if actualPort != tc.expectPort {
			t.Errorf("Test %d: Expected port '%s' but got '%s'", i, tc.expectPort, actualPort)
		}
	}
}

func TestJoinListenerAddr(t *testing.T) {
	for i, tc := range []struct {
		network, host, port string
		expect              string
	}{
		{
			network: "", host: "", port: "",
			expect: "",
		},
		{
			network: "tcp", host: "", port: "",
			expect: "tcp/",
		},
		{
			network: "", host: "foo", port: "",
			expect: "foo",
		},
		{
			network: "", host: "", port: "1234",
			expect: ":1234",
		},
		{
			network: "", host: "", port: "1234-5678",
			expect: ":1234-5678",
		},
		{
			network: "", host: "foo", port: "1234",
			expect: "foo:1234",
		},
		{
			network: "udp", host: "foo", port: "1234",
			expect: "udp/foo:1234",
		},
		{
			network: "udp", host: "", port: "1234",
			expect: "udp/:1234",
		},
	} {
		actual := joinListenAddr(tc.network, tc.host, tc.port)
		if actual != tc.expect {
			t.Errorf("Test %d: Expected '%s' but got '%s'", i, tc.expect, actual)
		}
	}
}

func TestParseListenerAddr(t *testing.T) {
	hostname, err := os.Hostname()
	if err != nil {
		t.Fatalf("Cannot ascertain system hostname: %v", err)
	}

	for i, tc := range []struct {
		input         string
		expectNetwork string
		expectAddrs   []string
		expectErr     bool
	}{
		{
			input:         "",
			expectNetwork: "tcp",
			expectErr:     true,
		},
		{
			input:         ":",
			expectNetwork: "tcp",
			expectErr:     true,
		},
		{
			input:         ":1234",
			expectNetwork: "tcp",
			expectAddrs:   []string{":1234"},
		},
		{
			input:         "tcp/:1234",
			expectNetwork: "tcp",
			expectAddrs:   []string{":1234"},
		},
		{
			input:         "tcp6/:1234",
			expectNetwork: "tcp6",
			expectAddrs:   []string{":1234"},
		},
		{
			input:         "tcp4/localhost:1234",
			expectNetwork: "tcp4",
			expectAddrs:   []string{"localhost:1234"},
		},
		{
			input:         "unix/localhost:1234-1236",
			expectNetwork: "unix",
			expectAddrs:   []string{"localhost:1234", "localhost:1235", "localhost:1236"},
		},
		{
			input:         "localhost:1234-1234",
			expectNetwork: "tcp",
			expectAddrs:   []string{"localhost:1234"},
		},
		{
			input:         "localhost:2-1",
			expectNetwork: "tcp",
			expectErr:     true,
		},
		{
			input:         "localhost:0",
			expectNetwork: "tcp",
			expectAddrs:   []string{"localhost:0"},
		},
		{
			input:         "{system.hostname}:0",
			expectNetwork: "tcp",
			expectAddrs:   []string{hostname + ":0"},
		},
	} {
		actualNetwork, actualAddrs, err := parseListenAddr(tc.input)
		if tc.expectErr && err == nil {
			t.Errorf("Test %d: Expected error but got: %v", i, err)
		}
		if !tc.expectErr && err != nil {
			t.Errorf("Test %d: Expected no error but got: %v", i, err)
		}
		if actualNetwork != tc.expectNetwork {
			t.Errorf("Test %d: Expected network '%s' but got '%s'", i, tc.expectNetwork, actualNetwork)
		}
		if !reflect.DeepEqual(tc.expectAddrs, actualAddrs) {
			t.Errorf("Test %d: Expected addresses %v but got %v", i, tc.expectAddrs, actualAddrs)
		}
	}
}
