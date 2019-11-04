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
	"reflect"
	"testing"
)

func TestSplitNetworkAddress(t *testing.T) {
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
		{
			input:         "unix//foo/bar",
			expectNetwork: "unix",
			expectHost:    "/foo/bar",
		},
		{
			input:         "unixgram//foo/bar",
			expectNetwork: "unixgram",
			expectHost:    "/foo/bar",
		},
		{
			input:         "unixpacket//foo/bar",
			expectNetwork: "unixpacket",
			expectHost:    "/foo/bar",
		},
	} {
		actualNetwork, actualHost, actualPort, err := SplitNetworkAddress(tc.input)
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

func TestJoinNetworkAddress(t *testing.T) {
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
		{
			network: "unix", host: "/foo/bar", port: "",
			expect: "unix//foo/bar",
		},
		{
			network: "", host: "::1", port: "1234",
			expect: "[::1]:1234",
		},
	} {
		actual := JoinNetworkAddress(tc.network, tc.host, tc.port)
		if actual != tc.expect {
			t.Errorf("Test %d: Expected '%s' but got '%s'", i, tc.expect, actual)
		}
	}
}

func TestParseNetworkAddress(t *testing.T) {
	for i, tc := range []struct {
		input          string
		expectListener *Listener
		expectErr      bool
	}{
		{
			input:     "",
			expectErr: true,
		},
		{
			input:     ":",
			expectErr: true,
		},
		{
			input: ":1234",
			expectListener: &Listener{
				Network:  "tcp",
				Host:     "",
				FromPort: 1234,
				ToPort:   1234,
			},
		},
		{
			input: "tcp/:1234",
			expectListener: &Listener{
				Network:  "tcp",
				Host:     "",
				FromPort: 1234,
				ToPort:   1234,
			},
		},
		{
			input: "tcp6/:1234",
			expectListener: &Listener{
				Network:  "tcp6",
				Host:     "",
				FromPort: 1234,
				ToPort:   1234,
			},
		},
		{
			input: "tcp4/localhost:1234",
			expectListener: &Listener{
				Network:  "tcp4",
				Host:     "localhost",
				FromPort: 1234,
				ToPort:   1234,
			},
		},
		{
			input: "unix//foo/bar",
			expectListener: &Listener{
				Network: "unix",
				Host:    "/foo/bar",
			},
		},
		{
			input: "localhost:1234-1234",
			expectListener: &Listener{
				Network:  "tcp",
				Host:     "localhost",
				FromPort: 1234,
				ToPort:   1234,
			},
		},
		{
			input:     "localhost:2-1",
			expectErr: true,
		},
		{
			input: "localhost:0",
			expectListener: &Listener{
				Network:  "tcp",
				Host:     "localhost",
				FromPort: 0,
				ToPort:   0,
			},
		},
	} {
		actualAddr, err := ParseNetworkAddress(tc.input)
		if tc.expectErr && err == nil {
			t.Errorf("Test %d: Expected error but got: %v", i, err)
		}
		if !tc.expectErr && err != nil {
			t.Errorf("Test %d: Expected no error but got: %v", i, err)
		}
		if (tc.expectListener == nil && actualAddr != nil) || (tc.expectListener != nil && actualAddr == nil) {
			t.Errorf("Test %d: Listener expectation not matching actual. Expected: %v  but got %v", i, tc.expectListener, actualAddr)
		}
		// expectation of nil listener are cleared, proceed to next if the expected listener is nil.
		if tc.expectListener == nil {
			continue
		}
		if actualAddr.Network != tc.expectListener.Network {
			t.Errorf("Test %d: Expected network '%v' but got '%v'", i, tc.expectListener, actualAddr)
		}
		if !reflect.DeepEqual(tc.expectListener, actualAddr) {
			t.Errorf("Test %d: Expected addresses %v but got %v", i, tc.expectListener, actualAddr)
		}
	}
}
