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

package internal

import (
	"errors"
	"testing"
)

func TestIsPrivilegedPort(t *testing.T) {
	for _, tc := range []struct {
		network, address string
		want             bool
	}{
		{"tcp", ":80", true},
		{"tcp4", "127.0.0.1:443", true},
		{"udp6", "[::1]:443", true},
		{"tcp", ":1023", true},
		{"tcp", ":1024", false},
		{"tcp", ":8080", false},
		{"tcp", ":0", false},
		{"unix", "/run/caddy.sock", false},
		{"fd", "3", false},
		{"ip4:icmp", "127.0.0.1", false},
	} {
		if got := isPrivilegedPort(tc.network, tc.address); got != tc.want {
			t.Errorf("isPrivilegedPort(%q, %q) = %v, want %v", tc.network, tc.address, got, tc.want)
		}
	}
}

func TestWithBindCapabilityPassthrough(t *testing.T) {
	before, err := shouldRaiseBindCapability()
	if err != nil {
		t.Fatalf("reading capabilities: %v", err)
	}

	sentinel := errors.New("sentinel")
	for _, tc := range []struct{ network, address string }{
		{"tcp", "localhost:80"},
		{"udp", ":8080"},
		{"unix", "/tmp/caddy.sock"},
	} {
		ln, err := WithBindCapability(tc.network, tc.address, func() (any, error) {
			return "listener", sentinel
		})
		if ln != "listener" || !errors.Is(err, sentinel) {
			t.Errorf("%s/%s: got (%v, %v), want listen's return values", tc.network, tc.address, ln, err)
		}
	}

	after, err := shouldRaiseBindCapability()
	if err != nil {
		t.Fatalf("reading capabilities: %v", err)
	}
	if before != after {
		t.Errorf("capabilities of calling thread changed")
	}
}
