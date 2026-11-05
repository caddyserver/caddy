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
	"net"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func TestIsPortBind(t *testing.T) {
	for _, tc := range []struct {
		network, address string
		want             bool
	}{
		{"tcp", ":80", true},
		{"tcp4", "127.0.0.1:443", true},
		{"udp6", "[::1]:443", true},
		{"tcp", ":1023", true},
		{"tcp", ":1024", true},
		{"tcp", ":8080", true},
		{"tcp", ":65535", true},
		{"tcp", ":65536", false},
		{"tcp", ":0", false},
		{"unix", "/run/caddy.sock", false},
		{"fd", "3", false},
		{"ip4:icmp", "127.0.0.1", false},
	} {
		if got := isPortBind(tc.network, tc.address); got != tc.want {
			t.Errorf("isPortBind(%q, %q) = %v, want %v", tc.network, tc.address, got, tc.want)
		}
	}
}

func TestWithBindCapabilityPassthrough(t *testing.T) {
	before, err := shouldRaiseBindCapability()
	if err != nil {
		t.Fatalf("reading capabilities: %v", err)
	}

	// a privileged-port EACCES is retried only if the capability can be raised
	retryCalls := 1
	if before {
		retryCalls = 2
	}

	// shaped like the error net.ListenConfig.Listen returns
	eacces := &net.OpError{Op: "listen", Net: "tcp", Err: os.NewSyscallError("bind", unix.EACCES)}
	sentinel := errors.New("sentinel")
	for _, tc := range []struct {
		network, address string
		err              error
		wantCalls        int
	}{
		{"tcp", "localhost:80", nil, 1},
		{"tcp", "localhost:80", sentinel, 1},
		{"udp", ":8080", sentinel, 1},
		{"unix", "/tmp/caddy.sock", eacces, 1},
		{"tcp", ":0", eacces, 1},
		{"tcp", "localhost:80", eacces, retryCalls},
	} {
		calls := 0
		ln, err := WithBindCapability(tc.network, tc.address, func() (any, error) {
			calls++
			return "listener", tc.err
		})
		if calls != tc.wantCalls {
			t.Errorf("%s/%s/%v: listen called %d times, want %d", tc.network, tc.address, tc.err, calls, tc.wantCalls)
		}
		if ln != "listener" || !errors.Is(err, tc.err) {
			t.Errorf("%s/%s/%v: got (%v, %v), want listen's return values", tc.network, tc.address, tc.err, ln, err)
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
