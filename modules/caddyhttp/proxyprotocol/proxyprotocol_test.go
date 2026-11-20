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

package proxyprotocol

import (
	"errors"
	"net"
	"reflect"
	"testing"
	"time"

	goproxy "github.com/pires/go-proxyproto"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

type customAddr struct {
	network string
	address string
}

func (a customAddr) Network() string { return a.network }
func (a customAddr) String() string  { return a.address }

func TestPolicy(t *testing.T) {
	for _, tc := range []struct {
		policy Policy
		str    string
	}{
		{PolicyUSE, "USE"},
		{PolicyIGNORE, "IGNORE"},
		{PolicyREJECT, "REJECT"},
		{PolicyREQUIRE, "REQUIRE"},
		{PolicySKIP, "SKIP"},
	} {
		t.Run("Marshal_"+tc.str, func(t *testing.T) {
			b, err := tc.policy.MarshalText()
			if err != nil {
				t.Fatalf("unexpected error marshaling %v: %v", tc.policy, err)
			}
			if string(b) != tc.str {
				t.Errorf("MarshalText() = %s, want %s", string(b), tc.str)
			}
		})

		t.Run("Unmarshal_"+tc.str, func(t *testing.T) {
			var p Policy
			if err := p.UnmarshalText([]byte(tc.str)); err != nil {
				t.Fatalf("unexpected error unmarshaling %s: %v", tc.str, err)
			}
			if p != tc.policy {
				t.Errorf("UnmarshalText() = %v, want %v", p, tc.policy)
			}
		})
	}

	// Case insensitivity
	t.Run("CaseInsensitive", func(t *testing.T) {
		for _, s := range []string{"use", "Use", "ignore", "Ignore", "reject", "require", "skip"} {
			var p Policy
			if err := p.UnmarshalText([]byte(s)); err != nil {
				t.Errorf("expected %q to unmarshal successfully, got %v", s, err)
			}
		}
	})

	// Invalid policies
	t.Run("Invalid", func(t *testing.T) {
		for _, invalid := range []string{"INVALID", "unknown", "", "123"} {
			var p Policy
			err := p.UnmarshalText([]byte(invalid))
			if err == nil {
				t.Errorf("expected error for invalid policy %q, got nil", invalid)
			}
			if !errors.Is(err, errInvalidPolicy) {
				t.Errorf("expected errInvalidPolicy, got %v", err)
			}
		}
	})
}

func TestProvision(t *testing.T) {
	t.Run("valid CIDRs", func(t *testing.T) {
		pp := &ListenerWrapper{
			Allow: []string{"192.168.1.0/24", "2001:db8::/32"},
			Deny:  []string{"10.0.0.0/8"},
		}
		if err := pp.Provision(caddy.Context{}); err != nil {
			t.Fatalf("Provision() failed with valid CIDRs: %v", err)
		}
		if len(pp.allow) != 2 {
			t.Errorf("len(pp.allow) = %d, want 2", len(pp.allow))
		}
		if len(pp.deny) != 1 {
			t.Errorf("len(pp.deny) = %d, want 1", len(pp.deny))
		}
	})

	t.Run("invalid allow CIDR", func(t *testing.T) {
		pp := &ListenerWrapper{
			Allow: []string{"invalid-cidr"},
		}
		if err := pp.Provision(caddy.Context{}); err == nil {
			t.Error("expected Provision() to fail on invalid allow CIDR, but got nil")
		}
	})

	t.Run("invalid deny CIDR", func(t *testing.T) {
		pp := &ListenerWrapper{
			Deny: []string{"10.0.0.1/999"},
		}
		if err := pp.Provision(caddy.Context{}); err == nil {
			t.Error("expected Provision() to fail on invalid deny CIDR, but got nil")
		}
	})
}

func TestPolicyFunc(t *testing.T) {
	pp := &ListenerWrapper{
		Allow:          []string{"192.168.1.0/24"},
		Deny:           []string{"10.0.0.0/8"},
		FallbackPolicy: PolicySKIP,
	}
	if err := pp.Provision(caddy.Context{}); err != nil {
		t.Fatalf("Provision() error: %v", err)
	}

	for _, tc := range []struct {
		name       string
		addr       net.Addr
		wantPolicy goproxy.Policy
		wantErr    bool
	}{
		{
			name:       "unix network",
			addr:       &net.UnixAddr{Name: "/var/run/caddy.sock", Net: "unix"},
			wantPolicy: goproxy.USE,
		},
		{
			name:       "denied IP",
			addr:       &net.TCPAddr{IP: net.ParseIP("10.2.3.4"), Port: 12345},
			wantPolicy: goproxy.REJECT,
		},
		{
			name:       "allowed IP",
			addr:       &net.TCPAddr{IP: net.ParseIP("192.168.1.100"), Port: 54321},
			wantPolicy: goproxy.USE,
		},
		{
			name:       "fallback IP",
			addr:       &net.TCPAddr{IP: net.ParseIP("172.16.0.5"), Port: 8080},
			wantPolicy: goproxy.SKIP,
		},
		{
			name:       "missing port",
			addr:       customAddr{network: "tcp", address: "192.168.1.1"},
			wantPolicy: goproxy.REJECT,
			wantErr:    true,
		},
		{
			name:       "invalid IP",
			addr:       customAddr{network: "tcp", address: "notanip:1234"},
			wantPolicy: goproxy.REJECT,
			wantErr:    true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gotPolicy, err := pp.policy(goproxy.ConnPolicyOptions{Upstream: tc.addr})
			if (err != nil) != tc.wantErr {
				t.Fatalf("pp.policy() error = %v, wantErr %v", err, tc.wantErr)
			}
			if gotPolicy != tc.wantPolicy {
				t.Errorf("pp.policy() = %v, want %v", gotPolicy, tc.wantPolicy)
			}
		})
	}
}

func TestUnmarshalCaddyfile(t *testing.T) {
	t.Run("valid configuration", func(t *testing.T) {
		input := `proxy_protocol {
			timeout 2s
			allow 10.0.0.0/8 192.168.0.0/16
			deny 172.16.0.0/12
			fallback_policy require
		}`
		d := caddyfile.NewTestDispenser(input)
		var w ListenerWrapper
		if err := w.UnmarshalCaddyfile(d); err != nil {
			t.Fatalf("UnmarshalCaddyfile() error: %v", err)
		}

		if w.Timeout != caddy.Duration(2*time.Second) {
			t.Errorf("Timeout = %v, want 2s", w.Timeout)
		}
		wantAllow := []string{"10.0.0.0/8", "192.168.0.0/16"}
		if !reflect.DeepEqual(w.Allow, wantAllow) {
			t.Errorf("Allow = %v, want %v", w.Allow, wantAllow)
		}
		wantDeny := []string{"172.16.0.0/12"}
		if !reflect.DeepEqual(w.Deny, wantDeny) {
			t.Errorf("Deny = %v, want %v", w.Deny, wantDeny)
		}
		if w.FallbackPolicy != PolicyREQUIRE {
			t.Errorf("FallbackPolicy = %v, want %v", w.FallbackPolicy, PolicyREQUIRE)
		}
	})

	for _, tc := range []struct {
		name  string
		input string
	}{
		{
			name:  "same-line argument not allowed",
			input: `proxy_protocol extra_arg`,
		},
		{
			name:  "missing timeout argument",
			input: `proxy_protocol { timeout }`,
		},
		{
			name:  "invalid timeout duration",
			input: `proxy_protocol { timeout invalid }`,
		},
		{
			name:  "missing fallback_policy argument",
			input: `proxy_protocol { fallback_policy }`,
		},
		{
			name:  "invalid fallback_policy name",
			input: `proxy_protocol { fallback_policy nonexistent }`,
		},
		{
			name:  "unknown directive",
			input: `proxy_protocol { unknown_block foo }`,
		},
	} {
		t.Run("error_"+tc.name, func(t *testing.T) {
			d := caddyfile.NewTestDispenser(tc.input)
			var w ListenerWrapper
			if err := w.UnmarshalCaddyfile(d); err == nil {
				t.Errorf("expected error for input %q, got nil", tc.input)
			}
		})
	}
}

func TestWrapListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer ln.Close()

	pp := &ListenerWrapper{
		Timeout: caddy.Duration(3 * time.Second),
	}
	if err := pp.Provision(caddy.Context{}); err != nil {
		t.Fatalf("Provision() error: %v", err)
	}

	wrapped := pp.WrapListener(ln)
	if wrapped == nil {
		t.Fatal("expected non-nil wrapped listener")
	}
	defer wrapped.Close()

	pl, ok := wrapped.(*goproxy.Listener)
	if !ok {
		t.Fatalf("expected *goproxy.Listener, got %T", wrapped)
	}
	if pl.ReadHeaderTimeout != 3*time.Second {
		t.Errorf("ReadHeaderTimeout = %v, want 3s", pl.ReadHeaderTimeout)
	}
}
