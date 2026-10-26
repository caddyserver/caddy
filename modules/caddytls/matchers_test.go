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

package caddytls

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestServerNameMatcher(t *testing.T) {
	for i, tc := range []struct {
		names  []string
		input  string
		expect bool
	}{
		{
			names:  []string{"example.com"},
			input:  "example.com",
			expect: true,
		},
		{
			names:  []string{"example.com"},
			input:  "foo.com",
			expect: false,
		},
		{
			names:  []string{"example.com"},
			input:  "",
			expect: false,
		},
		{
			names:  []string{},
			input:  "",
			expect: false,
		},
		{
			names:  []string{"foo", "example.com"},
			input:  "example.com",
			expect: true,
		},
		{
			names:  []string{"foo", "example.com"},
			input:  "sub.example.com",
			expect: false,
		},
		{
			names:  []string{"foo", "example.com"},
			input:  "foo.com",
			expect: false,
		},
		{
			names:  []string{"*.example.com"},
			input:  "example.com",
			expect: false,
		},
		{
			names:  []string{"*.example.com"},
			input:  "sub.example.com",
			expect: true,
		},
		{
			names:  []string{"*.example.com", "*.sub.example.com"},
			input:  "sub2.sub.example.com",
			expect: true,
		},
		{
			names:  []string{"つ.localhost"},
			input:  "xn--k9j.localhost",
			expect: true,
		},
		{
			names:  []string{"つ.Localhost"},
			input:  "XN--K9J.LOCALHOST",
			expect: true,
		},
		{
			names:  []string{"*.つ.localhost"},
			input:  "sub.xn--k9j.localhost",
			expect: true,
		},
		{
			names:  []string{"*.つ.Localhost"},
			input:  "Sub.XN--K9J.LOCALHOST",
			expect: true,
		},
	} {
		chi := &tls.ClientHelloInfo{ServerName: tc.input}
		actual := MatchServerName(tc.names).Match(chi)
		if actual != tc.expect {
			t.Errorf("Test %d: Expected %t but got %t (input=%s match=%v)",
				i, tc.expect, actual, tc.input, tc.names)
		}
	}
}

func TestServerNameREMatcher(t *testing.T) {
	for i, tc := range []struct {
		pattern string
		input   string
		expect  bool
	}{
		{
			pattern: "^example\\.(com|net)$",
			input:   "example.com",
			expect:  true,
		},
		{
			pattern: "^example\\.(com|net)$",
			input:   "foo.com",
			expect:  false,
		},
		{
			pattern: "^example\\.(com|net)$",
			input:   "",
			expect:  false,
		},
		{
			pattern: "",
			input:   "",
			expect:  true,
		},
		{
			pattern: "^example\\.(com|net)$",
			input:   "foo.example.com",
			expect:  false,
		},
	} {
		chi := &tls.ClientHelloInfo{ServerName: tc.input}
		mre := MatchServerNameRE{MatchRegexp{Pattern: tc.pattern}}
		ctx, _ := caddy.NewContext(caddy.Context{Context: context.Background()})
		if mre.Provision(ctx) != nil {
			t.Errorf("Test %d: Failed to provision a regexp matcher (pattern=%v)", i, tc.pattern)
		}
		actual := mre.Match(chi)
		if actual != tc.expect {
			t.Errorf("Test %d: Expected %t but got %t (input=%s match=%v)",
				i, tc.expect, actual, tc.input, tc.pattern)
		}
	}
}

func TestRemoteIPMatcher(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	for i, tc := range []struct {
		ranges    []string
		notRanges []string
		input     string
		expect    bool
	}{
		{
			ranges: []string{"127.0.0.1"},
			input:  "127.0.0.1:12345",
			expect: true,
		},
		{
			ranges: []string{"127.0.0.1"},
			input:  "127.0.0.2:12345",
			expect: false,
		},
		{
			ranges: []string{"127.0.0.1/16"},
			input:  "127.0.1.23:12345",
			expect: true,
		},
		{
			ranges: []string{"127.0.0.1", "192.168.1.105"},
			input:  "192.168.1.105:12345",
			expect: true,
		},
		{
			notRanges: []string{"127.0.0.1"},
			input:     "127.0.0.1:12345",
			expect:    false,
		},
		{
			notRanges: []string{"127.0.0.2"},
			input:     "127.0.0.1:12345",
			expect:    true,
		},
		{
			ranges:    []string{"127.0.0.1"},
			notRanges: []string{"127.0.0.2"},
			input:     "127.0.0.1:12345",
			expect:    true,
		},
		{
			ranges:    []string{"127.0.0.2"},
			notRanges: []string{"127.0.0.2"},
			input:     "127.0.0.2:12345",
			expect:    false,
		},
		{
			ranges:    []string{"127.0.0.2"},
			notRanges: []string{"127.0.0.2"},
			input:     "127.0.0.3:12345",
			expect:    false,
		},
	} {
		matcher := MatchRemoteIP{Ranges: tc.ranges, NotRanges: tc.notRanges}
		err := matcher.Provision(ctx)
		if err != nil {
			t.Fatalf("Test %d: Provision failed: %v", i, err)
		}

		addr := testAddr(tc.input)
		chi := &tls.ClientHelloInfo{Conn: testConn{addr: addr}}

		actual := matcher.Match(chi)
		if actual != tc.expect {
			t.Errorf("Test %d: Expected %t but got %t (input=%s ranges=%v notRanges=%v)",
				i, tc.expect, actual, tc.input, tc.ranges, tc.notRanges)
		}
	}
}

func TestLocalIPMatcher(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	for i, tc := range []struct {
		ranges []string
		input  string
		expect bool
	}{
		{
			ranges: []string{"127.0.0.1"},
			input:  "127.0.0.1:12345",
			expect: true,
		},
		{
			ranges: []string{"127.0.0.1"},
			input:  "127.0.0.2:12345",
			expect: false,
		},
		{
			ranges: []string{"127.0.0.1/16"},
			input:  "127.0.1.23:12345",
			expect: true,
		},
		{
			ranges: []string{"127.0.0.1", "192.168.1.105"},
			input:  "192.168.1.105:12345",
			expect: true,
		},
		{
			input:  "127.0.0.1:12345",
			expect: true,
		},
		{
			ranges: []string{"127.0.0.1"},
			input:  "127.0.0.1:12345",
			expect: true,
		},
		{
			ranges: []string{"127.0.0.2"},
			input:  "127.0.0.3:12345",
			expect: false,
		},
		{
			ranges: []string{"127.0.0.2"},
			input:  "127.0.0.2",
			expect: true,
		},
		{
			ranges: []string{"127.0.0.2"},
			input:  "127.0.0.300",
			expect: false,
		},
	} {
		matcher := MatchLocalIP{Ranges: tc.ranges}
		err := matcher.Provision(ctx)
		if err != nil {
			t.Fatalf("Test %d: Provision failed: %v", i, err)
		}

		addr := testAddr(tc.input)
		chi := &tls.ClientHelloInfo{Conn: testConn{addr: addr}}

		actual := matcher.Match(chi)
		if actual != tc.expect {
			t.Errorf("Test %d: Expected %t but got %t (input=%s ranges=%v)",
				i, tc.expect, actual, tc.input, tc.ranges)
		}
	}
}

func TestNotMatcher(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	for i, tc := range []struct {
		config     string
		serverName string
		input      string
		expect     bool
	}{
		{
			config: `[]`,
			input:  "10.1.2.3:12345",
			expect: true,
		},
		{
			config: `[{"local_ip": {"ranges": ["10.1.2.3"]}}]`,
			input:  "10.1.2.3:12345",
			expect: false,
		},
		{
			config: `[{"local_ip": {"ranges": ["10.1.2.3"]}}]`,
			input:  "10.2.3.4:12345",
			expect: true,
		},
		{
			config:     `[{"remote_ip": {"ranges": ["10.0.0.0/8"]}, "sni": ["example.com"]}]`,
			serverName: "example.com",
			input:      "10.1.2.3:12345",
			expect:     false,
		},
		{
			config:     `[{"remote_ip": {"ranges": ["10.0.0.0/8"]}, "sni": ["example.com"]}]`,
			serverName: "example.net",
			input:      "10.1.2.3:12345",
			expect:     true,
		},
		{
			config:     `[{"remote_ip": {"ranges": ["10.0.0.0/8"]}}, {"sni": ["example.com"]}]`,
			serverName: "example.com",
			input:      "192.168.1.1:12345",
			expect:     false,
		},
		{
			config:     `[{"remote_ip": {"ranges": ["10.0.0.0/8"]}}, {"sni": ["example.com"]}]`,
			serverName: "example.net",
			input:      "192.168.1.1:12345",
			expect:     true,
		},
		{
			config: `[{"not": [{"remote_ip": {"ranges": ["10.0.0.0/8"]}}]}]`,
			input:  "10.1.2.3:12345",
			expect: true,
		},
	} {
		var matcher MatchNot
		if err := json.Unmarshal([]byte(tc.config), &matcher); err != nil {
			t.Fatalf("Test %d: unmarshaling config: %v", i, err)
		}
		if err := matcher.Provision(ctx); err != nil {
			t.Fatalf("Test %d: Provision failed: %v", i, err)
		}

		addr := testAddr(tc.input)
		chi := &tls.ClientHelloInfo{ServerName: tc.serverName, Conn: testConn{addr: addr}}

		actual := matcher.Match(chi)
		if actual != tc.expect {
			t.Errorf("Test %d: Expected %t but got %t (config=%s input=%s serverName=%s)",
				i, tc.expect, actual, tc.config, tc.input, tc.serverName)
		}
	}
}

func TestNotMatcherUnmarshalCaddyfile(t *testing.T) {
	for i, tc := range []struct {
		input   string
		expect  string
		wantErr bool
	}{
		{
			input:  `not local_ip 10.1.2.3`,
			expect: `[{"local_ip":{"ranges":["10.1.2.3"]}}]`,
		},
		{
			input: `not {
				remote_ip 10.0.0.0/8
				sni example.com
			}`,
			expect: `[{"remote_ip":{"ranges":["10.0.0.0/8"]},"sni":["example.com"]}]`,
		},
		{
			input: `not sni example.com
			not remote_ip 10.0.0.0/8`,
			expect: `[{"sni":["example.com"]},{"remote_ip":{"ranges":["10.0.0.0/8"]}}]`,
		},
		{
			input:  `not not sni example.com`,
			expect: `[{"not":[{"sni":["example.com"]}]}]`,
		},
		{
			input:   `not`,
			wantErr: true,
		},
		{
			input: `not {
			}`,
			wantErr: true,
		},
		{
			input:   `not foo`,
			wantErr: true,
		},
	} {
		var matcher MatchNot
		err := matcher.UnmarshalCaddyfile(caddyfile.NewTestDispenser(tc.input))
		if tc.wantErr {
			if err == nil {
				t.Errorf("Test %d: expected error but got none", i)
			}
			continue
		}
		if err != nil {
			t.Errorf("Test %d: unexpected error: %v", i, err)
			continue
		}

		actual, err := json.Marshal(matcher)
		if err != nil {
			t.Fatalf("Test %d: marshaling matcher: %v", i, err)
		}
		if string(actual) != tc.expect {
			t.Errorf("Test %d: expected %s, got %s", i, tc.expect, actual)
		}
	}
}

type testConn struct {
	*net.TCPConn
	addr testAddr
}

func (tc testConn) RemoteAddr() net.Addr { return tc.addr }
func (tc testConn) LocalAddr() net.Addr  { return tc.addr }

type testAddr string

func (testAddr) Network() string   { return "tcp" }
func (ta testAddr) String() string { return string(ta) }
