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
	"crypto/tls"
	"testing"
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
	} {
		chi := &tls.ClientHelloInfo{ServerName: tc.input}
		actual := MatchServerName(tc.names).Match(chi)
		if actual != tc.expect {
			t.Errorf("Test %d: Expected %t but got %t (input=%s match=%v)",
				i, tc.expect, actual, tc.input, tc.names)
		}
	}
}
