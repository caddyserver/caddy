// Copyright 2015 Matthew Holt and The Caddy Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package reverseproxy

import "testing"

func TestParseUpstreamDialAddress(t *testing.T) {
	for i, tc := range []struct {
		input          string
		expectHostPort string
		expectScheme   string
		expectErr      bool
	}{
		{
			input:          "foo",
			expectHostPort: "foo:80",
		},
		{
			input:          "foo:1234",
			expectHostPort: "foo:1234",
		},
		{
			input:          "127.0.0.1",
			expectHostPort: "127.0.0.1:80",
		},
		{
			input:          "127.0.0.1:1234",
			expectHostPort: "127.0.0.1:1234",
		},
		{
			input:          "[::1]",
			expectHostPort: "[::1]:80",
		},
		{
			input:          "[::1]:1234",
			expectHostPort: "[::1]:1234",
		},
		{
			input:          "{foo}",
			expectHostPort: "{foo}",
		},
		{
			input:          "{foo}:80",
			expectHostPort: "{foo}:80",
		},
		{
			input:          "{foo}:{bar}",
			expectHostPort: "{foo}:{bar}",
		},
		{
			input:          "http://foo",
			expectHostPort: "foo:80",
			expectScheme:   "http",
		},
		{
			input:          "http://foo:1234",
			expectHostPort: "foo:1234",
			expectScheme:   "http",
		},
		{
			input:          "http://127.0.0.1",
			expectHostPort: "127.0.0.1:80",
			expectScheme:   "http",
		},
		{
			input:          "http://127.0.0.1:1234",
			expectHostPort: "127.0.0.1:1234",
			expectScheme:   "http",
		},
		{
			input:          "http://[::1]",
			expectHostPort: "[::1]:80",
			expectScheme:   "http",
		},
		{
			input:          "http://[::1]:80",
			expectHostPort: "[::1]:80",
			expectScheme:   "http",
		},
		{
			input:          "https://foo",
			expectHostPort: "foo:443",
			expectScheme:   "https",
		},
		{
			input:          "https://foo:1234",
			expectHostPort: "foo:1234",
			expectScheme:   "https",
		},
		{
			input:          "https://127.0.0.1",
			expectHostPort: "127.0.0.1:443",
			expectScheme:   "https",
		},
		{
			input:          "https://127.0.0.1:1234",
			expectHostPort: "127.0.0.1:1234",
			expectScheme:   "https",
		},
		{
			input:          "https://[::1]",
			expectHostPort: "[::1]:443",
			expectScheme:   "https",
		},
		{
			input:          "https://[::1]:1234",
			expectHostPort: "[::1]:1234",
			expectScheme:   "https",
		},
		{
			input:          "h2c://foo",
			expectHostPort: "foo:80",
			expectScheme:   "h2c",
		},
		{
			input:          "h2c://foo:1234",
			expectHostPort: "foo:1234",
			expectScheme:   "h2c",
		},
		{
			input:          "h2c://127.0.0.1",
			expectHostPort: "127.0.0.1:80",
			expectScheme:   "h2c",
		},
		{
			input:          "h2c://127.0.0.1:1234",
			expectHostPort: "127.0.0.1:1234",
			expectScheme:   "h2c",
		},
		{
			input:          "h2c://[::1]",
			expectHostPort: "[::1]:80",
			expectScheme:   "h2c",
		},
		{
			input:          "h2c://[::1]:1234",
			expectHostPort: "[::1]:1234",
			expectScheme:   "h2c",
		},
		{
			input:          "localhost:1001-1009",
			expectHostPort: "localhost:1001-1009",
		},
		{
			input:          "{host}:1001-1009",
			expectHostPort: "{host}:1001-1009",
		},
		{
			input:          "http://localhost:1001-1009",
			expectHostPort: "localhost:1001-1009",
			expectScheme:   "http",
		},
		{
			input:          "https://localhost:1001-1009",
			expectHostPort: "localhost:1001-1009",
			expectScheme:   "https",
		},
		{
			input:          "unix//var/php.sock",
			expectHostPort: "unix//var/php.sock",
		},
		{
			input:          "unix+h2c//var/grpc.sock",
			expectHostPort: "unix//var/grpc.sock",
			expectScheme:   "h2c",
		},
		{
			input:          "unix/{foo}",
			expectHostPort: "unix/{foo}",
		},
		{
			input:          "unix+h2c/{foo}",
			expectHostPort: "unix/{foo}",
			expectScheme:   "h2c",
		},
		{
			input:          "unix//foo/{foo}/bar",
			expectHostPort: "unix//foo/{foo}/bar",
		},
		{
			input:          "unix+h2c//foo/{foo}/bar",
			expectHostPort: "unix//foo/{foo}/bar",
			expectScheme:   "h2c",
		},
		{
			input:     "http://{foo}",
			expectErr: true,
		},
		{
			input:     "http:// :80",
			expectErr: true,
		},
		{
			input:     "http://localhost/path",
			expectErr: true,
		},
		{
			input:     "http://localhost?key=value",
			expectErr: true,
		},
		{
			input:     "http://localhost#fragment",
			expectErr: true,
		},
		{
			input:     "http://localhost:8001-8002-8003",
			expectErr: true,
		},
		{
			input:     "http://localhost:8001-8002/foo:bar",
			expectErr: true,
		},
		{
			input:     "http://localhost:8001-8002/foo:1",
			expectErr: true,
		},
		{
			input:     "http://localhost:8001-8002/foo:1-2",
			expectErr: true,
		},
		{
			input:     "http://localhost:8001-8002#foo:1",
			expectErr: true,
		},
		{
			input:     "http://foo:443",
			expectErr: true,
		},
		{
			input:     "https://foo:80",
			expectErr: true,
		},
		{
			input:     "h2c://foo:443",
			expectErr: true,
		},
		{
			input:          `unix/c:\absolute\path`,
			expectHostPort: `unix/c:\absolute\path`,
		},
		{
			input:          `unix+h2c/c:\absolute\path`,
			expectHostPort: `unix/c:\absolute\path`,
			expectScheme:   "h2c",
		},
		{
			input:          "unix/c:/absolute/path",
			expectHostPort: "unix/c:/absolute/path",
		},
		{
			input:          "unix+h2c/c:/absolute/path",
			expectHostPort: "unix/c:/absolute/path",
			expectScheme:   "h2c",
		},
	} {
		actualAddr, err := parseUpstreamDialAddress(tc.input)
		if tc.expectErr && err == nil {
			t.Errorf("Test %d: Expected error but got %v", i, err)
		}
		if !tc.expectErr && err != nil {
			t.Errorf("Test %d: Expected no error but got %v", i, err)
		}
		if actualAddr.dialAddr() != tc.expectHostPort {
			t.Errorf("Test %d: input %s: Expected host and port '%s' but got '%s'", i, tc.input, tc.expectHostPort, actualAddr.dialAddr())
		}
		if actualAddr.scheme != tc.expectScheme {
			t.Errorf("Test %d: Expected scheme '%s' but got '%s'", i, tc.expectScheme, actualAddr.scheme)
		}
	}
}
